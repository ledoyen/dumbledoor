# Linux Platform Implementation Plan (Namespace-Based)

## Context

The Linux platform in `process-manager` is a full stub (hardcoded PID 12345, all no-ops). The goal is a real implementation using Linux PID namespaces for process isolation — no reaper, no shepherd binary. CI tests for Linux are disabled in the test matrix and must be re-enabled.

The mechanism mirrors what Docker does. A thin **namespace init** runs as PID 1 and the actual managed command runs as PID 2:

```
ProcessManager
  └── [clone NEWUSER|NEWPID] → namespace_init (PID 1)   ← PR_SET_PDEATHSIG(SIGKILL)
                                    └── [fork] → command (PID 2, actual managed process)
                                                    └── [fork] → grandchild (PID 3...)
                                                                     └── ...
```

- `PR_SET_PDEATHSIG(SIGKILL)` on the namespace init: dies when ProcessManager dies
- `PR_SET_CHILD_SUBREAPER(1)` on the namespace init: adopts orphaned processes instead of init(1)
- **Orphan safety**: if `command` exits early (e.g. `yarn start &`) but spawned background processes, those processes are reparented to the namespace init and keep running. Explicit `stop_process` kills the init → all namespace processes die.
- **Kill-9 guarantee**: ProcessManager SIGKILL'd → PR_SET_PDEATHSIG → init SIGKILL'd → kernel kills every remaining process in namespace

Kill guarantee matrix:
| Scenario | Covered by |
|---|---|
| Graceful stop of command + all descendants | `kill(init_pid, SIGTERM)` then `kill(init_pid, SIGKILL)` → PID 1 dies → kernel kills namespace |
| Command exits early, background processes survive | Init stays alive (subreaper), background procs reparented |
| Kill-9 of ProcessManager | `PR_SET_PDEATHSIG(SIGKILL)` → init dies → kernel kills namespace |

No external binary. The namespace init loop is implemented entirely inline in the `clone()` child path inside `unsafe-linux-process`.

---

## Files to Modify

1. **`unsafe-linux-process/src/lib.rs`** — New clone-based spawn with inline init loop
2. **`process-manager/src/platform/linux.rs`** — Full rewrite of all stubs
3. **`.github/workflows/ci.yml`** — Uncomment `ubuntu-latest`

No new binaries, no new crates.

---

## Part 1: `unsafe-linux-process/src/lib.rs`

### New types (Linux only, + stubs for non-Linux)

```rust
#[cfg(target_os = "linux")]
pub struct LinuxProcessConfig {
    pub command: String,
    pub args: Vec<String>,
    pub working_directory: Option<String>,
    pub environment: HashMap<String, String>,
    pub log_file: Option<String>,
}

#[cfg(target_os = "linux")]
pub struct LinuxSpawnResult {
    pub init_pid: u32,    // namespace PID 1 — kill this to stop everything
    pub command_pid: u32, // actual managed command (PID 2 in namespace, real PID in parent ns)
}
```

Non-Linux stubs have same struct shapes with no functional fields, and stub functions returning `Err(io::Error::new(Unsupported, ...))`.

### `safe_spawn_process(config: LinuxProcessConfig) -> Result<LinuxSpawnResult, UnsafeLinuxError>`

Uses `syscall(SYS_clone)` with `child_stack=0` (fork-style copy-on-write stack) for the init process, then a nested fork for the actual command.

**Setup pipes** (before clone):
- Sync pipe `(sync_r, sync_w)`: child waits for parent to write UID/GID mappings, then proceeds
- Comm pipe `(comm_r, comm_w)`: child writes command_pid to parent after forking grandchild

**clone() call**:
```rust
let init_pid = libc::syscall(
    libc::SYS_clone,
    (libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::SIGCHLD) as libc::c_long,
    0i64,  // child_stack=0 → copy-on-write (fork semantics)
    0i64,  // ptid = NULL
    0i64,  // ctid = NULL
    0i64,  // tls  = NULL
);
```

**In child** (init_pid == 0 path):
```
close(sync_w), close(comm_r)

// 1. Wait for parent to set up UID/GID mappings
read(sync_r, &mut byte, 1)
close(sync_r)

// 2. Setup init process
prctl(PR_SET_PDEATHSIG, SIGKILL)    // die when ProcessManager dies
prctl(PR_SET_CHILD_SUBREAPER, 1)    // adopt orphaned processes

// 3. Fork the actual command
let cmd_pid = fork()
if cmd_pid == 0 {   // grandchild: actual command
    prctl(PR_SET_PDEATHSIG, SIGKILL)  // also die if init dies
    setpgid(0, 0)
    chdir(working_dir) if set
    if log_file: open + dup2 stdout/stderr
    build argv/envp (CString arrays)
    execve(command, argv, envp)
    _exit(1)  // exec failed
}

// 4. Send command PID to parent
write(comm_w, &cmd_pid.to_ne_bytes(), 4)
close(comm_w)

// 5. Namespace init loop: reap orphaned processes, stay alive
loop {
    let pid = waitpid(-1, &mut status, 0)
    if pid == -1 && errno == ECHILD {
        pause()  // no children, sleep until signalled
    }
    // loop back to waitpid (reap next orphan or wait for more)
}
```

**In parent** (init_pid > 0 path):
```
close(sync_r), close(comm_w)

// Set up UID/GID mappings for child (user namespace requirement)
write_file("/proc/{init_pid}/uid_map", "{uid} {uid} 1\n")
write_file("/proc/{init_pid}/setgroups", "deny\n")        // required before gid_map
write_file("/proc/{init_pid}/gid_map", "{gid} {gid} 1\n")

// Signal child to proceed
write(sync_w, &[0u8], 1)
close(sync_w)

// Read command PID from child
read(comm_r, &mut buf, 4) → command_pid
close(comm_r)

Ok(LinuxSpawnResult { init_pid: init_pid as u32, command_pid })
```

Identity UID/GID mapping (`{uid} {uid} 1`) preserves the user's actual permissions inside the namespace.

### Additional new functions

**`safe_become_subreaper() -> Result<(), UnsafeLinuxError>`**
- `prctl(PR_SET_CHILD_SUBREAPER, 1)` — makes ProcessManager the reaper for all orphaned grandchildren (including namespace processes after their init dies)
- Called once in `LinuxPlatformManager::new()`

**`safe_send_signal(pid: u32, signal: i32) -> Result<(), UnsafeLinuxError>`**
- `libc::kill(pid, signal)`, ESRCH → Ok (already gone)

**`safe_try_wait(pid: u32) -> Result<Option<ExitInfo>, UnsafeLinuxError>`**
- `waitpid(pid, &mut status, WNOHANG)` → None if running, Some(ExitInfo) if exited

**`safe_wait(pid: u32) -> Result<ExitInfo, UnsafeLinuxError>`**
- `waitpid(pid, &mut status, 0)` (blocking)

**`safe_reap_orphans() -> Vec<(u32, ExitInfo)>`**
- `waitpid(-1, WNOHANG)` in a loop until ECHILD — reaps all available zombie children
- Returns list of `(reaped_pid, exit_info)` so callers can update state
- Called after killing init to reap orphaned namespace processes that were reparented to ProcessManager

**`safe_is_process_running(pid: u32) -> bool`**
- `kill(pid, 0)` → true if exists, false if ESRCH

**`safe_install_signal_handlers(handler: extern "C" fn(libc::c_int)) -> Result<(), UnsafeLinuxError>`**
- Install SIGTERM + SIGINT handlers via `libc::sigaction` (same pattern as `unsafe-macos-process`)

**`safe_cleanup_process_group() -> Result<(), UnsafeLinuxError>`**
- `kill(-getpgrp(), SIGKILL)` for ProcessManager's SIGTERM/SIGINT handler

**`safe_scan_proc_for_children(parent_pid: u32) -> Vec<u32>`** (safe Rust)
- Read `/proc/*/status`, find `PPid: {parent_pid}` lines

**`ExitInfo` struct** (Linux only):
```rust
pub struct ExitInfo {
    pub exit_code: Option<i32>,   // from WEXITSTATUS
    pub signal: Option<i32>,      // from WTERMSIG
}
```

All new functions have `#[cfg(not(target_os = "linux"))]` stubs.

---

## Part 2: `process-manager/src/platform/linux.rs` — Full Rewrite

### Updated structs

```rust
#[derive(Debug, Clone)]
enum CachedExitStatus {
    Running,
    Exited { exit_code: i32, exit_time: SystemTime },
    Terminated { signal: Option<i32>, exit_time: SystemTime },
}

#[derive(Debug)]
struct LinuxProcessState {
    init_pid: u32,       // namespace PID 1 — what we kill to stop everything
    command_pid: u32,    // actual command's real PID (for reporting)
    cached_status: CachedExitStatus,
}

#[derive(Debug, Clone)]
pub struct LinuxProcess {
    init_pid: u32,    // internal tracking key
    command_pid: u32, // reported via pid() for user visibility
}
// PlatformProcess::pid() returns self.command_pid
```

`LinuxPlatformManager`:
- Remove `use_namespaces` and `namespace_fd` (always namespace-based now)
- Keep `process_state: Arc<RwLock<HashMap<u32, LinuxProcessState>>>` keyed by `init_pid`
- Add `cleanup_handler_installed: Arc<RwLock<bool>>`
- `new()` calls `safe_become_subreaper()` so orphaned namespace children are reparented to ProcessManager when their namespace init dies

### Method implementations

**`spawn_process`**:
1. Convert `ProcessConfig` → `LinuxProcessConfig`
2. Call `unsafe_linux_process::safe_spawn_process(config)` → `LinuxSpawnResult { init_pid, command_pid }`
3. Store `LinuxProcessState { init_pid, command_pid, cached_status: Running }` keyed by `init_pid`
4. Return `LinuxProcess { init_pid, command_pid }`

**`query_process_status`**:
- Status is driven by the **init process**: init alive = namespace active
- Look up state by `process.init_pid`
- If cached Exited/Terminated: return it
- Call `safe_try_wait(init_pid)`:
  - None → `Running { pid: process.command_pid }`
  - Some(exit_info) → cache and return `Exited { exit_code }` or `Terminated { signal }`

Note: `Running` is returned even if the original command exited early (e.g. `yarn start`) as long as the init (and thus the namespace with background processes) is alive.

**`terminate_process(graceful)`**:
1. Look up state by `init_pid`. If already Exited/Terminated: return Ok
2. Graceful: `safe_send_signal(init_pid, SIGTERM)`, poll `safe_is_process_running(init_pid)` up to 5s, then fall through to forced
3. Forced: `safe_send_signal(init_pid, SIGKILL)`
4. `safe_wait(init_pid)` — blocks until init is confirmed dead. At this point, kernel has sent SIGKILL to all remaining namespace processes; they are reparented to ProcessManager (subreaper).
5. Call `safe_reap_orphans()` — `waitpid(-1, WNOHANG)` loop to reap all namespace orphans. When this returns with ECHILD, all namespace processes are confirmed gone.
6. Cache exit status, remove from `process_state`
7. Return `Ok(())` — at this point all processes are deterministically gone, no polling needed in callers

**`cleanup_all_processes`**:
- For each process: `safe_send_signal(init_pid, SIGKILL)` + `safe_wait(init_pid)`
- Then `safe_reap_orphans()` once to catch all reparented children
- Clear map

**`setup_cleanup_handler`**:
- Idempotent via `cleanup_handler_installed`
- Call `safe_install_signal_handlers(cleanup_signal_handler)`
- Handler: calls `safe_cleanup_process_group()` (kills ProcessManager's own pgid on SIGTERM/SIGINT)

**`get_child_processes`**:
- `safe_scan_proc_for_children(process.command_pid)`

**`needs_reaper`**: `false`

**`create_process_group`**: unchanged

### Helper methods

```rust
fn convert_config(config: &ProcessConfig) -> LinuxProcessConfig { ... }
fn convert_error(e: UnsafeLinuxError) -> PlatformError { ... }
```

Mirror `MacOSPlatformManager::convert_config` / `convert_error` from `process-manager/src/platform/macos.rs`.

### Unit test updates

- Remove all tests asserting `pid == 12345` or creating fake `LinuxProcess { pid: 1234 }`
- Remove `test_namespace_detection` (field `use_namespaces` no longer exists)
- Add `test_process_spawning`: spawn real `/bin/echo`, assert `pid > 0`, status becomes Exited
- Keep structural tests: `test_linux_platform_manager_creation`, `test_reaper_requirement`

---

## Part 3: `.github/workflows/ci.yml`

```yaml
matrix:
  os:
    - ubuntu-latest    # re-enabled: Linux platform now fully implemented with PID namespaces
    - macos-latest
    - windows-latest
```

---

## Cross-Platform Safety Checklist

- `LinuxProcessConfig`, `LinuxSpawnResult`, `ExitInfo` + all new functions have `#[cfg(not(target_os = "linux"))]` stubs
- `linux.rs` is `#[cfg(target_os = "linux")]` — not compiled on macOS/Windows
- `libc::SYS_clone` is Linux-only in libc crate — correctly cfg-gated ✓
- `libc` dep in `process-manager` is `[target.'cfg(unix)'.dependencies]` — Linux is Unix ✓
- No new crate dependencies needed
- The inline init loop uses only async-signal-safe libc calls (no Rust stdlib allocations after fork/clone)

---

## E2E Test Gap Analysis

### Existing tests — what they cover

| Test | Covers |
|---|---|
| `test_basic_process_lifecycle` | spawn, Running status, graceful stop |
| `test_multiple_process_management` | concurrent processes, bulk termination |
| `test_process_configuration_features` | env vars, working directory, log redirection |
| `test_error_handling_and_edge_cases` | invalid commands, nonexistent handles, shared state |
| `test_sigkill_cleanup_guarantee` | kill-9 of parent → direct children die |
| `test_rapid_spawn_terminate` | 50 rapid cycles, zombie accumulation |

### Gap: orphan survival + cleanup (NEW TEST REQUIRED)

### New test: `test_early_exit_orphan_cleanup` (all platforms)

To add to `e2e_test.rs`.

**Algorithm**:
```
1. Create tmp file: orphan_pid_file
2. Start a command that backgrounds a long-running process, writes its PID to orphan_pid_file, then exits with code 0
3. Wait for orphan_pid_file to appear (timeout 5s) → confirms command ran and exited
4. Read orphan_pid from file
5. Assert orphan is still running (survived launcher's exit, reparented to namespace init)
6. Query ProcessManager status → assert Running (namespace init still alive)
7. stop_process(handle) — synchronous, blocks until ALL namespace processes are confirmed dead
8. Assert immediately (no sleep, no polling): process_exists(orphan_pid) == false
```

**Platform-specific commands** (add to `PlatformCommands` in `common/mod.rs`):

```
// Linux/macOS:
background_launcher: sh -c "/bin/sleep 3600 & echo $! > {orphan_pid_file}"

// Windows:
background_launcher: powershell -Command "$p = Start-Process ping -ArgumentList '127.0.0.1 -n 3600' -PassThru -WindowStyle Hidden; $p.Id | Set-Content '{orphan_pid_file}'"
```

---

## Verification

```sh
just format
just lint
just test-unit       # updated unit tests in linux.rs
just test-e2e        # all 7 e2e tests (6 existing + test_early_exit_orphan_cleanup)
just check-cross     # cross-compile Linux + Windows + macOS
```

Key acceptance criteria:
- `test_sigkill_cleanup_guarantee`: kill victim → all `sleep` children die within 5s
- `test_rapid_spawn_terminate`: 50 spawn/stop cycles without zombie accumulation
- `test_basic_process_lifecycle`: real PID > 0, real status, real termination
- `test_early_exit_orphan_cleanup`: launcher exits early, orphan survives, orphan dies immediately on stop (no polling)

---

## Critical Reference Files

- `unsafe-macos-process/src/lib.rs` — fork/execve pattern, signal blocking, argv/envp CString setup, waitpid macros
- `process-manager/src/platform/macos.rs` — `convert_config`, `convert_error`, `cleanup_handler_installed` pattern
- `process-manager/tests/e2e_test.rs` — acceptance tests (especially `test_sigkill_cleanup_guarantee`)
- `process-manager/tests/test_victims/sigkill_victim.rs` — kill-9 proof stack end-to-end
