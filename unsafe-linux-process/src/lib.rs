//! Unsafe Linux process management operations with safe wrappers
//!
//! This crate provides safe wrappers around unsafe Linux system calls for process management.
//! All unsafe operations are contained within this crate and exposed through safe APIs.

// ─── Linux implementation ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

/// Errors that can occur during unsafe Linux operations
#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
pub enum UnsafeLinuxError {
    #[error("System call failed: {syscall}: {errno}")]
    SystemCallFailed { syscall: String, errno: i32 },

    #[error("Invalid parameter: {details}")]
    InvalidParameter { details: String },

    #[error("Process not found")]
    ProcessNotFound,

    #[error("Permission denied: {operation}")]
    PermissionDenied { operation: String },
}

/// Configuration for spawning a Linux process inside a PID namespace
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct LinuxProcessConfig {
    /// Command to execute
    pub command: String,
    /// Command line arguments (not including argv\[0\])
    pub args: Vec<String>,
    /// Working directory (None = current directory)
    pub working_directory: Option<String>,
    /// Environment variables
    pub environment: HashMap<String, String>,
    /// Optional log file for stdout/stderr redirection
    pub log_file: Option<String>,
}

/// Result of spawning a Linux process in a PID namespace
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct LinuxSpawnResult {
    /// PID of the namespace init (PID 1 in namespace). Kill this to stop everything.
    pub init_pid: u32,
    /// PID of the actual managed command (PID 2 in namespace, real PID in parent ns).
    pub command_pid: u32,
}

/// Exit information for a waited process
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct ExitInfo {
    /// Exit code if process exited normally
    pub exit_code: Option<i32>,
    /// Signal number if process was killed by signal
    pub signal: Option<i32>,
}

/// Spawn a process inside a new PID + user namespace (Docker-style isolation).
///
/// Architecture:
///   ProcessManager
///     └── [clone NEWUSER|NEWPID] → namespace_init (PID 1)  ← PR_SET_PDEATHSIG(SIGKILL)
///                                       └── \[fork\] → command (PID 2, the managed process)
///
/// - When ProcessManager dies (even SIGKILL), kernel kills namespace_init via PR_SET_PDEATHSIG,
///   which kills every process in the namespace.
/// - When command exits early but spawned background jobs, those are reparented to namespace_init
///   (which stays alive as subreaper), so they survive until explicit stop_process.
/// - CLONE_NEWUSER enables unprivileged namespace creation (no root required).
#[cfg(target_os = "linux")]
pub fn safe_spawn_process(
    config: LinuxProcessConfig,
) -> Result<LinuxSpawnResult, UnsafeLinuxError> {
    if config.command.is_empty() {
        return Err(UnsafeLinuxError::InvalidParameter {
            details: "Command cannot be empty".to_string(),
        });
    }

    // Pre-build all CStrings before fork so we don't allocate after clone.
    let command_cstr =
        CString::new(config.command.as_str()).map_err(|_| UnsafeLinuxError::InvalidParameter {
            details: "Command contains null bytes".to_string(),
        })?;

    let mut args_cstrings = vec![command_cstr.clone()]; // argv[0] = command
    for arg in &config.args {
        args_cstrings.push(CString::new(arg.as_str()).map_err(|_| {
            UnsafeLinuxError::InvalidParameter {
                details: format!("Argument '{}' contains null bytes", arg),
            }
        })?);
    }

    let mut env_cstrings: Vec<CString> = Vec::new();
    for (k, v) in &config.environment {
        env_cstrings.push(CString::new(format!("{}={}", k, v)).map_err(|_| {
            UnsafeLinuxError::InvalidParameter {
                details: format!("Environment variable '{}={}' contains null bytes", k, v),
            }
        })?);
    }

    let working_dir_cstr: Option<CString> = match &config.working_directory {
        Some(wd) => {
            Some(
                CString::new(wd.as_str()).map_err(|_| UnsafeLinuxError::InvalidParameter {
                    details: "Working directory contains null bytes".to_string(),
                })?,
            )
        }
        None => None,
    };

    // Open log file in parent before clone so errors are reported early.
    let log_file = if let Some(ref path) = config.log_file {
        Some(
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(path)
                .map_err(|e| UnsafeLinuxError::SystemCallFailed {
                    syscall: "open(log_file)".to_string(),
                    errno: e.raw_os_error().unwrap_or(libc::EIO),
                })?,
        )
    } else {
        None
    };

    // sync_pipe: parent signals child after UID/GID mappings are written.
    // comm_pipe: child sends command_pid (4 bytes) back to parent.
    let (sync_r, sync_w) = create_pipe()?;
    let (comm_r, comm_w) = create_pipe()?;

    // Block signals before clone so the namespace init does not receive a
    // signal before it has set up PR_SET_PDEATHSIG / reset handlers.
    let orig_mask = block_signals_for_fork();

    // Clone with CLONE_NEWUSER | CLONE_NEWPID | SIGCHLD.
    // child_stack = 0 → copy-on-write (same semantics as fork).
    let init_pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            (libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::SIGCHLD) as libc::c_long,
            0i64, // child_stack = 0 → copy-on-write
            0i64, // ptid  = NULL
            0i64, // ctid  = NULL
            0i64, // tls   = NULL
        )
    };

    if init_pid == -1 {
        unsafe { libc::sigprocmask(libc::SIG_SETMASK, &orig_mask, std::ptr::null_mut()) };
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        unsafe {
            libc::close(sync_r);
            libc::close(sync_w);
            libc::close(comm_r);
            libc::close(comm_w);
        }
        return Err(UnsafeLinuxError::SystemCallFailed {
            syscall: "clone(NEWUSER|NEWPID)".to_string(),
            errno,
        });
    }

    if init_pid == 0 {
        // ── Child (namespace init, PID 1 in new namespace) ──────────────────
        // IMPORTANT: must only use async-signal-safe functions here.
        unsafe {
            libc::close(sync_w);
            libc::close(comm_r);

            // Reset signal handlers to SIG_DFL before restoring the mask.
            // The parent may have installed custom handlers (e.g. SIGTERM →
            // kill-process-group). If those fire in the namespace init before
            // exec(), they would signal the parent's process group, killing
            // the test binary. execve() resets handlers automatically for the
            // grandchild, but the namespace init never calls execve().
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGHUP, libc::SIG_DFL);

            // Restore signal mask before any prctl calls.
            libc::sigprocmask(libc::SIG_SETMASK, &orig_mask, std::ptr::null_mut());

            // Wait for parent to write UID/GID mappings.
            let mut byte: u8 = 0;
            libc::read(sync_r, &mut byte as *mut u8 as *mut libc::c_void, 1);
            libc::close(sync_r);

            // Become namespace init: die when ProcessManager dies, adopt orphans.
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

            // Fork the actual command (becomes PID 2 in namespace).
            let cmd_pid = libc::fork();

            if cmd_pid == 0 {
                // ── Grandchild: the actual managed command ───────────────────
                libc::close(comm_w);

                // Die if namespace init dies.
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);

                // Own process group.
                libc::setpgid(0, 0);

                // Reset signal handlers to default.
                libc::signal(libc::SIGTERM, libc::SIG_DFL);
                libc::signal(libc::SIGINT, libc::SIG_DFL);

                // Set working directory.
                if let Some(ref wd) = working_dir_cstr {
                    libc::chdir(wd.as_ptr());
                }

                // Redirect stdout/stderr.
                if let Some(ref lf) = log_file {
                    let fd = lf.as_raw_fd();
                    libc::dup2(fd, libc::STDOUT_FILENO);
                    libc::dup2(fd, libc::STDERR_FILENO);
                } else {
                    let dev_null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
                    if dev_null != -1 {
                        libc::dup2(dev_null, libc::STDOUT_FILENO);
                        libc::dup2(dev_null, libc::STDERR_FILENO);
                        libc::close(dev_null);
                    }
                }

                // Build argv / envp and exec.
                let mut argv: Vec<*const libc::c_char> =
                    args_cstrings.iter().map(|s| s.as_ptr()).collect();
                argv.push(std::ptr::null());

                let envp: Vec<*const libc::c_char> = if env_cstrings.is_empty() {
                    // Minimal fallback environment.
                    let path = CString::new("PATH=/usr/bin:/bin").unwrap();
                    vec![path.as_ptr(), std::ptr::null()]
                } else {
                    let mut v: Vec<*const libc::c_char> =
                        env_cstrings.iter().map(|s| s.as_ptr()).collect();
                    v.push(std::ptr::null());
                    v
                };

                libc::execve(command_cstr.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127); // exec failed
            }

            // ── Namespace init loop ──────────────────────────────────────────
            // Send command PID to parent.
            let cmd_pid_u32 = cmd_pid as u32;
            let bytes = cmd_pid_u32.to_ne_bytes();
            libc::write(comm_w, bytes.as_ptr() as *const libc::c_void, 4);
            libc::close(comm_w);

            // Reap orphaned processes and stay alive until killed.
            loop {
                let mut status: libc::c_int = 0;
                let pid = libc::waitpid(-1, &mut status, 0);
                if pid == -1 {
                    let err = *libc::__errno_location();
                    if err == libc::ECHILD {
                        // No more children — park until we receive a signal.
                        libc::pause();
                    }
                    // Other errors: loop and try again.
                }
            }
        }
    }

    // ── Parent ───────────────────────────────────────────────────────────────
    unsafe {
        libc::sigprocmask(libc::SIG_SETMASK, &orig_mask, std::ptr::null_mut());
        libc::close(sync_r);
        libc::close(comm_w);
    }

    let init_pid_u32 = init_pid as u32;

    // Write UID/GID mappings so the namespace process runs with our identity.
    write_uid_gid_mappings(init_pid_u32)?;

    // Signal the child to proceed.
    unsafe {
        let byte: u8 = 1;
        libc::write(sync_w, &byte as *const u8 as *const libc::c_void, 1);
        libc::close(sync_w);
    }

    // Read command PID from child.
    let command_pid = unsafe {
        let mut buf = [0u8; 4];
        let n = libc::read(comm_r, buf.as_mut_ptr() as *mut libc::c_void, 4);
        libc::close(comm_r);
        if n != 4 {
            return Err(UnsafeLinuxError::SystemCallFailed {
                syscall: "read(comm_pipe)".to_string(),
                errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
            });
        }
        u32::from_ne_bytes(buf)
    };

    if command_pid == 0 {
        return Err(UnsafeLinuxError::SystemCallFailed {
            syscall: "fork(command)".to_string(),
            errno: libc::ECHILD,
        });
    }

    Ok(LinuxSpawnResult {
        init_pid: init_pid_u32,
        command_pid,
    })
}

/// Write identity UID/GID mappings into the child's user namespace.
#[cfg(target_os = "linux")]
fn write_uid_gid_mappings(child_pid: u32) -> Result<(), UnsafeLinuxError> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // uid_map: "inside_uid outside_uid count"
    let uid_map = format!("{} {} 1\n", uid, uid);
    std::fs::write(format!("/proc/{}/uid_map", child_pid), &uid_map).map_err(|e| {
        UnsafeLinuxError::SystemCallFailed {
            syscall: "write(uid_map)".to_string(),
            errno: e.raw_os_error().unwrap_or(libc::EIO),
        }
    })?;

    // Must write "deny" to setgroups before writing gid_map (kernel requirement).
    std::fs::write(format!("/proc/{}/setgroups", child_pid), "deny\n").map_err(|e| {
        UnsafeLinuxError::SystemCallFailed {
            syscall: "write(setgroups)".to_string(),
            errno: e.raw_os_error().unwrap_or(libc::EIO),
        }
    })?;

    let gid_map = format!("{} {} 1\n", gid, gid);
    std::fs::write(format!("/proc/{}/gid_map", child_pid), &gid_map).map_err(|e| {
        UnsafeLinuxError::SystemCallFailed {
            syscall: "write(gid_map)".to_string(),
            errno: e.raw_os_error().unwrap_or(libc::EIO),
        }
    })?;

    Ok(())
}

/// Block SIGTERM/SIGINT/SIGHUP before fork/clone; returns the old mask to restore later.
#[cfg(target_os = "linux")]
fn block_signals_for_fork() -> libc::sigset_t {
    unsafe {
        let mut block_set: libc::sigset_t = std::mem::zeroed();
        let mut orig_mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut block_set);
        libc::sigaddset(&mut block_set, libc::SIGTERM);
        libc::sigaddset(&mut block_set, libc::SIGINT);
        libc::sigaddset(&mut block_set, libc::SIGHUP);
        libc::sigprocmask(libc::SIG_BLOCK, &block_set, &mut orig_mask);
        orig_mask
    }
}

/// Create a pipe; returns (read_fd, write_fd).
#[cfg(target_os = "linux")]
fn create_pipe() -> Result<(i32, i32), UnsafeLinuxError> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(UnsafeLinuxError::SystemCallFailed {
            syscall: "pipe".to_string(),
            errno,
        });
    }
    Ok((fds[0], fds[1]))
}

/// Make the calling process a subreaper: orphaned grandchildren will be reparented to us
/// instead of to the system init. Required so we can reap namespace orphans after init dies.
#[cfg(target_os = "linux")]
pub fn safe_become_subreaper() -> Result<(), UnsafeLinuxError> {
    let ret = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    if ret == -1 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(UnsafeLinuxError::SystemCallFailed {
            syscall: "prctl(PR_SET_CHILD_SUBREAPER)".to_string(),
            errno,
        });
    }
    Ok(())
}

/// Send a signal to a process. ESRCH (process already gone) is treated as success.
#[cfg(target_os = "linux")]
pub fn safe_send_signal(pid: u32, signal: i32) -> Result<(), UnsafeLinuxError> {
    let ret = unsafe { libc::kill(pid as libc::pid_t, signal) };
    if ret == -1 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::ESRCH {
            return Ok(());
        }
        if errno == libc::EPERM {
            return Err(UnsafeLinuxError::PermissionDenied {
                operation: format!("kill({}, {})", pid, signal),
            });
        }
        return Err(UnsafeLinuxError::SystemCallFailed {
            syscall: format!("kill({}, {})", pid, signal),
            errno,
        });
    }
    Ok(())
}

/// Non-blocking wait: returns None if process is still running, Some(ExitInfo) if it exited.
#[cfg(target_os = "linux")]
pub fn safe_try_wait(pid: u32) -> Result<Option<ExitInfo>, UnsafeLinuxError> {
    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
    match ret {
        -1 => {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::ECHILD {
                // Not our child or already reaped — treat as exited.
                return Ok(Some(ExitInfo {
                    exit_code: None,
                    signal: None,
                }));
            }
            Err(UnsafeLinuxError::SystemCallFailed {
                syscall: "waitpid(WNOHANG)".to_string(),
                errno,
            })
        }
        0 => Ok(None), // still running
        _ => Ok(Some(decode_wait_status(status))),
    }
}

/// Blocking wait: blocks until the process exits and returns its exit info.
#[cfg(target_os = "linux")]
pub fn safe_wait(pid: u32) -> Result<ExitInfo, UnsafeLinuxError> {
    let mut status: libc::c_int = 0;
    loop {
        let ret = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
        if ret == -1 {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::EINTR {
                continue; // interrupted by signal, retry
            }
            if errno == libc::ECHILD {
                return Ok(ExitInfo {
                    exit_code: None,
                    signal: None,
                });
            }
            return Err(UnsafeLinuxError::SystemCallFailed {
                syscall: "waitpid".to_string(),
                errno,
            });
        }
        return Ok(decode_wait_status(status));
    }
}

/// Reap all zombie children (non-blocking). Returns the list of (pid, ExitInfo) reaped.
/// Call after safe_wait(init_pid) to drain orphaned namespace processes reparented to us.
#[cfg(target_os = "linux")]
pub fn safe_reap_orphans() -> Vec<(u32, ExitInfo)> {
    let mut reaped = Vec::new();
    loop {
        let mut status: libc::c_int = 0;
        let ret = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        match ret {
            -1 | 0 => break, // ECHILD or nothing pending
            pid => reaped.push((pid as u32, decode_wait_status(status))),
        }
    }
    reaped
}

/// Decode a raw waitpid status integer into an ExitInfo.
#[cfg(target_os = "linux")]
fn decode_wait_status(status: libc::c_int) -> ExitInfo {
    if libc::WIFEXITED(status) {
        ExitInfo {
            exit_code: Some(libc::WEXITSTATUS(status)),
            signal: None,
        }
    } else if libc::WIFSIGNALED(status) {
        ExitInfo {
            exit_code: None,
            signal: Some(libc::WTERMSIG(status)),
        }
    } else {
        ExitInfo {
            exit_code: Some(-1),
            signal: None,
        }
    }
}

/// Returns true if the process exists (kill -0 succeeds or EPERM).
#[cfg(target_os = "linux")]
pub fn safe_is_process_running(pid: u32) -> bool {
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if ret == 0 {
        return true;
    }
    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    errno == libc::EPERM // process exists but we lack permission
}

/// Install SIGTERM and SIGINT handlers for graceful cleanup.
#[cfg(target_os = "linux")]
pub fn safe_install_signal_handlers(
    handler: extern "C" fn(libc::c_int),
) -> Result<(), UnsafeLinuxError> {
    let handler_fn = libc::SIG_DFL; // placeholder for type inference
    let _ = handler_fn;

    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = handler as libc::sighandler_t;
    unsafe {
        libc::sigemptyset(&mut sa.sa_mask);
    }
    sa.sa_flags = libc::SA_RESTART;

    for &sig in &[libc::SIGTERM, libc::SIGINT] {
        if unsafe { libc::sigaction(sig, &sa, std::ptr::null_mut()) } == -1 {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(UnsafeLinuxError::SystemCallFailed {
                syscall: format!("sigaction({})", sig),
                errno,
            });
        }
    }
    Ok(())
}

/// Kill all processes in the ProcessManager's own process group (used in signal handlers).
#[cfg(target_os = "linux")]
pub fn safe_cleanup_process_group() -> Result<(), UnsafeLinuxError> {
    let pgid = unsafe { libc::getpgrp() };
    let ret = unsafe { libc::kill(-pgid, libc::SIGKILL) };
    if ret == -1 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::ESRCH {
            return Ok(());
        }
        return Err(UnsafeLinuxError::SystemCallFailed {
            syscall: "kill(-pgid, SIGKILL)".to_string(),
            errno,
        });
    }
    Ok(())
}

/// Scan /proc to find PIDs whose parent is `parent_pid`. Pure safe Rust.
#[cfg(target_os = "linux")]
pub fn safe_scan_proc_for_children(parent_pid: u32) -> Vec<u32> {
    let ppid_line = format!("PPid:\t{}", parent_pid);
    let mut children = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return children;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        let status_path = format!("/proc/{}/status", pid);
        if let Ok(content) = std::fs::read_to_string(&status_path) {
            if content.lines().any(|l| l == ppid_line) {
                children.push(pid);
            }
        }
    }
    children
}

// ─── Existing functions kept as-is ───────────────────────────────────────────

/// Safely check if a process is alive
#[cfg(target_os = "linux")]
pub fn safe_is_process_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Safely get the current process group ID
#[cfg(target_os = "linux")]
pub fn safe_get_process_group() -> i32 {
    unsafe { libc::getpgrp() }
}

/// Safely get the parent process ID
#[cfg(target_os = "linux")]
pub fn safe_get_parent_pid() -> u32 {
    unsafe { libc::getppid() as u32 }
}

/// Safely send SIGKILL to a process
#[cfg(target_os = "linux")]
pub fn safe_force_kill_process(pid: u32) -> Result<(), UnsafeLinuxError> {
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if result == -1 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::ESRCH {
            return Ok(());
        }
        return Err(UnsafeLinuxError::SystemCallFailed {
            syscall: "kill(SIGKILL)".to_string(),
            errno,
        });
    }
    Ok(())
}

/// Safely kill all processes in the current process group
#[cfg(target_os = "linux")]
pub fn safe_kill_process_group() -> Result<(), UnsafeLinuxError> {
    let process_group = unsafe { libc::getpgrp() };
    let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if result == -1 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::ESRCH {
            return Ok(());
        }
        return Err(UnsafeLinuxError::SystemCallFailed {
            syscall: "kill(-pgid, SIGKILL)".to_string(),
            errno,
        });
    }
    Ok(())
}

/// Safely create a new process group for the current process
#[cfg(target_os = "linux")]
pub fn safe_create_process_group() -> Result<i32, UnsafeLinuxError> {
    let pid = unsafe { libc::getpid() };
    if unsafe { libc::setpgid(pid, pid) } == -1 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(UnsafeLinuxError::SystemCallFailed {
            syscall: "setpgid".to_string(),
            errno,
        });
    }
    Ok(pid)
}

// ─── Non-Linux stubs ─────────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone)]
pub struct LinuxProcessConfig {
    pub command: String,
    pub args: Vec<String>,
    pub working_directory: Option<String>,
    pub environment: std::collections::HashMap<String, String>,
    pub log_file: Option<String>,
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct LinuxSpawnResult {
    pub init_pid: u32,
    pub command_pid: u32,
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone)]
pub struct ExitInfo {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

#[cfg(not(target_os = "linux"))]
pub fn safe_spawn_process(_config: LinuxProcessConfig) -> Result<LinuxSpawnResult, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Linux process spawning not supported on this platform",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn safe_become_subreaper() -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Not supported on this platform",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn safe_send_signal(_pid: u32, _signal: i32) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Not supported on this platform",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn safe_try_wait(_pid: u32) -> Result<Option<ExitInfo>, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Not supported on this platform",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn safe_wait(_pid: u32) -> Result<ExitInfo, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Not supported on this platform",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn safe_reap_orphans() -> Vec<(u32, ExitInfo)> {
    Vec::new()
}

#[cfg(not(target_os = "linux"))]
pub fn safe_is_process_running(_pid: u32) -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
pub fn safe_install_signal_handlers(_handler: extern "C" fn(i32)) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Not supported on this platform",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn safe_cleanup_process_group() -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Not supported on this platform",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn safe_scan_proc_for_children(_parent_pid: u32) -> Vec<u32> {
    Vec::new()
}

#[cfg(not(target_os = "linux"))]
pub fn safe_is_process_alive(_pid: u32) -> bool {
    false
}

#[cfg(not(target_os = "linux"))]
pub fn safe_get_process_group() -> i32 {
    -1
}

#[cfg(not(target_os = "linux"))]
pub fn safe_get_parent_pid() -> u32 {
    0
}

#[cfg(not(target_os = "linux"))]
pub fn safe_force_kill_process(_pid: u32) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Force kill not supported on this platform",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn safe_kill_process_group() -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Process group kill not supported on this platform",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn safe_create_process_group() -> Result<i32, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Process groups not supported on this platform",
    ))
}
