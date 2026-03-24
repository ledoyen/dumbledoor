# Dumbledoor - Agent Development Guide

## Project Overview

Dumbledoor is a cross-platform daemon that supplies application requirements (databases, etc.) just-in-time for developer apps.

The `process-manager` crate handles OS-specific process lifecycle management.

## Architecture: Platform Isolation

```
process-manager (100% safe Rust, zero unsafe blocks)
├── src/platform/linux.rs   ← cfg(target_os = "linux")
├── src/platform/macos.rs   ← cfg(target_os = "macos")
├── src/platform/windows.rs ← cfg(target_os = "windows")
│
unsafe-linux-process/   ← Linux syscalls (libc)
unsafe-macos-process/   ← macOS syscalls (libc, fork/exec)
unsafe-windows-process/ ← Windows API (winapi, Job Objects)
```

Each platform module is conditionally compiled.

## Critical Rule: Cross-Platform Safety

**This project targets Linux, macOS, and Windows. Every change MUST compile on all three.**

Before considering any change complete, run:
```sh
just check-cross
```

This cross-compiles for all three targets. It does NOT run tests (that requires the native platform), but it catches:
- Missing `#[cfg(...)]` guards
- Broken imports or type mismatches on other platforms
- Incomplete match arms for platform-specific enums
- Stub/trait inconsistencies

### When modifying platform-specific code

1. **Never assume your current platform is the only one.** After editing `platform/linux.rs`, also check that `platform/windows.rs` and `platform/macos.rs` still compile.
2. **Shared code is the danger zone.** Files like `lib.rs`, `error.rs`, `plugin.rs`, `reaper.rs` are compiled on ALL platforms. Any change to shared types, enums, or traits must be compatible with all three platform modules.
3. **Match the stub APIs.** The `unsafe-*-process` crates have stub implementations for non-native platforms (e.g., `#[cfg(not(target_os = "macos"))]` blocks). When changing a function signature in the real implementation, update the stub too.
4. **Platform enums need exhaustive handling.** If you add a variant to `ReaperChannel` or similar platform-conditional enums, ensure all `match` arms are covered on all platforms.

### When adding new platform functionality

1. Define the interface in the shared code first (types, trait bounds).
2. Implement for ALL three platforms, even if two are stubs/`todo!()`.
3. Run `just check-cross` before moving on.

## Build & Test Commands

```sh
just build          # Build all targets
just test           # Run all tests (current platform only)
just test-unit      # Unit tests only
just test-e2e       # E2E integration tests only
just lint           # Clippy with strict warnings
just check-format   # Verify formatting
just ci             # Full CI locally (format + lint + test + audit)
just check-cross    # Cross-compile check for linux + windows + macos (REQUIRED before completing work)
```

## Code Conventions

- **Zero unsafe except in unsafe crates**: All unsafe code lives in `unsafe-*-process` crates. Do not add `unsafe` blocks to other crates.
- **Builder pattern** for `ProcessConfig`.
- **Interior mutability** with `Arc<RwLock<T>>` for thread-safe shared state.
- **Graceful degradation**: Plugin failures are logged but don't crash. Process cleanup is best-effort.
- Rust edition 2021, MSRV 1.92.0.

## Known Platform Differences

| Mechanism               | Linux                                      | macOS                        | Windows                         |
|-------------------------|--------------------------------------------|------------------------------|---------------------------------|
| Process grouping        | User namespaces (fallback: process groups) | POSIX process groups         | Job Objects                     |
| Cleanup on parent death | Namespace auto-cleanup / reaper            | Signal-based + reaper        | Job Object kill-on-close        |
| Process spawning        | `Command` + namespace setup                | `fork/execve` (unsafe crate) | `CreateProcessW` (unsafe crate) |
| Reaper IPC              | Unix sockets                               | Unix sockets                 | Named pipes (planned)           |
