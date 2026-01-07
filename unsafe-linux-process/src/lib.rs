//! Unsafe Linux process management operations with safe wrappers
//!
//! This crate provides safe wrappers around unsafe Linux system calls for process management.
//! All unsafe operations are contained within this crate and exposed through safe APIs.

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
            // Process doesn't exist, which is fine
            return Ok(());
        } else {
            return Err(UnsafeLinuxError::SystemCallFailed {
                syscall: "kill(SIGKILL)".to_string(),
                errno,
            });
        }
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
            // Process group doesn't exist, which is fine
            return Ok(());
        } else {
            return Err(UnsafeLinuxError::SystemCallFailed {
                syscall: "kill(-pgid, SIGKILL)".to_string(),
                errno,
            });
        }
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

// Provide stub implementations for non-Linux platforms
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