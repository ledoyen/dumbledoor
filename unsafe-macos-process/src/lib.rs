//! Unsafe macOS process management operations with safe wrappers
//!
//! This crate provides safe wrappers around unsafe macOS system calls for process management.
//! All unsafe operations are contained within this crate and exposed through safe APIs.

#[cfg(target_os = "macos")]
use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::fs::File;
#[cfg(target_os = "macos")]
use std::io::{self};
#[cfg(target_os = "macos")]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "macos")]
use std::time::SystemTime;

/// Errors that can occur during unsafe macOS operations
#[cfg(target_os = "macos")]
#[derive(Debug, thiserror::Error)]
pub enum UnsafeMacOSError {
    #[error("System call failed: {syscall}: {errno}")]
    SystemCallFailed { syscall: String, errno: i32 },

    #[error("Invalid parameter: {details}")]
    InvalidParameter { details: String },

    #[error("Process not found")]
    ProcessNotFound,

    #[error("Permission denied: {operation}")]
    PermissionDenied { operation: String },
}

/// Configuration for spawning a macOS process
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct MacOSProcessConfig {
    /// Command to execute
    pub command: String,
    /// Command line arguments (not including argv[0])
    pub args: Vec<String>,
    /// Working directory (None = system root "/")
    pub working_directory: Option<String>,
    /// Environment variables (empty = no environment)
    pub environment: HashMap<String, String>,
    /// Optional log file for stdout/stderr redirection
    pub log_file: Option<String>,
}

/// Result of spawning a macOS process
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct MacOSProcessResult {
    /// Process ID
    pub pid: u32,
    /// Process group ID
    pub pgid: i32,
    /// Start time
    pub start_time: SystemTime,
}

/// Safe handle for a macOS process
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct SafeMacOSProcess {
    /// Process ID
    pub pid: u32,
    /// Process group ID
    pub pgid: i32,
    /// Start time
    pub start_time: SystemTime,
}

#[cfg(target_os = "macos")]
impl SafeMacOSProcess {
    /// Create a new safe process handle
    pub fn new(pid: u32, pgid: i32, start_time: SystemTime) -> Self {
        Self {
            pid,
            pgid,
            start_time,
        }
    }

    /// Get the process ID
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Get the process group ID
    pub fn pgid(&self) -> i32 {
        self.pgid
    }

    /// Get the start time
    pub fn start_time(&self) -> SystemTime {
        self.start_time
    }
}

/// Process status information
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub enum ProcessStatus {
    /// Process is running
    Running,
    /// Process exited with code
    Exited { exit_code: i32 },
    /// Process was terminated by signal
    Terminated { signal: i32 },
    /// Process not found
    NotFound,
}

/// Safely spawn a macOS process using fork/exec
#[cfg(target_os = "macos")]
pub fn safe_spawn_process(
    config: MacOSProcessConfig,
) -> Result<MacOSProcessResult, UnsafeMacOSError> {
    // Validate configuration
    if config.command.is_empty() {
        return Err(UnsafeMacOSError::InvalidParameter {
            details: "Command cannot be empty".to_string(),
        });
    }

    // Prepare command and arguments as C strings
    let command_cstring =
        CString::new(config.command.as_str()).map_err(|_| UnsafeMacOSError::InvalidParameter {
            details: "Command contains null bytes".to_string(),
        })?;

    let mut args_cstrings = vec![command_cstring.clone()]; // argv[0] is the command
    for arg in &config.args {
        let arg_cstring =
            CString::new(arg.as_str()).map_err(|_| UnsafeMacOSError::InvalidParameter {
                details: format!("Argument '{}' contains null bytes", arg),
            })?;
        args_cstrings.push(arg_cstring);
    }

    // Prepare environment variables as C strings
    let mut env_cstrings = Vec::new();
    for (key, value) in &config.environment {
        let env_string = format!("{}={}", key, value);
        let env_cstring =
            CString::new(env_string).map_err(|_| UnsafeMacOSError::InvalidParameter {
                details: format!(
                    "Environment variable '{}={}' contains null bytes",
                    key, value
                ),
            })?;
        env_cstrings.push(env_cstring);
    }

    // Prepare working directory
    let working_dir_cstring = if let Some(ref wd) = config.working_directory {
        Some(
            CString::new(wd.as_str()).map_err(|_| UnsafeMacOSError::InvalidParameter {
                details: "Working directory contains null bytes".to_string(),
            })?,
        )
    } else {
        Some(CString::new("/").unwrap()) // Default to root
    };

    // Prepare log file if specified
    let log_file = if let Some(ref log_path) = config.log_file {
        Some(
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(log_path)
                .map_err(|e| UnsafeMacOSError::SystemCallFailed {
                    syscall: "open".to_string(),
                    errno: e.raw_os_error().unwrap_or(libc::EIO),
                })?,
        )
    } else {
        None
    };

    // Fork the process
    let pid = unsafe { libc::fork() };

    if pid == -1 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(UnsafeMacOSError::SystemCallFailed {
            syscall: "fork".to_string(),
            errno,
        });
    }

    if pid == 0 {
        // Child process - set up environment and exec
        let result = setup_child_process(
            &command_cstring,
            &args_cstrings,
            &env_cstrings,
            working_dir_cstring.as_ref(),
            log_file,
        );

        // If we reach here, exec failed
        match result {
            Err(UnsafeMacOSError::SystemCallFailed { errno, .. }) => {
                unsafe { libc::_exit(errno) };
            }
            _ => {
                unsafe { libc::_exit(127) };
            }
        }
    } else {
        // Parent process
        let child_pid = pid as u32;
        let start_time = SystemTime::now();

        // The child process stays in the same process group as the parent
        let parent_pgid = unsafe { libc::getpgrp() };

        Ok(MacOSProcessResult {
            pid: child_pid,
            pgid: parent_pgid,
            start_time,
        })
    }
}

/// Set up the child process environment and exec the new program
#[cfg(target_os = "macos")]
fn setup_child_process(
    command: &CString,
    args: &[CString],
    env_vars: &[CString],
    working_dir: Option<&CString>,
    log_file: Option<File>,
) -> Result<(), UnsafeMacOSError> {
    // DO NOT create a new process group for this child process
    // Keep the child in the same process group as the parent for proper cleanup
    // This ensures that when the parent ProcessManager terminates, all children
    // in the same process group will be terminated as well

    // Set working directory
    if let Some(wd) = working_dir {
        if unsafe { libc::chdir(wd.as_ptr()) } == -1 {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(UnsafeMacOSError::SystemCallFailed {
                syscall: "chdir".to_string(),
                errno,
            });
        }
    }

    // Set up log file redirection or redirect to /dev/null
    if let Some(log_file) = log_file {
        let log_fd = log_file.as_raw_fd();

        // Redirect stdout to log file
        if unsafe { libc::dup2(log_fd, libc::STDOUT_FILENO) } == -1 {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(UnsafeMacOSError::SystemCallFailed {
                syscall: "dup2(stdout)".to_string(),
                errno,
            });
        }

        // Redirect stderr to log file
        if unsafe { libc::dup2(log_fd, libc::STDERR_FILENO) } == -1 {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(UnsafeMacOSError::SystemCallFailed {
                syscall: "dup2(stderr)".to_string(),
                errno,
            });
        }
    } else {
        // Redirect stdout and stderr to /dev/null if no log file specified
        let dev_null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY) };
        if dev_null != -1 {
            unsafe {
                libc::dup2(dev_null, libc::STDOUT_FILENO);
                libc::dup2(dev_null, libc::STDERR_FILENO);
                libc::close(dev_null);
            }
        }
    }

    // Prepare argv array
    let mut argv: Vec<*const libc::c_char> = args.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null()); // NULL-terminate the array

    // Prepare envp array - if empty, use a minimal environment
    let envp: Vec<*const libc::c_char> = if env_vars.is_empty() {
        // Provide minimal environment
        let path_env = CString::new("PATH=/usr/bin:/bin:/usr/sbin:/sbin").unwrap();
        vec![path_env.as_ptr(), std::ptr::null()]
    } else {
        let mut env_ptrs: Vec<*const libc::c_char> = env_vars.iter().map(|s| s.as_ptr()).collect();
        env_ptrs.push(std::ptr::null()); // NULL-terminate the array
        env_ptrs
    };

    // Execute the new program
    unsafe {
        libc::execve(command.as_ptr(), argv.as_ptr(), envp.as_ptr());
    }

    // If we reach here, exec failed
    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    Err(UnsafeMacOSError::SystemCallFailed {
        syscall: "execve".to_string(),
        errno,
    })
}

/// Safely terminate a process using signals
#[cfg(target_os = "macos")]
pub fn safe_terminate_process(
    process: &SafeMacOSProcess,
    graceful: bool,
) -> Result<(), UnsafeMacOSError> {
    let pid = process.pid();

    // First check if the process is still running
    if !safe_is_process_running(pid)? {
        // Process is already terminated, which is fine
        return Ok(());
    }

    if graceful {
        // First try graceful termination with SIGTERM to the individual process
        let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };

        if result == -1 {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::ESRCH {
                // Process doesn't exist, which is fine
                return Ok(());
            } else if errno == libc::EPERM {
                return Err(UnsafeMacOSError::PermissionDenied {
                    operation: "terminate process".to_string(),
                });
            } else {
                return Err(UnsafeMacOSError::SystemCallFailed {
                    syscall: "kill(SIGTERM)".to_string(),
                    errno,
                });
            }
        }

        // Give the process a moment to terminate gracefully
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Check if the process is still running
        if safe_is_process_running(process.pid())? {
            // Force termination with SIGKILL
            let kill_result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };

            if kill_result == -1 {
                let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::ESRCH {
                    // Process doesn't exist, which is fine
                    return Ok(());
                } else {
                    return Err(UnsafeMacOSError::SystemCallFailed {
                        syscall: "kill(SIGKILL)".to_string(),
                        errno,
                    });
                }
            }
        }
    } else {
        // Force termination with SIGKILL
        let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };

        if result == -1 {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::ESRCH {
                // Process doesn't exist, which is fine
                return Ok(());
            } else if errno == libc::EPERM {
                return Err(UnsafeMacOSError::PermissionDenied {
                    operation: "terminate process".to_string(),
                });
            } else {
                return Err(UnsafeMacOSError::SystemCallFailed {
                    syscall: "kill(SIGKILL)".to_string(),
                    errno,
                });
            }
        }
    }

    Ok(())
}

/// Safely check if a process is running
#[cfg(target_os = "macos")]
pub fn safe_is_process_running(pid: u32) -> Result<bool, UnsafeMacOSError> {
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };

    if result == 0 {
        Ok(true)
    } else {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        match errno {
            libc::ESRCH => Ok(false), // Process doesn't exist
            libc::EPERM => Ok(true),  // Process exists but we don't have permission to signal it
            _ => Err(UnsafeMacOSError::SystemCallFailed {
                syscall: "kill".to_string(),
                errno,
            }),
        }
    }
}

/// Safely get the exit status of a process
#[cfg(target_os = "macos")]
pub fn safe_get_process_status(pid: u32) -> Result<ProcessStatus, UnsafeMacOSError> {
    let mut status: libc::c_int = 0;
    let result = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };

    match result {
        -1 => {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::ECHILD {
                // Process doesn't exist or is not a child
                Ok(ProcessStatus::NotFound)
            } else {
                Err(UnsafeMacOSError::SystemCallFailed {
                    syscall: "waitpid".to_string(),
                    errno,
                })
            }
        }
        0 => {
            // Process is still running
            Ok(ProcessStatus::Running)
        }
        _ => {
            // Process has exited
            if libc::WIFEXITED(status) {
                Ok(ProcessStatus::Exited {
                    exit_code: libc::WEXITSTATUS(status),
                })
            } else if libc::WIFSIGNALED(status) {
                Ok(ProcessStatus::Terminated {
                    signal: libc::WTERMSIG(status),
                })
            } else {
                Ok(ProcessStatus::Exited { exit_code: -1 }) // Unknown exit condition
            }
        }
    }
}

/// Safely install signal handlers for cleanup
#[cfg(target_os = "macos")]
pub fn safe_install_signal_handlers(
    handler: extern "C" fn(libc::c_int),
) -> Result<(), UnsafeMacOSError> {
    unsafe {
        // Handle SIGTERM
        if libc::signal(libc::SIGTERM, handler as libc::sighandler_t) == libc::SIG_ERR {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(UnsafeMacOSError::SystemCallFailed {
                syscall: "signal(SIGTERM)".to_string(),
                errno,
            });
        }

        // Handle SIGINT
        if libc::signal(libc::SIGINT, handler as libc::sighandler_t) == libc::SIG_ERR {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(UnsafeMacOSError::SystemCallFailed {
                syscall: "signal(SIGINT)".to_string(),
                errno,
            });
        }
    }

    Ok(())
}

/// Find child processes of a given process (simplified implementation)
#[cfg(target_os = "macos")]
pub fn safe_find_child_processes(parent_pid: u32) -> Result<Vec<u32>, UnsafeMacOSError> {
    // This is a simplified implementation that returns an empty list
    // A full implementation would parse process information or use system calls
    // to build the actual process tree
    let _ = parent_pid; // Suppress unused parameter warning
    Ok(Vec::new())
}

/// Safely create a new process group for the current process
#[cfg(target_os = "macos")]
pub fn safe_create_process_group() -> Result<i32, UnsafeMacOSError> {
    let pid = unsafe { libc::getpid() };

    if unsafe { libc::setpgid(pid, pid) } == -1 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(UnsafeMacOSError::SystemCallFailed {
            syscall: "setpgid".to_string(),
            errno,
        });
    }

    Ok(pid)
}

/// Safely exit the current process
#[cfg(target_os = "macos")]
pub fn safe_exit(code: i32) -> ! {
    unsafe { libc::_exit(code) }
}

/// Safely check if a process is alive (alternative to safe_is_process_running for reaper use)
#[cfg(target_os = "macos")]
pub fn safe_is_process_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Safely get the current process group ID
#[cfg(target_os = "macos")]
pub fn safe_get_process_group() -> i32 {
    unsafe { libc::getpgrp() }
}

/// Safely get the parent process ID
#[cfg(target_os = "macos")]
pub fn safe_get_parent_pid() -> u32 {
    unsafe { libc::getppid() as u32 }
}

/// Safely send SIGKILL to a process
#[cfg(target_os = "macos")]
pub fn safe_force_kill_process(pid: u32) -> Result<(), UnsafeMacOSError> {
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };

    if result == -1 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::ESRCH {
            // Process doesn't exist, which is fine
            return Ok(());
        } else {
            return Err(UnsafeMacOSError::SystemCallFailed {
                syscall: "kill(SIGKILL)".to_string(),
                errno,
            });
        }
    }

    Ok(())
}

/// Safely kill all processes in the current process group
#[cfg(target_os = "macos")]
pub fn safe_kill_process_group() -> Result<(), UnsafeMacOSError> {
    let process_group = unsafe { libc::getpgrp() };
    let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };

    if result == -1 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::ESRCH {
            // Process group doesn't exist, which is fine
            return Ok(());
        } else {
            return Err(UnsafeMacOSError::SystemCallFailed {
                syscall: "kill(-pgid, SIGKILL)".to_string(),
                errno,
            });
        }
    }

    Ok(())
}

/// Safely terminate all processes in the current process group gracefully, then force kill
#[cfg(target_os = "macos")]
pub fn safe_cleanup_process_group() -> Result<(), UnsafeMacOSError> {
    let process_group = unsafe { libc::getpgrp() };

    // First try graceful termination with SIGTERM
    let term_result = unsafe { libc::kill(-process_group, libc::SIGTERM) };
    if term_result == -1 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno != libc::ESRCH {
            return Err(UnsafeMacOSError::SystemCallFailed {
                syscall: "kill(-pgid, SIGTERM)".to_string(),
                errno,
            });
        }
    }

    // Give processes a moment to terminate gracefully
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Force kill any remaining processes
    let kill_result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if kill_result == -1 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno != libc::ESRCH {
            return Err(UnsafeMacOSError::SystemCallFailed {
                syscall: "kill(-pgid, SIGKILL)".to_string(),
                errno,
            });
        }
    }

    Ok(())
}

// Provide stub implementations for non-macOS platforms
#[cfg(not(target_os = "macos"))]
pub fn safe_is_process_alive(_pid: u32) -> bool {
    false
}

#[cfg(not(target_os = "macos"))]
pub fn safe_get_process_group() -> i32 {
    -1
}

#[cfg(not(target_os = "macos"))]
pub fn safe_get_parent_pid() -> u32 {
    0
}

#[cfg(not(target_os = "macos"))]
pub fn safe_force_kill_process(_pid: u32) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Force kill not supported on this platform",
    ))
}

#[cfg(not(target_os = "macos"))]
pub fn safe_kill_process_group() -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Process group kill not supported on this platform",
    ))
}

#[cfg(not(target_os = "macos"))]
pub fn safe_cleanup_process_group() -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Process group cleanup not supported on this platform",
    ))
}

#[cfg(not(target_os = "macos"))]
pub fn safe_create_process_group() -> Result<i32, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Process groups not supported on this platform",
    ))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_safe_process_spawn_and_terminate() {
        let config = MacOSProcessConfig {
            command: "/bin/echo".to_string(),
            args: vec!["hello".to_string(), "world".to_string()],
            working_directory: None,
            environment: HashMap::new(),
            log_file: None,
        };

        let result = safe_spawn_process(config).expect("Failed to spawn process");
        assert!(result.pid > 0);
        assert!(result.pgid > 0);

        let process = SafeMacOSProcess::new(result.pid, result.pgid, result.start_time);

        // Give the process a moment to complete (echo should finish quickly)
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Try to terminate (should be no-op if already finished)
        let terminate_result = safe_terminate_process(&process, true);
        assert!(terminate_result.is_ok());
    }

    #[test]
    fn test_process_status_check() {
        // Test with a non-existent PID
        let status = safe_get_process_status(999999).expect("Failed to check process status");
        match status {
            ProcessStatus::NotFound => {
                // Expected for non-existent process
            }
            _ => {
                // Other statuses might be valid depending on system state
            }
        }
    }

    #[test]
    fn test_is_process_running() {
        // Test with a non-existent PID
        let running =
            safe_is_process_running(999999).expect("Failed to check if process is running");
        assert!(!running);
    }

    #[test]
    fn test_config_validation() {
        let config = MacOSProcessConfig {
            command: "".to_string(), // Empty command should fail
            args: vec![],
            working_directory: None,
            environment: HashMap::new(),
            log_file: None,
        };

        let result = safe_spawn_process(config);
        assert!(result.is_err());
        match result {
            Err(UnsafeMacOSError::InvalidParameter { .. }) => {
                // Expected error
            }
            _ => panic!("Expected InvalidParameter error"),
        }
    }

    #[test]
    fn test_environment_variables() {
        let mut env = HashMap::new();
        env.insert("TEST_VAR".to_string(), "test_value".to_string());

        let config = MacOSProcessConfig {
            command: "/usr/bin/env".to_string(),
            args: vec![],
            working_directory: None,
            environment: env,
            log_file: Some("/tmp/test_env_output.log".to_string()),
        };

        let result = safe_spawn_process(config);
        assert!(result.is_ok());

        if let Ok(spawn_result) = result {
            let process =
                SafeMacOSProcess::new(spawn_result.pid, spawn_result.pgid, spawn_result.start_time);

            // Give the process time to complete
            std::thread::sleep(std::time::Duration::from_millis(200));

            // Clean up
            let _ = safe_terminate_process(&process, true);
            let _ = std::fs::remove_file("/tmp/test_env_output.log");
        }
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    #[test]
    fn test_stub_functionality() {
        // Test that the stub function works on non-macOS platforms
        assert!(!super::safe_is_process_alive(999999));
    }
}
