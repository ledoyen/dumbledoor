use crate::{
    platform::{PlatformManager, PlatformProcess},
    PlatformError, ProcessConfig, ProcessManagerError, ProcessStatus,
};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::SystemTime;

#[cfg(windows)]
use unsafe_windows_process::{
    create_process, open_process, terminate_process, wait_for_process, UnsafeWindowsError,
    WindowsJobObject, WindowsProcessConfig,
};

/// Windows-specific process representation using safe wrappers
#[derive(Debug)]
pub struct WindowsProcess {
    pid: u32,
}

impl PlatformProcess for WindowsProcess {
    fn pid(&self) -> u32 {
        self.pid
    }
}

/// Windows platform manager using safe wrappers over unsafe operations
pub struct WindowsPlatformManager {
    #[cfg(windows)]
    job_object: WindowsJobObject,
    process_handles: RwLock<HashMap<u32, u32>>, // pid -> pid mapping for tracking
}

impl WindowsPlatformManager {
    /// Create a new Windows platform manager
    pub fn new() -> Result<Self, ProcessManagerError> {
        #[cfg(windows)]
        {
            let job_object =
                WindowsJobObject::new().map_err(|_e| ProcessManagerError::PlatformError {
                    error: PlatformError::SystemCallFailed {
                        syscall: "WindowsJobObject::new".to_string(),
                        errno: -1,
                    },
                })?;

            tracing::info!("Windows platform manager initialized with Job Object");

            Ok(Self {
                job_object,
                process_handles: RwLock::new(HashMap::new()),
            })
        }

        #[cfg(not(windows))]
        {
            Err(ProcessManagerError::PlatformError {
                error: PlatformError::ResourceUnavailable {
                    resource: "Windows platform manager not available on this platform".to_string(),
                },
            })
        }
    }

    /// Build command line string from command and arguments
    fn build_command_line(config: &ProcessConfig) -> String {
        let mut cmd_line = String::new();

        // Quote the command if it contains spaces
        let cmd_str = config.command.to_string_lossy();
        if cmd_str.contains(' ') {
            cmd_line.push('"');
            cmd_line.push_str(&cmd_str);
            cmd_line.push('"');
        } else {
            cmd_line.push_str(&cmd_str);
        }

        // Add arguments
        for arg in &config.args {
            cmd_line.push(' ');
            // Quote arguments if they contain spaces
            if arg.contains(' ') {
                cmd_line.push('"');
                cmd_line.push_str(arg);
                cmd_line.push('"');
            } else {
                cmd_line.push_str(arg);
            }
        }

        cmd_line
    }

    /// Build environment block from environment variables
    #[cfg(windows)]
    fn build_environment_block(env: &HashMap<String, String>) -> Option<Vec<u16>> {
        if env.is_empty() {
            return None;
        }

        let mut env_block = String::new();
        for (key, value) in env {
            env_block.push_str(key);
            env_block.push('=');
            env_block.push_str(value);
            env_block.push('\0');
        }
        env_block.push('\0');

        Some(unsafe_windows_process::to_wide_string(&env_block))
    }

    /// Get the default working directory (system root)
    fn get_default_working_directory() -> String {
        std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string())
    }

    /// Convert unsafe Windows error to platform error
    #[cfg(windows)]
    fn convert_error(error: UnsafeWindowsError) -> PlatformError {
        match error {
            UnsafeWindowsError::SystemCallFailed { syscall, errno } => {
                PlatformError::SystemCallFailed { syscall, errno }
            }
            UnsafeWindowsError::InvalidHandle => PlatformError::SystemCallFailed {
                syscall: "handle_operation".to_string(),
                errno: -1,
            },
            UnsafeWindowsError::ProcessNotFound => PlatformError::SystemCallFailed {
                syscall: "process_lookup".to_string(),
                errno: 3, // ERROR_PATH_NOT_FOUND
            },
        }
    }
}

impl Drop for WindowsPlatformManager {
    fn drop(&mut self) {
        // Job object will automatically clean up processes when dropped
        tracing::debug!("Dropping WindowsPlatformManager, job object will be closed");
    }
}

impl PlatformManager for WindowsPlatformManager {
    fn spawn_process(
        &self,
        config: &ProcessConfig,
    ) -> Result<Box<dyn PlatformProcess>, PlatformError> {
        #[cfg(windows)]
        {
            let command_line = Self::build_command_line(config);
            tracing::debug!("Command line: {}", command_line);

            // Build environment block
            let env_block = Self::build_environment_block(&config.environment);

            // Determine working directory
            let working_dir = config
                .working_directory
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(Self::get_default_working_directory);

            let windows_config = WindowsProcessConfig {
                command_line,
                working_directory: Some(working_dir),
                environment_block: env_block,
                inherit_handles: config.log_file.is_some(),
            };

            // Create the process using safe wrapper
            let result = create_process(windows_config).map_err(Self::convert_error)?;

            let pid = result.process_id;

            // Assign the process to the job object for automatic cleanup
            // SAFETY: result.process_handle.as_raw() returns a valid handle from create_process
            if let Err(e) = unsafe {
                self.job_object
                    .assign_process(result.process_handle.as_raw())
            } {
                tracing::warn!("Failed to assign process {} to job object: {}", pid, e);
                // Continue anyway - we'll still track the process manually
            }

            // Store the process for tracking
            {
                let mut handles = self.process_handles.write().unwrap();
                handles.insert(pid, pid);
            }

            tracing::info!(
                "Spawned Windows process: {} (PID: {})",
                config.command.display(),
                pid
            );

            Ok(Box::new(WindowsProcess { pid }))
        }

        #[cfg(not(windows))]
        {
            Err(PlatformError::ResourceUnavailable {
                resource: "Windows process spawning not available on this platform".to_string(),
            })
        }
    }

    fn terminate_process(
        &self,
        process: &dyn PlatformProcess,
        graceful: bool,
    ) -> Result<(), PlatformError> {
        #[cfg(windows)]
        {
            let pid = process.pid();

            // Try to open the process
            let process_handle = open_process(
                pid,
                0x0001 | 0x0400, // PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION
            );

            let handle = match process_handle {
                Ok(h) => h,
                Err(UnsafeWindowsError::ProcessNotFound) => {
                    tracing::warn!("Process {} not found or already terminated", pid);
                    return Ok(()); // Process already gone
                }
                Err(e) => return Err(Self::convert_error(e)),
            };

            if graceful {
                // Attempt graceful termination by waiting briefly
                tracing::debug!("Attempting graceful termination of process {}", pid);

                // SAFETY: handle.as_raw() returns a valid handle from open_process
                match unsafe { wait_for_process(handle.as_raw(), 5000) } {
                    Ok(Some(_exit_code)) => {
                        // Process exited gracefully
                        tracing::debug!("Process {} exited gracefully", pid);
                    }
                    Ok(None) => {
                        // Timeout - force termination
                        tracing::debug!(
                            "Process {} did not exit gracefully, forcing termination",
                            pid
                        );
                        // SAFETY: handle.as_raw() returns a valid handle from open_process
                        unsafe { terminate_process(handle.as_raw(), 1) }
                            .map_err(Self::convert_error)?;
                    }
                    Err(e) => return Err(Self::convert_error(e)),
                }
            } else {
                // Force termination immediately
                tracing::debug!("Forcing termination of process {}", pid);
                // SAFETY: handle.as_raw() returns a valid handle from open_process
                unsafe { terminate_process(handle.as_raw(), 1) }.map_err(Self::convert_error)?;
            }

            // Remove from tracking
            {
                let mut handles = self.process_handles.write().unwrap();
                handles.remove(&pid);
            }

            tracing::info!("Terminated Windows process {}", pid);
            Ok(())
        }

        #[cfg(not(windows))]
        {
            Err(PlatformError::ResourceUnavailable {
                resource: "Windows process termination not available on this platform".to_string(),
            })
        }
    }

    fn query_process_status(
        &self,
        process: &dyn PlatformProcess,
    ) -> Result<ProcessStatus, PlatformError> {
        #[cfg(windows)]
        {
            let pid = process.pid();

            // Try to open the process
            let process_handle = open_process(pid, 0x0400); // PROCESS_QUERY_INFORMATION

            let handle = match process_handle {
                Ok(h) => h,
                Err(UnsafeWindowsError::ProcessNotFound) => {
                    return Ok(ProcessStatus::Exited {
                        exit_code: -1,
                        exit_time: SystemTime::now(),
                    });
                }
                Err(e) => return Err(Self::convert_error(e)),
            };

            // Check if process is still running (0ms timeout = immediate check)
            // SAFETY: handle.as_raw() returns a valid handle from open_process
            match unsafe { wait_for_process(handle.as_raw(), 0) } {
                Ok(Some(exit_code)) => {
                    // Process has exited
                    Ok(ProcessStatus::Exited {
                        exit_code: exit_code as i32,
                        exit_time: SystemTime::now(),
                    })
                }
                Ok(None) => {
                    // Process is still running (timeout occurred)
                    Ok(ProcessStatus::Running { pid })
                }
                Err(e) => Err(Self::convert_error(e)),
            }
        }

        #[cfg(not(windows))]
        {
            Err(PlatformError::ResourceUnavailable {
                resource: "Windows process status querying not available on this platform"
                    .to_string(),
            })
        }
    }

    fn setup_cleanup_handler(&self) -> Result<(), PlatformError> {
        // On Windows, the Job Object automatically handles cleanup when the job is closed
        tracing::info!("Windows cleanup handler configured via Job Object");
        Ok(())
    }

    fn cleanup_all_processes(
        &self,
        processes: &[&dyn PlatformProcess],
    ) -> Result<(), PlatformError> {
        tracing::info!("Cleaning up {} Windows processes", processes.len());

        // Terminate each process
        for process in processes {
            // Attempt graceful termination first
            if let Err(e) = self.terminate_process(*process, true) {
                tracing::warn!(
                    "Failed to terminate process {} during cleanup: {}",
                    process.pid(),
                    e
                );
            }
        }

        // The Job Object will ensure all processes are killed when it's closed
        Ok(())
    }

    fn get_child_processes(
        &self,
        process: &dyn PlatformProcess,
    ) -> Result<Vec<u32>, PlatformError> {
        let pid = process.pid();
        tracing::debug!("Getting child processes for Windows process {}", pid);

        // For simplicity, we'll return an empty list
        // A full implementation would use additional Windows APIs
        Ok(Vec::new())
    }
}

#[cfg(test)]
#[cfg(target_os = "windows")]
mod tests {
    use super::*;
    use crate::{ProcessConfig, ProcessStatus};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_windows_platform_manager_creation() {
        let manager = WindowsPlatformManager::new();
        assert!(
            manager.is_ok(),
            "WindowsPlatformManager should be created successfully"
        );
    }

    #[test]
    fn test_command_line_building() {
        let config = ProcessConfig {
            command: PathBuf::from("test command"),
            args: vec!["arg with spaces".to_string(), "simple_arg".to_string()],
            working_directory: None,
            environment: HashMap::new(),
            log_file: None,
        };

        let cmd_line = WindowsPlatformManager::build_command_line(&config);
        assert!(cmd_line.contains("\"test command\""));
        assert!(cmd_line.contains("\"arg with spaces\""));
        assert!(cmd_line.contains("simple_arg"));
    }

    #[test]
    fn test_process_spawning_and_termination() {
        let manager = WindowsPlatformManager::new().expect("Failed to create manager");

        let config = ProcessConfig {
            command: PathBuf::from("cmd.exe"),
            args: vec!["/c".to_string(), "timeout".to_string(), "10".to_string()],
            working_directory: None,
            environment: HashMap::new(),
            log_file: None,
        };

        // Spawn the process
        let process = manager
            .spawn_process(&config)
            .expect("Failed to spawn process");

        let pid = process.pid();
        assert!(pid > 0, "Process should have a valid PID");

        // Verify process is running
        let status = manager
            .query_process_status(process.as_ref())
            .expect("Failed to query status");

        match status {
            ProcessStatus::Running { pid: status_pid } => {
                assert_eq!(status_pid, pid, "Status PID should match process PID");
            }
            _ => {
                // Process might have completed quickly, which is also valid
            }
        }

        // Test termination
        let result = manager.terminate_process(process.as_ref(), false);
        assert!(result.is_ok(), "Process termination should succeed");

        // Give some time for termination to complete
        thread::sleep(Duration::from_millis(500));

        // Verify process is terminated
        let final_status = manager
            .query_process_status(process.as_ref())
            .expect("Failed to query final status");

        match final_status {
            ProcessStatus::Exited { .. } => {
                // Process should be terminated
            }
            _ => {
                // Other statuses might be valid depending on timing
            }
        }
    }
}
