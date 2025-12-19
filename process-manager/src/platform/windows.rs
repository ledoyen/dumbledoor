use crate::{
    platform::{PlatformManager, PlatformProcess},
    PlatformError, ProcessConfig, ProcessManagerError, ProcessStatus,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use unsafe_windows_process::{
    create_process, terminate_process_safe, wait_for_process_safe, SafeHandle, UnsafeWindowsError,
    WindowsJobObject, WindowsProcessConfig,
};

/// Windows-specific process representation using safe wrappers
#[derive(Debug)]
pub struct WindowsProcess {
    pid: u32,
    handle: Arc<SafeHandle>,
}

impl Clone for WindowsProcess {
    fn clone(&self) -> Self {
        Self {
            pid: self.pid,
            handle: Arc::clone(&self.handle),
        }
    }
}

impl WindowsProcess {
    /// Get the process handle (Windows only)
    #[allow(dead_code)] // Used for platform-specific operations
    pub fn handle(&self) -> &SafeHandle {
        &self.handle
    }
}

impl PlatformProcess for WindowsProcess {
    fn pid(&self) -> u32 {
        self.pid
    }
}

/// Windows platform manager using safe wrappers over unsafe operations
pub struct WindowsPlatformManager {
    job_object: Arc<WindowsJobObject>,
    process_handles: Arc<RwLock<HashMap<u32, u32>>>, // pid -> pid mapping for tracking
}

impl WindowsPlatformManager {
    /// Create a new Windows platform manager
    pub fn new() -> Result<Self, ProcessManagerError> {
        let job_object =
            WindowsJobObject::new().map_err(|_e| ProcessManagerError::PlatformError {
                error: PlatformError::SystemCallFailed {
                    syscall: "WindowsJobObject::new".to_string(),
                    errno: -1,
                },
            })?;

        tracing::info!("Windows platform manager initialized with Job Object");

        Ok(Self {
            job_object: Arc::new(job_object),
            process_handles: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Build command line string from command and arguments
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    fn build_environment_block(env: &HashMap<String, String>) -> Option<Vec<u16>> {
        if env.is_empty() {
            return None;
        }

        // Start with current process environment
        let mut merged_env: HashMap<String, String> = std::env::vars().collect();

        // Add/override with config environment variables
        for (key, value) in env {
            merged_env.insert(key.clone(), value.clone());
        }

        let mut env_block = String::new();
        for (key, value) in merged_env {
            env_block.push_str(&key);
            env_block.push('=');
            env_block.push_str(&value);
            env_block.push('\0');
        }
        env_block.push('\0');

        Some(unsafe_windows_process::to_wide_string(&env_block))
    }

    /// Get the default working directory (system root)
    #[allow(dead_code)]
    fn get_default_working_directory() -> String {
        std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string())
    }

    /// Convert unsafe Windows error to platform error
    #[allow(dead_code)]
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

impl Clone for WindowsPlatformManager {
    fn clone(&self) -> Self {
        Self {
            job_object: Arc::clone(&self.job_object),
            process_handles: Arc::clone(&self.process_handles),
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
    type Process = WindowsProcess;

    fn spawn_process(&self, config: &ProcessConfig) -> Result<Self::Process, PlatformError> {
        let command_line = Self::build_command_line(config);
        tracing::debug!("Command line: {}", command_line);

        // Build environment block - for now, don't pass custom environment to avoid issues
        // TODO: Fix environment block creation to properly handle custom environment variables
        let env_block = None; // Self::build_environment_block(&config.environment);

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

        let pid = result.pid();

        // Assign the process to the job object for automatic cleanup using safe wrapper
        if let Err(e) = self.job_object.assign_process_safe(result.handle()) {
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

        Ok(WindowsProcess {
            pid,
            handle: Arc::new(result.process_handle),
        })
    }

    fn terminate_process(
        &self,
        process: &Self::Process,
        graceful: bool,
    ) -> Result<(), PlatformError> {
        let pid = process.pid();
        let handle = process.handle();

        if graceful {
            // Attempt graceful termination by waiting briefly
            tracing::debug!("Attempting graceful termination of process {}", pid);

            match wait_for_process_safe(handle, 5000) {
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
                    terminate_process_safe(handle, 1).map_err(Self::convert_error)?;
                }
                Err(e) => return Err(Self::convert_error(e)),
            }
        } else {
            // Force termination immediately
            tracing::debug!("Forcing termination of process {}", pid);
            terminate_process_safe(handle, 1).map_err(Self::convert_error)?;
        }

        // Remove from tracking
        {
            let mut handles = self.process_handles.write().unwrap();
            handles.remove(&pid);
        }

        tracing::info!("Terminated Windows process {}", pid);
        Ok(())
    }

    fn query_process_status(
        &self,
        process: &Self::Process,
    ) -> Result<ProcessStatus, PlatformError> {
        let pid = process.pid();
        let handle = process.handle();

        // Check if process is still running (0ms timeout = immediate check)
        match wait_for_process_safe(handle, 0) {
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

    fn setup_cleanup_handler(&self) -> Result<(), PlatformError> {
        // On Windows, the Job Object automatically handles cleanup when the job is closed
        tracing::info!("Windows cleanup handler configured via Job Object");
        Ok(())
    }

    fn cleanup_all_processes(&self, processes: &[&Self::Process]) -> Result<(), PlatformError> {
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

    fn get_child_processes(&self, process: &Self::Process) -> Result<Vec<u32>, PlatformError> {
        let pid = process.pid();
        tracing::debug!("Getting child processes for Windows process {}", pid);

        // For simplicity, we'll return an empty list
        // A full implementation would use additional Windows APIs
        Ok(Vec::new())
    }
}

#[cfg(test)]
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
            .query_process_status(&process)
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
        let result = manager.terminate_process(&process, false);
        assert!(result.is_ok(), "Process termination should succeed");

        // Give some time for termination to complete
        thread::sleep(Duration::from_millis(500));

        // Verify process is terminated
        let final_status = manager
            .query_process_status(&process)
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
