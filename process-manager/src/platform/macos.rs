use crate::{
    platform::{PlatformManager, PlatformProcess},
    PlatformError, ProcessConfig, ProcessManagerError, ProcessStatus,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use unsafe_macos_process::{
    safe_create_process_group, safe_find_child_processes, safe_get_process_status,
    safe_install_signal_handlers, safe_is_process_running, safe_spawn_process,
    safe_terminate_process, MacOSProcessConfig, SafeMacOSProcess, UnsafeMacOSError,
};

/// macOS-specific process representation using safe wrappers
#[derive(Debug, Clone)]
pub struct MacOSProcess {
    inner: SafeMacOSProcess,
}

impl PlatformProcess for MacOSProcess {
    fn pid(&self) -> u32 {
        self.inner.pid()
    }
}

impl MacOSProcess {
    /// Create a new macOS process representation
    pub fn new(inner: SafeMacOSProcess) -> Self {
        Self { inner }
    }

    /// Get the process group ID
    pub fn pgid(&self) -> i32 {
        self.inner.pgid()
    }

    /// Get the start time
    pub fn start_time(&self) -> SystemTime {
        self.inner.start_time()
    }

    /// Get the inner safe process handle
    pub fn inner(&self) -> &SafeMacOSProcess {
        &self.inner
    }
}

/// macOS platform manager using safe wrappers over unsafe operations
#[derive(Clone)]
pub struct MacOSPlatformManager {
    process_handles: Arc<RwLock<HashMap<u32, SafeMacOSProcess>>>, // pid -> process mapping
    cleanup_handler_installed: Arc<RwLock<bool>>,
}

impl MacOSPlatformManager {
    /// Create a new macOS platform manager
    pub fn new() -> Result<Self, ProcessManagerError> {
        tracing::info!("Initializing macOS platform manager with safe wrappers");

        Ok(Self {
            process_handles: Arc::new(RwLock::new(HashMap::new())),
            cleanup_handler_installed: Arc::new(RwLock::new(false)),
        })
    }

    /// Convert unsafe macOS error to platform error
    fn convert_error(error: UnsafeMacOSError) -> PlatformError {
        match error {
            UnsafeMacOSError::SystemCallFailed { syscall, errno } => {
                PlatformError::SystemCallFailed { syscall, errno }
            }
            UnsafeMacOSError::InvalidParameter { details: _ } => PlatformError::SystemCallFailed {
                syscall: "parameter_validation".to_string(),
                errno: libc::EINVAL,
            },
            UnsafeMacOSError::ProcessNotFound => PlatformError::SystemCallFailed {
                syscall: "process_lookup".to_string(),
                errno: libc::ESRCH,
            },
            UnsafeMacOSError::PermissionDenied { operation } => {
                PlatformError::PermissionDenied { operation }
            }
        }
    }

    /// Convert ProcessConfig to MacOSProcessConfig
    fn convert_config(config: &ProcessConfig) -> MacOSProcessConfig {
        MacOSProcessConfig {
            command: config.command.to_string_lossy().to_string(),
            args: config.args.clone(),
            working_directory: config
                .working_directory
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            environment: config.environment.clone(),
            log_file: config
                .log_file
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
        }
    }

    /// Convert unsafe process status to platform process status
    fn convert_status(
        status: unsafe_macos_process::ProcessStatus,
        pid: u32,
        child_pids: Vec<u32>,
    ) -> ProcessStatus {
        match status {
            unsafe_macos_process::ProcessStatus::Running => ProcessStatus::Running { pid },
            unsafe_macos_process::ProcessStatus::Exited { exit_code } => {
                if !child_pids.is_empty() {
                    ProcessStatus::RunningDetached {
                        exit_code,
                        child_pids,
                    }
                } else {
                    ProcessStatus::Exited {
                        exit_code,
                        exit_time: SystemTime::now(),
                    }
                }
            }
            unsafe_macos_process::ProcessStatus::Terminated { signal } => {
                ProcessStatus::Terminated {
                    signal: Some(signal),
                    exit_time: SystemTime::now(),
                }
            }
            unsafe_macos_process::ProcessStatus::NotFound => ProcessStatus::Failed {
                error: "Process not found".to_string(),
            },
        }
    }
}

impl PlatformManager for MacOSPlatformManager {
    type Process = MacOSProcess;

    fn spawn_process(&self, config: &ProcessConfig) -> Result<Self::Process, PlatformError> {
        tracing::info!("Spawning macOS process: {:?}", config.command);

        // Convert to unsafe crate config
        let macos_config = Self::convert_config(config);

        // Spawn the process using safe wrapper
        let result = safe_spawn_process(macos_config).map_err(Self::convert_error)?;

        let safe_process = SafeMacOSProcess::new(result.pid, result.pgid, result.start_time);

        // Store the process for tracking
        {
            let mut handles = self.process_handles.write().unwrap();
            handles.insert(result.pid, safe_process.clone());
        }

        let process = MacOSProcess::new(safe_process);

        tracing::info!(
            "Successfully spawned macOS process with PID {} in process group {}",
            result.pid,
            result.pgid
        );

        Ok(process)
    }

    fn terminate_process(
        &self,
        process: &Self::Process,
        graceful: bool,
    ) -> Result<(), PlatformError> {
        let pid = process.pid();
        let pgid = process.pgid();

        tracing::info!(
            "Terminating macOS process {} (PGID: {}, graceful: {})",
            pid,
            pgid,
            graceful
        );

        // Terminate the process using safe wrapper
        safe_terminate_process(process.inner(), graceful).map_err(Self::convert_error)?;

        // Remove from tracking
        {
            let mut handles = self.process_handles.write().unwrap();
            handles.remove(&pid);
        }

        tracing::info!("Successfully terminated macOS process {}", pid);
        Ok(())
    }

    fn query_process_status(
        &self,
        process: &Self::Process,
    ) -> Result<ProcessStatus, PlatformError> {
        let pid = process.pid();

        // Check if process is still running first
        let is_running = safe_is_process_running(pid).map_err(Self::convert_error)?;

        if is_running {
            return Ok(ProcessStatus::Running { pid });
        }

        // Get detailed status
        let status = safe_get_process_status(pid).map_err(Self::convert_error)?;

        // Get child processes for detached process detection
        let child_pids = self.get_child_processes(process)?;

        Ok(Self::convert_status(status, pid, child_pids))
    }

    fn setup_cleanup_handler(&self) -> Result<(), PlatformError> {
        let already_installed = {
            let installed = self.cleanup_handler_installed.read().unwrap();
            *installed
        };

        if already_installed {
            tracing::debug!("Process cleanup handlers already installed");
            return Ok(());
        }

        // Only skip signal handlers for unit tests, not integration tests
        // Integration tests (like sigkill_cleanup_test) need signal handlers to work
        let is_unit_test = cfg!(test) && std::env::var("CARGO_PKG_NAME").is_ok();
        
        if is_unit_test {
            tracing::debug!("Skipping signal handler installation during unit tests");
            {
                let mut installed = self.cleanup_handler_installed.write().unwrap();
                *installed = true;
            }
            return Ok(());
        }

        tracing::info!("Setting up macOS signal-based cleanup handlers");

        // Create a new process group for this ProcessManager using safe wrapper
        // This ensures all child processes are in the same group for cleanup
        match unsafe_macos_process::safe_create_process_group() {
            Ok(pgid) => {
                tracing::info!("Created new process group: {}", pgid);
            }
            Err(e) => {
                tracing::warn!("Failed to create new process group: {}, continuing anyway", e);
            }
        }

        // Install signal handlers using safe wrapper
        safe_install_signal_handlers(cleanup_signal_handler).map_err(Self::convert_error)?;

        {
            let mut installed = self.cleanup_handler_installed.write().unwrap();
            *installed = true;
        }

        tracing::info!("macOS cleanup handlers installed successfully");
        Ok(())
    }

    fn cleanup_all_processes(&self, processes: &[&Self::Process]) -> Result<(), PlatformError> {
        tracing::info!("Cleaning up {} macOS processes", processes.len());

        for process in processes {
            if let Err(e) = self.terminate_process(process, true) {
                tracing::warn!("Failed to terminate process {}: {}", process.pid(), e);
                // Continue with other processes
            }
        }

        // Clear the process handles registry
        {
            let mut handles = self.process_handles.write().unwrap();
            handles.clear();
        }

        tracing::info!("macOS process cleanup completed");
        Ok(())
    }

    fn get_child_processes(&self, process: &Self::Process) -> Result<Vec<u32>, PlatformError> {
        tracing::debug!("Querying child processes for process {}", process.pid());

        safe_find_child_processes(process.pid()).map_err(Self::convert_error)
    }

    fn needs_reaper(&self) -> bool {
        // macOS needs a reaper for robust zombie cleanup and handling cases
        // where the main process is killed with SIGKILL (signal handlers don't run)
        // Unlike Windows Job Objects, macOS process groups don't automatically
        // clean up zombie processes
        true
    }

    fn create_process_group(&self) -> Result<i32, PlatformError> {
        safe_create_process_group().map_err(Self::convert_error)
    }
}

/// Signal handler for cleanup operations
extern "C" fn cleanup_signal_handler(signal: libc::c_int) {
    match signal {
        libc::SIGTERM => {
            tracing::warn!("Received SIGTERM, initiating process group cleanup");
            cleanup_process_group();
        }
        libc::SIGINT => {
            tracing::warn!("Received SIGINT, initiating process group cleanup");
            cleanup_process_group();
        }
        _ => {
            tracing::warn!("Received unknown signal {}, initiating cleanup", signal);
            cleanup_process_group();
        }
    }
}

/// Clean up all processes in the current process group
fn cleanup_process_group() {
    tracing::info!("Cleaning up process group");
    
    // Use safe wrapper for process group cleanup
    if let Err(e) = unsafe_macos_process::safe_cleanup_process_group() {
        tracing::warn!("Failed to cleanup process group: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProcessConfig;
    use std::collections::HashMap;

    #[test]
    fn test_macos_platform_manager_creation() {
        let manager = MacOSPlatformManager::new();
        assert!(
            manager.is_ok(),
            "MacOSPlatformManager should be created successfully"
        );
    }

    #[test]
    fn test_config_conversion() {
        let mut env = HashMap::new();
        env.insert("TEST_VAR".to_string(), "test_value".to_string());

        let config = ProcessConfig::new("/bin/echo")
            .args(["hello", "world"])
            .working_directory("/tmp")
            .env("TEST_VAR", "test_value")
            .log_file("/tmp/output.log");

        let macos_config = MacOSPlatformManager::convert_config(&config);

        assert_eq!(macos_config.command, "/bin/echo");
        assert_eq!(macos_config.args, vec!["hello", "world"]);
        assert_eq!(macos_config.working_directory, Some("/tmp".to_string()));
        assert_eq!(
            macos_config.environment.get("TEST_VAR"),
            Some(&"test_value".to_string())
        );
        assert_eq!(macos_config.log_file, Some("/tmp/output.log".to_string()));
    }

    #[test]
    fn test_error_conversion() {
        let unsafe_error = UnsafeMacOSError::SystemCallFailed {
            syscall: "fork".to_string(),
            errno: 12,
        };

        let platform_error = MacOSPlatformManager::convert_error(unsafe_error);

        match platform_error {
            PlatformError::SystemCallFailed { syscall, errno } => {
                assert_eq!(syscall, "fork");
                assert_eq!(errno, 12);
            }
            _ => panic!("Expected SystemCallFailed error"),
        }
    }

    #[test]
    fn test_status_conversion() {
        let unsafe_status = unsafe_macos_process::ProcessStatus::Running;
        let platform_status = MacOSPlatformManager::convert_status(unsafe_status, 1234, vec![]);

        match platform_status {
            ProcessStatus::Running { pid } => {
                assert_eq!(pid, 1234);
            }
            _ => panic!("Expected Running status"),
        }

        let unsafe_status = unsafe_macos_process::ProcessStatus::Exited { exit_code: 0 };
        let platform_status = MacOSPlatformManager::convert_status(unsafe_status, 1234, vec![5678]);

        match platform_status {
            ProcessStatus::RunningDetached {
                exit_code,
                child_pids,
            } => {
                assert_eq!(exit_code, 0);
                assert_eq!(child_pids, vec![5678]);
            }
            _ => panic!("Expected RunningDetached status"),
        }
    }

    #[test]
    fn test_process_spawning_and_termination() {
        let manager = MacOSPlatformManager::new().expect("Failed to create manager");

        let config = ProcessConfig::new("/bin/echo").args(["test"]);

        // Spawn the process
        let process = manager
            .spawn_process(&config)
            .expect("Failed to spawn process");

        let pid = process.pid();
        assert!(pid > 0, "Process should have a valid PID");

        // Give the process a moment to complete (echo should finish quickly)
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Test termination (should be no-op if already finished)
        let result = manager.terminate_process(&process, true);
        assert!(result.is_ok(), "Process termination should succeed");
    }
}
