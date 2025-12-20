//! Process Manager - Cross-platform process lifecycle management with guaranteed cleanup
//!
//! This library provides reliable process management across Linux, macOS, and Windows
//! with explicit configuration and guaranteed cleanup capabilities.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

pub use uuid::Uuid;

// Core modules
pub mod error;
mod platform;
pub mod plugin;
pub mod reaper;

// Re-export core types
pub use error::{PlatformError, ProcessManagerError};
use platform::{
    ConcretePlatformManager, ConcretePlatformProcess, PlatformManager, PlatformProcess,
};
pub use plugin::{ConfigurationPlugin, PluginRegistry};
pub use reaper::{ProcessReaper, ReaperMonitor};

/// Unique identifier for a managed process
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessHandle(pub Uuid);

impl ProcessHandle {
    /// Create a new unique process handle
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ProcessHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete specification for spawning a process
#[derive(Debug, Clone)]
pub struct ProcessConfig {
    /// Command to execute
    pub command: PathBuf,
    /// Command line arguments
    pub args: Vec<String>,
    /// Working directory (None = system root directory)
    pub working_directory: Option<PathBuf>,
    /// Environment variables (empty = no environment inheritance)
    pub environment: HashMap<String, String>,
    /// Optional log file for stdout/stderr redirection
    pub log_file: Option<PathBuf>,
}

impl ProcessConfig {
    /// Create a new process configuration with the specified command
    pub fn new<P: Into<PathBuf>>(command: P) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            working_directory: None,
            environment: HashMap::new(),
            log_file: None,
        }
    }

    /// Add command line arguments
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(|s| s.into()));
        self
    }

    /// Set working directory
    pub fn working_directory<P: Into<PathBuf>>(mut self, dir: P) -> Self {
        self.working_directory = Some(dir.into());
        self
    }

    /// Add environment variable
    pub fn env<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.environment.insert(key.into(), value.into());
        self
    }

    /// Set log file for stdout/stderr redirection
    pub fn log_file<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.log_file = Some(path.into());
        self
    }

    /// Validate the process configuration
    ///
    /// Ensures that:
    /// - Command path is not empty
    /// - Command exists (if absolute path)
    /// - Working directory exists (if specified)
    /// - Log file parent directory exists (if specified)
    /// - No environment variable keys are empty
    pub fn validate(&self) -> Result<(), ProcessManagerError> {
        // Validate command is not empty
        if self.command.as_os_str().is_empty() {
            return Err(ProcessManagerError::InvalidConfig {
                details: "Command path cannot be empty".to_string(),
            });
        }

        // Validate command exists if it's an absolute path
        if self.command.is_absolute() && !self.command.exists() {
            return Err(ProcessManagerError::InvalidConfig {
                details: format!("Command does not exist: {}", self.command.display()),
            });
        }

        // Validate working directory exists if specified
        if let Some(ref wd) = self.working_directory {
            if !wd.exists() {
                return Err(ProcessManagerError::InvalidConfig {
                    details: format!("Working directory does not exist: {}", wd.display()),
                });
            }
            if !wd.is_dir() {
                return Err(ProcessManagerError::InvalidConfig {
                    details: format!("Working directory is not a directory: {}", wd.display()),
                });
            }
        }

        // Validate log file parent directory exists if specified
        if let Some(ref log_file) = self.log_file {
            if let Some(parent) = log_file.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    return Err(ProcessManagerError::InvalidConfig {
                        details: format!(
                            "Log file parent directory does not exist: {}",
                            parent.display()
                        ),
                    });
                }
            }
        }

        // Validate environment variable keys are not empty
        for key in self.environment.keys() {
            if key.is_empty() {
                return Err(ProcessManagerError::InvalidConfig {
                    details: "Environment variable key cannot be empty".to_string(),
                });
            }
        }

        Ok(())
    }
}

/// Current status of a managed process
#[derive(Debug, Clone)]
pub enum ProcessStatus {
    /// Process is starting up
    Starting,
    /// Process is actively running
    Running { pid: u32 },
    /// Process exited but spawned long-running children
    RunningDetached {
        exit_code: i32,
        child_pids: Vec<u32>,
    },
    /// Process ran and exited with no active children
    Exited {
        exit_code: i32,
        exit_time: SystemTime,
    },
    /// Process was killed by signal
    Terminated {
        signal: Option<i32>,
        exit_time: SystemTime,
    },
    /// Process failed to start
    Failed { error: String },
}

/// Information about a managed process
#[derive(Debug)]
pub struct ProcessInfo {
    /// Unique handle for this process
    pub handle: ProcessHandle,
    /// Configuration used to spawn the process
    pub config: ProcessConfig,
    /// When the process was started
    pub start_time: SystemTime,
    /// Current status
    pub status: ProcessStatus,
    /// The actual platform process (optional, set when spawned)
    pub process: Option<ConcretePlatformProcess>,
}

impl Clone for ProcessInfo {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle,
            config: self.config.clone(),
            start_time: self.start_time,
            status: self.status.clone(),
            process: self.process.clone(),
        }
    }
}

/// Main process manager for cross-platform process lifecycle management
pub struct ProcessManager {
    platform_manager: ConcretePlatformManager,
    plugin_registry: Arc<RwLock<PluginRegistry>>,
    process_registry: Arc<RwLock<HashMap<ProcessHandle, ProcessInfo>>>,
    reaper_monitor: Arc<RwLock<Option<ReaperMonitor>>>,
}

impl ProcessManager {
    /// Create a new process manager instance
    pub fn new() -> Result<Self, ProcessManagerError> {
        let platform_manager = platform::create_platform_manager()?;
        let plugin_registry = Arc::new(RwLock::new(PluginRegistry::new()));
        let process_registry = Arc::new(RwLock::new(HashMap::new()));
        let reaper_monitor = Arc::new(RwLock::new(None));

        // Set up platform-specific cleanup handlers
        platform_manager
            .setup_cleanup_handler()
            .map_err(|e| ProcessManagerError::PlatformError { error: e })?;

        Ok(Self {
            platform_manager,
            plugin_registry,
            process_registry,
            reaper_monitor,
        })
    }

    /// Start a new process with the given configuration
    pub fn start_process(
        &self,
        config: ProcessConfig,
    ) -> Result<ProcessHandle, ProcessManagerError> {
        // Validate configuration before processing
        config.validate()?;

        // Apply plugins to enhance configuration
        let enhanced_config = {
            let registry = self.plugin_registry.read().unwrap();
            registry.apply_plugins(config)
        };

        // Validate enhanced configuration
        enhanced_config.validate()?;

        // Generate unique handle
        let handle = ProcessHandle::new();

        // Spawn the process via platform manager
        let process = self
            .platform_manager
            .spawn_process(&enhanced_config)
            .map_err(|e| ProcessManagerError::PlatformError { error: e })?;

        // Create process info
        let process_info = ProcessInfo {
            handle,
            config: enhanced_config.clone(),
            start_time: SystemTime::now(),
            status: ProcessStatus::Running { pid: process.pid() },
            process: Some(process),
        };

        // Register process
        {
            let mut registry = self.process_registry.write().unwrap();
            registry.insert(handle, process_info);
        }

        tracing::info!("Started process with handle {:?}", handle);

        Ok(handle)
    }

    /// Stop a managed process
    pub fn stop_process(&self, handle: ProcessHandle) -> Result<(), ProcessManagerError> {
        let process_info = {
            let registry = self.process_registry.read().unwrap();
            registry.get(&handle).cloned()
        };

        if let Some(info) = process_info {
            if let Some(process) = &info.process {
                // Terminate the process via platform manager
                self.platform_manager
                    .terminate_process(process, true)
                    .map_err(|e| ProcessManagerError::PlatformError { error: e })?;
            }

            // Remove from registry
            {
                let mut registry = self.process_registry.write().unwrap();
                registry.remove(&handle);
            }

            tracing::info!("Stopped process with handle {:?}", handle);
            Ok(())
        } else {
            Err(ProcessManagerError::ProcessNotFound { handle })
        }
    }

    /// Query the status of a managed process
    pub fn query_status(
        &self,
        handle: ProcessHandle,
    ) -> Result<ProcessStatus, ProcessManagerError> {
        let registry = self.process_registry.read().unwrap();
        if let Some(info) = registry.get(&handle) {
            if let Some(process) = &info.process {
                // Query current status from platform manager
                self.platform_manager
                    .query_process_status(process)
                    .map_err(|e| ProcessManagerError::PlatformError { error: e })
            } else {
                Ok(info.status.clone())
            }
        } else {
            Err(ProcessManagerError::ProcessNotFound { handle })
        }
    }

    /// List all managed processes
    pub fn list_processes(&self) -> Vec<ProcessHandle> {
        let registry = self.process_registry.read().unwrap();
        registry.keys().copied().collect()
    }

    /// Register a configuration plugin
    pub fn register_plugin(&self, plugin: Box<dyn ConfigurationPlugin>) {
        let mut registry = self.plugin_registry.write().unwrap();
        registry.register(plugin);
    }

    /// Clean up all managed processes
    pub fn cleanup_all(&self) -> Result<(), ProcessManagerError> {
        let processes: Vec<_> = {
            let registry = self.process_registry.read().unwrap();
            registry
                .values()
                .filter_map(|info| info.process.as_ref())
                .cloned()
                .collect()
        };

        if !processes.is_empty() {
            let process_refs: Vec<_> = processes.iter().collect();
            self.platform_manager
                .cleanup_all_processes(&process_refs)
                .map_err(|e| ProcessManagerError::PlatformError { error: e })?;

            // Clear the process registry after cleanup
            {
                let mut registry = self.process_registry.write().unwrap();
                registry.clear();
            }

            tracing::info!("Cleaned up {} processes", processes.len());
        }

        Ok(())
    }
}

impl Clone for ProcessManager {
    fn clone(&self) -> Self {
        Self {
            platform_manager: self.platform_manager.clone(),
            plugin_registry: Arc::clone(&self.plugin_registry),
            process_registry: Arc::clone(&self.process_registry),
            reaper_monitor: Arc::clone(&self.reaper_monitor),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_handle_creation() {
        let handle1 = ProcessHandle::new();
        let handle2 = ProcessHandle::new();
        assert_ne!(handle1, handle2);
    }

    #[test]
    fn test_process_handle_uniqueness() {
        let mut handles = std::collections::HashSet::new();
        for _ in 0..1000 {
            let handle = ProcessHandle::new();
            assert!(handles.insert(handle), "Duplicate handle generated");
        }
    }

    #[test]
    fn test_process_handle_default() {
        let handle = ProcessHandle::default();
        assert_ne!(handle, ProcessHandle::default());
    }

    #[test]
    fn test_process_config_builder() {
        let config = ProcessConfig::new("/bin/echo")
            .args(["hello", "world"])
            .working_directory("/tmp")
            .env("TEST", "value")
            .log_file("/tmp/output.log");

        assert_eq!(config.command, PathBuf::from("/bin/echo"));
        assert_eq!(config.args, vec!["hello", "world"]);
        assert_eq!(config.working_directory, Some(PathBuf::from("/tmp")));
        assert_eq!(config.environment.get("TEST"), Some(&"value".to_string()));
        assert_eq!(config.log_file, Some(PathBuf::from("/tmp/output.log")));
    }

    #[test]
    fn test_process_config_minimal() {
        let config = ProcessConfig::new("/bin/echo");
        assert_eq!(config.command, PathBuf::from("/bin/echo"));
        assert!(config.args.is_empty());
        assert!(config.working_directory.is_none());
        assert!(config.environment.is_empty());
        assert!(config.log_file.is_none());
    }

    #[test]
    fn test_process_config_validation_empty_command() {
        let config = ProcessConfig::new("");
        let result = config.validate();
        assert!(result.is_err());
        match result {
            Err(ProcessManagerError::InvalidConfig { details }) => {
                assert!(details.contains("Command path cannot be empty"));
            }
            _ => panic!("Expected InvalidConfig error"),
        }
    }

    #[test]
    fn test_process_config_validation_nonexistent_absolute_command() {
        // Use a platform-appropriate absolute path that doesn't exist
        #[cfg(unix)]
        let nonexistent_path = "/nonexistent/command/that/does/not/exist";
        #[cfg(windows)]
        let nonexistent_path = "C:\\nonexistent\\command\\that\\does\\not\\exist.exe";

        let config = ProcessConfig::new(nonexistent_path);
        let result = config.validate();
        assert!(result.is_err());
        match result {
            Err(ProcessManagerError::InvalidConfig { details }) => {
                assert!(details.contains("Command does not exist"));
            }
            _ => panic!("Expected InvalidConfig error"),
        }
    }

    #[test]
    fn test_process_config_validation_relative_command() {
        // Relative commands should pass validation (they'll be resolved via PATH)
        let config = ProcessConfig::new("echo");
        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_process_config_validation_nonexistent_working_directory() {
        let config = ProcessConfig::new("echo")
            .working_directory("/nonexistent/directory/that/does/not/exist");
        let result = config.validate();
        assert!(result.is_err());
        match result {
            Err(ProcessManagerError::InvalidConfig { details }) => {
                assert!(details.contains("Working directory does not exist"));
            }
            _ => panic!("Expected InvalidConfig error"),
        }
    }

    #[test]
    fn test_process_config_validation_working_directory_is_file() {
        // Create a temporary file
        let temp_file = std::env::temp_dir().join("test_file_not_dir");
        std::fs::write(&temp_file, "test").unwrap();

        let config = ProcessConfig::new("echo").working_directory(&temp_file);
        let result = config.validate();

        // Cleanup
        let _ = std::fs::remove_file(&temp_file);

        assert!(result.is_err());
        match result {
            Err(ProcessManagerError::InvalidConfig { details }) => {
                assert!(details.contains("is not a directory"));
            }
            _ => panic!("Expected InvalidConfig error"),
        }
    }

    #[test]
    fn test_process_config_validation_empty_env_key() {
        let config = ProcessConfig::new("echo").env("", "value");
        let result = config.validate();
        assert!(result.is_err());
        match result {
            Err(ProcessManagerError::InvalidConfig { details }) => {
                assert!(details.contains("Environment variable key cannot be empty"));
            }
            _ => panic!("Expected InvalidConfig error"),
        }
    }

    #[test]
    fn test_process_config_validation_log_file_invalid_parent() {
        let config = ProcessConfig::new("echo").log_file("/nonexistent/directory/output.log");
        let result = config.validate();
        assert!(result.is_err());
        match result {
            Err(ProcessManagerError::InvalidConfig { details }) => {
                assert!(details.contains("Log file parent directory does not exist"));
            }
            _ => panic!("Expected InvalidConfig error"),
        }
    }

    #[test]
    fn test_process_config_validation_valid_config() {
        let temp_dir = std::env::temp_dir();
        let config = ProcessConfig::new("echo")
            .args(["hello"])
            .working_directory(&temp_dir)
            .env("TEST", "value")
            .log_file(temp_dir.join("output.log"));

        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_process_status_variants() {
        let status_starting = ProcessStatus::Starting;
        let status_running = ProcessStatus::Running { pid: 1234 };
        let status_detached = ProcessStatus::RunningDetached {
            exit_code: 0,
            child_pids: vec![5678, 9012],
        };
        let status_exited = ProcessStatus::Exited {
            exit_code: 0,
            exit_time: SystemTime::now(),
        };
        let status_terminated = ProcessStatus::Terminated {
            signal: Some(9),
            exit_time: SystemTime::now(),
        };
        let status_failed = ProcessStatus::Failed {
            error: "Test error".to_string(),
        };

        // Verify all variants can be created
        match status_starting {
            ProcessStatus::Starting => {}
            _ => panic!("Wrong variant"),
        }
        match status_running {
            ProcessStatus::Running { pid } => assert_eq!(pid, 1234),
            _ => panic!("Wrong variant"),
        }
        match status_detached {
            ProcessStatus::RunningDetached {
                exit_code,
                child_pids,
            } => {
                assert_eq!(exit_code, 0);
                assert_eq!(child_pids, vec![5678, 9012]);
            }
            _ => panic!("Wrong variant"),
        }
        match status_exited {
            ProcessStatus::Exited { exit_code, .. } => assert_eq!(exit_code, 0),
            _ => panic!("Wrong variant"),
        }
        match status_terminated {
            ProcessStatus::Terminated { signal, .. } => assert_eq!(signal, Some(9)),
            _ => panic!("Wrong variant"),
        }
        match status_failed {
            ProcessStatus::Failed { error } => assert_eq!(error, "Test error"),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_process_info_creation() {
        let handle = ProcessHandle::new();
        let config = ProcessConfig::new("echo");
        let start_time = SystemTime::now();
        let status = ProcessStatus::Starting;

        let info = ProcessInfo {
            handle,
            config: config.clone(),
            start_time,
            status: status.clone(),
            process: None,
        };

        assert_eq!(info.handle, handle);
        assert_eq!(info.config.command, config.command);
        assert_eq!(info.start_time, start_time);
    }

    #[test]
    fn test_error_types() {
        let handle = ProcessHandle::new();

        let err1 = ProcessManagerError::InvalidConfig {
            details: "test".to_string(),
        };
        assert!(err1.to_string().contains("Invalid process configuration"));

        let err2 = ProcessManagerError::StartupFailed {
            reason: "test".to_string(),
        };
        assert!(err2.to_string().contains("Process failed to start"));

        let err3 = ProcessManagerError::ProcessNotFound { handle };
        assert!(err3.to_string().contains("Process not found"));

        let platform_err = PlatformError::SystemCallFailed {
            syscall: "fork".to_string(),
            errno: 12,
        };
        let err4 = ProcessManagerError::PlatformError {
            error: platform_err,
        };
        assert!(err4.to_string().contains("Platform operation failed"));

        let err5 = ProcessManagerError::CleanupFailed {
            details: "test".to_string(),
        };
        assert!(err5.to_string().contains("Cleanup failed"));
    }

    #[test]
    fn test_platform_error_types() {
        let err1 = PlatformError::SystemCallFailed {
            syscall: "fork".to_string(),
            errno: 12,
        };
        assert!(err1.to_string().contains("System call failed"));
        assert!(err1.to_string().contains("fork"));

        let err2 = PlatformError::PermissionDenied {
            operation: "spawn".to_string(),
        };
        assert!(err2.to_string().contains("Permission denied"));

        let err3 = PlatformError::ResourceUnavailable {
            resource: "memory".to_string(),
        };
        assert!(err3.to_string().contains("Resource unavailable"));
    }
}
