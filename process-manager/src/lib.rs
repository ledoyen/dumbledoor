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
pub mod cleanup;
pub mod error;
pub mod platform;
pub mod plugin;
pub mod reaper;

// Re-export core types
pub use cleanup::CleanupHandler;
pub use error::{PlatformError, ProcessManagerError};
pub use platform::PlatformManager;
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
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Unique handle for this process
    pub handle: ProcessHandle,
    /// Configuration used to spawn the process
    pub config: ProcessConfig,
    /// When the process was started
    pub start_time: SystemTime,
    /// Current status
    pub status: ProcessStatus,
}

/// Main process manager for cross-platform process lifecycle management
pub struct ProcessManager {
    platform_manager: Arc<dyn PlatformManager>,
    plugin_registry: Arc<RwLock<PluginRegistry>>,
    process_registry: Arc<RwLock<HashMap<ProcessHandle, ProcessInfo>>>,
    cleanup_handler: Arc<CleanupHandler>,
    reaper_monitor: Arc<RwLock<Option<ReaperMonitor>>>,
}

impl ProcessManager {
    /// Create a new process manager instance
    pub fn new() -> Result<Self, ProcessManagerError> {
        let platform_manager = platform::create_platform_manager()?;
        let plugin_registry = Arc::new(RwLock::new(PluginRegistry::new()));
        let process_registry = Arc::new(RwLock::new(HashMap::new()));
        let cleanup_handler = Arc::new(CleanupHandler::new()?);
        let reaper_monitor = Arc::new(RwLock::new(None));

        Ok(Self {
            platform_manager,
            plugin_registry,
            process_registry,
            cleanup_handler,
            reaper_monitor,
        })
    }

    /// Start a new process with the given configuration
    pub fn start_process(
        &self,
        config: ProcessConfig,
    ) -> Result<ProcessHandle, ProcessManagerError> {
        // Apply plugins to enhance configuration
        let enhanced_config = {
            let registry = self.plugin_registry.read().unwrap();
            registry.apply_plugins(config)
        };

        // Generate unique handle
        let handle = ProcessHandle::new();

        // Create process info
        let process_info = ProcessInfo {
            handle,
            config: enhanced_config.clone(),
            start_time: SystemTime::now(),
            status: ProcessStatus::Starting,
        };

        // Register process
        {
            let mut registry = self.process_registry.write().unwrap();
            registry.insert(handle, process_info);
        }

        // TODO: Implement actual process spawning via platform manager
        tracing::info!("Starting process with handle {:?}", handle);

        Ok(handle)
    }

    /// Stop a managed process
    pub fn stop_process(&self, handle: ProcessHandle) -> Result<(), ProcessManagerError> {
        // TODO: Implement process termination via platform manager
        tracing::info!("Stopping process with handle {:?}", handle);

        // Remove from registry
        {
            let mut registry = self.process_registry.write().unwrap();
            registry.remove(&handle);
        }

        Ok(())
    }

    /// Query the status of a managed process
    pub fn query_status(
        &self,
        handle: ProcessHandle,
    ) -> Result<ProcessStatus, ProcessManagerError> {
        let registry = self.process_registry.read().unwrap();
        match registry.get(&handle) {
            Some(info) => Ok(info.status.clone()),
            None => Err(ProcessManagerError::ProcessNotFound { handle }),
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
}

impl Clone for ProcessManager {
    fn clone(&self) -> Self {
        Self {
            platform_manager: Arc::clone(&self.platform_manager),
            plugin_registry: Arc::clone(&self.plugin_registry),
            process_registry: Arc::clone(&self.process_registry),
            cleanup_handler: Arc::clone(&self.cleanup_handler),
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
}
