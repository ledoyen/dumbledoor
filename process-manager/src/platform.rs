//! Platform abstraction layer for process management

use crate::{PlatformError, ProcessConfig, ProcessManagerError, ProcessStatus};
use std::fmt::Debug;
use std::sync::Arc;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows_safe;

/// Platform-specific process representation
pub trait PlatformProcess: Debug + Send + Sync {
    /// Get the process ID
    fn pid(&self) -> u32;
}

/// Platform-specific process management trait
pub trait PlatformManager: Send + Sync {
    /// Spawn a new process with the given configuration
    fn spawn_process(
        &self,
        config: &ProcessConfig,
    ) -> Result<Box<dyn PlatformProcess>, PlatformError>;

    /// Terminate a process (graceful if true, forced if false)
    fn terminate_process(
        &self,
        process: &dyn PlatformProcess,
        graceful: bool,
    ) -> Result<(), PlatformError>;

    /// Query the current status of a process
    fn query_process_status(
        &self,
        process: &dyn PlatformProcess,
    ) -> Result<ProcessStatus, PlatformError>;

    /// Set up platform-specific cleanup handlers
    fn setup_cleanup_handler(&self) -> Result<(), PlatformError>;

    /// Clean up all processes in the given list
    fn cleanup_all_processes(
        &self,
        processes: &[&dyn PlatformProcess],
    ) -> Result<(), PlatformError>;

    /// Get child processes spawned by the given process
    fn get_child_processes(&self, process: &dyn PlatformProcess)
        -> Result<Vec<u32>, PlatformError>;
}

/// Create the appropriate platform manager for the current system
pub fn create_platform_manager() -> Result<Arc<dyn PlatformManager>, ProcessManagerError> {
    #[cfg(target_os = "linux")]
    {
        Ok(Arc::new(
            crate::platform::linux::LinuxPlatformManager::new()?
        ))
    }

    #[cfg(target_os = "macos")]
    {
        Ok(Arc::new(
            crate::platform::macos::MacOSPlatformManager::new()?
        ))
    }

    #[cfg(target_os = "windows")]
    {
        Ok(Arc::new(
            crate::platform::windows_safe::WindowsPlatformManager::new()?,
        ))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(ProcessManagerError::PlatformError {
            error: PlatformError::ResourceUnavailable {
                resource: "Unsupported platform".to_string(),
            },
        })
    }
}
