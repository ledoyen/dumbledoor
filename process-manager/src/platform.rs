//! Platform abstraction layer for process management

use crate::{PlatformError, ProcessConfig, ProcessManagerError, ProcessStatus};
use std::fmt::Debug;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

/// Platform-specific process representation
pub trait PlatformProcess: Debug + Send + Sync {
    /// Get the process ID
    fn pid(&self) -> u32;
}

/// Platform-specific process management trait
#[allow(dead_code)] // Public API - methods will be used when fully implemented
pub trait PlatformManager: Send + Sync {
    /// The concrete process type this manager works with
    type Process: PlatformProcess;

    /// Spawn a new process with the given configuration
    fn spawn_process(&self, config: &ProcessConfig) -> Result<Self::Process, PlatformError>;

    /// Terminate a process (graceful if true, forced if false)
    fn terminate_process(
        &self,
        process: &Self::Process,
        graceful: bool,
    ) -> Result<(), PlatformError>;

    /// Query the current status of a process
    fn query_process_status(&self, process: &Self::Process)
        -> Result<ProcessStatus, PlatformError>;

    /// Set up platform-specific cleanup handlers
    fn setup_cleanup_handler(&self) -> Result<(), PlatformError>;

    /// Clean up all processes in the given list
    fn cleanup_all_processes(&self, processes: &[&Self::Process]) -> Result<(), PlatformError>;

    /// Get child processes spawned by the given process
    fn get_child_processes(&self, process: &Self::Process) -> Result<Vec<u32>, PlatformError>;

    /// Check if this platform needs a process reaper for zombie cleanup
    fn needs_reaper(&self) -> bool;
}

// Platform-specific concrete types (compile-time selected)
#[cfg(target_os = "linux")]
pub type ConcretePlatformManager = linux::LinuxPlatformManager;

#[cfg(target_os = "macos")]
pub type ConcretePlatformManager = macos::MacOSPlatformManager;

#[cfg(target_os = "windows")]
pub type ConcretePlatformManager = windows::WindowsPlatformManager;

#[cfg(target_os = "linux")]
pub type ConcretePlatformProcess = linux::LinuxProcess;

#[cfg(target_os = "macos")]
pub type ConcretePlatformProcess = macos::MacOSProcess;

#[cfg(target_os = "windows")]
pub type ConcretePlatformProcess = windows::WindowsProcess;

/// Create the appropriate platform manager for the current system
pub fn create_platform_manager() -> Result<ConcretePlatformManager, ProcessManagerError> {
    #[cfg(target_os = "linux")]
    {
        linux::LinuxPlatformManager::new()
    }

    #[cfg(target_os = "macos")]
    {
        macos::MacOSPlatformManager::new()
    }

    #[cfg(target_os = "windows")]
    {
        windows::WindowsPlatformManager::new()
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
