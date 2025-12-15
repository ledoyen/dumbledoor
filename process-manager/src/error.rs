//! Error types for the process manager

use crate::ProcessHandle;

/// Main error type for process manager operations
#[derive(Debug, thiserror::Error)]
pub enum ProcessManagerError {
    #[error("Invalid process configuration: {details}")]
    InvalidConfig { details: String },

    #[error("Process failed to start: {reason}")]
    StartupFailed { reason: String },

    #[error("Process not found: {handle:?}")]
    ProcessNotFound { handle: ProcessHandle },

    #[error("Platform operation failed: {error}")]
    PlatformError { error: PlatformError },

    #[error("Cleanup failed: {details}")]
    CleanupFailed { details: String },
}

/// Platform-specific error types
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("System call failed: {syscall}: {errno}")]
    SystemCallFailed { syscall: String, errno: i32 },

    #[error("Permission denied: {operation}")]
    PermissionDenied { operation: String },

    #[error("Resource unavailable: {resource}")]
    ResourceUnavailable { resource: String },
}

/// Plugin-specific error types (internal use only)
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("Configuration enhancement failed: {reason}")]
    EnhancementFailed { reason: String },

    #[error("System integration unavailable: {tool}")]
    SystemIntegrationUnavailable { tool: String },
}

/// Reaper-specific error types
#[derive(Debug, thiserror::Error)]
pub enum ReaperError {
    #[error("Failed to spawn reaper process: {reason}")]
    SpawnFailed { reason: String },

    #[error("Reaper communication failed: {reason}")]
    CommunicationFailed { reason: String },

    #[error("Reaper process died unexpectedly")]
    ReaperDied,
}
