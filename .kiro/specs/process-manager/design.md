# Process Manager Design Document

## Overview

The Process Manager is a cross-platform Rust library that provides reliable process lifecycle management with guaranteed cleanup capabilities. The system is designed around explicit configuration principles, ensuring that child processes are launched with precisely defined execution environments without inheriting from the parent process. The architecture supports extensible plugin systems for integration with common development environment managers while maintaining platform-specific optimizations for process cleanup.

## Architecture

The system follows a layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│                    Public API Layer                     │
├─────────────────────────────────────────────────────────┤
│                  Plugin System Layer                    │
├─────────────────────────────────────────────────────────┤
│                 Process Manager Core                    │
├─────────────────────────────────────────────────────────┤
│              Platform Abstraction Layer                │
├─────────────────────────────────────────────────────────┤
│    Linux (namespaces)  │  macOS (pgroups)  │  Windows   │
│         + POSIX        │     + POSIX       │ (Job Objects)│
└─────────────────────────────────────────────────────────┘
```

### Core Components

1. **ProcessManager**: Main orchestrator that manages the lifecycle of all child processes
2. **ProcessConfig**: Immutable configuration specification for process spawning
3. **ProcessHandle**: Unique identifier and control interface for individual processes
4. **PlatformManager**: Platform-specific implementation for process control and cleanup
5. **PluginRegistry**: Extensible system for configuration enhancement
6. **CleanupHandler**: Cross-platform cleanup coordination
7. **ProcessReaper**: Separate background process for zombie cleanup on systems without user namespaces

## Components and Interfaces

### ProcessManager

The central component responsible for process lifecycle management. Thread-safe for use in multi-threaded environments:

```rust
use std::sync::{Arc, RwLock};

pub struct ProcessManager {
    platform_manager: Arc<dyn PlatformManager>,
    plugin_registry: Arc<RwLock<PluginRegistry>>,
    process_registry: Arc<RwLock<HashMap<ProcessHandle, ProcessInfo>>>,
    cleanup_handler: Arc<CleanupHandler>,
    reaper_monitor: Arc<RwLock<Option<ReaperMonitor>>>,
}

impl ProcessManager {
    pub fn new() -> Result<Self, ProcessManagerError>;
    pub fn start_process(&self, config: ProcessConfig) -> Result<ProcessHandle, ProcessManagerError>;
    pub fn stop_process(&self, handle: ProcessHandle) -> Result<(), ProcessManagerError>;
    pub fn query_status(&self, handle: ProcessHandle) -> Result<ProcessStatus, ProcessManagerError>;
    pub fn list_processes(&self) -> Vec<ProcessHandle>;
    pub fn register_plugin(&self, plugin: Box<dyn ConfigurationPlugin>);
}

// ProcessManager implements Clone for easy sharing across threads
impl Clone for ProcessManager {
    fn clone(&self) -> Self {
        ProcessManager {
            platform_manager: Arc::clone(&self.platform_manager),
            plugin_registry: Arc::clone(&self.plugin_registry),
            process_registry: Arc::clone(&self.process_registry),
            cleanup_handler: Arc::clone(&self.cleanup_handler),
            reaper_monitor: Arc::clone(&self.reaper_monitor),
        }
    }
}
```

### ProcessConfig

Explicit configuration for process spawning:

```rust
#[derive(Debug, Clone)]
pub struct ProcessConfig {
    pub command: PathBuf,
    pub args: Vec<String>,
    pub working_directory: Option<PathBuf>,
    pub environment: HashMap<String, String>,
    pub log_file: Option<PathBuf>,
}
```

### PlatformManager Trait

Platform-specific process management abstraction:

```rust
pub trait PlatformManager: Send + Sync {
    fn spawn_process(&self, config: &ProcessConfig) -> Result<PlatformProcess, PlatformError>;
    fn terminate_process(&self, process: &PlatformProcess, graceful: bool) -> Result<(), PlatformError>;
    fn query_process_status(&self, process: &PlatformProcess) -> Result<ProcessStatus, PlatformError>;
    fn setup_cleanup_handler(&self) -> Result<(), PlatformError>;
    fn cleanup_all_processes(&self, processes: &[PlatformProcess]) -> Result<(), PlatformError>;
    
    // Track child processes spawned by managed processes
    fn get_child_processes(&self, process: &PlatformProcess) -> Result<Vec<u32>, PlatformError>;
}

// Send + Sync are required because:
// - Send: PlatformManager instances need to be moved between threads
// - Sync: Multiple threads may call PlatformManager methods simultaneously
// - The methods are &self (not &mut self) to allow concurrent access
// - Any internal state must be protected by the implementation (e.g., Mutex, AtomicXxx)
```

### Configuration Plugin System

Extensible configuration enhancement:

```rust
pub trait ConfigurationPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn is_applicable(&self, config: &ProcessConfig) -> bool;
    fn enhance_config(&self, config: ProcessConfig) -> Result<ProcessConfig, PluginError>;
    fn priority(&self) -> u32; // Lower numbers = higher priority
}

// Plugin errors are handled internally with tracing, not exposed to public API
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("Configuration enhancement failed: {reason}")]
    EnhancementFailed { reason: String },
    
    #[error("System integration unavailable: {tool}")]
    SystemIntegrationUnavailable { tool: String },
}

pub struct PluginRegistry {
    plugins: Vec<Box<dyn ConfigurationPlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self { /* ... */ }
    pub fn register(&mut self, plugin: Box<dyn ConfigurationPlugin>) { /* ... */ }
    
    // Plugin failures are logged but don't fail the operation
    pub fn apply_plugins(&self, config: ProcessConfig) -> ProcessConfig {
        let mut enhanced_config = config;
        
        for plugin in &self.plugins {
            if plugin.is_applicable(&enhanced_config) {
                match plugin.enhance_config(enhanced_config.clone()) {
                    Ok(new_config) => {
                        tracing::debug!("Plugin '{}' enhanced configuration", plugin.name());
                        enhanced_config = new_config;
                    }
                    Err(error) => {
                        tracing::warn!("Plugin '{}' failed: {}", plugin.name(), error);
                        // Continue with original config
                    }
                }
            }
        }
        
        enhanced_config
    }
}

### Process Reaper System

For platforms without user namespaces, a separate reaper process handles zombie cleanup:

```rust
pub struct ReaperMonitor {
    reaper_pid: u32,
    communication_channel: ReaperChannel,
    monitor_thread: JoinHandle<()>,
}

pub struct ProcessReaper {
    // Separate executable that runs as a daemon
    // Communicates with main process via IPC
    // Survives main process termination
    // Cleans up registered child processes
}

pub enum ReaperChannel {
    UnixSocket(UnixStream),
    NamedPipe(NamedPipe), // Windows
}

impl ReaperMonitor {
    pub fn spawn_reaper() -> Result<Self, ReaperError>;
    pub fn register_process(&self, pid: u32) -> Result<(), ReaperError>;
    pub fn unregister_process(&self, pid: u32) -> Result<(), ReaperError>;
    pub fn is_reaper_alive(&self) -> bool;
    pub fn restart_reaper(&mut self) -> Result<(), ReaperError>;
}
```
```

## Data Models

### Process State Management

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessHandle(uuid::Uuid);

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub handle: ProcessHandle,
    pub config: ProcessConfig,
    pub start_time: SystemTime,
    pub status: ProcessStatus,
}

#[derive(Debug, Clone)]
pub enum ProcessStatus {
    Starting,
    Running { pid: u32 },                                    // Process is actively running
    RunningDetached { exit_code: i32, child_pids: Vec<u32> }, // Process exited but spawned long-running children
    Exited { exit_code: i32, exit_time: SystemTime },        // Process ran and exited with no active children
    Terminated { signal: Option<i32>, exit_time: SystemTime }, // Process was killed by signal
    Failed { error: String },                                 // Process failed to start
}
```

### Platform-Specific Implementations

Platform implementations are responsible for their own thread safety and internal state management:

```rust
// Linux implementation using user namespaces when available
pub struct LinuxPlatformManager {
    use_namespaces: bool,
    namespace_fd: Option<RawFd>,
    needs_reaper: bool, // true when namespaces not available
    // Internal state protected by Mutex/RwLock as needed
    process_state: RwLock<HashMap<ProcessHandle, LinuxProcessState>>,
}

// macOS implementation using process groups
pub struct MacOSPlatformManager {
    // Internal state protected by Mutex/RwLock as needed
    process_groups: RwLock<HashMap<ProcessHandle, libc::pid_t>>,
}

// Windows implementation using Job Objects
pub struct WindowsPlatformManager {
    job_object: HANDLE,
    // Internal state protected by Mutex/RwLock as needed
    process_handles: RwLock<HashMap<ProcessHandle, HANDLE>>,
}
```

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

Based on the prework analysis, the following correctness properties ensure the system behaves correctly across all valid inputs:

**Property 1: Process spawning with explicit configuration**
*For any* valid ProcessConfig with command and arguments, starting the process should return a valid ProcessHandle and create a running child process
**Validates: Requirements 1.1**

**Property 2: Environment variable isolation**
*For any* ProcessConfig with specified environment variables, the child process should have exactly those environment variables and no others from the parent process
**Validates: Requirements 1.2, 6.2**

**Property 3: Working directory isolation**
*For any* ProcessConfig with a specified working directory, the child process should run in exactly that directory
**Validates: Requirements 1.3**



**Property 4: Configuration validation**
*For any* invalid ProcessConfig, the process manager should return appropriate validation errors without starting a process
**Validates: Requirements 1.7, 6.1, 6.5**

**Property 5: Process termination**
*For any* running process with a valid ProcessHandle, calling stop should terminate the process and remove it from the registry
**Validates: Requirements 2.1, 2.3**

**Property 6: Graceful termination sequence**
*For any* process termination operation, the system should attempt graceful termination before forcing termination
**Validates: Requirements 2.2, 3.5**

**Property 7: Idempotent stop operations**
*For any* already terminated process, attempting to stop it again should complete without error
**Validates: Requirements 2.4**

**Property 8: Process tree termination**
*For any* process that spawns child processes, stopping the parent should terminate the entire process tree
**Validates: Requirements 2.5**

**Property 9: Signal-based cleanup**
*For any* set of running processes, when the main program receives a termination signal, all child processes should be terminated
**Validates: Requirements 3.3**

**Property 10: Normal exit cleanup**
*For any* set of running processes, when the main program exits normally, all child processes should be terminated before exit
**Validates: Requirements 3.4**

**Property 11: Platform-appropriate termination methods**
*For any* process termination on any platform, the system should use the correct platform-specific termination APIs
**Validates: Requirements 4.4**

**Property 12: Capability detection and selection**
*For any* platform configuration, the system should automatically detect and select the most robust cleanup mechanism available
**Validates: Requirements 4.5**

**Property 13: Plugin registration and availability**
*For any* registered ConfigurationPlugin, it should be available for ProcessConfig enhancement when applicable
**Validates: Requirements 7.1**

**Property 14: Plugin ordering**
*For any* set of applicable plugins, they should be applied in deterministic priority order
**Validates: Requirements 7.3**

**Property 15: Plugin output validation**
*For any* plugin-modified ProcessConfig, the system should validate the configuration before process launch
**Validates: Requirements 7.4**

**Property 16: Plugin failure graceful degradation**
*For any* failing or unavailable plugin, the system should log a warning and continue with the original ProcessConfig
**Validates: Requirements 7.5**

**Property 17: System integration auto-detection**
*For any* detected system integration tools, appropriate plugin handlers should be automatically registered
**Validates: Requirements 7.6**

**Property 18: Process status querying**
*For any* valid ProcessHandle, querying status should return the current accurate state of the child process
**Validates: Requirements 8.1**

**Property 19: Exit code capture**
*For any* child process that exits, the exit code should be captured and available for querying
**Validates: Requirements 8.2**

**Property 20: Process listing**
*For any* set of active processes, querying all processes should return all active ProcessHandle instances
**Validates: Requirements 8.3**

**Property 21: Unresponsive process detection**
*For any* process that becomes unresponsive, the system should detect and report the unresponsive state
**Validates: Requirements 8.4**

**Property 22: Detached process tracking**
*For any* process that exits but spawns long-running children, the system should report it as RunningDetached rather than Exited
**Validates: Requirements 8.5**

**Property 23: Log file redirection**
*For any* ProcessConfig with a log file path specified, both stdout and stderr should be redirected to the same log file
**Validates: Requirements 8.6**

**Property 23: Reaper process spawning**
*For any* platform requiring a process reaper, the system should spawn and maintain a reaper process
**Validates: Requirements 3.6**

**Property 24: Reaper process monitoring**
*For any* terminated reaper process, the system should detect the termination and restart the reaper
**Validates: Requirements 3.7**

**Property 25: Reaper survival**
*For any* main process termination, the reaper process should continue running to clean up remaining children
**Validates: Requirements 3.8**

## Error Handling

The system implements comprehensive error handling across all layers:

### Error Types

```rust
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

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("System call failed: {syscall}: {errno}")]
    SystemCallFailed { syscall: String, errno: i32 },
    
    #[error("Permission denied: {operation}")]
    PermissionDenied { operation: String },
    
    #[error("Resource unavailable: {resource}")]
    ResourceUnavailable { resource: String },
}
```

### Error Recovery Strategies

1. **Configuration Validation**: Early validation prevents invalid processes from starting
2. **Graceful Degradation**: Plugin failures don't prevent core functionality
3. **Cleanup Guarantees**: Errors during cleanup are logged but don't prevent other processes from being cleaned up
4. **Platform Fallbacks**: If advanced platform features fail, fall back to basic POSIX/Windows APIs

## Crates structure

Avoid flat crates, use nested crates when needed, especially to hide implementation details.
Group struct traits and functions by feature crates, not by technical crates.

## Testing Strategy

The testing approach focuses on unit testing and integration testing:

### Unit Testing Approach

Unit tests focus on:
- Specific platform integration examples (Linux namespaces, Windows Job Objects, macOS process groups)
- Configuration validation edge cases
- Plugin system integration points
- Error condition handling
- Platform capability detection
- Process lifecycle management
- Reaper process functionality

**Dependencies:**
- Use the `tracing` crate for structured logging and plugin error reporting

### Test Data Generation

Custom generators for:
- Valid ProcessConfig instances with realistic commands and arguments
- Platform-specific configuration variations
- Network configuration combinations
- Environment variable sets
- Plugin configurations

### Integration Testing

- Cross-platform CI testing on Linux, macOS, and Windows
- Real process spawning and termination scenarios
- Signal handling and cleanup verification
- Plugin system integration with real environment managers (jenv, nvm, etc.)

## Implementation Notes

### Platform-Specific Considerations

**Linux:**
- Prefer user namespaces when available (requires unprivileged user namespaces)
- Fall back to process groups and signal handling
- Handle cgroup integration for resource management

**macOS:**
- Use process groups (setpgid) for process tree management
- Implement proper signal handling for cleanup
- Handle System Integrity Protection (SIP) restrictions

**Windows:**
- Use Job Objects for automatic process tree cleanup
- Handle Windows service integration
- Implement proper Windows process termination sequence

### Security Considerations

- Validate all process configurations to prevent command injection
- Implement proper privilege dropping when spawning processes
- Ensure cleanup handlers can't be bypassed by malicious processes
- Validate plugin inputs to prevent configuration tampering

### Thread Safety

The ProcessManager is designed for safe concurrent access across multiple threads:

- **Arc<RwLock<T>>**: Process registry and plugin registry use read-write locks for concurrent access
- **Immutable sharing**: Platform manager and cleanup handler are shared immutably via Arc
- **Clone semantics**: ProcessManager implements Clone for easy sharing across threads
- **Lock granularity**: Separate locks for process registry and plugin registry to minimize contention
- **Read-heavy optimization**: RwLock allows multiple concurrent readers for status queries

**Usage in multi-threaded environments:**
```rust
let process_manager = ProcessManager::new()?;
let manager_clone = process_manager.clone();

// Safe to use across threads
tokio::spawn(async move {
    manager_clone.start_process(config).await?;
});
```

### Performance Considerations

- Lazy initialization of platform-specific resources
- Efficient process registry using HashMap with UUID keys
- Minimal overhead for process status queries (read locks only)
- Batch operations for cleanup scenarios
- RwLock contention minimization through separate registries