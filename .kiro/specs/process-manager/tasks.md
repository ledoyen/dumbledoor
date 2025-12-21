# Implementation Plan

- [x] 1. Set up project structure and core interfaces





  - Create Rust workspace (this will contain multiple crates, process-manager is the first)
  - Create process-manager crate within the workspace
  - Set up workspace Cargo.toml and process-manager Cargo.toml with dependencies (tracing, thiserror, uuid, tokio)
  - Define core public API interfaces (ProcessManager, ProcessConfig, ProcessHandle, ProcessStatus)
  - Set up platform-specific module structure (linux, macos, windows)
  - _Requirements: 1.1, 2.1, 8.1_

- [x] 2. Implement core data models and error types





  - Implement ProcessConfig struct with validation
  - Implement ProcessHandle using UUID
  - Implement ProcessStatus enum with all states including RunningDetached
  - Implement ProcessInfo struct
  - Define comprehensive error types (ProcessManagerError, PlatformError)
  - _Requirements: 1.1, 1.7, 6.1, 8.5_

- [ ]* 2.1 Write unit tests for data models
  - Test ProcessConfig validation logic
  - Test ProcessHandle generation and uniqueness
  - Test ProcessStatus state transitions
  - Test error type serialization/deserialization
  - _Requirements: 1.7, 6.1_

- [ ] 4. Implement Linux platform manager
  - Implement LinuxPlatformManager with user namespace support
  - Add fallback to process groups when namespaces unavailable
  - Implement process spawning with explicit configuration
  - Implement process termination with graceful/forced sequence
  - Implement child process tracking for detached processes
  - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 4.1, 8.5_

- [ ]* 4.1 Write unit tests for Linux platform manager
  - Test process spawning with various configurations
  - Test environment variable isolation
  - Test working directory isolation
  - Test process termination sequences
  - Test child process detection
  - _Requirements: 1.2, 1.3, 2.2, 8.5_

- [ ] 4.2 Create E2E test framework
  - Set up cross-platform E2E test infrastructure
  - Create test utilities for process lifecycle validation
  - Implement cleanup verification helpers
  - Set up GitHub Actions CI matrix for Linux, macOS, Windows
  - _Requirements: 5.1, 5.4_

- [ ]* 4.3 Write E2E tests for Linux platform
  - Test complete process lifecycle on Linux
  - Test cleanup guarantees with signal termination
  - Test user namespace vs fallback behavior
  - Test detached process handling
  - Verify no orphaned processes remain after tests
  - _Requirements: 5.1, 5.2, 5.3, 5.5_

- [x] 5. Implement macOS platform manager
  - Implement MacOSPlatformManager using process groups
  - Implement POSIX signal handling for cleanup
  - Implement process spawning with explicit configuration
  - Implement process termination with platform-appropriate methods
  - Implement child process tracking for detached processes
  - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 4.2, 8.5_

- [x] 5.1 Write unit tests for macOS platform manager
  - Test process group management
  - Test signal-based termination
  - Test environment and working directory isolation
  - Test child process detection
  - _Requirements: 1.2, 1.3, 2.2, 8.5_

- [x] 5.2 Write E2E tests for macOS platform
  - Test complete process lifecycle on macOS
  - Test cleanup guarantees with signal termination
  - Test process group behavior
  - Test detached process handling
  - Verify no orphaned processes remain after tests
  - _Requirements: 5.1, 5.2, 5.3, 5.5_

- [x] 6. Implement Windows platform manager
  - Implement WindowsPlatformManager using Job Objects
  - Implement Windows-specific process termination (TerminateProcess)
  - Implement process spawning with explicit configuration
  - Implement child process tracking for detached processes
  - Handle Windows-specific path and environment handling
  - _Requirements: 1.1, 1.2, 1.3, 2.1, 2.2, 4.3, 8.5_

- [x] 6.1 Write unit tests for Windows platform manager
  - Test Job Object creation and management
  - Test Windows process termination
  - Test environment and working directory isolation
  - Test child process detection
  - _Requirements: 1.2, 1.3, 2.2, 8.5_

- [x] 6.2 Write E2E tests for Windows platform
  - Test complete process lifecycle on Windows
  - Test cleanup guarantees with process termination
  - Test Job Object behavior
  - Test detached process handling
  - Verify no orphaned processes remain after tests
  - _Requirements: 5.1, 5.2, 5.3, 5.5_

- [x] 7. Implement process reaper system
  - Create ProcessReaper as separate executable
  - Implement ReaperMonitor for reaper lifecycle management
  - Implement IPC communication (Unix sockets/Named pipes)
  - Implement reaper process monitoring and restart logic
  - Integrate reaper with platform managers when needed
  - _Requirements: 3.6, 3.7, 3.8_

- [ ]* 7.1 Write unit tests for reaper system
  - Test reaper process spawning and communication
  - Test reaper monitoring and restart logic
  - Test IPC message handling
  - Test reaper survival after main process termination
  - _Requirements: 3.6, 3.7, 3.8_

- [ ] 8. Implement plugin system
  - Create ConfigurationPlugin trait
  - Implement PluginRegistry with thread-safe operations
  - Implement plugin application with graceful error handling
  - Add tracing for plugin success/failure
  - Implement plugin priority ordering
  - _Requirements: 7.1, 7.3, 7.4, 7.5_

- [ ]* 8.1 Write unit tests for plugin system
  - Test plugin registration and ordering
  - Test plugin application and error handling
  - Test graceful degradation on plugin failures
  - Test tracing output for plugin operations
  - _Requirements: 7.1, 7.3, 7.5_

- [ ] 9. Implement example plugins
  - Create jenv integration plugin for Java environment management
  - Create nvm integration plugin for Node.js environment management
  - Implement system tool detection and auto-registration
  - Add plugin configuration validation
  - _Requirements: 7.2, 7.6_

- [ ]* 9.1 Write unit tests for example plugins
  - Test jenv plugin with various Java configurations
  - Test nvm plugin with Node.js configurations
  - Test system tool detection logic
  - Test plugin auto-registration
  - _Requirements: 7.2, 7.6_

- [ ] 10. Implement cleanup handler system
  - Create CleanupHandler for cross-platform cleanup coordination
  - Implement signal handlers for graceful shutdown
  - Implement cleanup on normal program exit
  - Integrate with platform managers and reaper system
  - Ensure cleanup attempts graceful termination before forcing
  - _Requirements: 3.3, 3.4, 3.5_

- [ ]* 10.1 Write unit tests for cleanup handler
  - Test signal-based cleanup scenarios
  - Test normal exit cleanup
  - Test graceful vs forced termination sequence
  - Test cleanup coordination with platform managers
  - _Requirements: 3.3, 3.4, 3.5_

- [ ] 11. Implement main ProcessManager
  - Create thread-safe ProcessManager with Arc/RwLock
  - Implement process spawning with plugin enhancement
  - Implement process stopping with proper cleanup
  - Implement process status querying with detached process handling
  - Implement process listing functionality
  - Add comprehensive tracing throughout
  - _Requirements: 1.1, 2.1, 2.3, 2.4, 8.1, 8.2, 8.3, 8.4_

- [ ]* 11.1 Write unit tests for ProcessManager
  - Test thread-safe operations across multiple threads
  - Test process lifecycle management
  - Test plugin integration during process spawning
  - Test status querying and process listing
  - Test error handling and edge cases
  - _Requirements: 1.1, 2.1, 8.1, 8.3_

- [ ] 12. Implement log file redirection
  - Add log file redirection to process spawning
  - Implement stdout/stderr redirection to single file
  - Handle log file creation and permissions
  - Add error handling for log file issues
  - _Requirements: 8.6_

- [ ]* 12.1 Write unit tests for log redirection
  - Test log file creation and writing
  - Test stdout/stderr combination in single file
  - Test log file permission handling
  - Test error scenarios with invalid log paths
  - _Requirements: 8.6_

- [ ] 13. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 14. Add comprehensive documentation
  - Write API documentation with examples
  - Create platform-specific usage guides
  - Document plugin development guidelines
  - Add troubleshooting guide for common issues
  - Create migration guide from other process managers

- [ ] 15. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.