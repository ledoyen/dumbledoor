# Process Manager Tests

This directory contains comprehensive tests for the process manager library, organized by feature and test type.

## Test Organization

### Core Test Files

- **`integration_focused_test.rs`** - Focused integration tests for core functionality not covered by E2E tests
- **`process_lifecycle_test.rs`** - Cross-platform E2E tests for complete process lifecycle management
- **`platform_features_test.rs`** - Platform-specific feature tests with conditional compilation
- **`reaper_test.rs`** - Tests for the process reaper system
- **`sigkill_cleanup_test.rs`** - End-to-end tests for cleanup when main process receives SIGKILL

### Support Files

- **`common/mod.rs`** - Common test utilities and cross-platform helpers
- **`test_victims/`** - Helper executables for testing process cleanup scenarios

## Test Categories

### Integration Tests
Focus on component integration and functionality not covered by E2E tests:
- ProcessManager creation and basic operations
- Configuration validation and builder patterns
- Plugin system integration
- Error handling and edge cases
- Multiple manager instances

### E2E (End-to-End) Tests
Comprehensive process lifecycle testing across all platforms:
- Complete process lifecycle (start → run → stop)
- Multiple process management
- Environment variable isolation
- Working directory isolation
- Log file redirection
- Detached process handling
- Concurrent operations
- Cleanup guarantees

### Platform-Specific Tests
Tests for platform-specific functionality:
- Windows Job Objects
- macOS process groups
- Linux namespaces/process groups
- Platform-specific cleanup mechanisms
- Reaper functionality
- Signal handling

## Cross-Platform Testing

All tests use common utilities from `common/mod.rs` to ensure consistent behavior across platforms:

- **Platform Commands**: Automatically selects appropriate commands for each OS
- **Process Validation**: Common validation logic for process states
- **Cleanup Helpers**: Platform-agnostic cleanup verification
- **Test Configuration**: Standardized test process configurations

## Running Tests

Use the justfile commands for organized test execution:

```bash
# Run all tests
just test

# Run specific test categories
just test-unit          # Unit tests only
just test-integration   # Integration tests only
just test-e2e          # E2E process lifecycle tests
just test-platform     # Platform-specific feature tests
just test-features     # All feature tests (integration + E2E + platform)
```

## CI Testing

The CI pipeline runs tests on multiple platforms:
- **Linux**: Ubuntu latest (currently disabled in CI)
- **macOS**: macOS latest
- **Windows**: Windows latest

Each platform runs the full test suite to ensure cross-platform compatibility.

## Test Design Principles

1. **Feature-Based Organization**: Tests are grouped by functionality rather than by platform
2. **Cross-Platform Compatibility**: Common utilities ensure tests work on all supported platforms
3. **Minimal Duplication**: Shared test logic reduces maintenance burden
4. **Platform-Specific Validation**: Platform-specific behavior is tested where appropriate
5. **Comprehensive Coverage**: Tests cover normal operation, edge cases, and error conditions

## SIGKILL Cleanup Tests

The SIGKILL cleanup tests use a multi-process architecture to verify that child processes are properly cleaned up when the ProcessManager host process is forcefully terminated:

1. **Test Orchestrator** (`sigkill_cleanup_test.rs`) - The main test process that manages the test scenario
2. **Victim Process** (`test_victims/sigkill_victim.rs`) - A separate executable that runs ProcessManager and spawns children
3. **Target Child Processes** - Long-running processes that should be cleaned up when the victim is killed

This architecture ensures that cleanup mechanisms work correctly even when the main process cannot perform graceful shutdown.