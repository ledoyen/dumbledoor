# Process Manager Tests

This directory contains a rationalized test suite for the process manager library, organized for clarity and minimal redundancy.

## Test Organization

### E2E Tests

- **`e2e_test.rs`** - Five comprehensive end-to-end tests covering all critical functionality:
  1. **Basic Process Lifecycle** - Core ProcessManager functionality (start, query, stop, cleanup)
  2. **Multiple Process Management** - Concurrent operations and bulk cleanup
  3. **Process Configuration Features** - Environment isolation, working directory, log redirection
  4. **Error Handling and Edge Cases** - Validation, failure modes, graceful degradation
  5. **SIGKILL Cleanup Guarantee** - Platform-specific cleanup mechanisms and reaper functionality

### Unit Tests

Unit tests are located within each source module using `#[cfg(test)]`:
- **`src/lib.rs`** - ProcessHandle, ProcessConfig, ProcessStatus, and error type tests
- **`src/platform/linux.rs`** - Linux platform manager unit tests
- **`src/platform/macos.rs`** - macOS platform manager unit tests  
- **`src/platform/windows.rs`** - Windows platform manager unit tests

### Support Files

- **`common/mod.rs`** - Minimal cross-platform test utilities and helpers
- **`test_victims/sigkill_victim.rs`** - Helper executable for SIGKILL cleanup testing

## Test Categories

### Unit Tests (in `src/`)
- Pure function testing
- Configuration validation
- Data structure behavior
- Error type construction
- Platform-specific configuration validation

### E2E Tests (in `tests/`)
- Full ProcessManager workflows
- Cross-platform compatibility
- Platform-specific cleanup verification
- Real process spawning and management
- Multi-process cleanup scenarios

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
just test-unit          # Unit tests only (in src/)
just test-e2e          # E2E tests only (in tests/)
```

## CI Testing

The CI pipeline runs tests on multiple platforms:
- **Linux**: Ubuntu latest
- **macOS**: macOS latest
- **Windows**: Windows latest

Each platform runs the full test suite to ensure cross-platform compatibility.

## Test Design Principles

1. **Minimal Redundancy**: Each test has a single, well-defined responsibility
2. **Cross-Platform Compatibility**: Common utilities ensure tests work on all supported platforms
3. **Focused Coverage**: Tests cover critical paths rather than variations
4. **Clear Categories**: Unit tests in source modules, E2E tests in dedicated files
5. **Efficient Execution**: Reduced test count for faster CI and development cycles

## SIGKILL Cleanup Testing

The SIGKILL cleanup test uses a multi-process architecture to verify that child processes are properly cleaned up when the ProcessManager host process is forcefully terminated:

1. **Test Orchestrator** (`e2e_test.rs`) - The main test process that manages the test scenario
2. **Victim Process** (`test_victims/sigkill_victim.rs`) - A separate executable that runs ProcessManager and spawns children
3. **Target Child Processes** - Long-running processes that should be cleaned up when the victim is killed

This architecture ensures that cleanup mechanisms work correctly even when the main process cannot perform graceful shutdown.

## Migration from Previous Structure

This rationalized structure replaces the previous complex test organization:
- ~50 test functions → ~15 test functions (10 unit + 5 E2E)
- 6 integration test files → 1 E2E test file
- Eliminated redundant process spawning and cleanup
- Focused on critical functionality rather than variations
- Maintained full coverage while improving maintainability