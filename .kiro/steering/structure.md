# Project Structure

## Workspace Organization

This is a Cargo workspace with multiple crates organized by functionality and safety boundaries.

### Root Level
- `Cargo.toml` - Workspace configuration and shared dependencies
- `justfile` - Development task automation
- `examples/` - Usage examples and platform tests
- Configuration files: `rustfmt.toml`, `clippy.toml`, `deny.toml`

### Core Crates

#### process-manager/
The main library crate containing **zero unsafe code**.

```
process-manager/
├── src/
│   ├── lib.rs              # Public API and ProcessManager
│   ├── error.rs            # Error types and handling
│   ├── platform.rs         # Platform abstraction traits
│   ├── platform/           # Platform-specific implementations
│   │   ├── linux.rs        # Linux process management
│   │   ├── macos.rs        # macOS process management
│   │   └── windows.rs      # Windows process management
│   ├── plugin.rs           # Configuration plugin system
│   ├── reaper.rs           # Process reaper for cleanup
│   └── bin/
│       └── reaper.rs       # Standalone reaper binary
└── tests/                  # Integration and E2E tests
    ├── integration_*.rs    # Integration test suites
    ├── platform_*.rs       # Platform-specific tests
    └── test_victims/       # Helper processes for testing
```

#### unsafe-windows-process/
Windows-specific unsafe operations isolated in dedicated crate.
- Contains **ALL** Windows API unsafe code
- Provides safe public API wrapping Job Objects
- Single responsibility: Windows process management

#### unsafe-macos-process/
macOS-specific unsafe operations (future expansion).
- Reserved for macOS-specific unsafe system calls
- Currently minimal, may grow with advanced features

### Testing Structure

#### Unit Tests
- Located within each module (`#[cfg(test)]`)
- Focus on individual function behavior
- Run with `just test-unit`

#### Integration Tests
- `tests/integration_*.rs` - Cross-platform integration
- `tests/platform_*.rs` - Platform-specific features
- `tests/process_lifecycle_*.rs` - End-to-end process management

#### Test Utilities
- `tests/common/mod.rs` - Shared test utilities
- `tests/test_victims/` - Helper processes for cleanup testing

## Architecture Patterns

### Safety Isolation
- **Main crate**: 100% safe Rust, no unsafe blocks
- **Platform crates**: Contain all unsafe operations
- **Trait abstraction**: Platform-specific code behind common traits

### Platform Abstraction
- `PlatformManager` trait for process operations
- `PlatformProcess` trait for process representation
- Compile-time selection via `cfg` attributes

### Error Handling
- `thiserror` for structured error types
- Platform errors wrapped in common error enum
- Detailed error context for debugging

### Configuration
- Builder pattern for `ProcessConfig`
- Plugin system for configuration enhancement
- Explicit environment (no inheritance)

## Development Workflow

### File Organization Rules
- One primary concept per file
- Platform-specific code in `platform/` subdirectory
- Tests co-located with implementation when possible
- Binaries in `src/bin/` for utilities

### Naming Conventions
- Snake_case for files and modules
- PascalCase for types and traits
- Descriptive names reflecting functionality
- Platform prefixes for platform-specific types