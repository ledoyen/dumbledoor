# Technology Stack

## Build System & Tools
- **Build System**: Cargo (Rust's native build system)
- **Task Runner**: Just (justfile for development commands)
- **Rust Version**: 1.92+ (MSRV compatibility maintained)
- **Edition**: Rust 2021

## Core Dependencies
- **tracing**: Structured logging and diagnostics
- **thiserror**: Error handling with derive macros
- **uuid**: Unique identifier generation (v4 features)
- **tokio**: Async runtime (full feature set)
- **libc**: Unix system calls (Unix platforms only)

## Development Tools
- **rustfmt**: Code formatting (max_width: 100, 4 spaces, Unix newlines)
- **clippy**: Linting with strict settings (`-D warnings`)
- **cargo-audit**: Security vulnerability scanning
- **cargo-llvm-cov**: Code coverage reporting
- **cargo-deny**: License and dependency validation

## Common Commands

### Development Workflow
```bash
just dev          # Format, build, test, lint
just build        # Build all targets
just test         # Run all tests
just lint         # Run clippy with strict settings
just format       # Format code with rustfmt
```

### Testing
```bash
just test-unit         # Unit tests only
just test-integration  # Integration tests
just test-e2e         # End-to-end tests
just test-platform    # Platform-specific tests
just test-all         # All test suites
```

### Quality Assurance
```bash
just ci           # Run all CI checks locally
just audit        # Security audit
just coverage     # Generate HTML coverage report
just doc          # Generate and open documentation
```

### Dependency Management
```bash
just check-deps      # Validate dependencies with cargo-deny
just check-outdated  # Check for outdated dependencies
just check-unused    # Check for unused dependencies (nightly)
```

## Platform-Specific Architecture
- **Linux**: User namespaces with process group fallback
- **macOS**: POSIX process groups with signal-based cleanup
- **Windows**: Job Objects via `unsafe-windows-process` crate

## Safety Guidelines
- Main `process-manager` crate must contain **zero unsafe blocks**
- All unsafe operations isolated to dedicated platform crates
- Platform crates provide safe public APIs wrapping unsafe system calls
- Every unsafe block requires thorough safety documentation