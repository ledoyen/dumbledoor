# Dumbledoor

A collection of Rust libraries and tools for system programming and development workflows.

## Crates

### process-manager

A cross-platform Rust library for reliable process lifecycle management with guaranteed cleanup capabilities.

**Features:**
- **Cross-platform support**: Linux, macOS, and Windows
- **Explicit configuration**: No inheritance from parent process environment
- **Guaranteed cleanup**: All spawned processes are terminated when the main program exits
- **Plugin system**: Extensible configuration enhancement for environment managers
- **Thread-safe**: Safe for use in multi-threaded environments

**Platform-Specific Features:**
- **Linux**: User namespaces for automatic cleanup (with fallback to process groups)
- **macOS**: POSIX process groups with signal-based cleanup
- **Windows**: Job Objects for automatic process tree cleanup

*More crates will be added to this workspace as the project grows.*

## Development Status

This is the initial project structure. Core functionality will be implemented in subsequent tasks.

## Requirements

- Rust 1.70+
- Platform-specific dependencies are handled automatically

## Development

### Available Commands

Use `just` to see all available development commands:

- `just build` - Build the project
- `just test` - Run all tests
- `just lint` - Run clippy linter
- `just format` - Format code with rustfmt
- `just audit` - Run security audit
- `just coverage` - Generate test coverage report
- `just doc` - Generate documentation

### CI/CD Pipeline

The project uses GitHub Actions for continuous integration with the following checks:

#### 🔍 **Quality Checks**
- **Formatting**: Ensures consistent code style with `rustfmt`
- **Linting**: Strict clippy rules with `-D warnings`
- **Documentation**: Validates all documentation builds without warnings

#### 🔒 **Security**
- **Audit**: Checks for known security vulnerabilities using `cargo-audit`
- **Dependencies**: Validates licenses and checks for banned/outdated dependencies

#### 🧪 **Testing**
- **Multi-platform**: Tests on Linux, macOS, and Windows
- **Multi-version**: Tests on stable and beta Rust versions
- **Coverage**: Generates code coverage reports with `cargo-llvm-cov`
- **MSRV**: Ensures compatibility with Rust 1.70+

#### 📊 **Quality Metrics**
- **Dependency analysis**: Checks for unused and outdated dependencies
- **License compliance**: Ensures all dependencies use approved licenses
- **Code coverage**: Maintains high test coverage standards




## License

TBD