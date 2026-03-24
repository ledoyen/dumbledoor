# Justfile for dumbledoor development

# Default recipe to display help
default:
    @just --list

# Build the project
build:
    cargo build --all-targets

# Run all tests
test:
    cargo test --verbose --all-targets

# Run clippy linter with strict settings
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Format code with rustfmt
format:
    cargo fmt --all

# Check if code is formatted
check-format:
    cargo fmt --all -- --check

# Run security audit
audit:
    cargo audit

# Generate test coverage report
coverage:
    cargo llvm-cov --all-features --workspace --html

# Generate documentation
doc:
    cargo doc --no-deps --document-private-items --open

# Clean build artifacts
clean:
    cargo clean

# Install development tools
install-tools:
    cargo install cargo-audit
    cargo install cargo-llvm-cov
    cargo install cargo-deny
    cargo install cargo-outdated
    cargo install cargo-udeps
    rustup component add clippy rustfmt llvm-tools-preview

# Run all CI checks locally
ci: check-format lint test audit
    @echo "All CI checks passed!"

# Development workflow
dev: format build test lint
    @echo "Development checks completed!"

# Check dependencies with cargo-deny
check-deps:
    cargo deny check

# Check for outdated dependencies
check-outdated:
    cargo outdated --exit-code 1

# Check for unused dependencies (requires nightly)
check-unused:
    cargo +nightly udeps --all-targets

# Run doc tests
test-doc:
    cargo test --verbose --doc

# Run E2E tests (cross-platform process lifecycle tests)
# Builds reaper binary first — required by macOS e2e tests for process cleanup
test-e2e:
    cargo build -p process-manager --features binary-deps
    cargo test --verbose --test e2e_test

# Run unit tests only
test-unit:
    cargo test --verbose --lib

# Run all tests (unit + E2E + doc)
test-all: test-unit test-e2e test-doc

# Cross-compile check for all supported platforms (catches platform-specific breakage)
# Also runs Clippy per target so dead code and warnings in platform-specific code
# are caught locally, not just in CI on the native platform runner.
check-cross:
    @echo "Checking native platform..."
    cargo check --all-targets
    @echo "Checking x86_64-unknown-linux-gnu..."
    cargo check --all-targets --target x86_64-unknown-linux-gnu
    cargo clippy --all-targets --target x86_64-unknown-linux-gnu -- -D warnings
    @echo "Checking x86_64-pc-windows-msvc..."
    cargo check --all-targets --target x86_64-pc-windows-msvc
    cargo clippy --all-targets --target x86_64-pc-windows-msvc -- -D warnings
    @echo "Checking aarch64-apple-darwin..."
    cargo check --all-targets --target aarch64-apple-darwin
    cargo clippy --all-targets --target aarch64-apple-darwin -- -D warnings
    @echo "All platforms compile and lint successfully!"

# Check MSRV compatibility
check-msrv:
    cargo +1.92.0 check --all-targets

# Generate coverage report in lcov format for CI
coverage-lcov:
    cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info