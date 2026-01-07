# Product Overview

**Dumbledoor** is a collection of Rust libraries and tools for system programming and development workflows, with a focus on cross-platform process lifecycle management.

## Core Product: process-manager

A cross-platform Rust library providing reliable process lifecycle management with guaranteed cleanup capabilities across Linux, macOS, and Windows.

### Key Features
- **Cross-platform support** with platform-specific optimizations
- **Explicit configuration** with no inheritance from parent process environment  
- **Guaranteed cleanup** ensuring all spawned processes are terminated on exit
- **Plugin system** for extensible configuration enhancement
- **Thread-safe** design for multi-threaded environments
- **100% Safe Rust** with unsafe operations isolated to dedicated platform crates

### Safety Architecture
The project maintains a strict safety boundary where all unsafe code is isolated into dedicated platform-specific crates (`unsafe-windows-process`, `unsafe-macos-process`), while the main `process-manager` crate contains zero unsafe blocks and relies entirely on safe abstractions.

## Development Status
This is an active development project with core functionality being implemented incrementally. The workspace is designed to grow with additional system programming utilities over time.