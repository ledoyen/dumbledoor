# ADR-001: Unsafe Code Isolation and Generic Platform Architecture

## Status
Accepted

## Date
2025-01-19

## Context

During the development of the process-manager crate, we needed to address several critical architectural concerns:

1. **Safety**: Eliminate all unsafe code from the main process-manager crate
2. **Type Safety**: Avoid runtime downcasting and type erasure patterns that can panic
3. **Platform Abstraction**: Support multiple platforms (Linux, macOS, Windows) without exposing platform-specific types in the public API
4. **Ergonomics**: Provide a clean, easy-to-use API that doesn't require users to deal with complex generic parameters

## Decision

We implemented a **Generic Platform Architecture with Unsafe Code Isolation** based on the following key decisions:

### 1. Complete Unsafe Code Isolation

**Decision**: All unsafe code is isolated in dedicated platform-specific crates (e.g., `unsafe-windows-process`).

**Rationale**: 
- Unsafe code is inherently risky and should be minimized and isolated
- Easier to audit and verify safety properties when unsafe code is contained
- Clear separation of concerns between safe abstractions and unsafe implementations

**Implementation**:
- `unsafe-windows-process` crate contains ALL Windows unsafe operations
- `process-manager` crate contains ZERO unsafe blocks
- Safe wrapper functions provide clean interfaces over unsafe operations

### 2. Generic Architecture with Associated Types

**Decision**: Use Rust generics with associated types instead of trait objects and downcasting.

**Rationale**:
- **Type Safety**: Eliminates runtime panics from failed downcasts
- **Performance**: Zero-cost abstractions with compile-time dispatch
- **Maintainability**: Compiler enforces type correctness at compile time

**Implementation**:
```rust
pub trait PlatformManager: Send + Sync {
    type Process: PlatformProcess;
    
    fn spawn_process(&self, config: &ProcessConfig) -> Result<Self::Process, PlatformError>;
    fn terminate_process(&self, process: &Self::Process, graceful: bool) -> Result<(), PlatformError>;
    // ... other methods
}
```

### 3. Compile-Time Platform Selection

**Decision**: Use conditional compilation and type aliases to hide platform-specific types from the public API.

**Rationale**:
- **Clean API**: Users don't see complex generic parameters
- **Platform Abstraction**: Implementation details remain hidden
- **Compile-Time Selection**: No runtime overhead for platform detection

**Implementation**:
```rust
// Private platform modules
#[cfg(target_os = "windows")]
mod windows_safe;

// Public type aliases (compile-time selected)
#[cfg(target_os = "windows")]
pub type ConcretePlatformManager = windows_safe::WindowsPlatformManager;

// Clean public API
pub struct ProcessManager {
    platform_manager: ConcretePlatformManager,
    // ...
}
```

### 4. Immutable Public API with Interior Mutability

**Decision**: Use `&self` for all public methods with `Arc<RwLock<...>>` for shared state.

**Rationale**:
- **Ergonomics**: Users don't need mutable references for basic operations
- **Thread Safety**: Multiple threads can safely share ProcessManager instances
- **Interior Mutability**: State changes handled internally through locks

**Implementation**:
```rust
pub struct ProcessManager {
    platform_manager: ConcretePlatformManager,
    process_registry: Arc<RwLock<HashMap<ProcessHandle, ProcessInfo>>>,
    // ...
}

impl ProcessManager {
    pub fn start_process(&self, config: ProcessConfig) -> Result<ProcessHandle, ProcessManagerError> {
        // Uses &self, not &mut self
    }
}
```

## Consequences

### Positive
- **Zero unsafe code** in the main process-manager crate
- **No runtime panics** from type casting
- **Clean public API** that hides platform complexity
- **Type safety** enforced at compile time
- **Thread-safe** operations without requiring mutable references
- **Performance** benefits from zero-cost abstractions

### Negative
- **Compile-time complexity** in the platform abstraction layer
- **Code duplication** across platform implementations
- **Learning curve** for contributors unfamiliar with advanced Rust patterns

### Neutral
- **Larger codebase** due to explicit platform abstractions
- **Build-time dependencies** on platform-specific crates

## Alternatives Considered

### 1. Trait Objects with Downcasting
**Rejected**: Runtime panics from failed downcasts are unacceptable in production code.

### 2. Enum-based Platform Selection
**Rejected**: Would require matching on platform types throughout the codebase, leading to maintenance burden.

### 3. Macro-based Code Generation
**Rejected**: Would reduce type safety and make debugging more difficult.

## Implementation Notes

### Safe Wrapper Pattern
All unsafe operations are wrapped in safe functions that validate inputs and handle errors:

```rust
// In unsafe-windows-process crate
pub fn terminate_process_safe(
    process_handle: &SafeHandle,
    exit_code: u32,
) -> Result<(), UnsafeWindowsError> {
    // SAFETY: SafeHandle guarantees the handle is valid
    unsafe { terminate_process(process_handle.as_raw(), exit_code) }
}
```

### Platform Module Structure
```
process-manager/src/
├── platform.rs              # Public traits and type aliases
├── platform/
│   ├── windows_safe.rs      # Windows implementation (private)
│   ├── linux.rs             # Linux implementation (private)
│   └── macos.rs             # macOS implementation (private)
└── lib.rs                   # Public API using concrete types
```

## Verification

The architecture was validated through:
- ✅ All unit tests passing (23/23)
- ✅ All integration tests passing (4/4)
- ✅ CI checks (clippy, format) passing
- ✅ Zero unsafe blocks in process-manager crate (verified by grep)
- ✅ Successful compilation on target platform

## Related Decisions

This ADR supersedes earlier approaches that used:
- Type erasure with `AnyPlatformManager` trait
- Runtime downcasting with `as_any()` methods
- Mutable references in public API methods

## References

- [Rust Book: Advanced Traits](https://doc.rust-lang.org/book/ch19-03-advanced-traits.html)
- [Rust API Guidelines: Type Safety](https://rust-lang.github.io/api-guidelines/type-safety.html)
- [Zero Cost Abstractions in Rust](https://blog.rust-lang.org/2015/05/11/traits.html)