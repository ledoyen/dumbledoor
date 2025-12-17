# Unsafe Windows Process Management

This crate contains all unsafe Windows API interactions for process management. It provides minimal safe wrappers around Windows process operations while keeping all unsafe code isolated and well-documented.

## ⚠️ Safety Warning

This crate contains unsafe code that directly interacts with Windows APIs. All unsafe operations are documented and justified, but incorrect usage can lead to:

- Memory corruption
- Resource leaks
- System instability
- Security vulnerabilities

## Design Principles

1. **Isolation**: All unsafe code is contained within this crate
2. **Minimal Surface**: Only essential Windows API operations are exposed
3. **Safe Defaults**: Public API provides safe abstractions over unsafe operations
4. **Documentation**: Every unsafe block is documented with safety requirements
5. **RAII**: Resources are automatically cleaned up using Rust's ownership system

## Unsafe Code Justification

### Why Unsafe Code is Required

The unsafe code in this crate is **unavoidable** because:

1. **Windows API Requirements**: Windows system calls require raw pointers and manual memory management
2. **Handle Management**: Windows HANDLEs must be managed manually and are inherently unsafe
3. **Memory Layout**: Windows API structures require specific memory layouts and zero-initialization
4. **Thread Safety**: Send/Sync implementations are needed for cross-thread handle sharing

### Safety Guarantees

Each unsafe block provides the following guarantees:

- **Resource Management**: All handles are wrapped in RAII types that ensure cleanup
- **Null Checking**: All handle operations check for null/invalid handles
- **Error Handling**: All Windows API calls are checked for errors
- **Memory Safety**: All memory operations use safe Rust patterns where possible

## Usage

This crate should only be used through the safe wrapper in the main `process-manager` crate. Direct usage requires careful attention to safety requirements.

```rust
// ✅ Recommended: Use through safe wrapper
use process_manager::WindowsPlatformManager;

// ❌ Not recommended: Direct unsafe usage
use unsafe_windows_process::create_process;
```

## Testing

All unsafe operations are tested to ensure:
- Proper resource cleanup
- Error handling
- Memory safety
- Thread safety

Run tests with:
```bash
cargo test --package unsafe-windows-process
```

## Security Considerations

- This crate requires Windows-specific privileges for process management
- Process creation and termination are privileged operations
- Job objects provide security boundaries for process isolation
- All operations respect Windows security model

## Maintenance

When modifying this crate:

1. Document all safety requirements
2. Add comprehensive tests
3. Verify resource cleanup
4. Check error handling paths
5. Review security implications