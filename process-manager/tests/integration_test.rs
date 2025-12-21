//! Integration tests for the process manager
//!
//! This file has been replaced by more focused test files:
//! - integration_focused_test.rs: Core integration functionality
//! - process_lifecycle_test.rs: Cross-platform E2E process lifecycle tests
//! - platform_features_test.rs: Platform-specific feature tests
//!
//! The tests below are kept for backward compatibility but are minimal.

use process_manager::{ProcessHandle, ProcessManager};

#[test]
fn test_process_manager_creation() {
    let manager = ProcessManager::new();
    assert!(
        manager.is_ok(),
        "ProcessManager should be created successfully"
    );
}

#[test]
fn test_process_handle_uniqueness() {
    let handle1 = ProcessHandle::new();
    let handle2 = ProcessHandle::new();
    assert_ne!(handle1, handle2, "Process handles should be unique");
}

// Note: Most integration tests have been moved to integration_focused_test.rs
// for better organization and to avoid duplication with E2E tests.
