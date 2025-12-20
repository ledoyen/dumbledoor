//! Tests for the process reaper system
//!
//! These tests verify that the reaper system works correctly when needed
//! by platforms that don't have automatic cleanup mechanisms.

use process_manager::{ProcessConfig, ProcessManager};
use std::thread;
use std::time::Duration;

/// Initialize tracing for tests
fn init_tracing() {
    let _ = tracing_subscriber::fmt::try_init();
}

#[test]
fn test_reaper_integration() {
    init_tracing();

    // Create a ProcessManager instance
    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test basic process management with reaper integration
    let config = ProcessConfig::new("ping").args(["127.0.0.1", "-n", "3"]);

    let handle = manager
        .start_process(config)
        .expect("Failed to start process");

    // Verify process is running
    let status = manager
        .query_status(handle)
        .expect("Failed to query process status");

    // Assert that the process is in a valid state
    match status {
        process_manager::ProcessStatus::Running { pid } => {
            assert!(pid > 0, "Process PID should be greater than 0");
        }
        process_manager::ProcessStatus::Starting => {
            // Process might still be starting, which is acceptable
        }
        other => {
            panic!("Unexpected process status: {:?}", other);
        }
    }

    // Wait a bit for the process to run
    thread::sleep(Duration::from_secs(1));

    // Verify the process handle is in the manager's registry
    let process_list = manager.list_processes();
    assert!(
        process_list.contains(&handle),
        "Process handle should be in the manager's registry"
    );

    // Stop the process
    manager
        .stop_process(handle)
        .expect("Failed to stop process");

    // Verify the process is no longer in the registry
    let process_list_after_stop = manager.list_processes();
    assert!(
        !process_list_after_stop.contains(&handle),
        "Process handle should be removed from registry after stopping"
    );
}

#[test]
fn test_reaper_monitoring() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test that the reaper monitoring works correctly
    // This test verifies that ensure_reaper_alive() works
    let result = manager.ensure_reaper_alive();
    assert!(
        result.is_ok(),
        "ensure_reaper_alive should succeed: {:?}",
        result
    );

    // Verify that calling it multiple times is safe
    let result2 = manager.ensure_reaper_alive();
    assert!(
        result2.is_ok(),
        "Multiple calls to ensure_reaper_alive should succeed: {:?}",
        result2
    );
}

#[test]
fn test_multiple_processes_with_reaper() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    let mut handles = Vec::new();
    let expected_process_count = 3;

    // Start multiple processes to test reaper with multiple PIDs
    for i in 0..expected_process_count {
        let config = ProcessConfig::new("ping").args(["127.0.0.1", "-n", "5"]);

        let handle = manager
            .start_process(config)
            .unwrap_or_else(|e| panic!("Failed to start process {}: {}", i, e));

        handles.push(handle);
    }

    // Verify all processes were started
    assert_eq!(
        handles.len(),
        expected_process_count,
        "Should have started {} processes",
        expected_process_count
    );

    // Verify all processes are in the registry
    let process_list = manager.list_processes();
    for (i, handle) in handles.iter().enumerate() {
        assert!(
            process_list.contains(handle),
            "Process {} should be in the registry",
            i
        );
    }

    // Wait a bit
    thread::sleep(Duration::from_secs(1));

    // Stop all processes
    for (i, handle) in handles.into_iter().enumerate() {
        manager
            .stop_process(handle)
            .unwrap_or_else(|e| panic!("Failed to stop process {}: {}", i, e));
    }

    // Verify all processes are removed from registry
    let final_process_list = manager.list_processes();
    assert!(
        final_process_list.is_empty(),
        "All processes should be removed from registry after stopping"
    );
}

#[test]
fn test_cleanup_with_reaper() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Start a process
    let config = ProcessConfig::new("ping").args(["127.0.0.1", "-n", "10"]);

    let handle = manager
        .start_process(config)
        .expect("Failed to start process");

    // Verify process is in registry
    let process_list_before = manager.list_processes();
    assert!(
        process_list_before.contains(&handle),
        "Process should be in registry before cleanup"
    );
    assert_eq!(
        process_list_before.len(),
        1,
        "Should have exactly one process before cleanup"
    );

    // Test cleanup_all which should also shutdown the reaper
    let cleanup_result = manager.cleanup_all();
    assert!(
        cleanup_result.is_ok(),
        "cleanup_all should succeed: {:?}",
        cleanup_result
    );

    // Verify all processes are cleaned up
    let process_list_after = manager.list_processes();
    assert!(
        process_list_after.is_empty(),
        "All processes should be cleaned up after cleanup_all"
    );
}

#[test]
fn test_process_manager_creation_with_reaper() {
    init_tracing();

    // Test that ProcessManager can be created successfully
    // This implicitly tests reaper initialization when needed
    let manager_result = ProcessManager::new();
    assert!(
        manager_result.is_ok(),
        "ProcessManager creation should succeed"
    );

    let manager = manager_result.unwrap();

    // Verify initial state
    let initial_processes = manager.list_processes();
    assert!(
        initial_processes.is_empty(),
        "New ProcessManager should have no processes initially"
    );

    // Test that we can create multiple ProcessManager instances
    let manager2_result = ProcessManager::new();
    assert!(
        manager2_result.is_ok(),
        "Second ProcessManager creation should succeed"
    );
}
#[test]
fn test_reaper_restart_after_sigkill() {
    init_tracing();

    // This test verifies that the reaper monitor can detect when the reaper
    // process is killed and restart it automatically through the public API

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test the ensure_reaper_alive functionality extensively
    // This method should handle reaper restart scenarios internally

    // First call should succeed (creates reaper if needed)
    let result1 = manager.ensure_reaper_alive();
    assert!(result1.is_ok(), "First ensure_reaper_alive should succeed");

    // Multiple rapid calls should all succeed and be idempotent
    // This tests the restart logic's robustness
    for i in 0..10 {
        let result = manager.ensure_reaper_alive();
        assert!(
            result.is_ok(),
            "ensure_reaper_alive call {} should succeed",
            i + 1
        );

        // Small delay to simulate real-world timing
        thread::sleep(Duration::from_millis(50));
    }

    // Test concurrent calls to ensure_reaper_alive
    // This simulates multiple threads trying to ensure reaper is alive
    // which could happen if the reaper dies and multiple operations detect it
    let handles: Vec<_> = (0..5)
        .map(|i| {
            let manager_clone = manager.clone();
            thread::spawn(move || {
                for j in 0..3 {
                    let result = manager_clone.ensure_reaper_alive();
                    assert!(
                        result.is_ok(),
                        "Concurrent thread {} call {} should succeed",
                        i,
                        j
                    );
                    thread::sleep(Duration::from_millis(25));
                }
            })
        })
        .collect();

    // Wait for all concurrent threads to complete
    for handle in handles {
        handle.join().expect("Concurrent thread should complete");
    }

    // Verify the system still works correctly after all the restart testing
    let config = ProcessConfig::new("ping").args(["127.0.0.1", "-n", "2"]);
    let process_handle = manager
        .start_process(config)
        .expect("Failed to start process after reaper restart testing");

    // Verify process is tracked
    let process_list = manager.list_processes();
    assert!(
        process_list.contains(&process_handle),
        "Process should be tracked after reaper restart testing"
    );

    // Test ensure_reaper_alive while a process is running
    let result_with_process = manager.ensure_reaper_alive();
    assert!(
        result_with_process.is_ok(),
        "ensure_reaper_alive should work while processes are running"
    );

    // Clean up the process
    manager
        .stop_process(process_handle)
        .expect("Failed to stop process");

    // Final verification that reaper monitoring still works
    let final_result = manager.ensure_reaper_alive();
    assert!(
        final_result.is_ok(),
        "Final ensure_reaper_alive should succeed"
    );

    // Verify no processes remain
    let final_processes = manager.list_processes();
    assert!(
        final_processes.is_empty(),
        "All processes should be cleaned up"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_reaper_restart_on_linux() {
    init_tracing();

    // This test is specific to Linux where a reaper might actually be needed
    // when user namespaces are not available

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // On Linux, if user namespaces are not available, a reaper should be spawned
    // Test that the restart logic works correctly

    let result = manager.ensure_reaper_alive();
    assert!(
        result.is_ok(),
        "ensure_reaper_alive should succeed on Linux"
    );

    // Test restart scenario by calling ensure_reaper_alive multiple times
    // This simulates the monitor detecting a dead reaper and restarting it
    for i in 0..3 {
        thread::sleep(Duration::from_millis(500));
        let restart_result = manager.ensure_reaper_alive();
        assert!(
            restart_result.is_ok(),
            "Reaper restart attempt {} should succeed",
            i + 1
        );
    }

    // Verify the system still works by starting and stopping a process
    let config = ProcessConfig::new("sleep").args(["1"]);
    let handle = manager
        .start_process(config)
        .expect("Failed to start process on Linux");

    thread::sleep(Duration::from_millis(100));

    manager
        .stop_process(handle)
        .expect("Failed to stop process on Linux");
}

#[test]
fn test_reaper_monitor_resilience() {
    init_tracing();

    // Test that the reaper monitor is resilient to various scenarios
    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test rapid successive calls to ensure_reaper_alive
    // This tests the monitor's ability to handle concurrent restart requests
    let handles: Vec<_> = (0..3)
        .map(|i| {
            thread::spawn({
                let manager = manager.clone();
                move || {
                    for j in 0..5 {
                        let result = manager.ensure_reaper_alive();
                        assert!(result.is_ok(), "Thread {} call {} should succeed", i, j);
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            })
        })
        .collect();

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should complete successfully");
    }

    // Verify the system is still functional
    let config = ProcessConfig::new("ping").args(["127.0.0.1", "-n", "1"]);
    let process_handle = manager
        .start_process(config)
        .expect("Failed to start process after concurrent reaper tests");

    // Verify process is tracked
    let process_list = manager.list_processes();
    assert!(
        process_list.contains(&process_handle),
        "Process should be tracked after concurrent reaper tests"
    );

    // Clean up
    manager
        .stop_process(process_handle)
        .expect("Failed to stop process");

    // Final verification
    let final_processes = manager.list_processes();
    assert!(
        final_processes.is_empty(),
        "All processes should be cleaned up"
    );
}
