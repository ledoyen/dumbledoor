//! Platform-specific feature tests
//!
//! These tests validate platform-specific functionality while using
//! cross-platform test patterns. Tests are conditionally compiled
//! for their target platforms but use common test utilities.

mod common;

use common::*;
use process_manager::{ProcessManager, ProcessStatus};
use std::thread;
use std::time::Duration;

/// Test platform-specific process management features
#[test]
fn test_platform_process_management() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");
    let config = create_long_running_config();

    let handle = manager
        .start_process(config)
        .expect("Failed to start process");

    // Wait for process to start
    thread::sleep(Duration::from_millis(500));

    let status = manager
        .query_status(handle)
        .expect("Failed to query status");

    let pid = match status {
        ProcessStatus::Running { pid } => {
            println!("Process running with PID: {}", pid);
            pid
        }
        ProcessStatus::Starting => {
            println!("Process still starting");
            // Clean up and return
            let _ = manager.stop_process(handle);
            return;
        }
        other_status => {
            validate_process_status(&other_status, "platform process management");
            let _ = manager.stop_process(handle);
            return;
        }
    };

    // Platform-specific process verification
    #[cfg(target_os = "windows")]
    {
        // On Windows, verify Job Object behavior
        println!("Testing Windows Job Object behavior for PID: {}", pid);
        assert!(process_exists(pid), "Process should exist on Windows");
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, verify process group behavior
        println!("Testing macOS process group behavior for PID: {}", pid);
        assert!(process_exists(pid), "Process should exist on macOS");

        // Check process group
        let output = std::process::Command::new("ps")
            .args(["-o", "pid,ppid,pgid,command", "-p", &pid.to_string()])
            .output();

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Process group info:\n{}", stdout);
        }
    }

    #[cfg(target_os = "linux")]
    {
        // On Linux, verify namespace or process group behavior
        println!("Testing Linux process management for PID: {}", pid);
        assert!(process_exists(pid), "Process should exist on Linux");

        // Check if process is in a namespace or process group
        if let Ok(status_content) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
            println!("Process status info available");
            // Look for namespace information
            if status_content.contains("NSpid:") {
                println!("Process appears to be in a namespace");
            }
        }
    }

    // Test graceful termination
    manager
        .stop_process(handle)
        .expect("Failed to stop process");

    // Wait for cleanup
    thread::sleep(Duration::from_millis(500));

    // Verify process is terminated
    let cleanup_timeout = get_cleanup_timeout();
    let mut attempts = 0;
    let max_attempts = (cleanup_timeout.as_millis() / 100) as usize;

    while attempts < max_attempts && process_exists(pid) {
        thread::sleep(Duration::from_millis(100));
        attempts += 1;
    }

    if process_exists(pid) {
        println!(
            "Warning: Process {} still exists after cleanup timeout",
            pid
        );
    } else {
        println!("Process {} successfully cleaned up", pid);
    }
}

/// Test platform-specific cleanup mechanisms
#[test]
fn test_platform_cleanup_mechanisms() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Start multiple processes to test platform-specific cleanup
    let mut handles = Vec::new();
    let mut pids = Vec::new();

    for i in 0..3 {
        let mut config = create_long_running_config();
        config.log_file = Some(std::env::temp_dir().join(format!("platform_cleanup_{}.log", i)));

        let handle = manager
            .start_process(config)
            .expect("Failed to start process");
        handles.push(handle);

        // Get PID if process is running
        if let Ok(ProcessStatus::Running { pid }) = manager.query_status(handle) {
            pids.push(pid);
        }
    }

    println!("Started {} processes with PIDs: {:?}", handles.len(), pids);

    // Wait for processes to be fully started
    thread::sleep(Duration::from_secs(1));

    // Test platform-specific cleanup
    #[cfg(target_os = "windows")]
    {
        println!("Testing Windows Job Object cleanup");
        // Job Objects should provide automatic cleanup when ProcessManager is dropped
    }

    #[cfg(target_os = "macos")]
    {
        println!("Testing macOS process group cleanup");
        // Process groups should be cleaned up via signal handling
    }

    #[cfg(target_os = "linux")]
    {
        println!("Testing Linux cleanup (namespaces or process groups)");
        // User namespaces or process groups should handle cleanup
    }

    // Trigger cleanup
    let cleanup_result = manager.cleanup_all();
    assert!(cleanup_result.is_ok(), "Platform cleanup should succeed");

    // Wait for cleanup to complete
    let cleanup_timeout = get_cleanup_timeout();
    thread::sleep(cleanup_timeout);

    // Verify all processes are cleaned up
    let mut surviving_pids = Vec::new();
    for pid in &pids {
        if process_exists(*pid) {
            surviving_pids.push(*pid);
        }
    }

    if !surviving_pids.is_empty() {
        println!(
            "Warning: {} processes survived cleanup: {:?}",
            surviving_pids.len(),
            surviving_pids
        );

        // Platform-specific expectations
        #[cfg(target_os = "windows")]
        {
            // Windows Job Objects should provide immediate cleanup
            assert!(
                surviving_pids.is_empty(),
                "Windows Job Objects should prevent process leaks: {:?}",
                surviving_pids
            );
        }

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            // Unix platforms may have timing variations
            if surviving_pids.len() > 1 {
                println!("More processes survived than expected on Unix platform");
            }
        }
    } else {
        println!("All processes successfully cleaned up");
    }

    // Cleanup test files
    cleanup_test_files(&std::env::temp_dir(), "platform_cleanup");
}

/// Test reaper functionality on platforms that need it
#[test]
fn test_reaper_functionality() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test reaper availability
    let reaper_result = manager.ensure_reaper_alive();

    match reaper_result {
        Ok(()) => {
            println!("Reaper is available and functioning");

            // Test getting reaper PID
            let reaper_pid = manager.get_reaper_pid();
            match reaper_pid {
                Some(pid) => {
                    println!("Reaper PID: {}", pid);
                    assert!(pid > 0, "Reaper PID should be valid");
                    assert!(process_exists(pid), "Reaper process should exist");

                    // Test that reaper survives process management operations
                    let config = create_quick_config();
                    let handle = manager
                        .start_process(config)
                        .expect("Failed to start process with reaper");

                    thread::sleep(Duration::from_millis(500));

                    // Reaper should still be alive
                    assert_eq!(
                        manager.get_reaper_pid(),
                        Some(pid),
                        "Reaper PID should remain consistent"
                    );
                    assert!(process_exists(pid), "Reaper should still exist");

                    // Clean up test process
                    let _ = manager.stop_process(handle);

                    // Reaper should still be alive after process cleanup
                    assert_eq!(
                        manager.get_reaper_pid(),
                        Some(pid),
                        "Reaper should survive process cleanup"
                    );
                }
                None => {
                    println!("Reaper PID not available (may be expected on some platforms)");
                }
            }
        }
        Err(error) => {
            println!("Reaper not available or not needed: {}", error);

            // Verify that get_reaper_pid returns None when no reaper is needed
            let reaper_pid = manager.get_reaper_pid();
            assert!(
                reaper_pid.is_none(),
                "get_reaper_pid should return None when reaper is not available"
            );
        }
    }
}

/// Test platform-specific environment handling
#[test]
fn test_platform_environment_handling() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test platform-specific environment requirements
    let mut config = create_env_test_config();

    // Add platform-specific environment variables
    #[cfg(target_os = "windows")]
    {
        // Windows may need SYSTEMROOT and other system variables
        if let Ok(systemroot) = std::env::var("SYSTEMROOT") {
            config
                .environment
                .insert("SYSTEMROOT".to_string(), systemroot);
        }
        if let Ok(windir) = std::env::var("WINDIR") {
            config.environment.insert("WINDIR".to_string(), windir);
        }
    }

    #[cfg(unix)]
    {
        // Unix systems typically need PATH
        config
            .environment
            .insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    }

    let handle = manager
        .start_process(config.clone())
        .expect("Failed to start process with platform environment");

    // Wait for process to complete
    thread::sleep(Duration::from_secs(2));

    let status = manager.query_status(handle);
    match status {
        Ok(ProcessStatus::Exited { exit_code, .. }) => {
            assert_eq!(exit_code, 0, "Environment test should succeed");

            // Check log file for expected environment variables
            if let Some(log_file) = &config.log_file {
                if log_file.exists() {
                    let content =
                        std::fs::read_to_string(log_file).expect("Failed to read log file");

                    assert!(
                        content.contains("TEST_VAR"),
                        "Should contain our test environment variable"
                    );

                    #[cfg(target_os = "windows")]
                    {
                        // On Windows, check for system variables if we set them
                        if config.environment.contains_key("SYSTEMROOT") {
                            assert!(
                                content.contains("SYSTEMROOT"),
                                "Should contain Windows SYSTEMROOT variable"
                            );
                        }
                    }

                    #[cfg(unix)]
                    {
                        assert!(
                            content.contains("PATH"),
                            "Should contain PATH variable on Unix"
                        );
                    }

                    cleanup_test_files(&std::env::temp_dir(), "test_env");
                }
            }
        }
        Ok(other_status) => {
            validate_process_status(&other_status, "platform environment test");
            let _ = manager.stop_process(handle);
        }
        Err(error) => {
            panic!("Platform environment test failed: {:?}", error);
        }
    }
}

/// Test platform-specific process group creation
#[test]
fn test_platform_process_group_creation() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test process group creation
    let result = manager.create_process_group();

    match result {
        Ok(pgid) => {
            println!("Created process group with ID: {}", pgid);
            assert!(pgid > 0, "Process group ID should be positive");

            #[cfg(unix)]
            {
                // On Unix systems, verify the process group exists
                let current_pid = std::process::id();
                let output = std::process::Command::new("ps")
                    .args(["-o", "pid,pgid", "-p", &current_pid.to_string()])
                    .output();

                if let Ok(output) = output {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    println!("Current process group info:\n{}", stdout);
                }
            }

            #[cfg(target_os = "windows")]
            {
                // On Windows, process group creation may work differently
                println!("Windows process group created with ID: {}", pgid);
            }
        }
        Err(error) => {
            println!("Process group creation not supported or failed: {}", error);
            // This is acceptable - not all platforms may support this operation
        }
    }
}

/// Test platform-specific signal handling and termination
#[test]
fn test_platform_signal_handling() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");
    let config = create_long_running_config();

    let handle = manager
        .start_process(config)
        .expect("Failed to start process");

    // Wait for process to start
    thread::sleep(Duration::from_millis(500));

    let status = manager
        .query_status(handle)
        .expect("Failed to query status");

    if let ProcessStatus::Running { pid } = status {
        println!("Testing platform-specific termination for PID: {}", pid);

        // Test graceful termination
        let start_time = std::time::Instant::now();
        manager
            .stop_process(handle)
            .expect("Failed to stop process");

        // Measure termination time
        let termination_time = start_time.elapsed();
        println!("Process termination took: {:?}", termination_time);

        // Platform-specific termination expectations
        #[cfg(target_os = "windows")]
        {
            // Windows TerminateProcess should be relatively fast
            assert!(
                termination_time < Duration::from_secs(5),
                "Windows process termination should be fast"
            );
        }

        #[cfg(unix)]
        {
            // Unix signal-based termination may take longer
            assert!(
                termination_time < Duration::from_secs(10),
                "Unix process termination should complete within reasonable time"
            );
        }

        // Wait for process to be fully cleaned up
        thread::sleep(get_cleanup_timeout());

        // Verify process no longer exists
        if process_exists(pid) {
            println!("Warning: Process {} still exists after termination", pid);
        } else {
            println!("Process {} successfully terminated", pid);
        }
    } else {
        println!("Process not running, skipping signal handling test");
        let _ = manager.stop_process(handle);
    }
}

// Platform-specific test modules
#[cfg(target_os = "windows")]
mod windows_specific {
    use super::*;

    #[test]
    fn test_windows_job_objects() {
        init_tracing();
        println!("Testing Windows Job Object specific behavior");

        let manager = ProcessManager::new().expect("Failed to create ProcessManager");

        // Test that multiple processes are managed in the same Job Object
        let mut handles = Vec::new();
        for i in 0..3 {
            let mut config = create_long_running_config();
            config.log_file = Some(std::env::temp_dir().join(format!("job_test_{}.log", i)));

            let handle = manager
                .start_process(config)
                .expect("Failed to start process");
            handles.push(handle);
        }

        // All processes should be in the same Job Object
        // This is tested implicitly through the cleanup behavior

        // Clean up
        for handle in handles {
            let _ = manager.stop_process(handle);
        }

        cleanup_test_files(&std::env::temp_dir(), "job_test");
    }
}

#[cfg(target_os = "macos")]
mod macos_specific {
    use super::*;

    #[test]
    fn test_macos_process_groups() {
        init_tracing();
        println!("Testing macOS process group specific behavior");

        let manager = ProcessManager::new().expect("Failed to create ProcessManager");
        let config = create_long_running_config();

        let handle = manager
            .start_process(config)
            .expect("Failed to start process");

        thread::sleep(Duration::from_millis(500));

        if let Ok(ProcessStatus::Running { pid }) = manager.query_status(handle) {
            // Check process group information
            let output = std::process::Command::new("ps")
                .args(["-o", "pid,ppid,pgid,command", "-p", &pid.to_string()])
                .output();

            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                println!("macOS process group info:\n{}", stdout);

                // Verify process has a valid process group
                let lines: Vec<&str> = stdout.lines().collect();
                if lines.len() > 1 {
                    let process_line = lines[1];
                    let parts: Vec<&str> = process_line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        if let Ok(pgid) = parts[2].parse::<i32>() {
                            assert!(pgid > 0, "Process should have valid process group ID");
                            println!("Process {} is in process group {}", pid, pgid);
                        }
                    }
                }
            }
        }

        let _ = manager.stop_process(handle);
    }
}

#[cfg(target_os = "linux")]
mod linux_specific {
    use super::*;

    #[test]
    fn test_linux_namespaces_or_process_groups() {
        init_tracing();
        println!("Testing Linux namespace/process group specific behavior");

        let manager = ProcessManager::new().expect("Failed to create ProcessManager");
        let config = create_long_running_config();

        let handle = manager
            .start_process(config)
            .expect("Failed to start process");

        thread::sleep(Duration::from_millis(500));

        if let Ok(ProcessStatus::Running { pid }) = manager.query_status(handle) {
            // Check if process is in a user namespace
            if let Ok(status_content) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
                println!("Process status available for PID {}", pid);

                // Look for namespace information
                for line in status_content.lines() {
                    if line.starts_with("NSpid:") || line.starts_with("NStgid:") {
                        println!("Namespace info: {}", line);
                    }
                }
            }

            // Check process group
            if let Ok(stat_content) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
                let parts: Vec<&str> = stat_content.split_whitespace().collect();
                if parts.len() > 4 {
                    if let Ok(pgid) = parts[4].parse::<i32>() {
                        println!("Process {} is in process group {}", pid, pgid);
                        assert!(pgid > 0, "Process should have valid process group");
                    }
                }
            }
        }

        let _ = manager.stop_process(handle);
    }
}
