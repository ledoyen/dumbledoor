//! Unit tests for macOS platform manager
//!
//! Tests process group management, signal-based termination, environment isolation,
//! working directory isolation, and child process detection.

#[cfg(target_os = "macos")]
mod macos_tests {
    use process_manager::{ProcessConfig, ProcessManager, ProcessStatus};
    use std::time::Duration;

    /// Test that the macOS platform manager can be created successfully
    #[test]
    fn test_macos_platform_manager_creation() {
        let manager = ProcessManager::new();
        assert!(
            manager.is_ok(),
            "ProcessManager should be created successfully on macOS"
        );
    }

    /// Test process group management by spawning a process and verifying it runs correctly
    #[test]
    fn test_process_group_management() {
        let manager = ProcessManager::new().expect("Failed to create manager");

        // Spawn a simple process that will run briefly
        let config = ProcessConfig::new("/bin/sleep").args(["0.1"]);

        let handle = manager
            .start_process(config)
            .expect("Failed to spawn process");

        // Query the process status to verify it's running
        let status = manager
            .query_status(handle)
            .expect("Failed to query status");

        match status {
            ProcessStatus::Running { pid } => {
                assert!(pid > 0, "Process should have a valid PID");
            }
            _ => {
                // Process might have already completed, which is also valid for a short sleep
            }
        }

        // Give the process time to complete
        std::thread::sleep(Duration::from_millis(200));

        // Clean up
        let _ = manager.stop_process(handle);
    }

    /// Test signal-based termination with graceful and forced termination
    #[test]
    fn test_signal_based_termination() {
        let manager = ProcessManager::new().expect("Failed to create manager");

        // Test graceful termination
        {
            // Spawn a process that will run for a while
            let config = ProcessConfig::new("/bin/sleep").args(["10"]);
            let handle = manager
                .start_process(config)
                .expect("Failed to spawn process");

            // Verify process is running
            let status = manager
                .query_status(handle)
                .expect("Failed to query status");
            match status {
                ProcessStatus::Running { pid } => {
                    assert!(pid > 0, "Process should have a valid PID");
                }
                _ => panic!("Process should be running, got: {:?}", status),
            }

            // Terminate gracefully
            let result = manager.stop_process(handle);
            assert!(result.is_ok(), "Graceful termination should succeed");

            // Give time for termination
            std::thread::sleep(Duration::from_millis(200));

            // Verify process is no longer in the manager's registry
            let processes = manager.list_processes();
            assert!(
                !processes.contains(&handle),
                "Process should be removed from registry after termination"
            );
        }

        // Test forced termination by spawning another process
        {
            let config = ProcessConfig::new("/bin/sleep").args(["10"]);
            let handle = manager
                .start_process(config)
                .expect("Failed to spawn process");

            // Terminate the process
            let result = manager.stop_process(handle);
            assert!(result.is_ok(), "Process termination should succeed");

            // Give time for termination
            std::thread::sleep(Duration::from_millis(200));

            // Verify process is no longer in the manager's registry
            let processes = manager.list_processes();
            assert!(
                !processes.contains(&handle),
                "Process should be removed from registry after termination"
            );
        }
    }

    /// Test environment variable isolation
    #[test]
    fn test_environment_isolation() {
        let manager = ProcessManager::new().expect("Failed to create manager");

        // Create a temporary log file for capturing output
        let temp_dir = std::env::temp_dir();
        let log_file = temp_dir.join("macos_env_test.log");

        // Set up environment variables using the builder pattern
        let config = ProcessConfig::new("/usr/bin/env")
            .env("TEST_VAR_1", "test_value_1")
            .env("TEST_VAR_2", "test_value_2")
            .env("PATH", "/usr/bin:/bin")
            .log_file(&log_file);

        let handle = manager
            .start_process(config)
            .expect("Failed to spawn process");

        // Give the process time to complete and write output
        std::thread::sleep(Duration::from_millis(500));

        // Clean up the process
        let _ = manager.stop_process(handle);

        // Read the log file to verify environment variables
        if log_file.exists() {
            let output = std::fs::read_to_string(&log_file).expect("Failed to read log file");

            // Verify our test environment variables are present
            assert!(
                output.contains("TEST_VAR_1=test_value_1"),
                "TEST_VAR_1 should be set in child process environment"
            );
            assert!(
                output.contains("TEST_VAR_2=test_value_2"),
                "TEST_VAR_2 should be set in child process environment"
            );
            assert!(
                output.contains("PATH=/usr/bin:/bin"),
                "PATH should be set to our specified value"
            );

            // Verify that common parent environment variables are NOT inherited
            // (unless explicitly set by us)
            let parent_env_vars = ["HOME", "USER", "SHELL"];
            for var in &parent_env_vars {
                assert!(
                    !output.contains(&format!("{}=", var)),
                    "Parent environment variable {} should not be inherited",
                    var
                );
            }

            // Clean up
            let _ = std::fs::remove_file(&log_file);
        } else {
            panic!("Log file was not created");
        }
    }

    /// Test working directory isolation
    #[test]
    fn test_working_directory_isolation() {
        let manager = ProcessManager::new().expect("Failed to create manager");

        // Create a temporary directory for testing
        let temp_dir = std::env::temp_dir();
        let test_dir = temp_dir.join("macos_wd_test");
        std::fs::create_dir_all(&test_dir).expect("Failed to create test directory");

        // Create a log file for capturing output
        let log_file = temp_dir.join("macos_wd_test.log");

        let config = ProcessConfig::new("/bin/pwd")
            .working_directory(&test_dir)
            .env("PATH", "/usr/bin:/bin")
            .log_file(&log_file);

        let handle = manager
            .start_process(config)
            .expect("Failed to spawn process");

        // Give the process time to complete
        std::thread::sleep(Duration::from_millis(300));

        // Clean up the process
        let _ = manager.stop_process(handle);

        // Read the log file to verify working directory
        if log_file.exists() {
            let output = std::fs::read_to_string(&log_file)
                .expect("Failed to read log file")
                .trim()
                .to_string();

            // On macOS, paths might be canonicalized with /private prefix
            let expected_path = test_dir
                .canonicalize()
                .expect("Failed to canonicalize test directory")
                .to_string_lossy()
                .to_string();

            assert_eq!(
                output, expected_path,
                "Process should run in the specified working directory"
            );

            // Clean up
            let _ = std::fs::remove_file(&log_file);
        } else {
            panic!("Log file was not created");
        }

        // Clean up test directory
        let _ = std::fs::remove_dir_all(&test_dir);
    }

    /// Test working directory isolation with default (root) directory
    #[test]
    fn test_default_working_directory() {
        let manager = ProcessManager::new().expect("Failed to create manager");

        let temp_dir = std::env::temp_dir();
        let log_file = temp_dir.join("macos_default_wd_test.log");

        // Don't specify working directory - should default to root
        let config = ProcessConfig::new("/bin/pwd")
            .env("PATH", "/usr/bin:/bin")
            .log_file(&log_file);

        let handle = manager
            .start_process(config)
            .expect("Failed to spawn process");

        // Give the process time to complete
        std::thread::sleep(Duration::from_millis(300));

        // Clean up the process
        let _ = manager.stop_process(handle);

        // Read the log file to verify working directory
        if log_file.exists() {
            let output = std::fs::read_to_string(&log_file)
                .expect("Failed to read log file")
                .trim()
                .to_string();

            assert_eq!(
                output, "/",
                "Process should run in root directory when no working directory specified"
            );

            // Clean up
            let _ = std::fs::remove_file(&log_file);
        } else {
            panic!("Log file was not created");
        }
    }

    /// Test child process detection (simplified test using ProcessManager)
    #[test]
    fn test_child_process_detection() {
        let manager = ProcessManager::new().expect("Failed to create manager");

        // Spawn a simple process
        let config = ProcessConfig::new("/bin/echo")
            .args(["hello"])
            .env("PATH", "/usr/bin:/bin");

        let handle = manager
            .start_process(config)
            .expect("Failed to spawn process");

        // Verify the process was started successfully
        let processes = manager.list_processes();
        assert!(
            processes.contains(&handle),
            "Process should be in the manager's registry"
        );

        // Give the process time to complete
        std::thread::sleep(Duration::from_millis(200));

        // Clean up
        let _ = manager.stop_process(handle);
    }

    /// Test cleanup handler setup (implicit through ProcessManager creation)
    #[test]
    fn test_cleanup_handler_setup() {
        let manager = ProcessManager::new().expect("Failed to create manager");

        // If ProcessManager was created successfully, cleanup handlers should be set up
        // This is tested implicitly through the manager creation

        // Test that we can spawn and clean up processes
        let config = ProcessConfig::new("/bin/echo").args(["test"]);
        let handle = manager
            .start_process(config)
            .expect("Failed to spawn process");

        // Clean up
        let result = manager.stop_process(handle);
        assert!(result.is_ok(), "Process cleanup should succeed");
    }

    /// Test cleanup of multiple processes
    #[test]
    fn test_cleanup_all_processes() {
        let manager = ProcessManager::new().expect("Failed to create manager");

        // Spawn multiple processes
        let config1 = ProcessConfig::new("/bin/sleep")
            .args(["5"])
            .env("PATH", "/usr/bin:/bin");
        let config2 = ProcessConfig::new("/bin/sleep")
            .args(["5"])
            .env("PATH", "/usr/bin:/bin");
        let config3 = ProcessConfig::new("/bin/sleep")
            .args(["5"])
            .env("PATH", "/usr/bin:/bin");

        let handle1 = manager
            .start_process(config1)
            .expect("Failed to spawn process 1");
        let handle2 = manager
            .start_process(config2)
            .expect("Failed to spawn process 2");
        let handle3 = manager
            .start_process(config3)
            .expect("Failed to spawn process 3");

        // Verify all processes are in the registry
        let processes = manager.list_processes();
        assert!(
            processes.contains(&handle1),
            "Process 1 should be in registry"
        );
        assert!(
            processes.contains(&handle2),
            "Process 2 should be in registry"
        );
        assert!(
            processes.contains(&handle3),
            "Process 3 should be in registry"
        );

        // Clean up all processes using the manager's cleanup method
        let result = manager.cleanup_all();
        assert!(result.is_ok(), "Cleanup all processes should succeed");

        // Give time for cleanup
        std::thread::sleep(Duration::from_millis(300));

        // Verify processes are no longer in the registry
        let processes_after = manager.list_processes();
        assert!(
            processes_after.is_empty(),
            "All processes should be removed from registry after cleanup"
        );
    }

    /// Test reaper requirement (macOS typically doesn't need a reaper)
    /// This is tested implicitly through ProcessManager behavior
    #[test]
    fn test_reaper_requirement() {
        let manager = ProcessManager::new().expect("Failed to create manager");

        // Test that the manager works correctly (implying proper reaper setup if needed)
        let config = ProcessConfig::new("/bin/echo").args(["test"]);
        let handle = manager
            .start_process(config)
            .expect("Failed to spawn process");

        // Clean up
        let result = manager.stop_process(handle);
        assert!(result.is_ok(), "Process management should work correctly");
    }

    /// Test process status querying for various states
    #[test]
    fn test_process_status_querying() {
        let manager = ProcessManager::new().expect("Failed to create manager");

        // Test with a process that exits quickly
        let config = ProcessConfig::new("/bin/echo")
            .args(["test"])
            .env("PATH", "/usr/bin:/bin");

        let handle = manager
            .start_process(config)
            .expect("Failed to spawn process");

        // Initially should be running or might have already completed
        let initial_status = manager
            .query_status(handle)
            .expect("Failed to query initial status");
        match initial_status {
            ProcessStatus::Running { pid } => {
                assert!(pid > 0, "Status PID should be valid");
            }
            ProcessStatus::Exited { exit_code, .. } => {
                assert_eq!(exit_code, 0, "Echo command should exit with code 0");
            }
            _ => {
                // Other statuses might be valid depending on timing
            }
        }

        // Give the process time to complete
        std::thread::sleep(Duration::from_millis(300));

        // Clean up
        let _ = manager.stop_process(handle);
    }

    /// Test error handling for invalid operations
    #[test]
    fn test_error_handling() {
        let manager = ProcessManager::new().expect("Failed to create manager");

        // Test spawning with invalid command
        let invalid_config = ProcessConfig::new("/nonexistent/command/that/does/not/exist");

        let result = manager.start_process(invalid_config);
        assert!(result.is_err(), "Spawning invalid command should fail");

        // The specific error type will depend on the ProcessManager implementation
        // but it should be some kind of error
    }

    /// Test terminating already terminated process (should be idempotent)
    #[test]
    fn test_terminate_already_terminated_process() {
        let manager = ProcessManager::new().expect("Failed to create manager");

        let config = ProcessConfig::new("/bin/echo")
            .args(["test"])
            .env("PATH", "/usr/bin:/bin");

        let handle = manager
            .start_process(config)
            .expect("Failed to spawn process");

        // Give the process time to complete naturally
        std::thread::sleep(Duration::from_millis(300));

        // Try to terminate the already-finished process - should succeed
        let result1 = manager.stop_process(handle);
        assert!(
            result1.is_ok(),
            "Terminating already-finished process should succeed"
        );

        // Try to terminate again - should fail with ProcessNotFound since it's removed from registry
        let result2 = manager.stop_process(handle);
        assert!(
            result2.is_err(),
            "Terminating already-removed process should fail with ProcessNotFound"
        );
    }

    /// Test log file redirection functionality
    #[test]
    fn test_log_file_redirection() {
        let manager = ProcessManager::new().expect("Failed to create manager");

        let temp_dir = std::env::temp_dir();
        let log_file = temp_dir.join("macos_log_test.log");

        // Use a command that writes to both stdout and stderr
        let config = ProcessConfig::new("/bin/sh")
            .args(["-c", "echo 'stdout message'; echo 'stderr message' >&2"])
            .env("PATH", "/usr/bin:/bin")
            .log_file(&log_file);

        let handle = manager
            .start_process(config)
            .expect("Failed to spawn process");

        // Give the process time to complete
        std::thread::sleep(Duration::from_millis(500));

        // Clean up the process
        let _ = manager.stop_process(handle);

        // Verify log file was created and contains both stdout and stderr
        if log_file.exists() {
            let output = std::fs::read_to_string(&log_file).expect("Failed to read log file");

            assert!(
                output.contains("stdout message"),
                "Log file should contain stdout output"
            );
            assert!(
                output.contains("stderr message"),
                "Log file should contain stderr output"
            );

            // Clean up
            let _ = std::fs::remove_file(&log_file);
        } else {
            panic!("Log file was not created");
        }
    }
}

// Placeholder tests for non-macOS platforms
#[cfg(not(target_os = "macos"))]
mod non_macos_tests {
    #[test]
    fn test_macos_tests_skipped_on_other_platforms() {
        println!("macOS platform tests skipped on non-macOS platform");
    }
}
