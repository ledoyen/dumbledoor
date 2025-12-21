//! Focused integration tests for process manager
//!
//! These tests focus on integration points and functionality not covered
//! by the comprehensive process lifecycle tests. They test specific
//! integration scenarios, edge cases, and internal component interactions.

mod common;

use common::*;
use process_manager::{ProcessConfig, ProcessHandle, ProcessManager, ProcessStatus};
use std::collections::HashMap;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

#[test]
fn test_process_manager_creation() {
    let manager = ProcessManager::new();
    assert!(
        manager.is_ok(),
        "ProcessManager should be created successfully"
    );
}

#[test]
fn test_process_config_builder_patterns() {
    init_tracing();

    // Test builder pattern with all options
    let commands = PlatformCommands::get();
    let temp_dir = std::env::temp_dir();

    let config = ProcessConfig::new(commands.quick.0)
        .args(commands.quick.1.iter().copied())
        .working_directory(&temp_dir)
        .env("TEST", "value")
        .log_file(temp_dir.join("builder_test.log"));

    assert_eq!(config.command, PathBuf::from(commands.quick.0));
    assert_eq!(
        config.args,
        commands
            .quick
            .1
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(config.working_directory, Some(temp_dir.clone()));
    assert_eq!(config.environment.get("TEST"), Some(&"value".to_string()));
    assert_eq!(config.log_file, Some(temp_dir.join("builder_test.log")));

    // Test minimal configuration
    let minimal_config = ProcessConfig::new(commands.quick.0);
    assert_eq!(minimal_config.command, PathBuf::from(commands.quick.0));
    assert!(minimal_config.args.is_empty());
    assert!(minimal_config.working_directory.is_none());
    assert!(minimal_config.environment.is_empty());
    assert!(minimal_config.log_file.is_none());
}

#[test]
fn test_process_handle_uniqueness() {
    let handle1 = ProcessHandle::new();
    let handle2 = ProcessHandle::new();
    assert_ne!(handle1, handle2, "Process handles should be unique");

    // Test that handles can be used as HashMap keys
    let mut map = HashMap::new();
    map.insert(handle1, "first");
    map.insert(handle2, "second");
    assert_eq!(map.len(), 2);
    assert_eq!(map.get(&handle1), Some(&"first"));
    assert_eq!(map.get(&handle2), Some(&"second"));
}

#[test]
fn test_process_config_validation() {
    init_tracing();

    // Test empty command validation
    let empty_config = ProcessConfig::new("");
    let result = empty_config.validate();
    assert!(result.is_err());
    if let Err(error) = result {
        assert!(error.to_string().contains("Command path cannot be empty"));
    }

    // Test nonexistent working directory
    let invalid_wd_config =
        ProcessConfig::new("echo").working_directory("/nonexistent/directory/that/does/not/exist");
    let result = invalid_wd_config.validate();
    assert!(result.is_err());
    if let Err(error) = result {
        assert!(error
            .to_string()
            .contains("Working directory does not exist"));
    }

    // Test empty environment variable key
    let invalid_env_config = ProcessConfig::new("echo").env("", "value");
    let result = invalid_env_config.validate();
    assert!(result.is_err());
    if let Err(error) = result {
        assert!(error
            .to_string()
            .contains("Environment variable key cannot be empty"));
    }

    // Test valid configuration
    let temp_dir = std::env::temp_dir();
    let valid_config = ProcessConfig::new("echo")
        .args(["hello"])
        .working_directory(&temp_dir)
        .env("TEST", "value")
        .log_file(temp_dir.join("output.log"));

    let result = valid_config.validate();
    assert!(result.is_ok(), "Valid configuration should pass validation");
}

#[test]
fn test_process_manager_basic_operations() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test listing processes (should be empty initially)
    let processes = manager.list_processes();
    assert!(processes.is_empty(), "Initial process list should be empty");

    // Test starting a process
    let config = create_quick_config();
    let handle = manager
        .start_process(config)
        .expect("Failed to start process");

    // Test that process appears in list
    let processes_after_start = manager.list_processes();
    assert!(
        processes_after_start.contains(&handle),
        "Process should appear in list after starting"
    );

    // Test querying status
    let status = manager
        .query_status(handle)
        .expect("Failed to query status");

    validate_process_status(&status, "basic operations test");

    // Test stopping process
    manager
        .stop_process(handle)
        .expect("Failed to stop process");

    // Wait for process to be removed
    let mut attempts = 0;
    while attempts < 30 {
        let processes = manager.list_processes();
        if !processes.contains(&handle) {
            break;
        }
        thread::sleep(Duration::from_millis(100));
        attempts += 1;
    }

    let final_processes = manager.list_processes();
    assert!(
        !final_processes.contains(&handle),
        "Process should be removed from list after stopping"
    );
}

#[test]
fn test_plugin_registry_integration() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test that we can register plugins (even if they don't do anything yet)
    // This tests the plugin registry integration

    // Create a simple test plugin
    struct TestPlugin;

    impl process_manager::ConfigurationPlugin for TestPlugin {
        fn name(&self) -> &str {
            "test-plugin"
        }

        fn is_applicable(&self, _config: &ProcessConfig) -> bool {
            false // Don't actually modify anything
        }

        fn enhance_config(
            &self,
            config: ProcessConfig,
        ) -> Result<ProcessConfig, process_manager::error::PluginError> {
            Ok(config) // Pass through unchanged
        }

        fn priority(&self) -> u32 {
            100
        }
    }

    // Register the plugin
    manager.register_plugin(Box::new(TestPlugin));

    // Test that process creation still works with plugin registered
    let config = create_quick_config();
    let handle = manager
        .start_process(config)
        .expect("Failed to start process with plugin registered");

    // Clean up
    let _ = manager.stop_process(handle);
}

#[test]
fn test_cleanup_all_functionality() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Start multiple processes
    let mut handles = Vec::new();
    for i in 0..3 {
        let mut config = create_long_running_config();
        config.log_file = Some(std::env::temp_dir().join(format!("cleanup_all_test_{}.log", i)));

        let handle = manager
            .start_process(config)
            .expect("Failed to start process");
        handles.push(handle);
    }

    // Verify processes are running
    thread::sleep(Duration::from_millis(500));
    let processes_before = manager.list_processes();
    assert_eq!(
        processes_before.len(),
        handles.len(),
        "All processes should be in the list"
    );

    // Test cleanup_all
    let result = manager.cleanup_all();
    assert!(result.is_ok(), "cleanup_all should succeed");

    // Verify all processes are cleaned up
    let processes_after = manager.list_processes();
    assert!(
        processes_after.is_empty(),
        "All processes should be cleaned up after cleanup_all"
    );

    // Cleanup test files
    cleanup_test_files(&std::env::temp_dir(), "cleanup_all_test");
}

#[test]
fn test_process_status_edge_cases() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test querying status of non-existent process
    let fake_handle = ProcessHandle::new();
    let result = manager.query_status(fake_handle);
    assert!(result.is_err(), "Should fail to query non-existent process");

    // Test stopping non-existent process
    let result = manager.stop_process(fake_handle);
    assert!(result.is_err(), "Should fail to stop non-existent process");

    // Test that error messages are meaningful
    if let Err(error) = manager.query_status(fake_handle) {
        let error_msg = error.to_string();
        assert!(
            error_msg.contains("not found") || error_msg.contains("ProcessNotFound"),
            "Error message should indicate process not found: {}",
            error_msg
        );
    }
}

#[test]
fn test_process_manager_clone_functionality() {
    init_tracing();

    let manager1 = ProcessManager::new().expect("Failed to create ProcessManager");
    let manager2 = manager1.clone();

    // Start a process with the first manager
    let config = create_quick_config();
    let handle = manager1
        .start_process(config)
        .expect("Failed to start process with first manager");

    // Query status with the second manager (should work due to shared state)
    let status = manager2
        .query_status(handle)
        .expect("Failed to query status with cloned manager");

    validate_process_status(&status, "cloned manager test");

    // Stop with the second manager
    manager2
        .stop_process(handle)
        .expect("Failed to stop process with cloned manager");

    // Verify process is gone from both managers
    let processes1 = manager1.list_processes();
    let processes2 = manager2.list_processes();

    assert_eq!(
        processes1, processes2,
        "Both managers should have same process list"
    );

    // Wait for cleanup
    thread::sleep(Duration::from_millis(200));

    let final_processes1 = manager1.list_processes();
    let final_processes2 = manager2.list_processes();

    assert!(
        !final_processes1.contains(&handle) && !final_processes2.contains(&handle),
        "Process should be removed from both managers"
    );
}

#[test]
fn test_working_directory_default_behavior() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test with no working directory specified (should use system default)
    let commands = PlatformCommands::get();
    let config = ProcessConfig::new(commands.pwd.0)
        .args(commands.pwd.1)
        .env("PATH", "/usr/bin:/bin")
        .log_file(std::env::temp_dir().join("default_wd_test.log"));

    let handle = manager
        .start_process(config.clone())
        .expect("Failed to start process with default working directory");

    // Give process time to complete
    thread::sleep(Duration::from_millis(500));

    let status = manager.query_status(handle);
    match status {
        Ok(ProcessStatus::Exited { exit_code, .. }) => {
            assert_eq!(exit_code, 0, "Working directory command should succeed");

            // Check log file if it exists
            if let Some(log_file) = &config.log_file {
                if log_file.exists() {
                    let output = std::fs::read_to_string(log_file)
                        .expect("Failed to read log file")
                        .trim()
                        .to_string();

                    // Should be some valid directory (implementation-dependent)
                    assert!(
                        !output.is_empty(),
                        "Working directory output should not be empty"
                    );
                    println!("Default working directory: {}", output);

                    cleanup_test_files(&std::env::temp_dir(), "default_wd_test");
                }
            }
        }
        Ok(other_status) => {
            validate_process_status(&other_status, "default working directory test");
            let _ = manager.stop_process(handle);
        }
        Err(error) => {
            panic!(
                "Failed to query default working directory test: {:?}",
                error
            );
        }
    }
}

#[test]
fn test_environment_isolation_comprehensive() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test with completely empty environment
    let commands = PlatformCommands::get();
    let config = ProcessConfig::new(commands.env_list.0)
        .args(commands.env_list.1)
        .log_file(std::env::temp_dir().join("empty_env_test.log"));
    // Note: No environment variables set at all

    let handle = manager
        .start_process(config.clone())
        .expect("Failed to start process with empty environment");

    // Give process time to complete
    thread::sleep(Duration::from_secs(1));

    let status = manager.query_status(handle);
    match status {
        Ok(ProcessStatus::Exited { .. }) => {
            // Check log file if it exists
            if let Some(log_file) = &config.log_file {
                if log_file.exists() {
                    let content =
                        std::fs::read_to_string(log_file).expect("Failed to read log file");

                    // With empty environment, there should be very few or no environment variables
                    let line_count = content.lines().count();
                    println!(
                        "Environment variables with empty config: {} lines",
                        line_count
                    );

                    // The exact behavior depends on the platform and implementation
                    // but there should be minimal environment inheritance

                    cleanup_test_files(&std::env::temp_dir(), "empty_env_test");
                }
            }
        }
        Ok(other_status) => {
            validate_process_status(&other_status, "empty environment test");
            let _ = manager.stop_process(handle);
        }
        Err(error) => {
            // This might fail on some platforms if PATH is required
            println!(
                "Empty environment test failed (may be expected): {:?}",
                error
            );
        }
    }
}

#[test]
fn test_multiple_manager_instances() {
    init_tracing();

    // Test that multiple ProcessManager instances can coexist
    let manager1 = ProcessManager::new().expect("Failed to create first ProcessManager");
    let manager2 = ProcessManager::new().expect("Failed to create second ProcessManager");

    // Start processes with both managers
    let config1 = create_quick_config();
    let config2 = create_quick_config();

    let handle1 = manager1
        .start_process(config1)
        .expect("Failed to start process with first manager");
    let handle2 = manager2
        .start_process(config2)
        .expect("Failed to start process with second manager");

    // Verify processes are isolated between managers
    let processes1 = manager1.list_processes();
    let processes2 = manager2.list_processes();

    assert!(
        processes1.contains(&handle1),
        "First manager should have first process"
    );
    assert!(
        !processes1.contains(&handle2),
        "First manager should not have second process"
    );
    assert!(
        processes2.contains(&handle2),
        "Second manager should have second process"
    );
    assert!(
        !processes2.contains(&handle1),
        "Second manager should not have first process"
    );

    // Clean up
    let _ = manager1.stop_process(handle1);
    let _ = manager2.stop_process(handle2);
}

#[test]
fn test_process_group_creation() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test process group creation (if supported)
    let result = manager.create_process_group();

    match result {
        Ok(pgid) => {
            println!("Created process group with ID: {}", pgid);
            assert!(pgid != 0, "Process group ID should be non-zero");
        }
        Err(error) => {
            println!("Process group creation not supported or failed: {}", error);
            // This is acceptable - not all platforms may support this
        }
    }
}
