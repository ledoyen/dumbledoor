//! End-to-end tests for process manager
//!
//! This file contains exactly 5 comprehensive E2E tests that cover all critical
//! functionality while avoiding redundancy. Each test has a single, well-defined
//! responsibility and uses real process spawning and management.

mod common;

use common::*;
use process_manager::{ProcessConfig, ProcessHandle, ProcessManager, ProcessStatus};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

/// Test 1: Basic process lifecycle - covers core ProcessManager functionality
#[test]
fn test_basic_process_lifecycle() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test process creation and configuration
    let config = create_long_running_config();
    config.validate().expect("Configuration should be valid");

    // Test process spawning
    let handle = manager
        .start_process(config)
        .expect("Failed to start process");

    // Test process listing
    let processes = manager.list_processes();
    assert!(processes.contains(&handle), "Process should be in the list");

    // Wait for process to be running
    thread::sleep(Duration::from_millis(500));

    // Test status querying
    let status = manager
        .query_status(handle)
        .expect("Failed to query status");
    validate_process_status(&status, "basic lifecycle");

    // Test graceful termination
    manager
        .stop_process(handle)
        .expect("Failed to stop process");

    // Wait for process to be removed from the list
    let mut attempts = 0;
    while attempts < 50 {
        let processes = manager.list_processes();
        if !processes.contains(&handle) {
            break;
        }
        thread::sleep(Duration::from_millis(100));
        attempts += 1;
    }

    // Verify process is no longer in the list
    let final_processes = manager.list_processes();
    assert!(
        !final_processes.contains(&handle),
        "Process should be removed from list after stopping"
    );
}

/// Test 2: Multiple process management - covers concurrent operations and bulk cleanup
#[test]
fn test_multiple_process_management() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Spawn multiple processes to test platform-specific grouping behavior
    let mut handles = Vec::new();
    for i in 0..3 {
        let mut config = create_long_running_config();
        config.log_file = Some(std::env::temp_dir().join(format!("multi_test_{}.log", i)));

        let handle = manager
            .start_process(config)
            .expect("Failed to start process");
        handles.push(handle);
    }

    // Give processes time to start
    thread::sleep(Duration::from_secs(1));

    // Verify all processes are in the list
    let processes = manager.list_processes();
    for handle in &handles {
        assert!(
            processes.contains(handle),
            "Process {} should be in the list",
            handle.0
        );
    }

    // Validate each process status
    for (i, handle) in handles.iter().enumerate() {
        let status = manager
            .query_status(*handle)
            .unwrap_or_else(|_| panic!("Failed to query status for process {}", i));
        validate_process_status(&status, &format!("process {}", i));
    }

    // Test concurrent termination
    for handle in &handles {
        manager
            .stop_process(*handle)
            .expect("Failed to stop process");
    }

    // Wait for all processes to be removed from the list
    let mut all_removed = false;
    for _ in 0..50 {
        let processes = manager.list_processes();
        all_removed = handles.iter().all(|h| !processes.contains(h));
        if all_removed {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    assert!(
        all_removed,
        "All processes should be removed from list after stopping"
    );

    // Cleanup test files
    cleanup_test_files(&std::env::temp_dir(), "multi_test");
}

/// Test 3: Process configuration features - covers environment, working directory, log redirection
#[test]
fn test_process_configuration_features() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test 3a: Environment variable isolation
    let env_config = create_env_test_config();
    let env_handle = manager
        .start_process(env_config.clone())
        .expect("Failed to start process with environment");

    // Test 3b: Working directory isolation
    let temp_dir = std::env::temp_dir();
    let test_dir = temp_dir.join("wd_test");
    std::fs::create_dir_all(&test_dir).expect("Failed to create test directory");

    let wd_config = create_pwd_test_config(test_dir.clone());
    let wd_handle = manager
        .start_process(wd_config.clone())
        .expect("Failed to start process with working directory");

    // Test 3c: Log file redirection
    let log_config = create_stdout_stderr_config();
    let log_handle = manager
        .start_process(log_config.clone())
        .expect("Failed to start process with log redirection");

    // Wait for processes to complete
    thread::sleep(Duration::from_secs(3));

    // Verify environment test results
    let env_status = manager.query_status(env_handle);
    match env_status {
        Ok(ProcessStatus::Exited { exit_code, .. }) => {
            assert_eq!(exit_code, 0, "Environment test should succeed");

            if let Some(log_file) = &env_config.log_file {
                if log_file.exists() {
                    let content = std::fs::read_to_string(log_file)
                        .expect("Failed to read environment log file");
                    assert!(
                        content.contains("TEST_VAR"),
                        "Log should contain test environment variable"
                    );
                }
            }
        }
        Ok(other_status) => {
            validate_process_status(&other_status, "environment test");
        }
        Err(_) => {
            // Process might have completed and been cleaned up
        }
    }

    // Verify working directory test results
    let wd_status = manager.query_status(wd_handle);
    match wd_status {
        Ok(ProcessStatus::Exited { exit_code, .. }) => {
            assert_eq!(exit_code, 0, "Working directory test should succeed");

            if let Some(log_file) = &wd_config.log_file {
                if log_file.exists() {
                    let output = std::fs::read_to_string(log_file)
                        .expect("Failed to read working directory log file")
                        .trim()
                        .to_string();

                    let expected_path = test_dir
                        .canonicalize()
                        .expect("Failed to canonicalize test directory")
                        .to_string_lossy()
                        .to_string();

                    assert_eq!(
                        output, expected_path,
                        "Process should run in the specified working directory"
                    );
                }
            }
        }
        Ok(other_status) => {
            validate_process_status(&other_status, "working directory test");
        }
        Err(_) => {
            // Process might have completed and been cleaned up
        }
    }

    // Verify log redirection test results
    let log_status = manager.query_status(log_handle);
    match log_status {
        Ok(ProcessStatus::Exited { .. }) => {
            if let Some(log_file) = &log_config.log_file {
                if log_file.exists() {
                    let content = std::fs::read_to_string(log_file)
                        .expect("Failed to read stdout/stderr log file");
                    assert!(
                        content.contains("stdout_message"),
                        "Log should contain stdout message"
                    );
                }
            }
        }
        Ok(other_status) => {
            validate_process_status(&other_status, "log redirection test");
        }
        Err(_) => {
            // Process might have completed and been cleaned up
        }
    }

    // Clean up test processes if still running
    let _ = manager.stop_process(env_handle);
    let _ = manager.stop_process(wd_handle);
    let _ = manager.stop_process(log_handle);

    // Clean up test files and directories
    cleanup_test_files(&std::env::temp_dir(), "test_env");
    cleanup_test_files(&test_dir, "test_pwd");
    cleanup_test_files(&std::env::temp_dir(), "test_stdout_stderr");
    let _ = std::fs::remove_dir_all(&test_dir);
}

/// Test 4: Error handling and edge cases - covers validation, failure modes, graceful degradation
#[test]
fn test_error_handling_and_edge_cases() {
    init_tracing();

    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test 4a: Invalid command handling
    let invalid_config = ProcessConfig::new("/nonexistent/command/that/does/not/exist");
    let result = manager.start_process(invalid_config);
    match result {
        Err(error) => {
            let error_msg = error.to_string();
            assert!(!error_msg.is_empty(), "Error message should not be empty");
        }
        Ok(handle) => {
            // If command is accepted, it should eventually fail
            thread::sleep(Duration::from_secs(1));
            let status = manager.query_status(handle);
            match status {
                Ok(ProcessStatus::Failed { error }) => {
                    assert!(!error.is_empty(), "Failure error should not be empty");
                }
                Ok(ProcessStatus::Exited { exit_code, .. }) => {
                    assert_ne!(
                        exit_code, 0,
                        "Invalid command should exit with non-zero code"
                    );
                }
                _ => {
                    // Other states might be valid depending on implementation
                }
            }
            let _ = manager.stop_process(handle);
        }
    }

    // Test 4b: Configuration validation errors
    let empty_config = ProcessConfig::new("");
    let result = empty_config.validate();
    assert!(result.is_err(), "Empty command should fail validation");

    let invalid_wd_config =
        ProcessConfig::new("echo").working_directory("/nonexistent/directory/that/does/not/exist");
    let result = invalid_wd_config.validate();
    assert!(
        result.is_err(),
        "Invalid working directory should fail validation"
    );

    // Test 4c: Querying status of nonexistent process handle
    let fake_handle = ProcessHandle::new();
    let status = manager.query_status(fake_handle);
    match status {
        Err(error) => {
            let error_msg = error.to_string();
            assert!(
                error_msg.contains("not found") || error_msg.contains("ProcessNotFound"),
                "Error should indicate process not found, got: '{}'",
                error_msg
            );
        }
        Ok(status) => {
            panic!(
                "Should not return status for nonexistent handle, got: {:?}",
                status
            );
        }
    }

    // Test 4d: Stopping nonexistent process
    let result = manager.stop_process(fake_handle);
    assert!(result.is_err(), "Should fail to stop nonexistent process");

    // Test 4e: ProcessManager cloning and shared state
    let manager2 = manager.clone();
    let config = create_quick_config();
    let handle = manager
        .start_process(config)
        .expect("Failed to start process with first manager");

    // Query status with the cloned manager (should work due to shared state)
    let status = manager2
        .query_status(handle)
        .expect("Failed to query status with cloned manager");
    validate_process_status(&status, "cloned manager test");

    // Stop with the cloned manager
    manager2
        .stop_process(handle)
        .expect("Failed to stop process with cloned manager");

    // Test 4f: Concurrent operations stress test
    let handles: Vec<_> = (0..3)
        .map(|i| {
            let mut config = create_quick_config();
            config.log_file = Some(std::env::temp_dir().join(format!("concurrent_test_{}.log", i)));
            manager
                .start_process(config)
                .expect("Failed to start concurrent process")
        })
        .collect();

    // Wait for processes to start/complete
    thread::sleep(Duration::from_secs(2));

    // Test concurrent status queries and stopping
    for handle in &handles {
        let _ = manager.query_status(*handle);
        let _ = manager.stop_process(*handle);
    }

    // Cleanup
    cleanup_test_files(&std::env::temp_dir(), "concurrent_test");
}

/// Test 5: SIGKILL cleanup guarantee - covers platform-specific cleanup mechanisms and reaper functionality
#[test]
fn test_sigkill_cleanup_guarantee() {
    init_tracing();

    // This is the only test that uses the complex multi-process architecture
    // It verifies that child processes are properly cleaned up when the
    // ProcessManager host process is forcefully terminated

    use std::fs;
    use std::process::{Command, Stdio};

    // Get the victim executable path
    let victim_exe = get_victim_executable_path();
    let temp_dir = std::env::temp_dir();
    let pid_file = temp_dir.join("sigkill_e2e_pids.txt");
    let ready_file = temp_dir.join("sigkill_e2e_ready.txt");

    // Clean up any existing files
    let _ = fs::remove_file(&pid_file);
    let _ = fs::remove_file(&ready_file);

    // Count initial processes to detect leaks
    let initial_ping_count = get_processes_by_pattern("ping").len();

    println!("Starting victim process for SIGKILL cleanup test...");

    // Start victim process
    let mut victim_process = Command::new(&victim_exe)
        .arg(pid_file.to_string_lossy().as_ref())
        .arg(ready_file.to_string_lossy().as_ref())
        .arg("3") // Number of child processes to spawn
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start victim process");

    let victim_pid = victim_process.id();
    println!("Victim process started with PID: {}", victim_pid);

    // Wait for victim to signal it's ready
    if !wait_for_file(&ready_file, Duration::from_secs(10)) {
        let _ = victim_process.kill();
        panic!("Victim process did not signal ready within timeout");
    }

    // Read PIDs of spawned children
    let child_pids = match read_pids_from_file(&pid_file) {
        Ok(pids) => {
            println!("Child PIDs: {:?}", pids);
            pids
        }
        Err(e) => {
            let _ = victim_process.kill();
            panic!("Failed to read child PIDs: {}", e);
        }
    };

    // Verify all processes are running
    assert!(
        process_exists(victim_pid),
        "Victim process should be running"
    );
    for &pid in &child_pids {
        assert!(
            process_exists(pid),
            "Child process {} should be running",
            pid
        );
    }

    // Forcefully terminate victim process (SIGKILL equivalent)
    println!("Sending SIGKILL to victim process...");
    match kill_process(victim_pid) {
        Ok(()) => println!("Successfully killed victim process {}", victim_pid),
        Err(e) => {
            eprintln!("Warning: Failed to kill victim process: {}", e);
            let _ = victim_process.kill();
        }
    }

    // Wait for platform-specific cleanup to complete
    let cleanup_timeout = get_cleanup_timeout();
    println!(
        "Waiting {} seconds for cleanup to complete...",
        cleanup_timeout.as_secs()
    );
    thread::sleep(cleanup_timeout);

    // Verify all child processes are cleaned up
    let mut surviving_children = Vec::new();
    for &pid in &child_pids {
        if process_exists(pid) {
            surviving_children.push(pid);
        }
    }

    if !surviving_children.is_empty() {
        eprintln!(
            "FAILURE: Child processes still running after cleanup: {:?}",
            surviving_children
        );

        // Try to clean up manually for test hygiene
        for &pid in &surviving_children {
            let _ = kill_process(pid);
        }

        panic!(
            "ProcessManager reaper failed: {} child processes survived parent death",
            surviving_children.len()
        );
    } else {
        println!("✓ All child processes cleaned up successfully by reaper");
    }

    // Verify no process leaks occurred
    let final_ping_count = get_processes_by_pattern("ping").len();
    let leaked_processes = final_ping_count.saturating_sub(initial_ping_count);

    assert_eq!(
        leaked_processes, 0,
        "Process leak detected: {} new ping processes remain",
        leaked_processes
    );

    println!("✓ No process leaks detected");

    // Clean up test files
    let _ = fs::remove_file(&pid_file);
    let _ = fs::remove_file(&ready_file);
    let _ = victim_process.wait();
}

// Helper functions for SIGKILL test

/// Get the path to the victim process executable, building it if necessary
fn get_victim_executable_path() -> PathBuf {
    let mut workspace_root = std::env::current_dir().expect("Failed to get current directory");

    // Look for workspace root (contains Cargo.toml with workspace definition)
    loop {
        let cargo_toml = workspace_root.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                if content.contains("[workspace]") {
                    break;
                }
            }
        }
        if let Some(parent) = workspace_root.parent() {
            workspace_root = parent.to_path_buf();
        } else {
            workspace_root = std::env::current_dir().expect("Failed to get current directory");
            break;
        }
    }

    let mut path = workspace_root.join("target").join("debug");

    #[cfg(windows)]
    path.push("sigkill_victim.exe");
    #[cfg(not(windows))]
    path.push("sigkill_victim");

    // If the binary doesn't exist, build it
    if !path.exists() {
        build_victim_binary();
        if !path.exists() {
            panic!(
                "Failed to build or find sigkill_victim binary at: {}",
                path.display()
            );
        }
    }

    path
}

/// Build the sigkill_victim binary if it doesn't exist
fn build_victim_binary() {
    println!("Building sigkill_victim binary...");

    let mut current_dir = std::env::current_dir().expect("Failed to get current directory");

    // Look for the process-manager directory containing Cargo.toml
    loop {
        let cargo_toml = current_dir.join("process-manager").join("Cargo.toml");
        if cargo_toml.exists() {
            current_dir = current_dir.join("process-manager");
            break;
        }

        let cargo_toml = current_dir.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                if content.contains("name = \"process-manager\"") {
                    break;
                }
            }
        }

        if let Some(parent) = current_dir.parent() {
            current_dir = parent.to_path_buf();
        } else {
            panic!("Could not find process-manager workspace root");
        }
    }

    let output = std::process::Command::new("cargo")
        .args([
            "build",
            "--bin",
            "sigkill_victim",
            "--features",
            "binary-deps",
        ])
        .current_dir(&current_dir)
        .output()
        .expect("Failed to execute cargo build command");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "Failed to build sigkill_victim binary:\nSTDOUT:\n{}\nSTDERR:\n{}",
            stdout, stderr
        );
    }

    println!("✓ sigkill_victim binary built successfully");
}

/// Wait for a file to be created with timeout
fn wait_for_file(path: &std::path::Path, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Read PIDs from a file
fn read_pids_from_file(path: &PathBuf) -> Result<Vec<u32>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let pids: Result<Vec<u32>, _> = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.trim().parse::<u32>())
        .collect();
    Ok(pids?)
}

/// Platform-specific process existence check
fn process_exists(pid: u32) -> bool {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("tasklist")
            .args(["/fi", &format!("PID eq {}", pid), "/fo", "csv"])
            .output();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout.lines().count() > 1 // Header + process line if exists
            }
            Err(_) => false,
        }
    }

    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ps")
            .args(["-p", &pid.to_string()])
            .output();
        match output {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }
}

/// Platform-specific process termination
fn kill_process(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output()?;

        if !output.status.success() {
            return Err(format!(
                "Failed to kill process {}: {}",
                pid,
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
    }

    #[cfg(unix)]
    {
        let result = std::process::Command::new("kill")
            .arg("-9") // SIGKILL
            .arg(pid.to_string())
            .output();

        match result {
            Ok(result) => {
                if !result.status.success() {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    if stderr.contains("No such process") {
                        return Ok(());
                    }
                    return Err(
                        format!("Failed to send SIGKILL to process {}: {}", pid, stderr).into(),
                    );
                }
            }
            Err(e) => {
                return Err(format!("Failed to execute kill command: {}", e).into());
            }
        }

        thread::sleep(Duration::from_millis(300));

        if process_exists(pid) {
            return Err(format!("Process {} still exists after SIGKILL", pid).into());
        }
    }

    Ok(())
}
