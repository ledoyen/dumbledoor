//! Integration tests for the process manager

use process_manager::{ProcessConfig, ProcessHandle, ProcessManager, ProcessStatus};

#[test]
fn test_process_manager_creation() {
    let manager = ProcessManager::new();
    assert!(
        manager.is_ok(),
        "ProcessManager should be created successfully"
    );
}

#[test]
fn test_process_config_builder() {
    #[cfg(windows)]
    let config = ProcessConfig::new("cmd.exe")
        .args(["hello", "world"])
        .working_directory("C:\\Windows")
        .env("TEST", "value")
        .log_file("C:\\temp\\output.log");

    #[cfg(unix)]
    let config = ProcessConfig::new("/bin/echo")
        .args(["hello", "world"])
        .working_directory("/tmp")
        .env("TEST", "value")
        .log_file("/tmp/output.log");

    #[cfg(windows)]
    {
        assert_eq!(config.command.to_str().unwrap(), "cmd.exe");
        assert_eq!(config.args, vec!["hello", "world"]);
        assert_eq!(
            config.working_directory.as_ref().unwrap().to_str().unwrap(),
            "C:\\Windows"
        );
        assert_eq!(config.environment.get("TEST").unwrap(), "value");
        assert_eq!(
            config.log_file.as_ref().unwrap().to_str().unwrap(),
            "C:\\temp\\output.log"
        );
    }

    #[cfg(unix)]
    {
        assert_eq!(config.command.to_str().unwrap(), "/bin/echo");
        assert_eq!(config.args, vec!["hello", "world"]);
        assert_eq!(
            config.working_directory.as_ref().unwrap().to_str().unwrap(),
            "/tmp"
        );
        assert_eq!(config.environment.get("TEST").unwrap(), "value");
        assert_eq!(
            config.log_file.as_ref().unwrap().to_str().unwrap(),
            "/tmp/output.log"
        );
    }
}

#[test]
fn test_process_handle_uniqueness() {
    let handle1 = ProcessHandle::new();
    let handle2 = ProcessHandle::new();
    assert_ne!(handle1, handle2, "Process handles should be unique");
}

#[test]
fn test_process_manager_basic_operations() {
    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    // Test listing processes (should be empty initially)
    let processes = manager.list_processes();
    assert!(processes.is_empty(), "Initial process list should be empty");

    // Test starting a process - use platform-appropriate command
    #[cfg(windows)]
    let config = ProcessConfig::new("cmd.exe").args(["/c", "echo", "test"]);
    #[cfg(unix)]
    let config = ProcessConfig::new("/bin/echo").args(["test"]);

    let handle = manager
        .start_process(config)
        .expect("Failed to start process");

    // Test querying status
    let status = manager
        .query_status(handle)
        .expect("Failed to query status");
    match status {
        ProcessStatus::Running { .. } => {
            // This is expected for our implementation
        }
        _ => panic!("Unexpected process status: {:?}", status),
    }

    // Test stopping process
    manager
        .stop_process(handle)
        .expect("Failed to stop process");
}
