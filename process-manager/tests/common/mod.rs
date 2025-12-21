//! Common test utilities and helpers for cross-platform testing

use process_manager::{ProcessConfig, ProcessManager, ProcessStatus};
use std::collections::HashMap;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime};

/// Initialize tracing for tests (idempotent)
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt::try_init();
}

/// Platform-specific test commands and configurations
pub struct PlatformCommands {
    /// Long-running command (should run for ~30 seconds)
    pub long_running: (&'static str, Vec<&'static str>),
    /// Quick command that completes immediately
    pub quick: (&'static str, Vec<&'static str>),
    /// Command that spawns background processes
    pub detached: (&'static str, Vec<&'static str>),
    /// Command that outputs to both stdout and stderr
    pub stdout_stderr: (&'static str, Vec<&'static str>),
    /// Command that lists environment variables
    pub env_list: (&'static str, Vec<&'static str>),
    /// Command that prints working directory
    pub pwd: (&'static str, Vec<&'static str>),
}

impl PlatformCommands {
    /// Get platform-specific commands
    pub fn get() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self {
                long_running: ("ping", vec!["127.0.0.1", "-n", "30"]),
                quick: ("cmd", vec!["/c", "echo", "Hello World"]),
                detached: (
                    "cmd",
                    vec!["/c", "start", "/b", "ping", "127.0.0.1", "-n", "10"],
                ),
                stdout_stderr: (
                    "cmd",
                    vec!["/c", "echo stdout_message && echo stderr_message 1>&2"],
                ),
                env_list: ("cmd", vec!["/c", "set"]),
                pwd: ("cmd", vec!["/c", "cd"]),
            }
        }
        #[cfg(target_os = "macos")]
        {
            Self {
                long_running: ("/bin/sleep", vec!["30"]),
                quick: ("/bin/echo", vec!["Hello World"]),
                detached: (
                    "/bin/sh",
                    vec!["-c", "sleep 10 & echo 'Background process started'"],
                ),
                stdout_stderr: (
                    "/bin/sh",
                    vec!["-c", "echo 'stdout_message'; echo 'stderr_message' >&2"],
                ),
                env_list: ("/usr/bin/env", vec![]),
                pwd: ("/bin/pwd", vec![]),
            }
        }
        #[cfg(target_os = "linux")]
        {
            Self {
                long_running: ("/bin/sleep", vec!["30"]),
                quick: ("/bin/echo", vec!["Hello World"]),
                detached: (
                    "/bin/sh",
                    vec!["-c", "sleep 10 & echo 'Background process started'"],
                ),
                stdout_stderr: (
                    "/bin/sh",
                    vec!["-c", "echo 'stdout_message'; echo 'stderr_message' >&2"],
                ),
                env_list: ("/usr/bin/env", vec![]),
                pwd: ("/bin/pwd", vec![]),
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        {
            // Fallback for other Unix-like systems
            Self {
                long_running: ("sleep", vec!["30"]),
                quick: ("echo", vec!["Hello World"]),
                detached: (
                    "sh",
                    vec!["-c", "sleep 10 & echo 'Background process started'"],
                ),
                stdout_stderr: (
                    "sh",
                    vec!["-c", "echo 'stdout_message'; echo 'stderr_message' >&2"],
                ),
                env_list: ("env", vec![]),
                pwd: ("pwd", vec![]),
            }
        }
    }
}

/// Helper to create a test configuration for a long-running process
pub fn create_long_running_config() -> ProcessConfig {
    let commands = PlatformCommands::get();
    let temp_dir = std::env::temp_dir();

    ProcessConfig {
        command: PathBuf::from(commands.long_running.0),
        args: commands
            .long_running
            .1
            .iter()
            .map(|s| s.to_string())
            .collect(),
        working_directory: Some(temp_dir.clone()),
        environment: get_minimal_environment(),
        log_file: Some(temp_dir.join("test_long_running.log")),
    }
}

/// Helper to create a test configuration for a quick process
pub fn create_quick_config() -> ProcessConfig {
    let commands = PlatformCommands::get();
    let temp_dir = std::env::temp_dir();

    ProcessConfig {
        command: PathBuf::from(commands.quick.0),
        args: commands.quick.1.iter().map(|s| s.to_string()).collect(),
        working_directory: Some(temp_dir.clone()),
        environment: get_minimal_environment(),
        log_file: Some(temp_dir.join("test_quick.log")),
    }
}

/// Helper to create a test configuration that spawns child processes
pub fn create_detached_config() -> ProcessConfig {
    let commands = PlatformCommands::get();
    let temp_dir = std::env::temp_dir();

    ProcessConfig {
        command: PathBuf::from(commands.detached.0),
        args: commands.detached.1.iter().map(|s| s.to_string()).collect(),
        working_directory: Some(temp_dir.clone()),
        environment: get_minimal_environment(),
        log_file: Some(temp_dir.join("test_detached.log")),
    }
}

/// Helper to create a test configuration for stdout/stderr testing
#[allow(dead_code)]
pub fn create_stdout_stderr_config() -> ProcessConfig {
    let commands = PlatformCommands::get();
    let temp_dir = std::env::temp_dir();

    ProcessConfig {
        command: PathBuf::from(commands.stdout_stderr.0),
        args: commands
            .stdout_stderr
            .1
            .iter()
            .map(|s| s.to_string())
            .collect(),
        working_directory: Some(temp_dir.clone()),
        environment: get_minimal_environment(),
        log_file: Some(temp_dir.join("test_stdout_stderr.log")),
    }
}

/// Helper to create a test configuration for environment variable testing
#[allow(dead_code)]
pub fn create_env_test_config() -> ProcessConfig {
    let commands = PlatformCommands::get();
    let temp_dir = std::env::temp_dir();
    let mut env = get_minimal_environment();
    env.insert("TEST_VAR".to_string(), "test_value".to_string());

    ProcessConfig {
        command: PathBuf::from(commands.env_list.0),
        args: commands.env_list.1.iter().map(|s| s.to_string()).collect(),
        working_directory: Some(temp_dir.clone()),
        environment: env,
        log_file: Some(temp_dir.join("test_env.log")),
    }
}

/// Helper to create a test configuration for working directory testing
#[allow(dead_code)]
pub fn create_pwd_test_config(working_dir: PathBuf) -> ProcessConfig {
    let commands = PlatformCommands::get();

    ProcessConfig {
        command: PathBuf::from(commands.pwd.0),
        args: commands.pwd.1.iter().map(|s| s.to_string()).collect(),
        working_directory: Some(working_dir.clone()),
        environment: get_minimal_environment(),
        log_file: Some(working_dir.join("test_pwd.log")),
    }
}

/// Get minimal environment variables needed for cross-platform compatibility
pub fn get_minimal_environment() -> HashMap<String, String> {
    let mut env = HashMap::new();

    #[cfg(unix)]
    {
        env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    }

    #[cfg(windows)]
    {
        // Windows typically needs more environment variables
        if let Ok(path) = std::env::var("PATH") {
            env.insert("PATH".to_string(), path);
        }
        if let Ok(systemroot) = std::env::var("SYSTEMROOT") {
            env.insert("SYSTEMROOT".to_string(), systemroot);
        }
    }

    env
}

/// Platform-specific process existence check
#[allow(dead_code)]
pub fn process_exists(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let output = Command::new("tasklist")
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
        use std::process::Command;
        let output = Command::new("ps").args(["-p", &pid.to_string()]).output();
        match output {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        // Fallback for other Unix-like systems
        use std::process::Command;
        let output = Command::new("ps").args(["-p", &pid.to_string()]).output();
        match output {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }
}

/// Get all processes with a specific name pattern
#[allow(dead_code)]
pub fn get_processes_by_pattern(pattern: &str) -> Vec<u32> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let output = Command::new("tasklist").args(["/fo", "csv"]).output();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout
                    .lines()
                    .skip(1) // Skip header
                    .filter_map(|line| {
                        let parts: Vec<&str> = line.split(',').collect();
                        if parts.len() >= 2 {
                            let name = parts[0].trim_matches('"');
                            let pid_str = parts[1].trim_matches('"');
                            if name.contains(pattern) {
                                pid_str.parse::<u32>().ok()
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect()
            }
            Err(_) => Vec::new(),
        }
    }

    #[cfg(unix)]
    {
        use std::process::Command;
        let output = Command::new("pgrep").arg(pattern).output();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout
                    .lines()
                    .filter_map(|line| line.trim().parse::<u32>().ok())
                    .collect()
            }
            Err(_) => Vec::new(),
        }
    }
}

/// Wait for a process to reach a specific status with timeout
#[allow(dead_code)]
pub fn wait_for_status(
    manager: &ProcessManager,
    handle: process_manager::ProcessHandle,
    expected_status: fn(&ProcessStatus) -> bool,
    timeout: Duration,
) -> Option<ProcessStatus> {
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        if let Ok(status) = manager.query_status(handle) {
            if expected_status(&status) {
                return Some(status);
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    None
}

/// Validate that a process status is in a reasonable state
pub fn validate_process_status(status: &ProcessStatus, context: &str) {
    match status {
        ProcessStatus::Running { pid } => {
            assert!(
                *pid > 0,
                "{}: Running process must have valid PID > 0, got: {}",
                context,
                pid
            );
            assert!(
                *pid < u32::MAX,
                "{}: PID should be reasonable, got: {}",
                context,
                pid
            );
        }
        ProcessStatus::Exited {
            exit_code: _,
            exit_time,
        } => {
            assert!(
                *exit_time <= SystemTime::now(),
                "{}: Exit time cannot be in the future",
                context
            );
            assert!(
                *exit_time >= SystemTime::now() - Duration::from_secs(60),
                "{}: Exit time should be recent (within 60 seconds)",
                context
            );
        }
        ProcessStatus::Terminated {
            signal: _,
            exit_time,
        } => {
            assert!(
                *exit_time <= SystemTime::now(),
                "{}: Termination time cannot be in the future",
                context
            );
            assert!(
                *exit_time >= SystemTime::now() - Duration::from_secs(60),
                "{}: Termination time should be recent (within 60 seconds)",
                context
            );
        }
        ProcessStatus::RunningDetached {
            exit_code: _,
            child_pids,
        } => {
            // Detached processes should have some indication of children or special exit
            // This is platform-dependent, so we're lenient here
            println!(
                "{}: Process is detached with {} children",
                context,
                child_pids.len()
            );
        }
        ProcessStatus::Failed { error } => {
            assert!(
                !error.is_empty(),
                "{}: Failed status should have non-empty error message",
                context
            );
        }
        ProcessStatus::Starting => {
            // Starting is always valid
        }
    }
}

/// Get the reaper PID if available
#[allow(dead_code)]
pub fn get_reaper_pid(manager: &ProcessManager) -> Option<u32> {
    manager.get_reaper_pid()
}

/// Clean up test files in a directory
pub fn cleanup_test_files(dir: &std::path::Path, pattern: &str) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.contains(pattern) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
}

/// Platform-specific cleanup timeout
#[allow(dead_code)]
pub fn get_cleanup_timeout() -> Duration {
    #[cfg(target_os = "windows")]
    {
        // Windows Job Objects should provide immediate cleanup
        Duration::from_secs(2)
    }

    #[cfg(target_os = "linux")]
    {
        // Linux user namespaces or process groups may take longer
        Duration::from_secs(5)
    }

    #[cfg(target_os = "macos")]
    {
        // macOS process groups may take longer
        Duration::from_secs(5)
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        // Conservative timeout for other platforms
        Duration::from_secs(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_commands() {
        let commands = PlatformCommands::get();

        // Verify all commands are non-empty
        assert!(!commands.long_running.0.is_empty());
        assert!(!commands.quick.0.is_empty());
        assert!(!commands.detached.0.is_empty());
        assert!(!commands.stdout_stderr.0.is_empty());
        assert!(!commands.env_list.0.is_empty());
        assert!(!commands.pwd.0.is_empty());
    }

    #[test]
    fn test_config_helpers() {
        let long_config = create_long_running_config();
        assert!(!long_config.command.as_os_str().is_empty());
        assert!(long_config.working_directory.is_some());
        assert!(long_config.log_file.is_some());

        let quick_config = create_quick_config();
        assert!(!quick_config.command.as_os_str().is_empty());

        let detached_config = create_detached_config();
        assert!(!detached_config.command.as_os_str().is_empty());
    }

    #[test]
    fn test_minimal_environment() {
        let env = get_minimal_environment();

        #[cfg(unix)]
        {
            assert!(env.contains_key("PATH"));
        }

        #[cfg(windows)]
        {
            // Windows environment may or may not have PATH depending on test environment
            // Just verify we can access the environment HashMap
            let _ = env.len(); // Validates env is accessible without useless comparison
        }
    }
}
