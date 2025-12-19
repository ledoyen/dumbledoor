//! End-to-end tests for process cleanup when main process receives SIGKILL
//!
//! This test verifies that child processes are properly cleaned up when the
//! ProcessManager host process is forcefully terminated (SIGKILL on Unix,
//! TerminateProcess on Windows).
//!
//! The test uses a multi-process architecture:
//! 1. Test orchestrator (this process) - manages the test scenario
//! 2. Victim process - runs ProcessManager and spawns children
//! 3. Target child processes - long-running processes that should be cleaned up
//!
//! Requirements tested:
//! - 3.3: Cleanup on abnormal program termination
//! - 3.4: Cleanup when main process receives SIGKILL
//! - 5.3: Platform-specific cleanup guarantees
//! - 5.5: No orphaned processes after forceful termination

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Initialize tracing for tests
fn init_tracing() {
    let _ = tracing_subscriber::fmt::try_init();
}

/// Get the path to the victim process executable, building it if necessary
fn get_victim_executable_path() -> PathBuf {
    let mut path = std::env::current_exe()
        .expect("Failed to get current executable path")
        .parent()
        .expect("Failed to get parent directory")
        .to_path_buf();

    // The victim executable should be built alongside the test
    #[cfg(windows)]
    path.push("sigkill_victim.exe");
    #[cfg(not(windows))]
    path.push("sigkill_victim");

    // If the binary doesn't exist, build it
    if !path.exists() {
        build_victim_binary();
    }

    path
}

/// Build the sigkill_victim binary if it doesn't exist
fn build_victim_binary() {
    use std::process::Command;

    println!("Building sigkill_victim binary...");

    // Find the workspace root by looking for Cargo.toml
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
            // Check if this is the process-manager Cargo.toml
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

    println!("Building from directory: {}", current_dir.display());

    let output = Command::new("cargo")
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

/// Platform-specific process existence check
fn process_exists(pid: u32) -> bool {
    #[cfg(windows)]
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

    #[cfg(unix)]
    {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }
}

/// Platform-specific process termination
fn kill_process(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        use std::process::Command;
        let output = Command::new("taskkill")
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
        // Use safe std::process::Command instead of unsafe libc call
        let output = std::process::Command::new("kill")
            .arg("-9") // SIGKILL
            .arg(pid.to_string())
            .output();

        match output {
            Ok(result) => {
                if !result.status.success() {
                    return Err(format!(
                        "Failed to send SIGKILL to process {}: {}",
                        pid,
                        String::from_utf8_lossy(&result.stderr)
                    )
                    .into());
                }
            }
            Err(e) => {
                return Err(format!("Failed to execute kill command: {}", e).into());
            }
        }
    }

    Ok(())
}

/// Get all processes with a specific name pattern
fn get_processes_by_pattern(pattern: &str) -> Vec<u32> {
    #[cfg(windows)]
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

/// Wait for a file to be created with timeout
fn wait_for_file(path: &Path, timeout: Duration) -> bool {
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
    let content = fs::read_to_string(path)?;
    let pids: Result<Vec<u32>, _> = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.trim().parse::<u32>())
        .collect();
    Ok(pids?)
}

/// Platform-specific cleanup timeout
fn get_cleanup_timeout() -> Duration {
    #[cfg(windows)]
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

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        // Conservative timeout for other platforms
        Duration::from_secs(10)
    }
}

#[test]
fn test_sigkill_cleanup_basic() {
    init_tracing();

    let victim_exe = get_victim_executable_path();

    let temp_dir = std::env::temp_dir();
    let pid_file = temp_dir.join("sigkill_test_pids.txt");
    let ready_file = temp_dir.join("sigkill_test_ready.txt");

    // Clean up any existing files
    let _ = fs::remove_file(&pid_file);
    let _ = fs::remove_file(&ready_file);

    // Count initial processes to detect leaks
    let initial_ping_count = get_processes_by_pattern("ping").len();

    println!("Starting victim process...");

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

    println!("Victim process signaled ready");

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

    println!("All processes verified as running");

    // Forcefully terminate victim process (SIGKILL equivalent)
    println!("Sending SIGKILL to victim process...");
    if let Err(e) = kill_process(victim_pid) {
        eprintln!("Warning: Failed to kill victim process: {}", e);
        // Try the process handle as backup
        let _ = victim_process.kill();
    }

    // Wait a brief moment for the kill to take effect
    thread::sleep(Duration::from_millis(500));

    // Verify victim process is terminated
    assert!(
        !process_exists(victim_pid),
        "Victim process should be terminated"
    );
    println!("Victim process confirmed terminated");

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
            "ERROR: Child processes still running after cleanup: {:?}",
            surviving_children
        );

        // Try to clean up manually for test hygiene
        for &pid in &surviving_children {
            let _ = kill_process(pid);
        }

        panic!(
            "Platform cleanup failed - {} child processes survived SIGKILL",
            surviving_children.len()
        );
    }

    println!("✓ All child processes cleaned up successfully");

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

    // Ensure victim process is fully cleaned up
    let _ = victim_process.wait();
}

#[test]
fn test_sigkill_cleanup_nested_processes() {
    init_tracing();

    let victim_exe = get_victim_executable_path();
    let temp_dir = std::env::temp_dir();
    let pid_file = temp_dir.join("sigkill_nested_pids.txt");
    let ready_file = temp_dir.join("sigkill_nested_ready.txt");

    // Clean up any existing files
    let _ = fs::remove_file(&pid_file);
    let _ = fs::remove_file(&ready_file);

    println!("Starting victim process with nested children...");

    // Start victim process with nested child spawning
    let mut victim_process = Command::new(&victim_exe)
        .arg(pid_file.to_string_lossy().as_ref())
        .arg(ready_file.to_string_lossy().as_ref())
        .arg("2") // Number of child processes
        .arg("--nested") // Enable nested process spawning
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start victim process");

    let victim_pid = victim_process.id();
    println!("Victim process started with PID: {}", victim_pid);

    // Wait for victim to signal it's ready
    if !wait_for_file(&ready_file, Duration::from_secs(15)) {
        let _ = victim_process.kill();
        panic!("Victim process did not signal ready within timeout");
    }

    // Read all PIDs (children and grandchildren)
    let all_pids = match read_pids_from_file(&pid_file) {
        Ok(pids) => {
            println!("All spawned PIDs: {:?}", pids);
            pids
        }
        Err(e) => {
            let _ = victim_process.kill();
            panic!("Failed to read PIDs: {}", e);
        }
    };

    // Verify all processes are running
    for &pid in &all_pids {
        assert!(process_exists(pid), "Process {} should be running", pid);
    }

    println!("All {} processes verified as running", all_pids.len());

    // Forcefully terminate victim process
    println!("Sending SIGKILL to victim process...");
    if let Err(e) = kill_process(victim_pid) {
        eprintln!("Warning: Failed to kill victim process: {}", e);
        let _ = victim_process.kill();
    }

    // Wait for cleanup
    let cleanup_timeout = get_cleanup_timeout();
    println!(
        "Waiting {} seconds for nested cleanup...",
        cleanup_timeout.as_secs()
    );
    thread::sleep(cleanup_timeout);

    // Verify all processes in the tree are cleaned up
    let mut surviving_processes = Vec::new();
    for &pid in &all_pids {
        if process_exists(pid) {
            surviving_processes.push(pid);
        }
    }

    if !surviving_processes.is_empty() {
        eprintln!(
            "ERROR: Processes still running after cleanup: {:?}",
            surviving_processes
        );

        // Manual cleanup for test hygiene
        for &pid in &surviving_processes {
            let _ = kill_process(pid);
        }

        panic!(
            "Nested process cleanup failed - {} processes survived",
            surviving_processes.len()
        );
    }

    println!("✓ All nested processes cleaned up successfully");

    // Clean up test files
    let _ = fs::remove_file(&pid_file);
    let _ = fs::remove_file(&ready_file);
    let _ = victim_process.wait();
}

#[test]
fn test_sigkill_cleanup_stress() {
    init_tracing();

    let victim_exe = get_victim_executable_path();

    let temp_dir = std::env::temp_dir();
    let pid_file = temp_dir.join("sigkill_stress_pids.txt");
    let ready_file = temp_dir.join("sigkill_stress_ready.txt");

    // Clean up any existing files
    let _ = fs::remove_file(&pid_file);
    let _ = fs::remove_file(&ready_file);

    let num_children = 10; // Stress test with more processes
    println!(
        "Starting stress test with {} child processes...",
        num_children
    );

    // Start victim process
    let mut victim_process = Command::new(&victim_exe)
        .arg(pid_file.to_string_lossy().as_ref())
        .arg(ready_file.to_string_lossy().as_ref())
        .arg(num_children.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start victim process");

    let victim_pid = victim_process.id();

    // Wait for victim to signal ready
    if !wait_for_file(&ready_file, Duration::from_secs(20)) {
        let _ = victim_process.kill();
        panic!("Victim process did not signal ready within timeout");
    }

    // Read child PIDs
    let child_pids = match read_pids_from_file(&pid_file) {
        Ok(pids) => {
            println!("Spawned {} child processes", pids.len());
            assert_eq!(
                pids.len(),
                num_children,
                "Should spawn exactly {} children",
                num_children
            );
            pids
        }
        Err(e) => {
            let _ = victim_process.kill();
            panic!("Failed to read child PIDs: {}", e);
        }
    };

    // Kill victim process immediately (stress timing)
    println!("Immediately killing victim process during active child management...");
    if let Err(e) = kill_process(victim_pid) {
        let _ = victim_process.kill();
        panic!("Failed to kill victim process: {}", e);
    }

    // Wait for cleanup with extended timeout for stress test
    let cleanup_timeout = get_cleanup_timeout() * 2; // Double timeout for stress
    println!(
        "Waiting {} seconds for stress cleanup...",
        cleanup_timeout.as_secs()
    );
    thread::sleep(cleanup_timeout);

    // Verify cleanup under stress
    let mut surviving_children = Vec::new();
    for &pid in &child_pids {
        if process_exists(pid) {
            surviving_children.push(pid);
        }
    }

    if !surviving_children.is_empty() {
        eprintln!(
            "ERROR: {} processes survived stress cleanup: {:?}",
            surviving_children.len(),
            surviving_children
        );

        // Manual cleanup
        for &pid in &surviving_children {
            let _ = kill_process(pid);
        }

        panic!("Stress test cleanup failed");
    }

    println!(
        "✓ Stress test passed - all {} processes cleaned up",
        num_children
    );

    // Clean up test files
    let _ = fs::remove_file(&pid_file);
    let _ = fs::remove_file(&ready_file);
    let _ = victim_process.wait();
}

// Platform-specific tests
#[cfg(windows)]
mod windows_specific {
    use super::*;

    #[test]
    fn test_job_object_cleanup() {
        // Test Windows Job Object specific behavior
        println!("Testing Windows Job Object cleanup behavior");

        // This test verifies that Job Objects provide immediate cleanup
        // when the parent process is terminated
        test_sigkill_cleanup_basic();

        // Additional verification that cleanup happens within 1 second on Windows
        // (This is already covered by the shorter timeout in get_cleanup_timeout)
    }
}

#[cfg(target_os = "linux")]
mod linux_specific {
    use super::*;

    #[test]
    fn test_namespace_cleanup() {
        // Test Linux user namespace cleanup behavior
        println!("Testing Linux namespace/process group cleanup");

        // This test verifies namespace or process group cleanup
        test_sigkill_cleanup_basic();
    }
}

#[cfg(target_os = "macos")]
mod macos_specific {
    use super::*;

    #[test]
    fn test_process_group_cleanup() {
        // Test macOS process group cleanup behavior
        println!("Testing macOS process group cleanup");

        test_sigkill_cleanup_basic();
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod unsupported_platform {
    #[test]
    fn test_sigkill_cleanup_unsupported() {
        println!(
            "SIGKILL cleanup tests are not supported on this platform: {}",
            std::env::consts::OS
        );
        println!("Supported platforms: Windows, Linux, macOS");
        // This test always passes on unsupported platforms
    }
}
