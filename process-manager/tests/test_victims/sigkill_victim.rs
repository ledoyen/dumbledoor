//! Victim process for SIGKILL cleanup testing
//!
//! This executable is used by the sigkill_cleanup_test to verify that
//! child processes are properly cleaned up when the ProcessManager
//! host process is forcefully terminated.
//!
//! Usage: sigkill_victim <pid_file> <ready_file> <num_children> [--nested]
//!
//! The victim process:
//! 1. Creates a ProcessManager instance (for future integration)
//! 2. Spawns the specified number of long-running child processes directly
//! 3. Writes all PIDs to the pid_file
//! 4. Creates the ready_file to signal the orchestrator
//! 5. Waits indefinitely (until killed by orchestrator)

use process_manager::ProcessManager;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "Usage: {} <pid_file> <ready_file> <num_children> [--nested]",
            args[0]
        );
        std::process::exit(1);
    }

    let pid_file = PathBuf::from(&args[1]);
    let ready_file = PathBuf::from(&args[2]);
    let num_children: usize = args[3].parse().expect("Invalid number of children");
    let nested = args.len() > 4 && args[4] == "--nested";

    println!("Victim process starting...");
    println!("PID file: {}", pid_file.display());
    println!("Ready file: {}", ready_file.display());
    println!("Number of children: {}", num_children);
    println!("Nested mode: {}", nested);

    // Create ProcessManager and use it to spawn managed processes
    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    let mut all_pids = Vec::new();
    let mut process_handles = Vec::new();
    let mut child_processes = Vec::new();

    // Use ProcessManager to spawn processes (this will test the reaper integration)
    for i in 0..num_children {
        let config = create_child_process_config(i, nested);

        match manager.start_process(config) {
            Ok(handle) => {
                // Query the PID from the process status
                match manager.query_status(handle) {
                    Ok(status) => {
                        if let process_manager::ProcessStatus::Running { pid } = status {
                            all_pids.push(pid);
                            process_handles.push(handle);
                            println!("Started managed child process {} with PID: {}", i, pid);
                        } else {
                            eprintln!("Child process {} not in running state: {:?}", i, status);
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to query status for child process {}: {}", i, e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to start managed child process {}: {}", i, e);
                // Fall back to direct spawning for compatibility
                if let Ok(child) = spawn_direct_child_process(i, nested) {
                    let pid = child.id();
                    all_pids.push(pid);
                    child_processes.push(child);
                    println!("Started direct child process {} with PID: {}", i, pid);
                }
            }
        }

        // If nested mode, spawn additional processes
        if nested {
            let nested_config = create_nested_process_config(i);
            match manager.start_process(nested_config) {
                Ok(handle) => {
                    if let Ok(status) = manager.query_status(handle) {
                        if let process_manager::ProcessStatus::Running { pid } = status {
                            all_pids.push(pid);
                            process_handles.push(handle);
                            println!("Started nested managed process {}.1 with PID: {}", i, pid);
                        }
                    }
                }
                Err(_) => {
                    // Fall back to direct spawning
                    if let Ok(grandchild) = spawn_direct_grandchild_process(i) {
                        let grandchild_pid = grandchild.id();
                        all_pids.push(grandchild_pid);
                        child_processes.push(grandchild);
                        println!(
                            "Started direct grandchild process {}.1 with PID: {}",
                            i, grandchild_pid
                        );
                    }
                }
            }
        }

        // Small delay between spawns to avoid overwhelming the system
        thread::sleep(Duration::from_millis(100));
    }

    println!("Spawned {} total processes", all_pids.len());

    // Write PIDs to file for orchestrator
    let pid_content = all_pids
        .iter()
        .map(|pid| pid.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    if let Err(e) = fs::write(&pid_file, pid_content) {
        eprintln!("Failed to write PID file: {}", e);
        std::process::exit(1);
    }

    println!("Wrote PIDs to file: {:?}", all_pids);

    // Signal that we're ready
    if let Err(e) = fs::write(&ready_file, "ready") {
        eprintln!("Failed to write ready file: {}", e);
        std::process::exit(1);
    }

    println!("Signaled ready to orchestrator");

    // Keep the process alive until killed
    // The child processes will remain running as long as this process is alive
    println!("Victim process ready - waiting for SIGKILL...");
    println!(
        "Managing {} managed processes and {} direct processes",
        process_handles.len(),
        child_processes.len()
    );

    loop {
        thread::sleep(Duration::from_secs(1));

        // Keep the child process handles alive
        // When this process is killed, the ProcessManager should clean up the managed processes
        // and the OS should clean up the direct processes
    }
}

/// Create a process configuration for a child process
fn create_child_process_config(index: usize, _nested: bool) -> process_manager::ProcessConfig {
    #[cfg(windows)]
    {
        process_manager::ProcessConfig::new("ping").args(["127.0.0.1", "-n", "3600"])
    }

    #[cfg(unix)]
    {
        process_manager::ProcessConfig::new("sleep").args(["3600"])
    }
}

/// Create a process configuration for a nested process
fn create_nested_process_config(_parent_index: usize) -> process_manager::ProcessConfig {
    #[cfg(windows)]
    {
        process_manager::ProcessConfig::new("ping").args(["127.0.0.1", "-n", "1800"])
    }

    #[cfg(unix)]
    {
        process_manager::ProcessConfig::new("sleep").args(["1800"])
    }
}

/// Spawn a child process directly (bypassing ProcessManager stub)
fn spawn_direct_child_process(
    _index: usize,
    _nested: bool,
) -> std::io::Result<std::process::Child> {
    #[cfg(windows)]
    {
        Command::new("ping")
            .args(["127.0.0.1", "-n", "3600"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    }

    #[cfg(unix)]
    {
        Command::new("sleep")
            .arg("3600")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    }
}

/// Spawn a grandchild process directly (for nested testing)
fn spawn_direct_grandchild_process(_parent_index: usize) -> std::io::Result<std::process::Child> {
    #[cfg(windows)]
    {
        Command::new("ping")
            .args(["127.0.0.1", "-n", "1800"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    }

    #[cfg(unix)]
    {
        Command::new("sleep")
            .arg("1800")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    }
}
