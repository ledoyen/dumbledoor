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

    // Create ProcessManager (for future integration when implementation is complete)
    let _manager = ProcessManager::new().expect("Failed to create ProcessManager");

    let mut all_pids = Vec::new();
    let mut child_processes = Vec::new();

    // For now, spawn processes directly since ProcessManager is still a stub
    // In the future, this will use the ProcessManager API
    for i in 0..num_children {
        let child = spawn_direct_child_process(i, nested)
            .unwrap_or_else(|_| panic!("Failed to spawn child process {}", i));

        let pid = child.id();
        all_pids.push(pid);
        child_processes.push(child);

        println!("Started child process {} with PID: {}", i, pid);

        // If nested mode, spawn grandchildren
        if nested {
            if let Ok(grandchild) = spawn_direct_grandchild_process(i) {
                let grandchild_pid = grandchild.id();
                all_pids.push(grandchild_pid);
                child_processes.push(grandchild);
                println!(
                    "Started grandchild process {}.1 with PID: {}",
                    i, grandchild_pid
                );
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
    println!("Managing {} child processes", child_processes.len());

    loop {
        thread::sleep(Duration::from_secs(1));

        // Keep the child process handles alive
        // When this process is killed, the OS should clean up the children
        // (on Windows via Job Objects, on Unix via process groups/namespaces)
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
