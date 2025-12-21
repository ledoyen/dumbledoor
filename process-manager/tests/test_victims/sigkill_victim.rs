//! Victim process for SIGKILL cleanup testing
//!
//! This executable is used by the sigkill_cleanup_test to verify that
//! child processes are properly cleaned up when the ProcessManager
//! host process is forcefully terminated.
//!
//! Usage: sigkill_victim <pid_file> <ready_file> <num_children> [--nested]
//!
//! The victim process:
//! 1. Creates a ProcessManager instance
//! 2. Spawns the specified number of long-running child processes via ProcessManager
//! 3. Writes all PIDs to the pid_file
//! 4. Creates the ready_file to signal the orchestrator
//! 5. Waits indefinitely (until killed by orchestrator)

use process_manager::ProcessManager;
use std::env;
use std::fs;
use std::path::PathBuf;
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

    // Create our own process group so we can be killed as a group
    #[cfg(unix)]
    {
        unsafe {
            let pid = libc::getpid();
            if libc::setpgid(pid, pid) == -1 {
                eprintln!("Warning: Failed to create process group");
            } else {
                println!("Created process group {}", pid);
            }
        }
    }

    #[cfg(windows)]
    {
        // On Windows, process groups are handled differently via Job Objects
        // The ProcessManager will handle this automatically
        println!("Windows process - process group handling via Job Objects");
    }

    // Create ProcessManager and use it to spawn managed processes
    let manager = ProcessManager::new().expect("Failed to create ProcessManager");

    let mut all_pids: Vec<u32> = Vec::new();
    let mut process_handles = Vec::new();

    // Use ProcessManager to spawn processes (this will test the cleanup integration)
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
                std::process::exit(1);
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
                Err(e) => {
                    eprintln!("Failed to start nested managed process: {}", e);
                    std::process::exit(1);
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
    println!("Managing {} ProcessManager handles", process_handles.len());

    loop {
        thread::sleep(Duration::from_secs(1));

        // Keep the ProcessManager and process handles alive
        // When this process is killed, the ProcessManager should clean up the managed processes
        // via platform-specific mechanisms (process groups, job objects, etc.)
    }
}

/// Create a process configuration for a child process
fn create_child_process_config(_index: usize, _nested: bool) -> process_manager::ProcessConfig {
    #[cfg(windows)]
    {
        process_manager::ProcessConfig::new("ping").args(["127.0.0.1", "-n", "3600"])
    }

    #[cfg(unix)]
    {
        process_manager::ProcessConfig::new("/bin/sleep").args(["3600"])
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
        process_manager::ProcessConfig::new("/bin/sleep").args(["1800"])
    }
}
