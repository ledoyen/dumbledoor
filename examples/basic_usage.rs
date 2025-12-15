//! Basic usage example for the process manager

use process_manager::{ProcessConfig, ProcessManager};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create a process manager
    let manager = ProcessManager::new()?;

    // Create a process configuration
    let config = ProcessConfig::new("/bin/echo")
        .args(["Hello", "World"])
        .env("TEST_VAR", "test_value")
        .working_directory("/tmp");

    // Start the process
    let handle = manager.start_process(config)?;
    println!("Started process with handle: {:?}", handle);

    // Query process status
    let status = manager.query_status(handle)?;
    println!("Process status: {:?}", status);

    // List all processes
    let processes = manager.list_processes();
    println!("Active processes: {:?}", processes);

    // Stop the process
    manager.stop_process(handle)?;
    println!("Process stopped");

    Ok(())
}
