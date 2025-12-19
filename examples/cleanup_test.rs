//! Test Windows platform manager cleanup functionality

#[cfg(target_os = "windows")]
use process_manager::{
    platform::windows_safe::WindowsPlatformManager, platform::PlatformManager, ProcessConfig,
};
#[cfg(target_os = "windows")]
use std::collections::HashMap;

#[cfg(target_os = "windows")]
fn spawn_long_running_process() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Testing Job Object Cleanup ===");

    // Create the Windows platform manager in a scope that will drop
    let manager = WindowsPlatformManager::new()?;
    println!("✓ Windows platform manager created");

    // Set up cleanup handler
    manager.setup_cleanup_handler()?;
    println!("✓ Cleanup handler configured");

    // Create a long-running process using ping
    let config = ProcessConfig {
        command: "ping".into(),
        args: vec![
            "127.0.0.1".to_string(),
            "-n".to_string(),
            "60".to_string(), // 60 pings = ~60 seconds
        ],
        working_directory: None,
        environment: HashMap::new(),
        log_file: None,
    };

    // Spawn multiple processes to test cleanup
    let mut processes = Vec::new();
    for i in 1..=3 {
        println!("Spawning process {}...", i);
        let process = manager.spawn_process(&config)?;
        println!("✓ Process {} spawned with PID: {}", i, process.pid());
        processes.push(process);
    }

    // Wait a bit to ensure processes are running
    std::thread::sleep(std::time::Duration::from_millis(2000));

    // Check that all processes are running
    for (i, process) in processes.iter().enumerate() {
        let status = manager.query_process_status(
            process.as_ref() as &dyn process_manager::platform::PlatformProcess
        )?;
        println!("Process {} status: {:?}", i + 1, status);
    }

    println!("All processes are running. Now the manager will drop and Job Object cleanup should kick in...");

    // Return the processes so they don't get dropped yet
    // But the manager will drop at the end of this function
    Ok(())
    // Manager drops here - Job Object should terminate all processes
}

#[cfg(target_os = "windows")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("Testing Windows Platform Manager Cleanup...");

    // Spawn processes in a function that will drop the manager
    spawn_long_running_process()?;

    println!("Manager has been dropped. Job Object should have terminated all processes.");
    println!("Waiting 3 seconds to let cleanup complete...");
    std::thread::sleep(std::time::Duration::from_millis(3000));

    println!("✓ Cleanup test completed!");
    println!("If you don't see any cmd.exe processes hanging around, the cleanup worked!");

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("This test is Windows-specific and can only run on Windows.");
    println!("Current platform: {}", std::env::consts::OS);
    Ok(())
}
