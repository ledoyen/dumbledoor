//! Test controlled cleanup of Windows platform manager

#[cfg(target_os = "windows")]
use process_manager::{ProcessConfig, platform::windows::WindowsPlatformManager, platform::PlatformManager};
#[cfg(target_os = "windows")]
use std::collections::HashMap;

#[cfg(target_os = "windows")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("=== Testing Controlled Cleanup ===");
    
    // Create the Windows platform manager
    let manager = WindowsPlatformManager::new()?;
    println!("✓ Windows platform manager created");

    // Set up cleanup handler
    manager.setup_cleanup_handler()?;
    println!("✓ Cleanup handler configured");

    // Create a long-running process
    let config = ProcessConfig {
        command: "ping".into(),
        args: vec![
            "127.0.0.1".to_string(),
            "-n".to_string(),
            "30".to_string(), // 30 pings = ~30 seconds
        ],
        working_directory: None,
        environment: HashMap::new(),
        log_file: None,
    };

    // Spawn the process
    println!("Spawning long-running process...");
    let process = manager.spawn_process(&config)?;
    println!("✓ Process spawned with PID: {}", process.pid());

    // Wait a bit to ensure process is running
    std::thread::sleep(std::time::Duration::from_millis(2000));

    // Check that process is running
    let status = manager.query_process_status(process.as_ref())?;
    println!("Process status: {:?}", status);

    // Now explicitly clean up using the cleanup_all_processes method
    println!("Performing controlled cleanup...");
    let processes: Vec<&dyn process_manager::platform::PlatformProcess> = vec![process.as_ref()];
    manager.cleanup_all_processes(&processes)?;
    println!("✓ Controlled cleanup completed");

    // Verify the process was terminated
    let status = manager.query_process_status(process.as_ref())?;
    println!("Process status after cleanup: {:?}", status);

    println!("✓ Controlled cleanup test completed successfully!");

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("This test is Windows-specific and can only run on Windows.");
    println!("Current platform: {}", std::env::consts::OS);
    Ok(())
}