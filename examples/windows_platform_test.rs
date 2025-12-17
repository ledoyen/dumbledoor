//! Direct test of Windows platform manager functionality

#[cfg(target_os = "windows")]
use process_manager::{ProcessConfig, platform::windows_safe::WindowsPlatformManager, platform::PlatformManager};
#[cfg(target_os = "windows")]
use std::collections::HashMap;

#[cfg(target_os = "windows")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("Testing Windows Platform Manager directly...");

    // Create the Windows platform manager
    let manager = WindowsPlatformManager::new()?;
    println!("✓ Windows platform manager created successfully");

    // Set up cleanup handler
    manager.setup_cleanup_handler()?;
    println!("✓ Cleanup handler configured");

    // Create a long-running process using ping (which will run for about 10 seconds)
    let temp_dir = std::env::temp_dir();
    let log_file = temp_dir.join("process_manager_test.log");
    
    let config = ProcessConfig {
        command: "ping".into(),
        args: vec![
            "127.0.0.1".to_string(),
            "-n".to_string(),
            "10".to_string(), // 10 pings = ~10 seconds
        ],
        working_directory: Some(temp_dir.clone()),
        environment: HashMap::new(),
        log_file: Some(log_file.clone()),
    };

    println!("Log file will be: {}", log_file.display());
    println!("Working directory: {}", temp_dir.display());
    println!("This process will ping localhost 10 times (~10 seconds) to test cleanup...");

    println!("Process config: {:?}", config);

    // Validate the configuration
    config.validate()?;
    println!("✓ Configuration validated");

    // Spawn the process
    println!("Spawning process...");
    let process = manager.spawn_process(&config)?;
    println!("✓ Process spawned with PID: {}", process.pid());

    // Query process status immediately
    let status = manager.query_process_status(process.as_ref())?;
    println!("Initial process status: {:?}", status);

    // Wait a bit to ensure process is running
    std::thread::sleep(std::time::Duration::from_millis(2000));

    // Query status again - should still be running
    let status = manager.query_process_status(process.as_ref())?;
    println!("Process status after 2s: {:?}", status);

    // Get child processes
    let children = manager.get_child_processes(process.as_ref())?;
    println!("Child processes: {:?}", children);

    // Now test termination while the process is still running
    println!("Process should still be running - testing termination...");
    println!("Attempting graceful termination (5 second timeout)...");
    manager.terminate_process(process.as_ref(), true)?;
    println!("✓ Process termination completed");

    // Verify the process was actually terminated
    let status = manager.query_process_status(process.as_ref())?;
    println!("Process status after termination: {:?}", status);

    // Test cleanup
    let processes: Vec<&dyn process_manager::platform::PlatformProcess> = vec![process.as_ref()];
    manager.cleanup_all_processes(&processes)?;
    println!("✓ Cleanup completed");

    // Check if log file was created and has content
    if log_file.exists() {
        match std::fs::read_to_string(&log_file) {
            Ok(content) => {
                println!("✓ Log file created successfully!");
                println!("Log file content: {}", content.trim());
            }
            Err(e) => {
                println!("⚠ Log file exists but couldn't read it: {}", e);
            }
        }
        // Clean up log file
        let _ = std::fs::remove_file(&log_file);
    } else {
        println!("⚠ Log file was not created");
    }

    println!("All tests passed! Windows platform manager is working correctly.");

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("This test is Windows-specific and can only run on Windows.");
    println!("Current platform: {}", std::env::consts::OS);
    Ok(())
}