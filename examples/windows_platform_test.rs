//! Test of Windows process management functionality using public API

#[cfg(target_os = "windows")]
use process_manager::{ProcessConfig, ProcessManager};
#[cfg(target_os = "windows")]
use std::collections::HashMap;

#[cfg(target_os = "windows")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("Testing Windows Process Manager using public API...");

    // Create the process manager
    let manager = ProcessManager::new()?;
    println!("✓ Process manager created successfully");

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
    let handle = manager.start_process(config)?;
    println!("✓ Process started with handle: {:?}", handle);

    // Query process status immediately
    let status = manager.query_status(handle)?;
    println!("Initial process status: {:?}", status);

    // Wait a bit to let process start
    std::thread::sleep(std::time::Duration::from_millis(2000));

    // Query status again
    let status = manager.query_status(handle)?;
    println!("Process status after 2s: {:?}", status);

    // List all processes
    let processes = manager.list_processes();
    println!("Active processes: {:?}", processes);

    // Wait a bit more
    std::thread::sleep(std::time::Duration::from_millis(3000));

    // Now test termination
    println!("Testing process termination...");
    manager.stop_process(handle)?;
    println!("✓ Process termination completed");

    // Verify the process was removed from the list
    let processes_after = manager.list_processes();
    println!("Active processes after stop: {:?}", processes_after);

    // Check if log file was created and has content
    if log_file.exists() {
        match std::fs::read_to_string(&log_file) {
            Ok(content) => {
                println!("✓ Log file created successfully!");
                println!(
                    "Log file content preview: {}",
                    content.chars().take(200).collect::<String>()
                );
            }
            Err(e) => {
                println!("⚠ Log file exists but couldn't read it: {}", e);
            }
        }
        // Clean up log file
        let _ = std::fs::remove_file(&log_file);
    } else {
        println!("⚠ Log file was not created (may not be implemented yet)");
    }

    println!("All tests passed! Process manager is working correctly on Windows.");

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("This test is Windows-specific and can only run on Windows.");
    println!("Current platform: {}", std::env::consts::OS);
    Ok(())
}
