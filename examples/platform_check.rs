//! Platform check example to demonstrate conditional compilation

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Platform Check Example");
    println!("Current OS: {}", std::env::consts::OS);
    println!("Current architecture: {}", std::env::consts::ARCH);
    
    #[cfg(target_os = "windows")]
    {
        println!("✓ Running on Windows - Windows-specific tests are available");
        println!("  - windows_platform_test");
        println!("  - cleanup_test");
        println!("  - controlled_cleanup_test");
    }
    
    #[cfg(target_os = "linux")]
    {
        println!("✓ Running on Linux - Linux-specific tests would be available");
        println!("  (Linux platform manager not yet implemented)");
    }
    
    #[cfg(target_os = "macos")]
    {
        println!("✓ Running on macOS - macOS-specific tests would be available");
        println!("  (macOS platform manager not yet implemented)");
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        println!("⚠ Running on unsupported platform");
        println!("  Supported platforms: Windows, Linux, macOS");
    }

    Ok(())
}