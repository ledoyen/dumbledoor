//! Standalone reaper process for zombie cleanup
//!
//! This binary runs as a separate process that survives the death of the
//! ProcessManager parent process and cleans up any registered child processes.

use process_manager::reaper::ProcessReaper;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    if args.len() >= 3 && args[1] == "--reaper-mode" {
        let channel_path = &args[2];

        tracing::info!(
            "Starting kill-9 proof reaper process with channel: {}",
            channel_path
        );

        let mut reaper = ProcessReaper::new();
        if let Err(e) = reaper.initialize(channel_path) {
            tracing::error!("Failed to initialize reaper: {}", e);
            return Err(e.into());
        }

        // Run the reaper main loop (includes kill-9 proof parent monitoring)
        if let Err(e) = reaper.run() {
            tracing::error!("Reaper run failed: {}", e);
            return Err(e.into());
        }

        tracing::info!("Kill-9 proof reaper process shutting down");
        Ok(())
    } else {
        eprintln!("Usage:");
        eprintln!("  {} --reaper-mode <channel_path>", args[0]);
        std::process::exit(1);
    }
}
