//! Process reaper binary - separate executable for zombie cleanup
//!
//! This binary runs as a separate process to monitor and clean up zombie processes
//! when the main process manager cannot use user namespaces or other automatic cleanup.

use process_manager::reaper::ProcessReaper;
use std::env;
use tracing_subscriber;

fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();

    // Check if we're being run in reaper mode
    if args.len() >= 3 && args[1] == "--reaper-mode" {
        let channel_path = &args[2];

        tracing::info!("Starting process reaper with channel: {}", channel_path);

        let mut reaper = ProcessReaper::new();

        if let Err(e) = reaper.initialize(channel_path) {
            tracing::error!("Failed to initialize reaper: {}", e);
            std::process::exit(1);
        }

        if let Err(e) = reaper.run() {
            tracing::error!("Reaper process failed: {}", e);
            std::process::exit(1);
        }
    } else {
        eprintln!("Usage: {} --reaper-mode <channel_path>", args[0]);
        std::process::exit(1);
    }
}
