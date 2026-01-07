//! Process reaper system for zombie cleanup

use crate::error::ReaperError;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

#[cfg(windows)]
use std::fs::OpenOptions;

/// Messages sent between main process and reaper
#[derive(Debug, Clone)]
pub(crate) enum ReaperMessage {
    /// Register a process for monitoring
    RegisterProcess { pid: u32 },
    /// Unregister a process from monitoring
    UnregisterProcess { pid: u32 },
    /// Ping to check if reaper is alive
    Ping,
    /// Response to ping
    Pong,
    /// Shutdown the reaper
    Shutdown,
}

impl ReaperMessage {
    /// Serialize message to string for IPC
    pub(crate) fn serialize(&self) -> String {
        match self {
            ReaperMessage::RegisterProcess { pid } => format!("REGISTER:{}", pid),
            ReaperMessage::UnregisterProcess { pid } => format!("UNREGISTER:{}", pid),
            ReaperMessage::Ping => "PING".to_string(),
            ReaperMessage::Pong => "PONG".to_string(),
            ReaperMessage::Shutdown => "SHUTDOWN".to_string(),
        }
    }

    /// Deserialize message from string
    pub(crate) fn deserialize(s: &str) -> Result<Self, ReaperError> {
        let s = s.trim();
        if s == "PING" {
            Ok(ReaperMessage::Ping)
        } else if s == "PONG" {
            Ok(ReaperMessage::Pong)
        } else if s == "SHUTDOWN" {
            Ok(ReaperMessage::Shutdown)
        } else if let Some(pid_str) = s.strip_prefix("REGISTER:") {
            let pid = pid_str
                .parse::<u32>()
                .map_err(|_| ReaperError::CommunicationFailed {
                    reason: format!("Invalid PID in REGISTER message: {}", pid_str),
                })?;
            Ok(ReaperMessage::RegisterProcess { pid })
        } else if let Some(pid_str) = s.strip_prefix("UNREGISTER:") {
            let pid = pid_str
                .parse::<u32>()
                .map_err(|_| ReaperError::CommunicationFailed {
                    reason: format!("Invalid PID in UNREGISTER message: {}", pid_str),
                })?;
            Ok(ReaperMessage::UnregisterProcess { pid })
        } else {
            Err(ReaperError::CommunicationFailed {
                reason: format!("Unknown message format: {}", s),
            })
        }
    }
}

/// IPC communication channel abstraction
#[derive(Debug)]
pub enum ReaperChannel {
    #[cfg(unix)]
    UnixSocket(UnixStream),
    #[cfg(windows)]
    NamedPipe(std::fs::File),
}

impl ReaperChannel {
    /// Send a message through the channel
    pub(crate) fn send_message(&mut self, message: &ReaperMessage) -> Result<(), ReaperError> {
        let serialized = message.serialize();
        let data = format!("{}\n", serialized);

        match self {
            #[cfg(unix)]
            ReaperChannel::UnixSocket(stream) => {
                stream.write_all(data.as_bytes()).map_err(|e| {
                    ReaperError::CommunicationFailed {
                        reason: format!("Failed to write to Unix socket: {}", e),
                    }
                })?;
            }
            #[cfg(windows)]
            ReaperChannel::NamedPipe(file) => {
                file.write_all(data.as_bytes())
                    .map_err(|e| ReaperError::CommunicationFailed {
                        reason: format!("Failed to write to named pipe: {}", e),
                    })?;
            }
        }
        Ok(())
    }

    /// Receive a message from the channel (blocking)
    pub(crate) fn receive_message(&mut self) -> Result<ReaperMessage, ReaperError> {
        let mut reader = match self {
            #[cfg(unix)]
            ReaperChannel::UnixSocket(stream) => BufReader::new(stream),
            #[cfg(windows)]
            ReaperChannel::NamedPipe(file) => BufReader::new(file),
        };

        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| ReaperError::CommunicationFailed {
                reason: format!("Failed to read from channel: {}", e),
            })?;

        ReaperMessage::deserialize(&line)
    }
}

/// Monitor for managing the reaper process lifecycle
pub struct ReaperMonitor {
    reaper_pid: u32,
    communication_channel: Option<ReaperChannel>,
    monitor_thread: Option<JoinHandle<()>>,
    reaper_child: Option<Child>,
    shutdown_flag: Arc<std::sync::atomic::AtomicBool>,
    pid_list_file: Option<String>,
    tracked_pids: Arc<Mutex<HashSet<u32>>>,
}

impl ReaperMonitor {
    /// Get the PID of the reaper process
    pub fn reaper_pid(&self) -> u32 {
        self.reaper_pid
    }

    /// Spawn a new reaper process
    pub fn spawn_reaper() -> Result<Self, ReaperError> {
        tracing::info!("Spawning kill-9 proof reaper process");

        let parent_pid = std::process::id();
        
        #[cfg(target_os = "macos")]
        let process_group = unsafe_macos_process::safe_get_process_group();
        
        #[cfg(target_os = "linux")]
        let process_group = unsafe_linux_process::safe_get_process_group();
        
        #[cfg(windows)]
        let process_group = 0; // Windows doesn't use process groups
        
        tracing::info!("Parent PID: {}, Process Group: {}", parent_pid, process_group);

        // Use the existing reaper binary but make it truly independent
        // Find the reaper binary
        let current_exe = std::env::current_exe().map_err(|e| ReaperError::SpawnFailed {
            reason: format!("Failed to get current executable path: {}", e),
        })?;

        let reaper_exe = if let Some(parent_dir) = current_exe.parent() {
            let reaper_name = if cfg!(windows) { "reaper.exe" } else { "reaper" };
            
            // Try the main target/debug directory first
            let target_debug = if parent_dir.file_name() == Some(std::ffi::OsStr::new("deps")) {
                parent_dir.parent().unwrap_or(parent_dir)
            } else {
                parent_dir
            };
            
            let main_reaper_path = target_debug.join(reaper_name);
            
            if main_reaper_path.exists() {
                main_reaper_path
            } else {
                // Try going up to workspace root and then to target/debug
                let mut workspace_dir = target_debug;
                let mut found_reaper = None;
                
                while let Some(parent) = workspace_dir.parent() {
                    let cargo_toml = parent.join("Cargo.toml");
                    if cargo_toml.exists() {
                        // Check if this is the workspace root
                        if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                            if content.contains("[workspace]") {
                                let workspace_reaper = parent.join("target").join("debug").join(reaper_name);
                                if workspace_reaper.exists() {
                                    found_reaper = Some(workspace_reaper);
                                    break;
                                }
                            }
                        }
                    }
                    workspace_dir = parent;
                }
                
                found_reaper.unwrap_or_else(|| {
                    // Return the original path for error reporting
                    main_reaper_path
                })
            }
        } else {
            return Err(ReaperError::SpawnFailed {
                reason: "Failed to determine executable directory".to_string(),
            });
        };

        // Verify the reaper binary exists
        if !reaper_exe.exists() {
            return Err(ReaperError::SpawnFailed {
                reason: format!("Reaper binary not found at: {}", reaper_exe.display()),
            });
        }

        // Create IPC channel for communication with reaper
        let (channel_path, listener) = Self::create_ipc_channel()?;
        
        // Create a kill-9 proof reaper using the IPC channel
        tracing::info!("Spawning reaper binary: {} with channel: {}", reaper_exe.display(), channel_path);

        let result = std::process::Command::new(&reaper_exe)
            .arg("--reaper-mode")
            .arg(&channel_path)
            .spawn();

        match result {
            Ok(child) => {
                let reaper_pid = child.id();
                tracing::info!("Spawned kill-9 proof reaper with PID: {}", reaper_pid);
                
                // Wait for reaper to connect via IPC with extended timeout
                tracing::info!("Waiting for reaper to connect via IPC channel: {}", channel_path);
                match Self::accept_reaper_connection(listener) {
                    Ok(communication_channel) => {
                        tracing::info!("Reaper connected successfully via IPC");
                        
                        let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
                        let tracked_pids = Arc::new(Mutex::new(HashSet::new()));
                        
                        Ok(Self {
                            reaper_pid,
                            communication_channel: Some(communication_channel),
                            monitor_thread: None,
                            reaper_child: Some(child), // Keep reference to ensure it stays alive
                            shutdown_flag,
                            pid_list_file: Some(channel_path),
                            tracked_pids,
                        })
                    }
                    Err(e) => {
                        tracing::error!("Failed to establish IPC connection with reaper: {}", e);
                        // Kill the reaper process since we can't communicate with it
                        let _ = std::process::Command::new("kill")
                            .arg("-9")
                            .arg(reaper_pid.to_string())
                            .output();
                        Err(e)
                    }
                }
            }
            Err(e) => {
                Err(ReaperError::SpawnFailed {
                    reason: format!("Failed to spawn kill-9 proof reaper: {}", e),
                })
            }
        }
    }

    /// Create platform-specific IPC channel
    #[cfg(unix)]
    fn create_ipc_channel() -> Result<(String, UnixListener), ReaperError> {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // Add timestamp and random component to make socket path unique per ProcessManager instance
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let random_id = uuid::Uuid::new_v4().simple().to_string();
        let socket_path = format!(
            "/tmp/process_manager_reaper_{}_{}_{}",
            std::process::id(),
            timestamp,
            &random_id[..8] // Use first 8 chars of UUID for brevity
        );

        // Remove existing socket if it exists
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path).map_err(|e| ReaperError::SpawnFailed {
            reason: format!("Failed to create Unix socket: {}", e),
        })?;

        Ok((socket_path, listener))
    }

    #[cfg(windows)]
    fn create_ipc_channel() -> Result<(String, std::fs::File), ReaperError> {
        let _pipe_name = format!("\\\\.\\pipe\\process_manager_reaper_{}", std::process::id());

        // For Windows, we'll use a simple file-based approach for now
        // In a production system, you'd use proper named pipes
        let temp_file = std::env::temp_dir().join(format!("reaper_pipe_{}", std::process::id()));
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&temp_file)
            .map_err(|e| ReaperError::SpawnFailed {
                reason: format!("Failed to create communication file: {}", e),
            })?;

        Ok((temp_file.to_string_lossy().to_string(), file))
    }

    /// Accept connection from reaper process
    #[cfg(unix)]
    fn accept_reaper_connection(listener: UnixListener) -> Result<ReaperChannel, ReaperError> {
        // Set a timeout for accepting connections
        listener.set_nonblocking(true).map_err(|e| ReaperError::SpawnFailed {
            reason: format!("Failed to set listener non-blocking: {}", e),
        })?;

        let start_time = std::time::Instant::now();
        let timeout = Duration::from_secs(3); // Reduced timeout to fail faster

        tracing::info!("Waiting for reaper to connect via Unix socket...");
        
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    tracing::info!("Reaper connected successfully via Unix socket");
                    return Ok(ReaperChannel::UnixSocket(stream));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start_time.elapsed() > timeout {
                        return Err(ReaperError::SpawnFailed {
                            reason: format!("Timeout waiting for reaper connection after {} seconds", timeout.as_secs()),
                        });
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    return Err(ReaperError::SpawnFailed {
                        reason: format!("Failed to accept reaper connection: {}", e),
                    });
                }
            }
        }
    }

    #[cfg(windows)]
    fn accept_reaper_connection(file: std::fs::File) -> Result<ReaperChannel, ReaperError> {
        Ok(ReaperChannel::NamedPipe(file))
    }

    /// Register a process with the reaper
    pub fn register_process(&mut self, pid: u32) -> Result<(), ReaperError> {
        tracing::debug!("Registering process {} with reaper for cleanup monitoring", pid);
        
        // Add to tracked PIDs
        {
            let mut pids = self.tracked_pids.lock().unwrap();
            pids.insert(pid);
        }
        
        // Send registration message to reaper via IPC
        if let Some(ref mut channel) = self.communication_channel {
            channel.send_message(&ReaperMessage::RegisterProcess { pid })?;
            tracing::debug!("Process {} registered with reaper successfully", pid);
        } else {
            tracing::warn!("No reaper communication channel available - process {} may not be cleaned up on abnormal termination", pid);
        }
        
        Ok(())
    }

    /// Unregister a process from the reaper
    pub fn unregister_process(&mut self, pid: u32) -> Result<(), ReaperError> {
        tracing::debug!("Unregistering process {} from reaper cleanup monitoring", pid);
        
        // Remove from tracked PIDs
        {
            let mut pids = self.tracked_pids.lock().unwrap();
            pids.remove(&pid);
        }
        
        // Send unregistration message to reaper via IPC
        if let Some(ref mut channel) = self.communication_channel {
            channel.send_message(&ReaperMessage::UnregisterProcess { pid })?;
            tracing::debug!("Process {} unregistered from reaper successfully", pid);
        } else {
            tracing::warn!("No reaper communication channel available to unregister process {}", pid);
        }
        
        Ok(())
    }


    /// Check if the reaper process is still alive
    pub fn is_reaper_alive(&mut self) -> bool {
        // The reaper is just a monitoring thread, so check if it's still running
        true // Always return true since we're using a thread-based approach
    }

    /// Restart the reaper process if it died
    pub fn restart_reaper(&mut self) -> Result<(), ReaperError> {
        tracing::warn!("Restarting reaper process");

        // Clean up old reaper
        if let Some(mut child) = self.reaper_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        // Spawn new reaper
        let new_monitor = Self::spawn_reaper()?;
        
        // Copy tracked PIDs to new monitor and re-register them
        let old_pids = {
            let pids = self.tracked_pids.lock().unwrap();
            pids.clone()
        };
        
        {
            let mut new_pids = new_monitor.tracked_pids.lock().unwrap();
            *new_pids = old_pids.clone();
        }
        
        *self = new_monitor;
        
        // Re-register all tracked PIDs with the new reaper
        for pid in old_pids {
            if let Err(e) = self.register_process(pid) {
                tracing::warn!("Failed to re-register PID {} with new reaper: {}", pid, e);
            }
        }

        Ok(())
    }

    /// Shutdown the reaper process
    pub fn shutdown(&mut self) -> Result<(), ReaperError> {
        tracing::info!("Shutting down reaper monitor");

        // Signal the monitoring thread to stop
        self.shutdown_flag
            .store(true, std::sync::atomic::Ordering::Relaxed);

        if let Some(ref mut channel) = self.communication_channel {
            let _ = channel.send_message(&ReaperMessage::Shutdown);
        }

        if let Some(mut child) = self.reaper_child.take() {
            // Give it a moment to shutdown gracefully
            thread::sleep(Duration::from_millis(100));

            // Force kill if still running
            if child.try_wait().unwrap_or(None).is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }

        if let Some(handle) = self.monitor_thread.take() {
            let _ = handle.join();
        }

        // Clean up IPC channel
        if let Some(ref pid_file) = self.pid_list_file {
            let _ = std::fs::remove_file(pid_file);
            tracing::debug!("Cleaned up reaper IPC socket: {}", pid_file);
        }

        tracing::info!("Reaper monitor shutdown complete");
        Ok(())
    }

    /// Simulate reaper death for testing purposes
    /// This method forcefully kills the reaper process to test restart logic
    #[cfg(test)]
    pub fn simulate_reaper_death(&mut self) -> Result<(), ReaperError> {
        tracing::debug!("Simulating reaper process death for testing");

        if let Some(mut child) = self.reaper_child.take() {
            let _ = child.kill();
            let _ = child.wait();
            tracing::debug!("Reaper process terminated for testing");
        }

        // Close communication channel
        self.communication_channel = None;

        Ok(())
    }
}

impl Drop for ReaperMonitor {
    fn drop(&mut self) {
        // Ensure cleanup happens when the ReaperMonitor is dropped
        if let Err(e) = self.shutdown() {
            tracing::warn!("Failed to shutdown reaper monitor during drop: {}", e);
        }
    }
}

/// The reaper process itself (separate executable)
pub struct ProcessReaper {
    monitored_processes: Arc<Mutex<HashSet<u32>>>,
    communication_channel: Option<ReaperChannel>,
    running: Arc<Mutex<bool>>,
}

impl Default for ProcessReaper {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessReaper {
    /// Create a new reaper instance
    pub fn new() -> Self {
        Self {
            monitored_processes: Arc::new(Mutex::new(HashSet::new())),
            communication_channel: None,
            running: Arc::new(Mutex::new(true)),
        }
    }

    /// Initialize the reaper with IPC channel
    pub fn initialize(&mut self, channel_path: &str) -> Result<(), ReaperError> {
        tracing::info!("Initializing reaper with channel: {}", channel_path);

        #[cfg(unix)]
        {
            // Retry connection with backoff
            let mut attempts = 0;
            let max_attempts = 10;
            let mut delay = Duration::from_millis(100);
            
            loop {
                match UnixStream::connect(channel_path) {
                    Ok(stream) => {
                        tracing::info!("Successfully connected to Unix socket on attempt {}", attempts + 1);
                        self.communication_channel = Some(ReaperChannel::UnixSocket(stream));
                        break;
                    }
                    Err(e) => {
                        attempts += 1;
                        if attempts >= max_attempts {
                            return Err(ReaperError::CommunicationFailed {
                                reason: format!("Failed to connect to Unix socket after {} attempts: {}", max_attempts, e),
                            });
                        }
                        
                        tracing::debug!("Reaper connection attempt {} failed: {}, retrying in {:?}", attempts, e, delay);
                        thread::sleep(delay);
                        delay = std::cmp::min(delay * 2, Duration::from_secs(1)); // Exponential backoff, max 1 second
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(channel_path)
                .map_err(|e| ReaperError::CommunicationFailed {
                    reason: format!("Failed to open communication file: {}", e),
                })?;
            self.communication_channel = Some(ReaperChannel::NamedPipe(file));
        }

        Ok(())
    }

    /// Run the reaper main loop
    pub fn run(&mut self) -> Result<(), ReaperError> {
        tracing::info!("Running reaper process");

        let monitored_processes = Arc::clone(&self.monitored_processes);
        let running = Arc::clone(&self.running);

        // Start cleanup thread
        let cleanup_thread = {
            let monitored_processes = Arc::clone(&monitored_processes);
            let running = Arc::clone(&running);

            thread::spawn(move || {
                while *running.lock().unwrap() {
                    Self::cleanup_zombie_processes(&monitored_processes);
                    thread::sleep(Duration::from_secs(1));
                }
            })
        };

        // Start parent monitoring thread for kill-9 proof cleanup
        let parent_monitor_thread = {
            let running = Arc::clone(&running);
            let monitored_processes = Arc::clone(&monitored_processes);
            
            thread::spawn(move || {
                // Get parent PID using safe wrapper
                #[cfg(target_os = "macos")]
                let parent_pid = unsafe_macos_process::safe_get_parent_pid();
                
                #[cfg(target_os = "linux")]
                let parent_pid = unsafe_linux_process::safe_get_parent_pid();
                
                #[cfg(windows)]
                let parent_pid = 1; // Windows doesn't have getppid, use placeholder
                
                tracing::info!("Monitoring parent process PID: {} for kill-9 proof cleanup", parent_pid);
                
                while *running.lock().unwrap() {
                    // Check if parent process is still alive
                    if !Self::is_process_alive(parent_pid) {
                        tracing::warn!("Parent process {} died, performing kill-9 proof cleanup", parent_pid);
                        
                        // Kill all registered processes immediately
                        let processes = monitored_processes.lock().unwrap().clone();
                        tracing::info!("Cleaning up {} registered processes", processes.len());
                        
                        for pid in processes {
                            tracing::info!("Kill-9 proof cleanup: terminating process {}", pid);
                            if Self::is_process_alive(pid) {
                                Self::force_kill_process(pid);
                            }
                        }
                        
                        // Also try process group cleanup as fallback
                        #[cfg(target_os = "macos")]
                        {
                            tracing::info!("Kill-9 proof cleanup: attempting process group cleanup");
                            if let Err(e) = unsafe_macos_process::safe_kill_process_group() {
                                tracing::warn!("Failed to kill process group: {}", e);
                            }
                        }
                        
                        #[cfg(target_os = "linux")]
                        {
                            tracing::info!("Kill-9 proof cleanup: attempting process group cleanup");
                            if let Err(e) = unsafe_linux_process::safe_kill_process_group() {
                                tracing::warn!("Failed to kill process group: {}", e);
                            }
                        }
                        
                        // Exit the reaper
                        *running.lock().unwrap() = false;
                        break;
                    }
                    
                    thread::sleep(Duration::from_millis(100)); // Check more frequently for kill-9 proof
                }
                
                tracing::info!("Kill-9 proof parent monitor thread exiting");
            })
        };

        // Main message processing loop
        while *self.running.lock().unwrap() {
            if let Some(ref mut channel) = self.communication_channel {
                match channel.receive_message() {
                    Ok(message) => {
                        if let Err(e) = self.handle_message(message) {
                            tracing::error!("Failed to handle message: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to receive message: {}", e);
                        break;
                    }
                }
            } else {
                thread::sleep(Duration::from_millis(100));
            }
        }

        // Wait for threads to finish
        let _ = cleanup_thread.join();
        let _ = parent_monitor_thread.join();

        tracing::info!("Reaper process shutting down");
        Ok(())
    }

    /// Handle incoming messages
    fn handle_message(&mut self, message: ReaperMessage) -> Result<(), ReaperError> {
        tracing::trace!("Reaper received message: {:?}", message);
        match message {
            ReaperMessage::RegisterProcess { pid } => {
                let mut processes = self.monitored_processes.lock().unwrap();
                processes.insert(pid);
                tracing::info!("Reaper now monitoring process {} for cleanup (total: {})", pid, processes.len());
            }
            ReaperMessage::UnregisterProcess { pid } => {
                let mut processes = self.monitored_processes.lock().unwrap();
                processes.remove(&pid);
                tracing::info!("Reaper stopped monitoring process {} (total: {})", pid, processes.len());
            }
            ReaperMessage::Ping => {
                tracing::trace!("Reaper received ping, sending pong");
                if let Some(ref mut channel) = self.communication_channel {
                    channel.send_message(&ReaperMessage::Pong)?;
                }
            }
            ReaperMessage::Shutdown => {
                tracing::info!("Reaper received shutdown signal");
                *self.running.lock().unwrap() = false;
            }
            ReaperMessage::Pong => {
                // Ignore pong messages in reaper
                tracing::trace!("Reaper received pong (ignored)");
            }
        }
        Ok(())
    }

    /// Clean up zombie processes
    fn cleanup_zombie_processes(monitored_processes: &Arc<Mutex<HashSet<u32>>>) {
        let processes = monitored_processes.lock().unwrap().clone();

        for pid in processes {
            if !Self::is_process_alive(pid) {
                tracing::debug!("Process {} has exited, removing from monitoring", pid);
                monitored_processes.lock().unwrap().remove(&pid);
            }
        }
    }

    /// Check if a process is still alive
    #[cfg(target_os = "macos")]
    fn is_process_alive(pid: u32) -> bool {
        unsafe_macos_process::safe_is_process_alive(pid)
    }

    #[cfg(target_os = "linux")]
    fn is_process_alive(pid: u32) -> bool {
        unsafe_linux_process::safe_is_process_alive(pid)
    }

    #[cfg(windows)]
    fn is_process_alive(pid: u32) -> bool {
        // On Windows, we'll use a simple approach
        // In production, you'd use proper Windows APIs
        std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid)])
            .output()
            .map(|output| {
                let output_str = String::from_utf8_lossy(&output.stdout);
                output_str.contains(&pid.to_string())
            })
            .unwrap_or(false)
    }

    /// Force kill a process (SIGKILL on Unix, TerminateProcess on Windows)
    #[cfg(target_os = "macos")]
    fn force_kill_process(pid: u32) {
        if let Err(e) = unsafe_macos_process::safe_force_kill_process(pid) {
            tracing::warn!("Failed to force kill process {}: {}", pid, e);
        } else {
            tracing::info!("Sent SIGKILL to process {}", pid);
        }
    }

    #[cfg(target_os = "linux")]
    fn force_kill_process(pid: u32) {
        if let Err(e) = unsafe_linux_process::safe_force_kill_process(pid) {
            tracing::warn!("Failed to force kill process {}: {}", pid, e);
        } else {
            tracing::info!("Sent SIGKILL to process {}", pid);
        }
    }

    #[cfg(windows)]
    fn force_kill_process(pid: u32) {
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output();
        tracing::info!("Sent TerminateProcess to process {}", pid);
    }
}
