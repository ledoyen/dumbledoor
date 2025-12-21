//! Process reaper system for zombie cleanup

use crate::error::ReaperError;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

#[cfg(windows)]
use std::fs::OpenOptions;

/// Messages sent between main process and reaper
#[derive(Debug, Clone)]
pub enum ReaperMessage {
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
    pub fn serialize(&self) -> String {
        match self {
            ReaperMessage::RegisterProcess { pid } => format!("REGISTER:{}", pid),
            ReaperMessage::UnregisterProcess { pid } => format!("UNREGISTER:{}", pid),
            ReaperMessage::Ping => "PING".to_string(),
            ReaperMessage::Pong => "PONG".to_string(),
            ReaperMessage::Shutdown => "SHUTDOWN".to_string(),
        }
    }

    /// Deserialize message from string
    pub fn deserialize(s: &str) -> Result<Self, ReaperError> {
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
    pub fn send_message(&mut self, message: &ReaperMessage) -> Result<(), ReaperError> {
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
    pub fn receive_message(&mut self) -> Result<ReaperMessage, ReaperError> {
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
}

impl ReaperMonitor {
    /// Get the PID of the reaper process
    pub fn reaper_pid(&self) -> u32 {
        self.reaper_pid
    }

    /// Spawn a new reaper process
    pub fn spawn_reaper() -> Result<Self, ReaperError> {
        tracing::info!("Spawning reaper process");

        // Create IPC channel
        let (channel_path, listener) = Self::create_ipc_channel()?;

        // Spawn the reaper process
        let reaper_child =
            Command::new(
                std::env::current_exe().map_err(|e| ReaperError::SpawnFailed {
                    reason: format!("Failed to get current executable path: {}", e),
                })?,
            )
            .arg("--reaper-mode")
            .arg(&channel_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| ReaperError::SpawnFailed {
                reason: format!("Failed to spawn reaper process: {}", e),
            })?;

        let reaper_pid = reaper_child.id();
        tracing::info!("Spawned reaper process with PID: {}", reaper_pid);

        // Accept connection from reaper
        let communication_channel = Self::accept_reaper_connection(listener)?;

        // Start monitoring thread
        let monitor_thread = Some(thread::spawn(move || {
            // Monitor thread implementation would go here
            // For now, just log that monitoring started
            tracing::debug!("Reaper monitor thread started");
        }));

        Ok(Self {
            reaper_pid,
            communication_channel: Some(communication_channel),
            monitor_thread,
            reaper_child: Some(reaper_child),
        })
    }

    /// Create platform-specific IPC channel
    #[cfg(unix)]
    fn create_ipc_channel() -> Result<(String, UnixListener), ReaperError> {
        let socket_path = format!("/tmp/process_manager_reaper_{}", std::process::id());

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
        let (stream, _) = listener.accept().map_err(|e| ReaperError::SpawnFailed {
            reason: format!("Failed to accept reaper connection: {}", e),
        })?;
        Ok(ReaperChannel::UnixSocket(stream))
    }

    #[cfg(windows)]
    fn accept_reaper_connection(file: std::fs::File) -> Result<ReaperChannel, ReaperError> {
        Ok(ReaperChannel::NamedPipe(file))
    }

    /// Register a process with the reaper
    pub fn register_process(&mut self, pid: u32) -> Result<(), ReaperError> {
        if let Some(ref mut channel) = self.communication_channel {
            let message = ReaperMessage::RegisterProcess { pid };
            channel.send_message(&message)?;
            tracing::debug!("Registered process {} with reaper", pid);
        }
        Ok(())
    }

    /// Unregister a process from the reaper
    pub fn unregister_process(&mut self, pid: u32) -> Result<(), ReaperError> {
        if let Some(ref mut channel) = self.communication_channel {
            let message = ReaperMessage::UnregisterProcess { pid };
            channel.send_message(&message)?;
            tracing::debug!("Unregistered process {} from reaper", pid);
        }
        Ok(())
    }

    /// Check if the reaper process is still alive
    pub fn is_reaper_alive(&mut self) -> bool {
        if let Some(ref mut child) = self.reaper_child {
            match child.try_wait() {
                Ok(Some(_)) => {
                    tracing::warn!("Reaper process has exited");
                    false
                }
                Ok(None) => true, // Still running
                Err(e) => {
                    tracing::error!("Failed to check reaper status: {}", e);
                    false
                }
            }
        } else {
            false
        }
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
        *self = new_monitor;

        Ok(())
    }

    /// Shutdown the reaper process
    pub fn shutdown(&mut self) -> Result<(), ReaperError> {
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

        Ok(())
    }

    /// Simulate reaper death for testing purposes
    /// This method forcefully kills the reaper process to test restart logic
    #[cfg(test)]
    pub fn simulate_reaper_death(&mut self) -> Result<(), ReaperError> {
        tracing::debug!("Simulating reaper death for testing");

        if let Some(mut child) = self.reaper_child.take() {
            let _ = child.kill();
            let _ = child.wait();
            tracing::debug!("Reaper process killed for testing");
        }

        // Close communication channel
        self.communication_channel = None;

        Ok(())
    }
}

impl Drop for ReaperMonitor {
    fn drop(&mut self) {
        let _ = self.shutdown();
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
            let stream = UnixStream::connect(channel_path).map_err(|e| {
                ReaperError::CommunicationFailed {
                    reason: format!("Failed to connect to Unix socket: {}", e),
                }
            })?;
            self.communication_channel = Some(ReaperChannel::UnixSocket(stream));
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

        // Wait for cleanup thread to finish
        let _ = cleanup_thread.join();

        tracing::info!("Reaper process shutting down");
        Ok(())
    }

    /// Handle incoming messages
    fn handle_message(&mut self, message: ReaperMessage) -> Result<(), ReaperError> {
        match message {
            ReaperMessage::RegisterProcess { pid } => {
                let mut processes = self.monitored_processes.lock().unwrap();
                processes.insert(pid);
                tracing::debug!("Registered process {} for monitoring", pid);
            }
            ReaperMessage::UnregisterProcess { pid } => {
                let mut processes = self.monitored_processes.lock().unwrap();
                processes.remove(&pid);
                tracing::debug!("Unregistered process {} from monitoring", pid);
            }
            ReaperMessage::Ping => {
                if let Some(ref mut channel) = self.communication_channel {
                    channel.send_message(&ReaperMessage::Pong)?;
                }
            }
            ReaperMessage::Shutdown => {
                tracing::info!("Received shutdown signal");
                *self.running.lock().unwrap() = false;
            }
            ReaperMessage::Pong => {
                // Ignore pong messages in reaper
            }
        }
        Ok(())
    }

    /// Clean up zombie processes
    fn cleanup_zombie_processes(monitored_processes: &Arc<Mutex<HashSet<u32>>>) {
        let processes = monitored_processes.lock().unwrap().clone();

        for pid in processes {
            if !Self::is_process_alive(pid) {
                tracing::debug!(
                    "Process {} is no longer alive, removing from monitoring",
                    pid
                );
                monitored_processes.lock().unwrap().remove(&pid);
            }
        }
    }

    /// Check if a process is still alive
    #[cfg(target_os = "macos")]
    fn is_process_alive(pid: u32) -> bool {
        unsafe_macos_process::safe_is_process_alive(pid)
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    fn is_process_alive(pid: u32) -> bool {
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
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
}
