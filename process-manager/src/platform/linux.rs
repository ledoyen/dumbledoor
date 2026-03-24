use crate::{
    platform::{PlatformManager, PlatformProcess},
    PlatformError, ProcessConfig, ProcessManagerError, ProcessStatus,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use unsafe_linux_process::{
    safe_become_subreaper, safe_cleanup_process_group, safe_install_signal_handlers,
    safe_is_process_running, safe_reap_orphans, safe_scan_proc_for_children, safe_send_signal,
    safe_spawn_process, safe_try_wait, safe_wait, ExitInfo, LinuxProcessConfig, UnsafeLinuxError,
};

// ─── Types ────────────────────────────────────────────────────────────────────

/// Linux-specific process representation.
/// `init_pid` is the host PID of the namespace init returned by `clone()`.
/// It is used both as the state-map key and as the externally visible PID.
#[derive(Debug, Clone)]
pub struct LinuxProcess {
    pub(super) init_pid: u32,
}

impl PlatformProcess for LinuxProcess {
    fn pid(&self) -> u32 {
        self.init_pid
    }
}

/// Cached status for a managed process.
#[derive(Debug, Clone)]
enum CachedExitStatus {
    Running,
    Exited {
        exit_code: i32,
        exit_time: SystemTime,
    },
    Terminated {
        signal: Option<i32>,
        exit_time: SystemTime,
    },
}

/// Per-process runtime state tracked by the manager.
/// The HashMap key is `init_pid`.
#[derive(Debug)]
struct LinuxProcessState {
    cached_status: CachedExitStatus,
}

// ─── Manager ──────────────────────────────────────────────────────────────────

/// Linux platform manager using PID namespaces for process isolation.
///
/// Each managed process runs as PID 1 of its own PID + user namespace (Docker-style).
/// This guarantees that all descendants — however deeply nested — are killed when the
/// namespace init exits, making cleanup deterministic without a reaper process.
#[derive(Clone)]
pub struct LinuxPlatformManager {
    process_state: Arc<RwLock<HashMap<u32, LinuxProcessState>>>,
    cleanup_handler_installed: Arc<RwLock<bool>>,
}

impl LinuxPlatformManager {
    pub fn new() -> Result<Self, ProcessManagerError> {
        // Become a subreaper so that when a namespace init dies, its orphaned children
        // (background processes started by the managed command) are reparented to us
        // rather than to the system init.  This lets us reap them in terminate_process.
        if let Err(e) = safe_become_subreaper() {
            tracing::warn!(
                "Failed to become subreaper: {} — orphan reaping may be incomplete",
                e
            );
        }

        tracing::info!("Linux platform manager initialised (PID namespace isolation)");

        Ok(Self {
            process_state: Arc::new(RwLock::new(HashMap::new())),
            cleanup_handler_installed: Arc::new(RwLock::new(false)),
        })
    }

    fn convert_config(config: &ProcessConfig) -> LinuxProcessConfig {
        LinuxProcessConfig {
            command: config.command.to_string_lossy().to_string(),
            args: config.args.clone(),
            working_directory: config
                .working_directory
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            environment: config.environment.clone(),
            log_file: config
                .log_file
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
        }
    }

    fn convert_error(e: UnsafeLinuxError) -> PlatformError {
        match e {
            UnsafeLinuxError::SystemCallFailed { syscall, errno } => {
                PlatformError::SystemCallFailed { syscall, errno }
            }
            UnsafeLinuxError::InvalidParameter { .. } => PlatformError::SystemCallFailed {
                syscall: "parameter_validation".to_string(),
                errno: libc::EINVAL,
            },
            UnsafeLinuxError::ProcessNotFound => PlatformError::SystemCallFailed {
                syscall: "process_lookup".to_string(),
                errno: libc::ESRCH,
            },
            UnsafeLinuxError::PermissionDenied { operation } => {
                PlatformError::PermissionDenied { operation }
            }
        }
    }

    fn exit_info_to_status(info: ExitInfo, exit_time: SystemTime) -> CachedExitStatus {
        if let Some(sig) = info.signal {
            CachedExitStatus::Terminated {
                signal: Some(sig),
                exit_time,
            }
        } else {
            CachedExitStatus::Exited {
                exit_code: info.exit_code.unwrap_or(-1),
                exit_time,
            }
        }
    }
}

// ─── PlatformManager impl ─────────────────────────────────────────────────────

impl PlatformManager for LinuxPlatformManager {
    type Process = LinuxProcess;

    fn spawn_process(&self, config: &ProcessConfig) -> Result<Self::Process, PlatformError> {
        tracing::info!("Spawning Linux process: {:?}", config.command);

        let linux_config = Self::convert_config(config);
        let result = safe_spawn_process(linux_config).map_err(Self::convert_error)?;

        tracing::info!(
            "Spawned Linux process: namespace_init_pid={}",
            result.init_pid,
        );

        {
            let mut state = self.process_state.write().unwrap();
            state.insert(
                result.init_pid,
                LinuxProcessState {
                    cached_status: CachedExitStatus::Running,
                },
            );
        }

        Ok(LinuxProcess {
            init_pid: result.init_pid,
        })
    }

    fn terminate_process(
        &self,
        process: &Self::Process,
        graceful: bool,
    ) -> Result<(), PlatformError> {
        let init_pid = process.init_pid;

        tracing::info!(
            "Terminating Linux process init_pid={} (graceful={})",
            init_pid,
            graceful
        );

        // Check cached status — nothing to do if already finished.
        {
            let state = self.process_state.read().unwrap();
            if let Some(s) = state.get(&init_pid) {
                if !matches!(s.cached_status, CachedExitStatus::Running) {
                    return Ok(());
                }
            }
        }

        if graceful {
            // Send SIGTERM and give the process up to 5 seconds to exit cleanly.
            safe_send_signal(init_pid, libc::SIGTERM).map_err(Self::convert_error)?;

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                if !safe_is_process_running(init_pid) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }

        // Force-kill if still running.
        if safe_is_process_running(init_pid) {
            safe_send_signal(init_pid, libc::SIGKILL).map_err(Self::convert_error)?;
        }

        // Block until the namespace init is fully reaped.
        // At this point the kernel has sent SIGKILL to every remaining process in the
        // namespace; they will be reparented to us (subreaper) as zombies.
        let exit_info = safe_wait(init_pid).map_err(Self::convert_error)?;

        // Drain orphaned namespace processes reparented to us.
        safe_reap_orphans();

        // Update cached state.
        let cached = Self::exit_info_to_status(exit_info, SystemTime::now());
        {
            let mut state = self.process_state.write().unwrap();
            if let Some(s) = state.get_mut(&init_pid) {
                s.cached_status = cached;
            }
        }

        tracing::info!("Terminated Linux process init_pid={}", init_pid);
        Ok(())
    }

    fn query_process_status(
        &self,
        process: &Self::Process,
    ) -> Result<ProcessStatus, PlatformError> {
        let init_pid = process.init_pid;

        let mut state = self.process_state.write().unwrap();
        let Some(entry) = state.get_mut(&init_pid) else {
            return Ok(ProcessStatus::Failed {
                error: "Unknown process".to_string(),
            });
        };

        // Return cached status if already finalised.
        match &entry.cached_status {
            CachedExitStatus::Exited {
                exit_code,
                exit_time,
            } => {
                return Ok(ProcessStatus::Exited {
                    exit_code: *exit_code,
                    exit_time: *exit_time,
                })
            }
            CachedExitStatus::Terminated { signal, exit_time } => {
                return Ok(ProcessStatus::Terminated {
                    signal: *signal,
                    exit_time: *exit_time,
                })
            }
            CachedExitStatus::Running => {}
        }

        // Non-blocking check: has the namespace init exited?
        match safe_try_wait(init_pid).map_err(Self::convert_error)? {
            None => Ok(ProcessStatus::Running { pid: init_pid }),
            Some(info) => {
                let cached = Self::exit_info_to_status(info, SystemTime::now());
                let result = match &cached {
                    CachedExitStatus::Exited {
                        exit_code,
                        exit_time,
                    } => ProcessStatus::Exited {
                        exit_code: *exit_code,
                        exit_time: *exit_time,
                    },
                    CachedExitStatus::Terminated { signal, exit_time } => {
                        ProcessStatus::Terminated {
                            signal: *signal,
                            exit_time: *exit_time,
                        }
                    }
                    CachedExitStatus::Running => ProcessStatus::Running { pid: init_pid },
                };
                entry.cached_status = cached;
                Ok(result)
            }
        }
    }

    fn setup_cleanup_handler(&self) -> Result<(), PlatformError> {
        let already_installed = *self.cleanup_handler_installed.read().unwrap();
        if already_installed {
            return Ok(());
        }

        tracing::info!("Installing Linux signal-based cleanup handlers");

        safe_install_signal_handlers(cleanup_signal_handler).map_err(Self::convert_error)?;

        *self.cleanup_handler_installed.write().unwrap() = true;
        tracing::info!("Linux cleanup handlers installed");
        Ok(())
    }

    fn cleanup_all_processes(&self, processes: &[&Self::Process]) -> Result<(), PlatformError> {
        tracing::info!("Cleaning up {} Linux processes", processes.len());

        for process in processes {
            let init_pid = process.init_pid;
            if safe_is_process_running(init_pid) {
                let _ = safe_send_signal(init_pid, libc::SIGKILL);
                let _ = safe_wait(init_pid);
            }
        }

        // Drain all namespace orphans at once.
        safe_reap_orphans();

        {
            let mut state = self.process_state.write().unwrap();
            state.clear();
        }

        tracing::info!("Linux process cleanup complete");
        Ok(())
    }

    fn get_child_processes(&self, process: &Self::Process) -> Result<Vec<u32>, PlatformError> {
        Ok(safe_scan_proc_for_children(process.init_pid))
    }

    fn needs_reaper(&self) -> bool {
        // Linux uses PID namespaces for cleanup — no reaper process needed.
        false
    }

    fn create_process_group(&self) -> Result<i32, PlatformError> {
        unsafe_linux_process::safe_create_process_group().map_err(|e| {
            PlatformError::SystemCallFailed {
                syscall: "setpgid".to_string(),
                errno: match e {
                    UnsafeLinuxError::SystemCallFailed { errno, .. } => errno,
                    _ => -1,
                },
            }
        })
    }
}

// ─── Signal handler ───────────────────────────────────────────────────────────

/// Signal handler for SIGTERM/SIGINT — kills the ProcessManager's own process group.
extern "C" fn cleanup_signal_handler(signal: libc::c_int) {
    match signal {
        libc::SIGTERM => tracing::warn!("Received SIGTERM, cleaning up process group"),
        libc::SIGINT => tracing::warn!("Received SIGINT, cleaning up process group"),
        _ => tracing::warn!("Received signal {}, cleaning up process group", signal),
    }
    let _ = safe_cleanup_process_group();
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProcessConfig;

    #[test]
    fn test_linux_platform_manager_creation() {
        let manager = LinuxPlatformManager::new();
        assert!(
            manager.is_ok(),
            "LinuxPlatformManager should be created successfully"
        );
    }

    #[test]
    fn test_reaper_requirement() {
        let manager = LinuxPlatformManager::new().expect("Failed to create manager");
        assert!(
            !manager.needs_reaper(),
            "Linux uses namespaces — no reaper needed"
        );
    }

    #[test]
    fn test_process_spawning() {
        let manager = LinuxPlatformManager::new().expect("Failed to create manager");
        let config = ProcessConfig::new("/bin/echo").args(["test"]);

        let process = manager
            .spawn_process(&config)
            .expect("Failed to spawn process");

        assert!(process.pid() > 0, "Process should have a real PID > 0");

        // Give echo time to finish, then clean up.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let _ = manager.terminate_process(&process, false);
    }

    #[test]
    fn test_cleanup_handler_setup() {
        let manager = LinuxPlatformManager::new().expect("Failed to create manager");
        // Idempotent — calling twice should not error.
        manager
            .setup_cleanup_handler()
            .expect("First install failed");
        manager
            .setup_cleanup_handler()
            .expect("Second install failed");
    }
}
