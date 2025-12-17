use crate::{
    platform::{PlatformManager, PlatformProcess},
    PlatformError, ProcessConfig, ProcessManagerError, ProcessStatus,
};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use std::sync::RwLock;
use std::time::SystemTime;
use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
use winapi::shared::winerror::WAIT_TIMEOUT;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::jobapi2::{
    AssignProcessToJobObject, CreateJobObjectW, QueryInformationJobObject, SetInformationJobObject,
};
use winapi::um::processthreadsapi::{
    CreateProcessW, GetExitCodeProcess, OpenProcess, TerminateProcess, PROCESS_INFORMATION,
    STARTUPINFOW,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{
    CREATE_NEW_PROCESS_GROUP, STARTF_USESTDHANDLES,
};
use winapi::um::winnt::{
    JobObjectBasicLimitInformation, JobObjectExtendedLimitInformation, HANDLE,
    JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE,
};

/// Wrapper around Windows HANDLE that is Send + Sync
/// Safety: We ensure proper synchronization through RwLock in WindowsPlatformManager
#[derive(Debug)]
struct SafeHandle(HANDLE);

unsafe impl Send for SafeHandle {}
unsafe impl Sync for SafeHandle {}

impl SafeHandle {
    fn new(handle: HANDLE) -> Self {
        SafeHandle(handle)
    }

    fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                CloseHandle(self.0);
            }
        }
    }
}

/// Windows-specific process representation
#[derive(Debug)]
pub struct WindowsProcess {
    pid: u32,
    #[allow(dead_code)] // Used for Drop implementation
    handle: SafeHandle,
}

impl PlatformProcess for WindowsProcess {
    fn pid(&self) -> u32 {
        self.pid
    }
}

/// Windows platform manager using Job Objects
pub struct WindowsPlatformManager {
    job_object: SafeHandle,
    process_handles: RwLock<HashMap<u32, SafeHandle>>,
}

impl WindowsPlatformManager {
    /// Create a new Windows platform manager
    pub fn new() -> Result<Self, ProcessManagerError> {
        unsafe {
            // Create a Job Object for automatic process cleanup
            let job_object_raw = CreateJobObjectW(ptr::null_mut(), ptr::null());
            if job_object_raw.is_null() {
                return Err(ProcessManagerError::PlatformError {
                    error: PlatformError::SystemCallFailed {
                        syscall: "CreateJobObjectW".to_string(),
                        errno: io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                    },
                });
            }

            // Configure the job object to kill all processes when the job is closed
            let mut job_info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = mem::zeroed();
            job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            let result = SetInformationJobObject(
                job_object_raw,
                JobObjectExtendedLimitInformation,
                &mut job_info as *mut _ as *mut _,
                mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD,
            );

            if result == 0 {
                CloseHandle(job_object_raw);
                return Err(ProcessManagerError::PlatformError {
                    error: PlatformError::SystemCallFailed {
                        syscall: "SetInformationJobObject".to_string(),
                        errno: io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                    },
                });
            }

            tracing::info!("Windows platform manager initialized with Job Object");

            Ok(Self {
                job_object: SafeHandle::new(job_object_raw),
                process_handles: RwLock::new(HashMap::new()),
            })
        }
    }

    /// Convert a Rust string to a Windows wide string (UTF-16)
    fn to_wide_string(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    /// Build command line string from command and arguments
    fn build_command_line(config: &ProcessConfig) -> String {
        let mut cmd_line = String::new();

        // Quote the command if it contains spaces
        let cmd_str = config.command.to_string_lossy();
        if cmd_str.contains(' ') {
            cmd_line.push('"');
            cmd_line.push_str(&cmd_str);
            cmd_line.push('"');
        } else {
            cmd_line.push_str(&cmd_str);
        }

        // Add arguments
        for arg in &config.args {
            cmd_line.push(' ');
            // Quote arguments if they contain spaces
            if arg.contains(' ') {
                cmd_line.push('"');
                cmd_line.push_str(arg);
                cmd_line.push('"');
            } else {
                cmd_line.push_str(arg);
            }
        }

        cmd_line
    }

    /// Build environment block from environment variables
    fn build_environment_block(env: &HashMap<String, String>) -> Option<Vec<u16>> {
        if env.is_empty() {
            // Empty environment - return None to inherit parent environment
            return None;
        }

        let mut env_block = String::new();
        for (key, value) in env {
            env_block.push_str(key);
            env_block.push('=');
            env_block.push_str(value);
            env_block.push('\0');
        }
        env_block.push('\0');

        Some(Self::to_wide_string(&env_block))
    }

    /// Get the default working directory (system root)
    fn get_default_working_directory() -> String {
        std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string())
    }
}

impl Drop for WindowsPlatformManager {
    fn drop(&mut self) {
        // SafeHandle will automatically close the job object handle
        // which will terminate all processes in the job
        tracing::debug!("Dropping WindowsPlatformManager, job object will be closed");
    }
}

impl PlatformManager for WindowsPlatformManager {
    fn spawn_process(
        &self,
        config: &ProcessConfig,
    ) -> Result<Box<dyn PlatformProcess>, PlatformError> {
        unsafe {
            let command_line = Self::build_command_line(config);
            tracing::debug!("Command line: {}", command_line);
            let mut command_line_wide = Self::to_wide_string(&command_line);

            // Build environment block
            let env_block = Self::build_environment_block(&config.environment);
            let env_ptr = env_block
                .as_ref()
                .map(|v| v.as_ptr() as *mut _)
                .unwrap_or(ptr::null_mut());

            // Determine working directory
            let working_dir = config
                .working_directory
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(Self::get_default_working_directory);
            tracing::debug!("Working directory: {}", working_dir);
            let working_dir_wide = Self::to_wide_string(&working_dir);

            // Set up startup info
            let mut startup_info: STARTUPINFOW = mem::zeroed();
            startup_info.cb = mem::size_of::<STARTUPINFOW>() as DWORD;

            // Handle log file redirection if specified
            let _stdout_file = if let Some(ref log_path) = config.log_file {
                // Open or create the log file
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log_path)
                    .map_err(|e| PlatformError::SystemCallFailed {
                        syscall: "OpenOptions::open".to_string(),
                        errno: e.raw_os_error().unwrap_or(-1),
                    })?;

                let handle = file.as_raw_handle() as HANDLE;

                // Set up redirection
                startup_info.dwFlags |= STARTF_USESTDHANDLES;
                startup_info.hStdOutput = handle;
                startup_info.hStdError = handle;
                startup_info.hStdInput = ptr::null_mut();

                // Keep file alive until process is created
                Some(file)
            } else {
                None
            };

            let mut process_info: PROCESS_INFORMATION = mem::zeroed();

            // Create the process
            let result = CreateProcessW(
                ptr::null(),
                command_line_wide.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                if config.log_file.is_some() { TRUE } else { FALSE }, // Inherit handles if redirecting
                CREATE_NEW_PROCESS_GROUP, // Removed CREATE_BREAKAWAY_FROM_JOB as it requires special privileges
                env_ptr,
                working_dir_wide.as_ptr(),
                &mut startup_info,
                &mut process_info,
            );

            if result == 0 {
                let err = io::Error::last_os_error();
                tracing::error!(
                    "Failed to spawn Windows process: {} (command: {})",
                    err,
                    command_line
                );
                return Err(PlatformError::SystemCallFailed {
                    syscall: "CreateProcessW".to_string(),
                    errno: err.raw_os_error().unwrap_or(-1),
                });
            }

            let pid = process_info.dwProcessId;
            let process_handle = process_info.hProcess;

            // Close thread handle as we don't need it
            CloseHandle(process_info.hThread);

            // Assign the process to the job object for automatic cleanup
            let assign_result = AssignProcessToJobObject(self.job_object.as_raw(), process_handle);
            if assign_result == 0 {
                let err = io::Error::last_os_error();
                tracing::warn!(
                    "Failed to assign process {} to job object: {}",
                    pid,
                    err
                );
                // Continue anyway - we'll still track the process manually
            }

            // Store the process handle for tracking
            {
                let mut handles = self.process_handles.write().unwrap();
                handles.insert(pid, SafeHandle::new(process_handle));
            }

            tracing::info!(
                "Spawned Windows process: {} (PID: {})",
                config.command.display(),
                pid
            );

            Ok(Box::new(WindowsProcess {
                pid,
                handle: SafeHandle::new(process_handle),
            }))
        }
    }

    fn terminate_process(
        &self,
        process: &dyn PlatformProcess,
        graceful: bool,
    ) -> Result<(), PlatformError> {
        let pid = process.pid();

        // Get the process handle
        let process_handle = {
            let handles = self.process_handles.read().unwrap();
            if let Some(h) = handles.get(&pid) {
                h.as_raw()
            } else {
                // Try to open the process if we don't have a handle
                unsafe {
                    let h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, pid);
                    if h.is_null() || h == INVALID_HANDLE_VALUE {
                        tracing::warn!("Process {} not found or already terminated", pid);
                        return Ok(()); // Process already gone
                    }
                    h
                }
            }
        };

        unsafe {
            if graceful {
                // On Windows, graceful termination is attempted by waiting briefly
                // before forcing termination
                tracing::debug!("Attempting graceful termination of process {}", pid);

                // Wait for up to 5 seconds for the process to exit
                let wait_result = WaitForSingleObject(process_handle, 5000);

                if wait_result == WAIT_TIMEOUT {
                    tracing::debug!(
                        "Process {} did not exit gracefully, forcing termination",
                        pid
                    );
                    // Force termination
                    let result = TerminateProcess(process_handle, 1);
                    if result == 0 {
                        let err = io::Error::last_os_error();
                        tracing::error!("Failed to terminate process {}: {}", pid, err);
                        return Err(PlatformError::SystemCallFailed {
                            syscall: "TerminateProcess".to_string(),
                            errno: err.raw_os_error().unwrap_or(-1),
                        });
                    }
                }
            } else {
                // Force termination immediately
                tracing::debug!("Forcing termination of process {}", pid);
                let result = TerminateProcess(process_handle, 1);
                if result == 0 {
                    let err = io::Error::last_os_error();
                    // Check if the process is already gone
                    if err.raw_os_error() == Some(5) {
                        // ERROR_ACCESS_DENIED might mean process is already gone
                        tracing::debug!("Process {} may already be terminated", pid);
                    } else {
                        tracing::error!("Failed to terminate process {}: {}", pid, err);
                        return Err(PlatformError::SystemCallFailed {
                            syscall: "TerminateProcess".to_string(),
                            errno: err.raw_os_error().unwrap_or(-1),
                        });
                    }
                }
            }

            // Remove from tracking
            {
                let mut handles = self.process_handles.write().unwrap();
                handles.remove(&pid);
            }

            tracing::info!("Terminated Windows process {}", pid);
        }

        Ok(())
    }

    fn query_process_status(
        &self,
        process: &dyn PlatformProcess,
    ) -> Result<ProcessStatus, PlatformError> {
        let pid = process.pid();

        // Get the process handle
        let process_handle = {
            let handles = self.process_handles.read().unwrap();
            if let Some(h) = handles.get(&pid) {
                h.as_raw()
            } else {
                // Try to open the process if we don't have a handle
                unsafe {
                    let h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                    if h.is_null() || h == INVALID_HANDLE_VALUE {
                        return Ok(ProcessStatus::Exited {
                            exit_code: -1,
                            exit_time: SystemTime::now(),
                        });
                    }
                    h
                }
            }
        };

        unsafe {
            // Check if process is still running
            let wait_result = WaitForSingleObject(process_handle, 0);

            if wait_result == WAIT_TIMEOUT {
                // Process is still running
                Ok(ProcessStatus::Running { pid })
            } else {
                // Process has exited, get exit code
                let mut exit_code: DWORD = 0;
                let result = GetExitCodeProcess(process_handle, &mut exit_code);

                if result == 0 {
                    return Err(PlatformError::SystemCallFailed {
                        syscall: "GetExitCodeProcess".to_string(),
                        errno: io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                    });
                }

                // Check for child processes
                let child_pids = self.get_child_processes(process)?;

                if !child_pids.is_empty() {
                    Ok(ProcessStatus::RunningDetached {
                        exit_code: exit_code as i32,
                        child_pids,
                    })
                } else {
                    Ok(ProcessStatus::Exited {
                        exit_code: exit_code as i32,
                        exit_time: SystemTime::now(),
                    })
                }
            }
        }
    }

    fn setup_cleanup_handler(&self) -> Result<(), PlatformError> {
        // On Windows, the Job Object automatically handles cleanup when the job is closed
        // This happens in the Drop implementation
        tracing::info!("Windows cleanup handler configured via Job Object");
        Ok(())
    }

    fn cleanup_all_processes(
        &self,
        processes: &[&dyn PlatformProcess],
    ) -> Result<(), PlatformError> {
        tracing::info!("Cleaning up {} Windows processes", processes.len());

        // Terminate each process
        for process in processes {
            // Attempt graceful termination first
            if let Err(e) = self.terminate_process(*process, true) {
                tracing::warn!(
                    "Failed to terminate process {} during cleanup: {}",
                    process.pid(),
                    e
                );
            }
        }

        // The Job Object will ensure all processes are killed when it's closed
        Ok(())
    }

    fn get_child_processes(
        &self,
        process: &dyn PlatformProcess,
    ) -> Result<Vec<u32>, PlatformError> {
        // On Windows, detecting child processes requires using toolhelp32 or NtQuerySystemInformation
        // For now, we'll use a simplified approach that checks if processes in the job are still running
        
        let pid = process.pid();
        tracing::debug!("Getting child processes for Windows process {}", pid);

        unsafe {
            // Query the job object for process list
            let mut basic_info: JOBOBJECT_BASIC_LIMIT_INFORMATION = mem::zeroed();
            let result = QueryInformationJobObject(
                self.job_object.as_raw(),
                JobObjectBasicLimitInformation,
                &mut basic_info as *mut _ as *mut _,
                mem::size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as DWORD,
                ptr::null_mut(),
            );

            if result == 0 {
                tracing::debug!("Failed to query job object for child processes");
                return Ok(Vec::new());
            }

            // For simplicity, we'll return an empty list
            // A full implementation would use CreateToolhelp32Snapshot to enumerate processes
            Ok(Vec::new())
        }
    }
}
