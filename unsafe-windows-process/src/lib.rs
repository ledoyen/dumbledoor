//! Unsafe Windows Process Management Primitives
//!
//! This crate contains all unsafe Windows API interactions for process management.
//! It provides a minimal safe wrapper around Windows process operations while
//! keeping all unsafe code isolated and well-documented.
//!
//! # Safety
//!
//! This crate contains unsafe code that directly interacts with Windows APIs.
//! All unsafe operations are documented and justified. The public API provides
//! safe abstractions over these unsafe operations.

#![cfg(windows)]

use std::ffi::OsStr;
use std::io;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
use winapi::shared::winerror::WAIT_TIMEOUT;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::jobapi2::{AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject};
use winapi::um::processthreadsapi::{
    CreateProcessW, GetExitCodeProcess, OpenProcess, TerminateProcess, PROCESS_INFORMATION,
    STARTUPINFOW,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::CREATE_NEW_PROCESS_GROUP;
use winapi::um::winnt::{
    JobObjectExtendedLimitInformation, HANDLE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

/// Error types for unsafe Windows operations
#[derive(Debug)]
pub enum UnsafeWindowsError {
    SystemCallFailed { syscall: String, errno: i32 },
    InvalidHandle,
    ProcessNotFound,
}

impl std::fmt::Display for UnsafeWindowsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnsafeWindowsError::SystemCallFailed { syscall, errno } => {
                write!(f, "System call failed: {}: {}", syscall, errno)
            }
            UnsafeWindowsError::InvalidHandle => write!(f, "Invalid handle"),
            UnsafeWindowsError::ProcessNotFound => write!(f, "Process not found"),
        }
    }
}

impl std::error::Error for UnsafeWindowsError {}

/// Safe wrapper around Windows HANDLE with automatic cleanup
///
/// # Safety
///
/// This type implements Send + Sync because:
/// - Windows HANDLEs are safe to send between threads
/// - All operations are protected by the Windows kernel
/// - The Drop implementation ensures proper cleanup
#[derive(Debug)]
pub struct SafeHandle(HANDLE);

// SAFETY: Windows HANDLEs are safe to send between threads
unsafe impl Send for SafeHandle {}
// SAFETY: Windows HANDLEs are safe to share between threads (kernel-protected)
unsafe impl Sync for SafeHandle {}

impl SafeHandle {
    /// Create a new SafeHandle from a raw Windows HANDLE
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - The handle is valid or INVALID_HANDLE_VALUE
    /// - The handle is not already owned by another SafeHandle
    /// - The handle will not be closed by other code
    pub unsafe fn new(handle: HANDLE) -> Self {
        SafeHandle(handle)
    }

    /// Get the raw handle value
    pub fn as_raw(&self) -> HANDLE {
        self.0
    }

    /// Check if the handle is valid
    pub fn is_valid(&self) -> bool {
        !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        // SAFETY: We own this handle and ensure it's only closed once
        unsafe {
            if self.is_valid() {
                CloseHandle(self.0);
            }
        }
    }
}

/// Configuration for creating a Windows process
#[derive(Debug, Clone)]
pub struct WindowsProcessConfig {
    pub command_line: String,
    pub working_directory: Option<String>,
    pub environment_block: Option<Vec<u16>>,
    pub inherit_handles: bool,
}

/// Result of creating a Windows process
#[derive(Debug)]
pub struct WindowsProcessResult {
    pub process_handle: SafeHandle,
    pub process_id: u32,
}

impl WindowsProcessResult {
    /// Get the process handle as a SafeHandle reference
    pub fn handle(&self) -> &SafeHandle {
        &self.process_handle
    }

    /// Get the process ID
    pub fn pid(&self) -> u32 {
        self.process_id
    }
}

/// Safe wrapper for Windows Job Object operations
pub struct WindowsJobObject {
    job_handle: SafeHandle,
}

impl WindowsJobObject {
    /// Create a new Windows Job Object with kill-on-close behavior
    ///
    /// # Errors
    ///
    /// Returns an error if the job object cannot be created or configured
    pub fn new() -> Result<Self, UnsafeWindowsError> {
        // SAFETY: CreateJobObjectW is safe to call with null parameters
        let job_handle_raw = unsafe { CreateJobObjectW(ptr::null_mut(), ptr::null()) };

        if job_handle_raw.is_null() {
            return Err(UnsafeWindowsError::SystemCallFailed {
                syscall: "CreateJobObjectW".to_string(),
                errno: io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            });
        }

        // SAFETY: We just created this handle and own it exclusively
        let job_handle = unsafe { SafeHandle::new(job_handle_raw) };

        // Configure job to kill all processes when closed
        // SAFETY: We're initializing a struct with zeroed memory, which is safe for this Windows API struct
        let mut job_info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
        job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        // SAFETY: SetInformationJobObject is safe with valid parameters
        let result = unsafe {
            SetInformationJobObject(
                job_handle.as_raw(),
                JobObjectExtendedLimitInformation,
                &mut job_info as *mut _ as *mut _,
                mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD,
            )
        };

        if result == 0 {
            return Err(UnsafeWindowsError::SystemCallFailed {
                syscall: "SetInformationJobObject".to_string(),
                errno: io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            });
        }

        Ok(Self { job_handle })
    }

    /// Assign a process to this job object
    ///
    /// This is a SAFE wrapper that takes a SafeHandle instead of raw HANDLE
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be assigned to the job
    pub fn assign_process_safe(
        &self,
        process_handle: &SafeHandle,
    ) -> Result<(), UnsafeWindowsError> {
        // SAFETY: SafeHandle guarantees the handle is valid
        unsafe { self.assign_process(process_handle.as_raw()) }
    }

    /// Assign a process to this job object (internal unsafe version)
    ///
    /// # Safety
    ///
    /// The caller must ensure that `process_handle` is a valid Windows process handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be assigned to the job
    unsafe fn assign_process(&self, process_handle: HANDLE) -> Result<(), UnsafeWindowsError> {
        // SAFETY: AssignProcessToJobObject is safe with valid handles
        let result = AssignProcessToJobObject(self.job_handle.as_raw(), process_handle);

        if result == 0 {
            return Err(UnsafeWindowsError::SystemCallFailed {
                syscall: "AssignProcessToJobObject".to_string(),
                errno: io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            });
        }

        Ok(())
    }

    /// Get the raw job handle
    pub fn as_raw(&self) -> HANDLE {
        self.job_handle.as_raw()
    }
}

/// Convert a Rust string to a Windows wide string (UTF-16)
pub fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Create a Windows process with the given configuration
///
/// # Safety
///
/// This function contains unsafe Windows API calls but provides a safe interface.
/// The caller must ensure the configuration is valid.
///
/// # Errors
///
/// Returns an error if the process cannot be created
pub fn create_process(
    config: WindowsProcessConfig,
) -> Result<WindowsProcessResult, UnsafeWindowsError> {
    let mut command_line_wide = to_wide_string(&config.command_line);

    let env_ptr = config
        .environment_block
        .as_ref()
        .map(|v| v.as_ptr() as *mut _)
        .unwrap_or(ptr::null_mut());

    let working_dir_wide = config
        .working_directory
        .as_ref()
        .map(|wd| to_wide_string(wd));
    let working_dir_ptr = working_dir_wide
        .as_ref()
        .map(|v| v.as_ptr())
        .unwrap_or(ptr::null());

    // SAFETY: Initializing Windows API structs with zeroed memory is safe
    let mut startup_info: STARTUPINFOW = unsafe { mem::zeroed() };
    startup_info.cb = mem::size_of::<STARTUPINFOW>() as DWORD;

    let mut process_info: PROCESS_INFORMATION = unsafe { mem::zeroed() };

    // SAFETY: CreateProcessW is safe with properly initialized parameters
    let result = unsafe {
        CreateProcessW(
            ptr::null(),
            command_line_wide.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            if config.inherit_handles { TRUE } else { FALSE },
            CREATE_NEW_PROCESS_GROUP,
            env_ptr,
            working_dir_ptr,
            &mut startup_info,
            &mut process_info,
        )
    };

    if result == 0 {
        return Err(UnsafeWindowsError::SystemCallFailed {
            syscall: "CreateProcessW".to_string(),
            errno: io::Error::last_os_error().raw_os_error().unwrap_or(-1),
        });
    }

    let pid = process_info.dwProcessId;
    let process_handle = process_info.hProcess;

    // Close thread handle as we don't need it
    // SAFETY: We own this handle from CreateProcessW
    unsafe {
        CloseHandle(process_info.hThread);
    }

    // SAFETY: We own the process handle from CreateProcessW
    let safe_handle = unsafe { SafeHandle::new(process_handle) };

    Ok(WindowsProcessResult {
        process_handle: safe_handle,
        process_id: pid,
    })
}

/// Terminate a Windows process using a SafeHandle
///
/// This is a SAFE wrapper that takes a SafeHandle instead of raw HANDLE
///
/// # Errors
///
/// Returns an error if the process cannot be terminated
pub fn terminate_process_safe(
    process_handle: &SafeHandle,
    exit_code: u32,
) -> Result<(), UnsafeWindowsError> {
    // SAFETY: SafeHandle guarantees the handle is valid
    unsafe { terminate_process(process_handle.as_raw(), exit_code) }
}

/// Terminate a Windows process
///
/// # Safety
///
/// The caller must ensure that `process_handle` is a valid Windows process handle.
///
/// # Errors
///
/// Returns an error if the process cannot be terminated
pub unsafe fn terminate_process(
    process_handle: HANDLE,
    exit_code: u32,
) -> Result<(), UnsafeWindowsError> {
    // SAFETY: TerminateProcess is safe with a valid handle
    let result = TerminateProcess(process_handle, exit_code);

    if result == 0 {
        let err = io::Error::last_os_error();
        // Check if process is already gone (access denied might indicate this)
        if err.raw_os_error() == Some(5) {
            // ERROR_ACCESS_DENIED - process might already be terminated
            return Ok(());
        }
        return Err(UnsafeWindowsError::SystemCallFailed {
            syscall: "TerminateProcess".to_string(),
            errno: err.raw_os_error().unwrap_or(-1),
        });
    }

    Ok(())
}

/// Open a process handle by PID
///
/// # Errors
///
/// Returns an error if the process cannot be opened
pub fn open_process(pid: u32, desired_access: DWORD) -> Result<SafeHandle, UnsafeWindowsError> {
    // SAFETY: OpenProcess is safe to call
    let handle = unsafe { OpenProcess(desired_access, FALSE, pid) };

    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(UnsafeWindowsError::ProcessNotFound);
    }

    // SAFETY: We own this handle from OpenProcess
    Ok(unsafe { SafeHandle::new(handle) })
}

/// Wait for a process to exit or timeout using a SafeHandle
///
/// This is a SAFE wrapper that takes a SafeHandle instead of raw HANDLE
///
/// # Returns
///
/// - `Ok(Some(exit_code))` if process exited
/// - `Ok(None)` if timeout occurred
/// - `Err(_)` if an error occurred
pub fn wait_for_process_safe(
    process_handle: &SafeHandle,
    timeout_ms: u32,
) -> Result<Option<u32>, UnsafeWindowsError> {
    // SAFETY: SafeHandle guarantees the handle is valid
    unsafe { wait_for_process(process_handle.as_raw(), timeout_ms) }
}

/// Wait for a process to exit or timeout
///
/// # Safety
///
/// The caller must ensure that `process_handle` is a valid Windows process handle.
///
/// # Returns
///
/// - `Ok(Some(exit_code))` if process exited
/// - `Ok(None)` if timeout occurred
/// - `Err(_)` if an error occurred
pub unsafe fn wait_for_process(
    process_handle: HANDLE,
    timeout_ms: u32,
) -> Result<Option<u32>, UnsafeWindowsError> {
    // SAFETY: WaitForSingleObject is safe with valid parameters
    let wait_result = WaitForSingleObject(process_handle, timeout_ms);

    if wait_result == WAIT_TIMEOUT {
        return Ok(None);
    }

    // Process exited, get exit code
    let mut exit_code: DWORD = 0;
    // SAFETY: GetExitCodeProcess is safe with valid parameters
    let result = GetExitCodeProcess(process_handle, &mut exit_code);

    if result == 0 {
        return Err(UnsafeWindowsError::SystemCallFailed {
            syscall: "GetExitCodeProcess".to_string(),
            errno: io::Error::last_os_error().raw_os_error().unwrap_or(-1),
        });
    }

    Ok(Some(exit_code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_object_creation() {
        let job = WindowsJobObject::new();
        assert!(job.is_ok(), "Job object creation should succeed");
    }

    #[test]
    fn test_safe_handle_validity() {
        // SAFETY: INVALID_HANDLE_VALUE is safe to use for testing
        let invalid_handle = unsafe { SafeHandle::new(INVALID_HANDLE_VALUE) };
        assert!(!invalid_handle.is_valid());
    }

    #[test]
    fn test_wide_string_conversion() {
        let wide = to_wide_string("test");
        assert!(wide.len() > 4); // Should include null terminator
        assert_eq!(wide[wide.len() - 1], 0); // Should be null-terminated
    }
}
