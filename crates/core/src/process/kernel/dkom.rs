use super::OnyxDriver;
use super::types::*;
use crate::win32::*;
use std::mem::size_of;
use std::ptr::null_mut;

impl OnyxDriver {
    pub fn hide_process(&self, pid: u32) -> Result<(), String> {
        let mut input_pid = pid;
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_HIDE_PROCESS,
                &mut input_pid as *mut _ as LPVOID,
                size_of::<u32>() as DWORD,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(())
        } else {
            Err(format!(
                "Failed to hide process PID {} via DKOM (os error: {})",
                pid,
                std::io::Error::last_os_error()
            ))
        }
    }

    pub fn restore_process(&self, pid: u32) -> Result<(), String> {
        let mut input_pid = pid;
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_RESTORE_PROCESS,
                &mut input_pid as *mut _ as LPVOID,
                size_of::<u32>() as DWORD,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(())
        } else {
            Err(format!(
                "Failed to restore process PID {} via DKOM (os error: {})",
                pid,
                std::io::Error::last_os_error()
            ))
        }
    }

    pub fn set_protection(&self, pid: u32, enable: bool) -> Result<(), String> {
        let mut inp = CeSetProtectionInput {
            process_id: pid as u64,
            enable: if enable { 1 } else { 0 },
        };
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_SET_PROCESS_PROTECTION,
                &mut inp as *mut _ as LPVOID,
                size_of::<CeSetProtectionInput>() as DWORD,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(())
        } else {
            Err(format!("Failed to set process protection for PID {}", pid))
        }
    }

    pub fn hide_thread(&self, tid: u32) -> Result<(), String> {
        let mut returned: DWORD = 0;
        let mut target_tid = tid;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_HIDE_THREAD,
                &mut target_tid as *mut _ as LPVOID,
                size_of::<u32>() as DWORD,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(())
        } else {
            Err(format!("IOCTL_CE_HIDE_THREAD failed for TID {}", tid))
        }
    }
}
