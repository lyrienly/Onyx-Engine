use super::OnyxDriver;
use super::types::*;
use crate::win32::*;
use std::mem::size_of;
use std::ptr::null_mut;

impl OnyxDriver {
    pub fn strip_callbacks_mode(&self, mode: u32) -> Result<u32, String> {
        let mut inp = CeStripCallbacksInput { restore: mode };
        let mut affected: u32 = 0;
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_STRIP_CALLBACKS,
                &mut inp as *mut _ as LPVOID,
                size_of::<CeStripCallbacksInput>() as DWORD,
                &mut affected as *mut _ as LPVOID,
                size_of::<u32>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(affected)
        } else {
            Err("Failed to execute callback strip/unlink operation".to_string())
        }
    }

    pub fn strip_callbacks(&self, restore: bool) -> Result<u32, String> {
        self.strip_callbacks_mode(if restore { 1 } else { 0 })
    }

    pub fn unlink_callbacks_dkom(&self) -> Result<u32, String> {
        self.strip_callbacks_mode(2)
    }

    pub fn enum_callbacks(&self) -> Result<Vec<KernelObCallbackInfo>, String> {
        let mut output = EnumCallbacksOutput::default();
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_ENUM_CALLBACKS,
                null_mut(),
                0,
                &mut output as *mut _ as LPVOID,
                size_of::<EnumCallbacksOutput>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            let count = (output.count as usize).min(32);
            Ok(output.callbacks[..count].to_vec())
        } else {
            Err(format!(
                "Failed to enumerate kernel callbacks (os error: {})",
                std::io::Error::last_os_error()
            ))
        }
    }
}
