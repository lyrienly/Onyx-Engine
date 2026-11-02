use crate::process::ModuleEntry;
use crate::process::kernel::OnyxDriver;
use crate::process::kernel::types::*;
use crate::win32::*;
use std::mem::size_of;
use std::ptr::null_mut;

impl OnyxDriver {
    pub fn freeze_process(&self, pid: u32, freeze: bool) -> Result<(), String> {
        let mut inp = CeFreezeProcessInput {
            process_id: pid as u64,
            freeze: if freeze { 1 } else { 0 },
        };
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_FREEZE_PROCESS,
                &mut inp as *mut _ as LPVOID,
                size_of::<CeFreezeProcessInput>() as DWORD,
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
                "Failed to {} process PID {}",
                if freeze { "freeze" } else { "thaw" },
                pid
            ))
        }
    }
}
