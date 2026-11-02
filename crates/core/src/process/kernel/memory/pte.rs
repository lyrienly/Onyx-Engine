use crate::process::ModuleEntry;
use crate::process::kernel::OnyxDriver;
use crate::process::kernel::types::*;
use crate::win32::*;
use std::mem::size_of;
use std::ptr::null_mut;

impl OnyxDriver {
    pub fn stealth_read_pte(
        &self,
        pid: u32,
        virtual_address: u64,
        len: usize,
    ) -> Result<Vec<u8>, String> {
        let input = CeStealthReadInput {
            process_id: pid as u64,
            virtual_address,
            size: len as u32,
        };
        let mut buffer = vec![0u8; len];
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_STEALTH_READ_PTE,
                &input as *const _ as LPVOID,
                size_of::<CeStealthReadInput>() as DWORD,
                buffer.as_mut_ptr() as LPVOID,
                len as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            buffer.truncate(returned as usize);
            Ok(buffer)
        } else {
            Err(format!(
                "IOCTL_CE_STEALTH_READ_PTE failed for PID {} at {:#X}",
                pid, virtual_address
            ))
        }
    }
}
