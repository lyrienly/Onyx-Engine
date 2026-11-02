use crate::process::ModuleEntry;
use crate::process::kernel::OnyxDriver;
use crate::process::kernel::types::*;
use crate::win32::*;
use std::mem::size_of;
use std::ptr::null_mut;

impl OnyxDriver {
    pub fn read_memory(&self, pid: u32, address: usize, len: usize) -> Result<Vec<u8>, String> {
        let mut result = Vec::with_capacity(len);
        let mut offset = 0;

        while offset < len {
            let chunk_len = ((len - offset).min(0xFFFF)) as u16;
            let inp = CeReadMemoryInput {
                process_id: pid as u64,
                start_address: (address + offset) as u64,
                bytes_to_read: chunk_len,
            };

            let mut out_buf = vec![0u8; chunk_len as usize];
            let mut returned: DWORD = 0;

            let ok = unsafe {
                DeviceIoControl(
                    self.device_handle,
                    IOCTL_CE_READMEMORY,
                    &inp as *const _ as LPVOID,
                    size_of::<CeReadMemoryInput>() as DWORD,
                    out_buf.as_mut_ptr() as LPVOID,
                    chunk_len as DWORD,
                    &mut returned,
                    null_mut(),
                )
            };

            if ok == TRUE && returned > 0 {
                result.extend_from_slice(&out_buf[..returned as usize]);
                offset += returned as usize;
            } else {
                return Err(format!(
                    "OnyxDriver IOCTL_CE_READMEMORY failed at 0x{:X}",
                    address + offset
                ));
            }
        }

        Ok(result)
    }

    pub fn write_memory(&self, pid: u32, address: usize, data: &[u8]) -> Result<usize, String> {
        let mut total_written = 0;
        let mut offset = 0;

        while offset < data.len() {
            let chunk_len = ((data.len() - offset).min(0xFFFF)) as u16;
            let header = CeWriteMemoryHeader {
                process_id: pid as u64,
                start_address: (address + offset) as u64,
                bytes_to_write: chunk_len,
            };

            let header_size = size_of::<CeWriteMemoryHeader>();
            let mut packet = vec![0u8; header_size + chunk_len as usize];

            unsafe {
                std::ptr::copy_nonoverlapping(
                    &header as *const _ as *const u8,
                    packet.as_mut_ptr(),
                    header_size,
                );
                std::ptr::copy_nonoverlapping(
                    data[offset..].as_ptr(),
                    packet.as_mut_ptr().add(header_size),
                    chunk_len as usize,
                );
            }

            let mut returned: DWORD = 0;
            let ok = unsafe {
                DeviceIoControl(
                    self.device_handle,
                    IOCTL_CE_WRITEMEMORY,
                    packet.as_mut_ptr() as LPVOID,
                    packet.len() as DWORD,
                    null_mut(),
                    0,
                    &mut returned,
                    null_mut(),
                )
            };

            if ok == TRUE {
                total_written += chunk_len as usize;
                offset += chunk_len as usize;
            } else {
                return Err(format!(
                    "OnyxDriver IOCTL_CE_WRITEMEMORY failed at 0x{:X}",
                    address + offset
                ));
            }
        }

        Ok(total_written)
    }

    pub fn allocate_memory(
        &self,
        pid: u32,
        preferred_base: u64,
        size: usize,
        protect: u32,
    ) -> Result<u64, String> {
        let input = CeAllocMemoryInput {
            process_id: pid as u64,
            base_address: preferred_base,
            size: size as u64,
            allocation_type: 0x3000,
            protect,
        };
        let mut output = CeAllocMemoryOutput {
            base_address: 0,
            status: 0,
        };
        let mut returned: DWORD = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_ALLOCATE_PROCESS_MEMORY,
                &input as *const _ as LPVOID,
                size_of::<CeAllocMemoryInput>() as DWORD,
                &mut output as *mut _ as LPVOID,
                size_of::<CeAllocMemoryOutput>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };

        let base = output.base_address;
        let status = output.status;
        if ok == TRUE && base != 0 {
            Ok(base)
        } else {
            Err(format!(
                "OnyxDriver IOCTL_CE_ALLOCATE_PROCESS_MEMORY failed for PID {} (status {:#X})",
                pid, status
            ))
        }
    }

    pub fn free_memory(&self, pid: u32, base_address: u64) -> Result<(), String> {
        let input = CeFreeMemoryInput {
            process_id: pid as u64,
            base_address,
            size: 0,
            free_type: 0x8000,
        };
        let mut returned: DWORD = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_FREE_PROCESS_MEMORY,
                &input as *const _ as LPVOID,
                size_of::<CeFreeMemoryInput>() as DWORD,
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
                "OnyxDriver IOCTL_CE_FREE_PROCESS_MEMORY failed for PID {} at {:#X}",
                pid, base_address
            ))
        }
    }

    pub fn protect_memory(
        &self,
        pid: u32,
        base_address: u64,
        size: usize,
        new_protect: u32,
    ) -> Result<u32, String> {
        let input = CeProtectMemoryInput {
            process_id: pid as u64,
            base_address,
            size: size as u64,
            new_protect,
        };
        let mut output = CeProtectMemoryOutput {
            base_address: 0,
            size: 0,
            old_protect: 0,
            status: 0,
        };
        let mut returned: DWORD = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_PROTECT_PROCESS_MEMORY,
                &input as *const _ as LPVOID,
                size_of::<CeProtectMemoryInput>() as DWORD,
                &mut output as *mut _ as LPVOID,
                size_of::<CeProtectMemoryOutput>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };

        let old_protect = output.old_protect;
        let status = output.status;
        if ok == TRUE {
            Ok(old_protect)
        } else {
            Err(format!(
                "OnyxDriver IOCTL_CE_PROTECT_PROCESS_MEMORY failed for PID {} at {:#X} (status {:#X})",
                pid, base_address, status
            ))
        }
    }
}
