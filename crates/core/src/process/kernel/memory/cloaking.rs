use crate::process::ModuleEntry;
use crate::process::kernel::OnyxDriver;
use crate::process::kernel::types::*;
use crate::win32::*;
use std::mem::size_of;
use std::ptr::null_mut;

impl OnyxDriver {
    pub fn cloak_page(&self, pid: u32, virtual_address: u64) -> Result<(), String> {
        let input = CeCloakInput {
            process_id: pid,
            virtual_address,
        };
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_CLOAK_PAGE,
                &input as *const _ as LPVOID,
                size_of::<CeCloakInput>() as DWORD,
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
                "IOCTL_CE_CLOAK_PAGE failed for PID {} at {:#X}",
                pid, virtual_address
            ))
        }
    }

    pub fn uncloak_page(&self, pid: u32, virtual_address: u64) -> Result<(), String> {
        let input = CeCloakInput {
            process_id: pid,
            virtual_address,
        };
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_UNCLOAK_PAGE,
                &input as *const _ as LPVOID,
                size_of::<CeCloakInput>() as DWORD,
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
                "IOCTL_CE_UNCLOAK_PAGE failed for PID {} at {:#X}",
                pid, virtual_address
            ))
        }
    }

    pub fn write_cloaked(&self, pid: u32, virtual_address: u64, data: &[u8]) -> Result<(), String> {
        let header_size = size_of::<CeWriteCloakedHeader>();
        let total_size = header_size + data.len();
        let mut buffer = vec![0u8; total_size];

        let header = CeWriteCloakedHeader {
            process_id: pid,
            virtual_address,
            size: data.len() as u32,
        };

        unsafe {
            std::ptr::copy_nonoverlapping(
                &header as *const _ as *const u8,
                buffer.as_mut_ptr(),
                header_size,
            );
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                buffer.as_mut_ptr().add(header_size),
                data.len(),
            );
        }

        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_WRITE_CLOAKED,
                buffer.as_ptr() as LPVOID,
                total_size as DWORD,
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
                "IOCTL_CE_WRITE_CLOAKED failed for PID {} at {:#X}",
                pid, virtual_address
            ))
        }
    }

    pub fn cloak_region(&self, pid: u32, virtual_address: u64, data: &[u8]) -> Result<(), String> {
        let header_size = size_of::<CeCloakRegionHeader>();
        let total_size = header_size + data.len();
        let mut buffer = vec![0u8; total_size];

        let header = CeCloakRegionHeader {
            process_id: pid as u64,
            virtual_address,
            size: data.len() as u32,
        };

        unsafe {
            std::ptr::copy_nonoverlapping(
                &header as *const _ as *const u8,
                buffer.as_mut_ptr(),
                header_size,
            );
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                buffer.as_mut_ptr().add(header_size),
                data.len(),
            );
        }

        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_CLOAK_REGION,
                buffer.as_ptr() as LPVOID,
                total_size as DWORD,
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
                "IOCTL_CE_CLOAK_REGION failed for PID {} at {:#X}",
                pid, virtual_address
            ))
        }
    }

    pub fn get_dbvm_status(&self) -> Result<(bool, u32), String> {
        let mut status = CeDbvmStatusOutput::default();
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_GET_DBVM_STATUS,
                null_mut(),
                0,
                &mut status as *mut _ as LPVOID,
                size_of::<CeDbvmStatusOutput>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok((status.is_active != 0, status.version))
        } else {
            Err("IOCTL_CE_GET_DBVM_STATUS failed".to_string())
        }
    }
}
