// language: Rust, file: kernel.rs, target: Windows 11, MSVC
// Cheat Engine DBKKernel driver client interface (DBK64 / DBK32)

use std::mem::size_of;
use std::ptr::null_mut;
use crate::win32::*;

// Exact IOCTL codes calculated from Cheat Engine DBKKernel/IOPLDispatcher.h:
// CTL_CODE(FILE_DEVICE_UNKNOWN = 0x22, func, METHOD_BUFFERED = 0, FILE_READ_ACCESS | FILE_WRITE_ACCESS = 3)
pub const IOCTL_CE_READMEMORY: DWORD = 0x22E000;
pub const IOCTL_CE_WRITEMEMORY: DWORD = 0x22E004;
pub const IOCTL_CE_OPENPROCESS: DWORD = 0x22E008;
pub const IOCTL_CE_QUERY_VIRTUAL_MEMORY: DWORD = 0x22E00C;
pub const IOCTL_CE_TEST: DWORD = 0x22E010;
pub const IOCTL_CE_GETPEPROCESS: DWORD = 0x22E014;
pub const IOCTL_CE_READPHYSICALMEMORY: DWORD = 0x22E018;
pub const IOCTL_CE_WRITEPHYSICALMEMORY: DWORD = 0x22E01C;
pub const IOCTL_CE_GETPHYSICALADDRESS: DWORD = 0x22E020;
pub const IOCTL_CE_GETCR3: DWORD = 0x22E028;
pub const IOCTL_CE_SETCR3: DWORD = 0x22E02C;
pub const IOCTL_CE_GETVERSION: DWORD = 0x22E058;

#[repr(C, packed)]
struct CeReadMemoryInput {
    process_id: u64,
    start_address: u64,
    bytes_to_read: u16,
}

#[repr(C, packed)]
struct CeWriteMemoryHeader {
    process_id: u64,
    start_address: u64,
    bytes_to_write: u16,
}

#[repr(C)]
#[allow(dead_code)]
struct CeOpenProcessOutput {
    handle: u64,
    special: u8,
}

pub struct DbkDriver {
    pub device_handle: HANDLE,
    pub device_name: String,
}

unsafe impl Send for DbkDriver {}
unsafe impl Sync for DbkDriver {}

impl DbkDriver {
    /// Attempts to open a handle to \\.\DBK64, \\.\DBK32 or official CE driver versions
    pub fn connect() -> Result<Self, String> {
        let names = [
            "\\\\.\\DBK64",
            "\\\\.\\DBK32",
            "\\\\.\\CEDRIVER77",
            "\\\\.\\CEDRIVER76",
            "\\\\.\\CEDRIVER75",
            "\\\\.\\CEDRIVER74",
            "\\\\.\\CEDRIVER73",
        ];

        for name in &names {
            let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            let handle = unsafe {
                CreateFileW(
                    wide_name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null_mut(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    null_mut(),
                )
            };

            if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
                return Ok(DbkDriver {
                    device_handle: handle,
                    device_name: name.to_string(),
                });
            }
        }

        Err("Failed to connect to Cheat Engine kernel driver (DBK64/CEDRIVER77). Is DBK loaded?".to_string())
    }

    /// Verifies driver communication via IOCTL_CE_TEST
    pub fn test(&self) -> bool {
        let mut returned: DWORD = 0;
        let mut test_val: u32 = 0xAA55AA55;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_TEST,
                &mut test_val as *mut _ as LPVOID,
                size_of::<u32>() as DWORD,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        ok == TRUE
    }

    /// Queries DBK driver version
    pub fn get_version(&self) -> Result<u32, String> {
        let mut version: u32 = 0;
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_GETVERSION,
                null_mut(),
                0,
                &mut version as *mut _ as LPVOID,
                size_of::<u32>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(version)
        } else {
            Err("Failed to query DBK version".to_string())
        }
    }

    /// Kernel-level process handle acquisition (strips anti-cheat handle protection)
    pub fn open_process(&self, pid: u32) -> Result<HANDLE, String> {
        let mut input_pid: u64 = pid as u64;
        let mut output: CeOpenProcessOutput = unsafe { std::mem::zeroed() };
        let mut returned: DWORD = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_OPENPROCESS,
                &mut input_pid as *mut _ as LPVOID,
                size_of::<u64>() as DWORD,
                &mut output as *mut _ as LPVOID,
                size_of::<CeOpenProcessOutput>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };

        if ok == TRUE && output.handle != 0 {
            Ok(output.handle as HANDLE)
        } else {
            Err(format!("DBK IOCTL_CE_OPENPROCESS failed for PID {}", pid))
        }
    }

    /// Reads process memory via the DBKKernel driver (bypasses usermode hooks and stripped handles)
    pub fn read_memory(&self, pid: u32, address: usize, len: usize) -> Result<Vec<u8>, String> {
        let mut result = Vec::with_capacity(len);
        let mut offset = 0;

        // DBK reads in chunks of max 65535 bytes
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
                return Err(format!("DBK IOCTL_CE_READMEMORY failed at 0x{:X}", address + offset));
            }
        }

        Ok(result)
    }

    /// Writes process memory via DBKKernel driver
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
                return Err(format!("DBK IOCTL_CE_WRITEMEMORY failed at 0x{:X}", address + offset));
            }
        }

        Ok(total_written)
    }

    /// Obtains CR3 register for a process
    pub fn get_cr3(&self, pid: u32) -> Result<u64, String> {
        let mut input_pid = pid;
        let mut cr3: u64 = 0;
        let mut returned: DWORD = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_GETCR3,
                &mut input_pid as *mut _ as LPVOID,
                size_of::<u32>() as DWORD,
                &mut cr3 as *mut _ as LPVOID,
                size_of::<u64>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };

        if ok == TRUE {
            Ok(cr3)
        } else {
            Err(format!("DBK IOCTL_CE_GETCR3 failed for PID {}", pid))
        }
    }
}

impl Drop for DbkDriver {
    fn drop(&mut self) {
        if !self.device_handle.is_null() && self.device_handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.device_handle);
            }
        }
    }
}
