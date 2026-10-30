use crate::process::ModuleEntry;
use crate::win32::*;
use std::mem::size_of;
use std::ptr::null_mut;

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

pub const IOCTL_CE_GET_BASE: DWORD = 0x22E18C;
pub const IOCTL_CE_HIDEDRIVER: DWORD = 0x22E190;
pub const IOCTL_CE_ENUM_VAD_MODULES: DWORD = 0x22E194;
pub const IOCTL_CE_TRANSLATE_CR3: DWORD = 0x22E198;
pub const IOCTL_CE_CLOAK_PAGE: DWORD = 0x22E19C;
pub const IOCTL_CE_UNCLOAK_PAGE: DWORD = 0x22E1A0;
pub const IOCTL_CE_WRITE_CLOAKED: DWORD = 0x22E1A4;
pub const IOCTL_CE_BULK_DUMP_CR3: DWORD = 0x22E1A8;
pub const IOCTL_CE_STEALTH_READ_PTE: DWORD = 0x22E1AC;
pub const IOCTL_CE_STRIP_CALLBACKS: DWORD = 0x22E1B4;
pub const IOCTL_CE_PATTERN_SCAN: DWORD = 0x22E1B8;
pub const IOCTL_CE_FREEZE_PROCESS: DWORD = 0x22E1BC;
pub const IOCTL_CE_SET_PROCESS_PROTECTION: DWORD = 0x22E1C0;
pub const IOCTL_CE_CLEAN_KERNEL_TRACES: DWORD = 0x22E1C4;
pub const IOCTL_CE_CLOAK_DEVICE_SYMLINK: DWORD = 0x22E1C8;
pub const IOCTL_CE_PHYSICAL_RAM_SCAVENGE: DWORD = 0x22E1CC;
pub const IOCTL_CE_HIDE_PROCESS: DWORD = 0x22E1EC;

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

#[repr(C, packed)]
struct CeTranslateCr3Input {
    process_id: u32,
    virtual_address: u64,
}

#[repr(C, packed)]
struct CeBulkDumpInput {
    process_id: u64,
    base_address: u64,
    size: u32,
}

#[repr(C, packed)]
struct CeStripCallbacksInput {
    restore: u32,
}

#[repr(C, packed)]
struct CeFreezeProcessInput {
    process_id: u64,
    freeze: u32,
}

#[repr(C, packed)]
struct CeSetProtectionInput {
    process_id: u64,
    enable: u32,
}

#[repr(C, packed)]
struct CePatternScanInput {
    process_id: u64,
    start_address: u64,
    scan_size: u64,
    pattern_length: u32,
    pattern: [u8; 64],
    mask: [u8; 64],
}

#[repr(C)]
struct CePatternScanOutput {
    match_count: u32,
    matches: [u64; 32],
}

#[repr(C)]
struct VadModuleEntryRaw {
    base_address: u64,
    module_size: u64,
    module_name: [u16; 64],
    full_path: [u16; 260],
}

#[repr(C)]
struct VadEnumOutputHeader {
    count: u32,
}

pub struct DbkDriver {
    pub device_handle: HANDLE,
    pub device_name: String,
}

unsafe impl Send for DbkDriver {}
unsafe impl Sync for DbkDriver {}

impl DbkDriver {
    pub fn connect_device(device_path: &str) -> Result<Self, String> {
        let wide_name: Vec<u16> = device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
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
            let driver = DbkDriver {
                device_handle: handle,
                device_name: device_path.to_string(),
            };

            let _ = driver.hide_driver();
            let _ = driver.clean_traces();
            Ok(driver)
        } else {
            Err(format!("Failed to open device {}", device_path))
        }
    }

    pub fn connect() -> Result<Self, String> {
        let names = [
            "\\\\.\\OwMemDriver",
            "\\\\.\\lydumen",
            "\\\\.\\DBK64",
            "\\\\.\\DBK32",
            "\\\\.\\CEDRIVER77",
            "\\\\.\\CEDRIVER76",
            "\\\\.\\CEDRIVER75",
            "\\\\.\\CEDRIVER74",
            "\\\\.\\CEDRIVER73",
        ];

        for name in &names {
            if let Ok(driver) = Self::connect_device(name) {
                return Ok(driver);
            }
        }

        Err(
            "Failed to connect to kernel driver (OwMemDriver/lydumen/DBK64). Is driver loaded?"
                .to_string(),
        )
    }

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

    pub fn hide_driver(&self) -> Result<(), String> {
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_HIDEDRIVER,
                null_mut(),
                0,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(())
        } else {
            Err("Failed to hide driver from PsLoadedModuleList".to_string())
        }
    }

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
            Err(format!("Failed to hide process PID {} via DKOM", pid))
        }
    }

    pub fn strip_callbacks(&self, restore: bool) -> Result<u32, String> {
        let mut inp = CeStripCallbacksInput {
            restore: if restore { 1 } else { 0 },
        };
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
            Err("Failed to strip process callbacks".to_string())
        }
    }

    pub fn clean_traces(&self) -> Result<(), String> {
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_CLEAN_KERNEL_TRACES,
                null_mut(),
                0,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(())
        } else {
            Err("Failed to clean kernel driver traces".to_string())
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

    pub fn cloak_symlink(&self, new_symlink: &str) -> Result<(), String> {
        let wide: Vec<u16> = new_symlink
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_CLOAK_DEVICE_SYMLINK,
                wide.as_ptr() as LPVOID,
                (wide.len() * 2) as DWORD,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE {
            Ok(())
        } else {
            Err("Failed to cloak device symlink".to_string())
        }
    }

    pub fn get_process_base(&self, pid: u32) -> Result<u64, String> {
        let mut input_pid = pid;
        let mut base_addr: u64 = 0;
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_GET_BASE,
                &mut input_pid as *mut _ as LPVOID,
                size_of::<u32>() as DWORD,
                &mut base_addr as *mut _ as LPVOID,
                size_of::<u64>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE && base_addr != 0 {
            Ok(base_addr)
        } else {
            Err(format!(
                "Failed to resolve process base via kernel for PID {}",
                pid
            ))
        }
    }

    pub fn translate_cr3(&self, pid: u32, virtual_address: u64) -> Result<u64, String> {
        let mut inp = CeTranslateCr3Input {
            process_id: pid,
            virtual_address,
        };
        let mut phys_addr: u64 = 0;
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_TRANSLATE_CR3,
                &mut inp as *mut _ as LPVOID,
                size_of::<CeTranslateCr3Input>() as DWORD,
                &mut phys_addr as *mut _ as LPVOID,
                size_of::<u64>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE && phys_addr != 0 {
            Ok(phys_addr)
        } else {
            Err(format!(
                "Failed to translate VA 0x{:X} via CR3 for PID {}",
                virtual_address, pid
            ))
        }
    }

    pub fn bulk_dump_cr3(
        &self,
        pid: u32,
        base_address: u64,
        size: usize,
    ) -> Result<Vec<u8>, String> {
        let mut output = vec![0u8; size];
        let inp = CeBulkDumpInput {
            process_id: pid as u64,
            base_address,
            size: size as u32,
        };
        let mut returned: DWORD = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_BULK_DUMP_CR3,
                &inp as *const _ as LPVOID,
                size_of::<CeBulkDumpInput>() as DWORD,
                output.as_mut_ptr() as LPVOID,
                size as DWORD,
                &mut returned,
                null_mut(),
            )
        };
        if ok == TRUE && returned > 0 {
            output.truncate(returned as usize);
            Ok(output)
        } else {
            Err(format!("Bulk dump CR3 failed at 0x{:X}", base_address))
        }
    }

    pub fn pattern_scan_cr3(
        &self,
        pid: u32,
        start_address: u64,
        scan_size: u64,
        pattern: &[u8],
        mask: &[u8],
    ) -> Result<Vec<u64>, String> {
        if pattern.is_empty() || pattern.len() > 64 || pattern.len() != mask.len() {
            return Err("Invalid pattern or mask length (max 64 bytes)".to_string());
        }

        let mut inp = CePatternScanInput {
            process_id: pid as u64,
            start_address,
            scan_size,
            pattern_length: pattern.len() as u32,
            pattern: [0u8; 64],
            mask: [0u8; 64],
        };
        inp.pattern[..pattern.len()].copy_from_slice(pattern);
        inp.mask[..mask.len()].copy_from_slice(mask);

        let mut out: CePatternScanOutput = unsafe { std::mem::zeroed() };
        let mut returned: DWORD = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_PATTERN_SCAN,
                &mut inp as *mut _ as LPVOID,
                size_of::<CePatternScanInput>() as DWORD,
                &mut out as *mut _ as LPVOID,
                size_of::<CePatternScanOutput>() as DWORD,
                &mut returned,
                null_mut(),
            )
        };

        if ok == TRUE {
            let count = (out.match_count as usize).min(32);
            Ok(out.matches[..count].to_vec())
        } else {
            Err("Kernel pattern scan failed".to_string())
        }
    }

    pub fn enum_vad_modules(&self, pid: u32) -> Result<Vec<ModuleEntry>, String> {
        const MAX_MODULES: usize = 256;
        let buf_size =
            size_of::<VadEnumOutputHeader>() + MAX_MODULES * size_of::<VadModuleEntryRaw>();
        let mut buffer = vec![0u8; buf_size];
        let mut input_pid = pid;
        let mut returned: DWORD = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.device_handle,
                IOCTL_CE_ENUM_VAD_MODULES,
                &mut input_pid as *mut _ as LPVOID,
                size_of::<u32>() as DWORD,
                buffer.as_mut_ptr() as LPVOID,
                buf_size as DWORD,
                &mut returned,
                null_mut(),
            )
        };

        if ok != TRUE || returned < size_of::<VadEnumOutputHeader>() as DWORD {
            return Err(format!("Failed to enumerate VAD modules for PID {}", pid));
        }

        let header = unsafe { &*(buffer.as_ptr() as *const VadEnumOutputHeader) };
        let count = (header.count as usize).min(MAX_MODULES);
        let entries_ptr = unsafe {
            buffer.as_ptr().add(size_of::<VadEnumOutputHeader>()) as *const VadModuleEntryRaw
        };

        let mut modules = Vec::with_capacity(count);
        for i in 0..count {
            let entry = unsafe { &*entries_ptr.add(i) };
            let name_len = entry
                .module_name
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.module_name.len());
            let name = String::from_utf16_lossy(&entry.module_name[..name_len]);

            let path_len = entry
                .full_path
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.full_path.len());
            let path = String::from_utf16_lossy(&entry.full_path[..path_len]);

            if !name.is_empty() && entry.base_address > 0 {
                modules.push(ModuleEntry {
                    name,
                    path,
                    base: entry.base_address as usize,
                    size: entry.module_size as usize,
                });
            }
        }

        Ok(modules)
    }

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
                    "DBK IOCTL_CE_READMEMORY failed at 0x{:X}",
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
                    "DBK IOCTL_CE_WRITEMEMORY failed at 0x{:X}",
                    address + offset
                ));
            }
        }

        Ok(total_written)
    }

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

    pub fn read_memory_cr3(&self, pid: u32, address: u64, len: usize) -> Result<Vec<u8>, String> {
        self.bulk_dump_cr3(pid, address, len)
    }

    pub fn is_secure_boot_active() -> bool {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("powershell")
                .args(["-NoProfile", "-Command", "Confirm-SecureBootUEFI 2>$null"])
                .output()
            {
                let text = String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .to_lowercase();
                if text == "true" {
                    return true;
                }
            }
        }
        false
    }

    pub fn is_test_signing_enabled() -> bool {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("bcdedit")
                .args(["/enum", "{current}"])
                .output()
            {
                let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
                if text.contains("testsigning") && text.contains("yes") {
                    return true;
                }
            }
        }
        false
    }

    pub fn is_vbs_active() -> bool {
        #[cfg(target_os = "windows")]
        {
            let subkey: Vec<u16> = "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\0"
                .encode_utf16()
                .collect();
            let val_vbs: Vec<u16> = "EnableVirtualizationBasedSecurity\0"
                .encode_utf16()
                .collect();
            let mut data: u32 = 0;
            let mut size: DWORD = std::mem::size_of::<u32>() as DWORD;

            let res = unsafe {
                RegGetValueW(
                    HKEY_LOCAL_MACHINE,
                    subkey.as_ptr(),
                    val_vbs.as_ptr(),
                    RRF_RT_REG_DWORD,
                    std::ptr::null_mut(),
                    &mut data as *mut _ as LPVOID,
                    &mut size,
                )
            };

            if res == 0 && data == 1 {
                return true;
            }

            use std::process::Command;
            if let Ok(output) = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    "(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard 2>$null).VirtualizationBasedSecurityStatus",
                ])
                .output()
            {
                let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if text == "2" || text == "1" {
                    return true;
                }
            }
        }
        false
    }

    pub fn is_hvci_active() -> bool {
        #[cfg(target_os = "windows")]
        {
            let subkey_scenario: Vec<u16> =
                "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\0"
                    .encode_utf16()
                    .collect();
            let val_enabled: Vec<u16> = "Enabled\0".encode_utf16().collect();
            let mut data: u32 = 0;
            let mut size: DWORD = std::mem::size_of::<u32>() as DWORD;

            let res = unsafe {
                RegGetValueW(
                    HKEY_LOCAL_MACHINE,
                    subkey_scenario.as_ptr(),
                    val_enabled.as_ptr(),
                    RRF_RT_REG_DWORD,
                    std::ptr::null_mut(),
                    &mut data as *mut _ as LPVOID,
                    &mut size,
                )
            };

            if res == 0 && data == 1 {
                return true;
            }

            let subkey_dg: Vec<u16> = "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\0"
                .encode_utf16()
                .collect();
            let val_hvci: Vec<u16> = "HypervisorEnforcedCodeIntegrity\0".encode_utf16().collect();
            size = std::mem::size_of::<u32>() as DWORD;

            let res2 = unsafe {
                RegGetValueW(
                    HKEY_LOCAL_MACHINE,
                    subkey_dg.as_ptr(),
                    val_hvci.as_ptr(),
                    RRF_RT_REG_DWORD,
                    std::ptr::null_mut(),
                    &mut data as *mut _ as LPVOID,
                    &mut size,
                )
            };

            if res2 == 0 && data == 1 {
                return true;
            }

            use std::process::Command;
            if let Ok(output) = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    "((Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard 2>$null).SecurityServicesRunning -contains 2)",
                ])
                .output()
            {
                let text = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
                if text == "true" {
                    return true;
                }
            }
        }
        false
    }

    pub fn is_cr3_interception_risk() -> bool {
        Self::is_vbs_active()
    }

    pub fn evaluate_security_profile() -> KernelSecurityProfile {
        let secure_boot = Self::is_secure_boot_active();
        let test_signing = Self::is_test_signing_enabled();
        let vbs = Self::is_vbs_active();
        let hvci = Self::is_hvci_active();
        let cr3_risk = vbs;

        KernelSecurityProfile {
            secure_boot_active: secure_boot,
            test_signing_active: test_signing,
            vbs_active: vbs,
            hvci_active: hvci,
            cr3_interception_risk: cr3_risk,
        }
    }

    pub fn check_cr3_intercept_advisory(pid: u32) -> Option<String> {
        if Self::is_cr3_interception_risk() {
            Some(format!(
                "Aviso: VBS (Seguranca Baseada em Virtualizacao) esta ativo. Traducoes fisicas de CR3 para o PID {} operam sob SLAT/EPT do hipervisor; paginas protegidas do Secure Kernel (VTL 1) nao podem ser acessadas diretamente.",
                pid
            ))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KernelSecurityProfile {
    pub secure_boot_active: bool,
    pub test_signing_active: bool,
    pub vbs_active: bool,
    pub hvci_active: bool,
    pub cr3_interception_risk: bool,
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
