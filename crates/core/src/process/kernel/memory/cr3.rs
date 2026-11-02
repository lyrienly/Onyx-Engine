use crate::process::ModuleEntry;
use crate::process::kernel::OnyxDriver;
use crate::process::kernel::types::*;
use crate::win32::*;
use std::mem::size_of;
use std::ptr::null_mut;

impl OnyxDriver {
    pub fn is_canonical_va(va: u64) -> bool {
        let high = va >> 47;
        high == 0 || high == 0x1FFFF
    }

    pub fn translate_cr3(&self, pid: u32, virtual_address: u64) -> Result<u64, String> {
        if !Self::is_canonical_va(virtual_address) {
            return Err(format!(
                "Non-canonical virtual address 0x{:X} rejected for CR3 translation",
                virtual_address
            ));
        }

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
            Err(format!("OnyxDriver IOCTL_CE_GETCR3 failed for PID {}", pid))
        }
    }

    pub fn read_memory_cr3(&self, pid: u32, address: u64, len: usize) -> Result<Vec<u8>, String> {
        self.bulk_dump_cr3(pid, address, len)
    }

    pub fn write_memory_cr3(&self, pid: u32, address: u64, data: &[u8]) -> Result<usize, String> {
        self.write_memory(pid, address as usize, data)
    }
}
