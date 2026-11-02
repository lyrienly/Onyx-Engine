use super::OnyxDriver;
use super::types::*;
use crate::process::ModuleEntry;
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
