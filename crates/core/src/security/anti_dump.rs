use crate::win32::*;
use std::ffi::c_void;

pub struct AntiDump;

impl AntiDump {
    pub fn distort_peb_size_of_image(extra_bytes: u32) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        unsafe {
            let peb_ptr = Self::get_peb_address();
            if peb_ptr.is_null() {
                return Err("Failed to resolve PEB address".to_string());
            }

            let (ldr_offset, list_entry_offset, size_of_image_offset) = if cfg!(target_pointer_width = "64") {
                (0x18usize, 0x10usize, 0x40usize)
            } else {
                (0x0Cusize, 0x0Cusize, 0x20usize)
            };

            let ldr_ptr = *(peb_ptr.add(ldr_offset) as *const *mut u8);
            if ldr_ptr.is_null() {
                return Err("PEB.Ldr is null".to_string());
            }

            let first_entry = *(ldr_ptr.add(list_entry_offset) as *const *mut u8);
            if first_entry.is_null() {
                return Err("InLoadOrderModuleList is empty".to_string());
            }

            let size_of_image_ptr = first_entry.add(size_of_image_offset) as *mut u32;

            let old_val = *size_of_image_ptr;
            *size_of_image_ptr = old_val.wrapping_add(extra_bytes);

            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = extra_bytes;
            Ok(())
        }
    }

    pub fn erase_pe_headers(module_base: usize) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        unsafe {
            if module_base == 0 {
                return Err("Invalid module base".to_string());
            }

            let base = module_base as *mut u8;
            let mut old_protect: DWORD = 0;

            if VirtualProtect(
                base as *mut c_void,
                0x1000,
                PAGE_READWRITE,
                &mut old_protect,
            ) == TRUE
            {
                std::ptr::write_bytes(base, 0, 0x1000);
                let mut dummy: DWORD = 0;
                VirtualProtect(base as *mut c_void, 0x1000, old_protect, &mut dummy);
                Ok(())
            } else {
                Err("Failed to change memory protection for PE header".to_string())
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = module_base;
            Ok(())
        }
    }

    #[cfg(target_os = "windows")]
    unsafe fn get_peb_address() -> *mut u8 {
        type NtQueryInfoProcessFn =
            unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32;

        unsafe {
            let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
            if ntdll.is_null() {
                return std::ptr::null_mut();
            }

            let p_fn = GetProcAddress(ntdll, b"NtQueryInformationProcess\0".as_ptr());
            if p_fn.is_null() {
                return std::ptr::null_mut();
            }

            let query_fn: NtQueryInfoProcessFn = std::mem::transmute(p_fn);

            #[repr(C)]
            struct ProcessBasicInformation {
                exit_status: i32,
                peb_base_address: *mut u8,
                affinity_mask: usize,
                base_priority: i32,
                unique_process_id: usize,
                inherited_from_unique_process_id: usize,
            }

            let mut pbi: ProcessBasicInformation = std::mem::zeroed();
            let mut ret_len: u32 = 0;
            let status = query_fn(
                GetCurrentProcess(),
                0,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut ret_len,
            );

            if status >= 0 {
                pbi.peb_base_address
            } else {
                std::ptr::null_mut()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_dump_distort() {
        let res = AntiDump::distort_peb_size_of_image(0x100000);
        #[cfg(target_os = "windows")]
        {
            assert!(res.is_ok());
        }
    }
}
