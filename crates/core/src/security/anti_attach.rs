use std::ffi::c_void;
use crate::win32::*;

const RET_ZERO_STUB: [u8; 3] = [0x31, 0xC0, 0xC3];
const NOP_RET_STUB: [u8; 2] = [0x90, 0xC3];

pub struct AntiAttach;

impl AntiAttach {
    pub fn enable() -> Result<(), String> {
        #[cfg(target_os = "windows")]
        unsafe {
            let ntdll_name = b"ntdll.dll\0";
            let h_ntdll = GetModuleHandleA(ntdll_name.as_ptr());
            if h_ntdll.is_null() {
                return Err("Failed to obtain handle to ntdll.dll".to_string());
            }

            let breakin_name = b"DbgUiRemoteBreakin\0";
            let p_breakin = GetProcAddress(h_ntdll, breakin_name.as_ptr());
            if !p_breakin.is_null() {
                Self::patch_memory(p_breakin as *mut u8, &RET_ZERO_STUB)?;
            }

            let breakpoint_name = b"DbgBreakPoint\0";
            let p_breakpoint = GetProcAddress(h_ntdll, breakpoint_name.as_ptr());
            if !p_breakpoint.is_null() {
                Self::patch_memory(p_breakpoint as *mut u8, &NOP_RET_STUB)?;
            }

            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(())
        }
    }

    unsafe fn patch_memory(target: *mut u8, patch: &[u8]) -> Result<(), String> {
        let mut old_protect: DWORD = 0;
        let ok = VirtualProtect(
            target as *mut c_void,
            patch.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );

        if ok != TRUE {
            return Err("VirtualProtect PAGE_EXECUTE_READWRITE failed".to_string());
        }

        unsafe {
            std::ptr::copy_nonoverlapping(patch.as_ptr(), target, patch.len());
        }

        let mut dummy: DWORD = 0;
        unsafe {
            VirtualProtect(target as *mut c_void, patch.len(), old_protect, &mut dummy);
        }

        Ok(())
    }

    pub fn is_active() -> bool {
        #[cfg(target_os = "windows")]
        unsafe {
            let ntdll_name = b"ntdll.dll\0";
            let h_ntdll = GetModuleHandleA(ntdll_name.as_ptr());
            if h_ntdll.is_null() {
                return false;
            }

            let breakin_name = b"DbgUiRemoteBreakin\0";
            let p_breakin = GetProcAddress(h_ntdll, breakin_name.as_ptr()) as *const u8;
            if p_breakin.is_null() {
                return false;
            }

            *p_breakin == RET_ZERO_STUB[0]
                && *p_breakin.add(1) == RET_ZERO_STUB[1]
                && *p_breakin.add(2) == RET_ZERO_STUB[2]
        }
        #[cfg(not(target_os = "windows"))]
        {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_attach_lifecycle() {
        let _ = AntiAttach::enable();
        #[cfg(target_os = "windows")]
        {
            assert!(AntiAttach::is_active());
        }
    }
}
