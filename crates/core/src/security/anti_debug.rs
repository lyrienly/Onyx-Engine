use crate::win32::*;
use std::ffi::c_void;

const THREAD_HIDE_FROM_DEBUGGER: u32 = 0x11;

type NtSetInformationThreadFn = unsafe extern "system" fn(
    thread_handle: HANDLE,
    thread_information_class: u32,
    thread_information: *mut c_void,
    thread_information_length: u32,
) -> i32;

pub struct AntiDebug;

impl AntiDebug {
    pub fn hide_current_thread() -> Result<(), String> {
        #[cfg(target_os = "windows")]
        unsafe {
            let ntdll_name = b"ntdll.dll\0";
            let h_ntdll = GetModuleHandleA(ntdll_name.as_ptr());
            if h_ntdll.is_null() {
                return Err("Failed to obtain handle to ntdll.dll".to_string());
            }

            let fn_name = b"NtSetInformationThread\0";
            let p_fn = GetProcAddress(h_ntdll, fn_name.as_ptr());
            if p_fn.is_null() {
                return Err("NtSetInformationThread not found".to_string());
            }

            let nt_set_info: NtSetInformationThreadFn = std::mem::transmute(p_fn);
            let status = nt_set_info(
                GetCurrentThread(),
                THREAD_HIDE_FROM_DEBUGGER,
                std::ptr::null_mut(),
                0,
            );

            if status >= 0 {
                Ok(())
            } else {
                Err(format!(
                    "NtSetInformationThread failed with NTSTATUS 0x{:X}",
                    status
                ))
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok(())
        }
    }

    pub fn has_hardware_breakpoints() -> bool {
        #[cfg(target_os = "windows")]
        unsafe {
            let mut ctx: CONTEXT = std::mem::zeroed();
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            let h_thread = GetCurrentThread();
            if GetThreadContext(h_thread, &mut ctx) == TRUE {
                let dr_active = ctx.Dr0 != 0
                    || ctx.Dr1 != 0
                    || ctx.Dr2 != 0
                    || ctx.Dr3 != 0
                    || (ctx.Dr7 & 0xFF) != 0;
                return dr_active;
            }
        }
        false
    }

    pub fn is_remote_debugger_present() -> bool {
        #[cfg(target_os = "windows")]
        unsafe {
            let mut is_debugger: BOOL = FALSE;
            if CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut is_debugger) == TRUE {
                return is_debugger == TRUE;
            }
        }
        false
    }

    pub fn is_debugger_present() -> bool {
        #[cfg(target_os = "windows")]
        unsafe {
            if IsDebuggerPresent() == TRUE {
                return true;
            }
        }
        false
    }

    pub fn audit() -> AntiDebugReport {
        AntiDebugReport {
            debugger_present: Self::is_debugger_present(),
            remote_debugger: Self::is_remote_debugger_present(),
            hardware_breakpoints: Self::has_hardware_breakpoints(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AntiDebugReport {
    pub debugger_present: bool,
    pub remote_debugger: bool,
    pub hardware_breakpoints: bool,
}

impl AntiDebugReport {
    pub fn is_under_analysis(&self) -> bool {
        self.debugger_present || self.remote_debugger || self.hardware_breakpoints
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_debug_checks() {
        let report = AntiDebug::audit();
        assert!(!report.hardware_breakpoints);
        let _ = AntiDebug::hide_current_thread();
    }
}
