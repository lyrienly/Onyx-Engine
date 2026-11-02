//! onyx_shield: standalone injectable anti-analysis and process hardening DLL.
//!
//! Exposes a full C-ABI dynamic library wrapper around OnyxEngine's security shield:
//! - Anti-debugger audit and continuous PEB cloaking
//! - Anti-attach hooks (`DbgBreakPoint`, `DbgUiRemoteBreakin`)
//! - Analysis window & process hunter (x64dbg, IDA, Wireshark, Process Hacker)
//! - PE header distortion and Taskmgr cloaking

use core::sync::atomic::{AtomicBool, Ordering};

use onyx_core::security::{activate_full_onyx_shield, AntiDebug, AntiDump};

static SHIELD_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Starts background security surveillance and hardening.
#[no_mangle]
pub unsafe extern "C" fn onyx_shield_start() -> i32 {
    if SHIELD_ACTIVE.swap(true, Ordering::SeqCst) {
        return 1; // Already active
    }

    match activate_full_onyx_shield(None) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

/// Stops background security surveillance threads.
#[no_mangle]
pub unsafe extern "C" fn onyx_shield_stop() -> i32 {
    SHIELD_ACTIVE.store(false, Ordering::SeqCst);
    1
}

/// Returns 1 if protection shield is actively running, 0 otherwise.
#[no_mangle]
pub unsafe extern "C" fn onyx_shield_status() -> u32 {
    if SHIELD_ACTIVE.load(Ordering::Relaxed) {
        1
    } else {
        0
    }
}

/// Erases PE headers of the target module in memory.
#[no_mangle]
pub unsafe extern "C" fn onyx_shield_erase_pe_headers(module_base: usize) -> i32 {
    match AntiDump::erase_pe_headers(module_base) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

/// Hides current thread from kernel-level debugger attaching.
#[no_mangle]
pub unsafe extern "C" fn onyx_shield_hide_current_thread() -> i32 {
    match AntiDebug::hide_current_thread() {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

/// Audits environment and returns bitmask of detected debugging mechanisms.
#[no_mangle]
pub unsafe extern "C" fn onyx_shield_audit_threats() -> u32 {
    let report = AntiDebug::audit();
    let mut flags = 0u32;
    if report.debugger_present {
        flags |= 1 << 0;
    }
    if report.remote_debugger {
        flags |= 1 << 1;
    }
    if report.hardware_breakpoints {
        flags |= 1 << 2;
    }
    if report.peb_being_debugged {
        flags |= 1 << 3;
    }
    if report.peb_nt_global_flag != 0 {
        flags |= 1 << 4;
    }
    flags
}

#[cfg(windows)]
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: *mut core::ffi::c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut core::ffi::c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;

    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            let _ = onyx_shield_start();
        }
        DLL_PROCESS_DETACH => {
            let _ = onyx_shield_stop();
        }
        _ => {}
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shield_lifecycle() {
        let _ = unsafe { onyx_shield_status() };
        let _ = unsafe { onyx_shield_audit_threats() };
    }
}
