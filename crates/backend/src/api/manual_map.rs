use std::ffi::CStr;
use std::os::raw::c_char;

use onyx_core::injection::auxiliary::AuxiliaryInjector;
use onyx_core::process::Process;

#[no_mangle]
pub extern "C" fn onyx_manual_map_dll(target_pid: u32, dll_path: *const c_char) -> i32 {
    if target_pid == 0 || dll_path.is_null() {
        return -1;
    }

    let path = match unsafe { CStr::from_ptr(dll_path) }.to_str() {
        Ok(p) => p,
        Err(_) => return -2,
    };

    let proc = match Process::attach(target_pid) {
        Ok(p) => p,
        Err(_) => return -3,
    };

    match AuxiliaryInjector::inject_from_file(&proc, path, None) {
        Ok(_) => 0,
        Err(_) => -4,
    }
}

#[no_mangle]
pub extern "C" fn onyx_manual_map_available() -> i32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manual_map_available() {
        assert_eq!(onyx_manual_map_available(), 1);
    }

    #[test]
    fn test_invalid_parameters_rejected() {
        assert_eq!(onyx_manual_map_dll(0, std::ptr::null()), -1);
    }
}
