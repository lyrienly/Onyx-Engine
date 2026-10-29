use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub const OK: i32 = 0;
pub const ERR_NULL: i32 = -1;
pub const ERR_INVALID_UTF8: i32 = -2;
pub const ERR_INTERNAL: i32 = -3;
pub const ERR_NOT_FOUND: i32 = -4;
pub const ERR_PANIC: i32 = -5;
pub const ERR_NOT_IMPLEMENTED: i32 = -99;

pub unsafe fn cstr_to_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok()
}

pub fn string_to_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_abi_free_string(p: *mut c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p));
    }
}

pub fn guard<F: FnOnce() -> i32 + std::panic::UnwindSafe>(f: F) -> i32 {
    match std::panic::catch_unwind(f) {
        Ok(code) => code,
        Err(_) => ERR_PANIC,
    }
}
