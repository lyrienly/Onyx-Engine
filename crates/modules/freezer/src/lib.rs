// language: Rust, file: lib.rs (onyx_freezer), target: Windows 11, MSVC
// Modular Value Freezer Sub-DLL (modules/freezer/onyx_freezer.dll)

use std::ffi::CStr;
use std::os::raw::c_char;
use onyx_core::freeze::Freezer;
use onyx_core::process::Process;
use onyx_core::scanner::{ScanValue, ValType};

fn map_val_type(idx: i32) -> ValType {
    match idx {
        0 => ValType::I8,
        1 => ValType::U8,
        2 => ValType::I16,
        3 => ValType::U16,
        4 => ValType::I32,
        5 => ValType::U32,
        6 => ValType::I64,
        7 => ValType::U64,
        8 => ValType::Float,
        9 => ValType::Double,
        _ => ValType::I32,
    }
}

#[no_mangle]
pub extern "C" fn onyx_freezer_module_ping() -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn onyx_freezer_create(process: *mut Process, interval_ms: u64) -> *mut Freezer {
    if process.is_null() {
        return std::ptr::null_mut();
    }

    let proc = &*process;
    let freezer = Freezer::new();
    freezer.start(proc, if interval_ms == 0 { 50 } else { interval_ms });
    Box::into_raw(Box::new(freezer))
}

#[no_mangle]
pub unsafe extern "C" fn onyx_freezer_destroy(freezer: *mut Freezer) {
    if !freezer.is_null() {
        let f = Box::from_raw(freezer);
        f.stop();
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_freezer_add(
    freezer: *mut Freezer,
    address: usize,
    val_type_idx: i32,
    val_str: *const c_char,
    description: *const c_char,
) -> usize {
    if freezer.is_null() || val_str.is_null() {
        return 0;
    }

    let f = &mut *freezer;
    let vt = map_val_type(val_type_idx);
    let s = CStr::from_ptr(val_str).to_string_lossy();
    let desc = if description.is_null() {
        "Frozen".to_string()
    } else {
        CStr::from_ptr(description).to_string_lossy().to_string()
    };

    match ScanValue::parse(vt, s.trim()) {
        Ok(v) => f.freeze(address, v, &desc),
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_freezer_remove(freezer: *mut Freezer, entry_id: usize) -> i32 {
    if freezer.is_null() {
        return 0;
    }
    let f = &*freezer;
    if f.unfreeze(entry_id) { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_freezer_clear(freezer: *mut Freezer) {
    if !freezer.is_null() {
        let f = &*freezer;
        f.clear();
    }
}
