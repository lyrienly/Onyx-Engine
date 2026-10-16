// OnyxEngine Memory Freezer Backend API
// Multi-threaded background memory freezing for Pascal / Lazarus

use std::ffi::CStr;
use std::os::raw::c_char;
use onyx_core::freeze::Freezer;
use onyx_core::process::Process;
use onyx_core::scanner::{ScanValue, ValType};

fn map_val_type(idx: i32) -> ValType {
    match idx {
        // Direct CE TVariableType enum ordinals
        0 => ValType::I8,     // vtByte = 0
        1 => ValType::I16,    // vtWord = 1
        2 => ValType::I32,    // vtDword = 2
        3 => ValType::I64,    // vtQword = 3
        4 => ValType::Float,  // vtSingle = 4
        5 => ValType::Double, // vtDouble = 5
        6 | 7 | 16 => ValType::Str, // vtString = 6, vtUnicodeString = 7, vtCodePageString = 16
        8 | 15 => ValType::Aob,     // vtByteArray = 8, vtByteArrays = 15
        _ => ValType::I32,
    }
}

/// Create a new background freezer thread bound to a target process
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

/// Dynamically update target process handle in freezer
#[no_mangle]
pub unsafe extern "C" fn onyx_freezer_set_process(freezer: *mut Freezer, process: *mut Process) -> i32 {
    if freezer.is_null() || process.is_null() {
        return 0;
    }
    let f = &*freezer;
    let proc = &*process;
    f.update_process(proc);
    1
}

/// Stop and destroy the background freezer
#[no_mangle]
pub unsafe extern "C" fn onyx_freezer_destroy(freezer: *mut Freezer) {
    if !freezer.is_null() {
        let f = Box::from_raw(freezer);
        f.stop();
    }
}

/// Add an address to be actively frozen with a specific value
/// Returns the frozen entry ID (>0), or 0 on error
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

/// Update a frozen value dynamically by entry ID
#[no_mangle]
pub unsafe extern "C" fn onyx_freezer_update(
    freezer: *mut Freezer,
    entry_id: usize,
    val_type_idx: i32,
    val_str: *const c_char,
) -> i32 {
    if freezer.is_null() || val_str.is_null() || entry_id == 0 {
        return 0;
    }

    let f = &*freezer;
    let vt = map_val_type(val_type_idx);
    let s = CStr::from_ptr(val_str).to_string_lossy();

    match ScanValue::parse(vt, s.trim()) {
        Ok(v) => if f.update(entry_id, v) { 1 } else { 0 },
        Err(_) => 0,
    }
}

/// Remove an address from the freezer by entry ID
#[no_mangle]
pub unsafe extern "C" fn onyx_freezer_remove(freezer: *mut Freezer, entry_id: usize) -> i32 {
    if freezer.is_null() {
        return 0;
    }
    let f = &*freezer;
    if f.unfreeze(entry_id) { 1 } else { 0 }
}

/// Clear all frozen addresses
#[no_mangle]
pub unsafe extern "C" fn onyx_freezer_clear(freezer: *mut Freezer) {
    if !freezer.is_null() {
        let f = &*freezer;
        f.clear();
    }
}
