// OnyxEngine Process & Memory Win32 Backend API
// Direct C-ABI bridge for Pascal Cheat Engine front-end

use std::ffi::c_void;
use onyx_core::process::Process;
use crate::types::{OnyxModuleEntry, OnyxProcessEntry, OnyxMemoryRegion};

/// Enumerate all running processes into out_entries buffer
/// Returns the number of processes written, or -1 on error
#[no_mangle]
pub unsafe extern "C" fn onyx_process_list(
    out_entries: *mut OnyxProcessEntry,
    max_count: u32,
    out_total: *mut u32,
) -> i32 {
    if out_entries.is_null() || max_count == 0 {
        return -1;
    }

    match Process::list_all() {
        Ok(list) => {
            if !out_total.is_null() {
                *out_total = list.len() as u32;
            }

            let write_count = list.len().min(max_count as usize);
            for i in 0..write_count {
                *out_entries.add(i) = OnyxProcessEntry::new(list[i].pid, &list[i].name);
            }
            write_count as i32
        }
        Err(_) => -1,
    }
}

/// Attach to a target process by PID
/// Returns an opaque pointer to the Process struct, or NULL on error
#[no_mangle]
pub unsafe extern "C" fn onyx_process_attach(pid: u32) -> *mut Process {
    match Process::attach(pid) {
        Ok(proc) => Box::into_raw(Box::new(proc)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Close and free an attached process handle
#[no_mangle]
pub unsafe extern "C" fn onyx_process_close(handle: *mut Process) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Read process memory (compatible with ReadProcessMemory calling convention)
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub unsafe extern "C" fn onyx_process_read(
    handle: *mut Process,
    base_address: usize,
    buffer: *mut c_void,
    size: usize,
    out_bytes_read: *mut usize,
) -> i32 {
    if handle.is_null() || buffer.is_null() || size == 0 {
        return 0;
    }

    let proc = &*handle;
    let slice = std::slice::from_raw_parts_mut(buffer as *mut u8, size);

    match proc.read_raw(base_address, slice) {
        Ok(bytes_read) => {
            if !out_bytes_read.is_null() {
                *out_bytes_read = bytes_read;
            }
            1
        }
        Err(_) => 0,
    }
}

/// Write process memory (compatible with WriteProcessMemory calling convention)
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub unsafe extern "C" fn onyx_process_write(
    handle: *mut Process,
    base_address: usize,
    buffer: *const c_void,
    size: usize,
    out_bytes_written: *mut usize,
) -> i32 {
    if handle.is_null() || buffer.is_null() || size == 0 {
        return 0;
    }

    let proc = &*handle;
    let slice = std::slice::from_raw_parts(buffer as *const u8, size);

    match proc.write_raw(base_address, slice) {
        Ok(_) => {
            if !out_bytes_written.is_null() {
                *out_bytes_written = size;
            }
            1
        }
        Err(_) => 0,
    }
}

/// Change memory protection (compatible with VirtualProtectEx)
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub unsafe extern "C" fn onyx_process_protect(
    handle: *mut Process,
    base_address: usize,
    size: usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    if handle.is_null() {
        return 0;
    }

    let proc = &*handle;
    match proc.protect(base_address, size, new_protect) {
        Ok(old) => {
            if !old_protect.is_null() {
                *old_protect = old;
            }
            1
        }
        Err(_) => 0,
    }
}

/// Allocate memory in target process (compatible with VirtualAllocEx)
/// Returns allocated base address, or 0 on error
#[no_mangle]
pub unsafe extern "C" fn onyx_process_alloc(
    handle: *mut Process,
    _preferred_address: usize,
    size: usize,
    _alloc_type: u32,
    protect: u32,
) -> usize {
    if handle.is_null() || size == 0 {
        return 0;
    }

    let proc = &*handle;
    proc.alloc(size, protect).unwrap_or(0)
}

/// Free memory in target process (compatible with VirtualFreeEx)
/// Returns 1 on success, 0 on error
#[no_mangle]
pub unsafe extern "C" fn onyx_process_free(
    handle: *mut Process,
    base_address: usize,
    _size: usize,
    _free_type: u32,
) -> i32 {
    if handle.is_null() {
        return 0;
    }

    let proc = &*handle;
    match proc.free(base_address) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

/// Enumerate modules of attached process
/// Returns number of modules written, or -1 on error
#[no_mangle]
pub unsafe extern "C" fn onyx_process_modules(
    handle: *mut Process,
    out_modules: *mut OnyxModuleEntry,
    max_count: u32,
    out_total: *mut u32,
) -> i32 {
    if handle.is_null() || out_modules.is_null() || max_count == 0 {
        return -1;
    }

    let proc = &*handle;
    match proc.modules() {
        Ok(mods) => {
            if !out_total.is_null() {
                *out_total = mods.len() as u32;
            }
            let count = mods.len().min(max_count as usize);
            for i in 0..count {
                *out_modules.add(i) = OnyxModuleEntry::new(mods[i].base, mods[i].size, &mods[i].name);
            }
            count as i32
        }
        Err(_) => -1,
    }
}

/// Enumerate memory regions of attached process
#[no_mangle]
pub unsafe extern "C" fn onyx_process_regions(
    handle: *mut Process,
    out_regions: *mut OnyxMemoryRegion,
    max_count: u32,
    out_total: *mut u32,
) -> i32 {
    if handle.is_null() || out_regions.is_null() || max_count == 0 {
        return -1;
    }

    let proc = &*handle;
    match proc.regions(false) {
        Ok(regs) => {
            if !out_total.is_null() {
                *out_total = regs.len() as u32;
            }
            let count = regs.len().min(max_count as usize);
            for i in 0..count {
                *out_regions.add(i) = OnyxMemoryRegion {
                    base: regs[i].base,
                    size: regs[i].size,
                    state: regs[i].state,
                    protect: regs[i].protect,
                    region_type: regs[i].mem_type,
                };
            }
            count as i32
        }
        Err(_) => -1,
    }
}
