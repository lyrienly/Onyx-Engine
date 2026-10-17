// OnyxEngine Process & Memory Win32 Backend API
// Direct C-ABI bridge for Pascal Cheat Engine front-end

use std::ffi::{c_void, CStr};
use std::os::raw::c_char;
use onyx_core::process::{Process, ProcessWatcher, ProcessWatchEvent, DbgHelpSymbolEngine};
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

/// Atomically suspends target process via NtSuspendProcess
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub unsafe extern "C" fn onyx_process_suspend(handle: *mut Process) -> i32 {
    if handle.is_null() {
        return 0;
    }
    match (*handle).suspend() {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

/// Atomically resumes target process via NtResumeProcess
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub unsafe extern "C" fn onyx_process_resume(handle: *mut Process) -> i32 {
    if handle.is_null() {
        return 0;
    }
    match (*handle).resume() {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

// Process Watcher API

#[no_mangle]
pub unsafe extern "C" fn onyx_process_watcher_create() -> *mut ProcessWatcher {
    Box::into_raw(Box::new(ProcessWatcher::new()))
}

#[no_mangle]
pub unsafe extern "C" fn onyx_process_watcher_destroy(watcher: *mut ProcessWatcher) {
    if !watcher.is_null() {
        drop(Box::from_raw(watcher));
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_process_watcher_add_target(
    watcher: *mut ProcessWatcher,
    target_name: *const c_char,
) {
    if !watcher.is_null() && !target_name.is_null() {
        if let Ok(c_str) = CStr::from_ptr(target_name).to_str() {
            (*watcher).add_target(c_str);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_process_watcher_start(
    watcher: *mut ProcessWatcher,
    poll_ms: u32,
) -> i32 {
    if watcher.is_null() {
        return 0;
    }
    match (*watcher).start(poll_ms as u64) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_process_watcher_stop(watcher: *mut ProcessWatcher) {
    if !watcher.is_null() {
        (*watcher).stop();
    }
}

/// Polls for next process event.
/// Returns 1 if event returned, 0 if queue empty.
/// out_event_type: 1 = Created, 2 = Terminated
#[no_mangle]
pub unsafe extern "C" fn onyx_process_watcher_poll(
    watcher: *mut ProcessWatcher,
    out_entry: *mut OnyxProcessEntry,
    out_event_type: *mut i32,
) -> i32 {
    if watcher.is_null() || out_entry.is_null() || out_event_type.is_null() {
        return 0;
    }
    match (*watcher).poll_event() {
        Some(ProcessWatchEvent::Created(p)) => {
            *out_entry = OnyxProcessEntry::new(p.pid, &p.name);
            *out_event_type = 1;
            1
        }
        Some(ProcessWatchEvent::Terminated(pid)) => {
            *out_entry = OnyxProcessEntry::new(pid, "");
            *out_event_type = 2;
            1
        }
        None => 0,
    }
}

// PDB Symbol Resolver API

#[no_mangle]
pub unsafe extern "C" fn onyx_symbol_init_pdb(
    process_handle: *mut c_void,
    search_path: *const c_char,
) -> *mut DbgHelpSymbolEngine {
    match DbgHelpSymbolEngine::new(process_handle) {
        Ok(engine) => {
            if !search_path.is_null() {
                if let Ok(p) = CStr::from_ptr(search_path).to_str() {
                    engine.set_search_path(p);
                }
            }
            Box::into_raw(Box::new(engine))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_symbol_close_pdb(engine: *mut DbgHelpSymbolEngine) {
    if !engine.is_null() {
        drop(Box::from_raw(engine));
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_symbol_load_module(
    engine: *mut DbgHelpSymbolEngine,
    image_path: *const c_char,
    base: usize,
    size: usize,
) -> u64 {
    if engine.is_null() || image_path.is_null() {
        return 0;
    }
    let path_str = match CStr::from_ptr(image_path).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    match (*engine).load_module(path_str, base, size) {
        Ok(base_res) => base_res,
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_symbol_resolve_name(
    engine: *mut DbgHelpSymbolEngine,
    name: *const c_char,
    out_address: *mut usize,
) -> i32 {
    if engine.is_null() || name.is_null() || out_address.is_null() {
        return 0;
    }
    let sym_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    match (*engine).resolve_name(sym_str) {
        Some(addr) => {
            *out_address = addr;
            1
        }
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_symbol_resolve_address(
    engine: *mut DbgHelpSymbolEngine,
    address: usize,
    out_name: *mut c_char,
    max_len: u32,
    out_disp: *mut usize,
) -> i32 {
    if engine.is_null() || out_name.is_null() || max_len == 0 {
        return 0;
    }
    match (*engine).resolve_address(address) {
        Some((name, disp)) => {
            let bytes = name.as_bytes();
            let write_len = bytes.len().min(max_len as usize - 1);
            std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_name, write_len);
            *out_name.add(write_len) = 0;
            if !out_disp.is_null() {
                *out_disp = disp;
            }
            1
        }
        None => 0,
    }
}
