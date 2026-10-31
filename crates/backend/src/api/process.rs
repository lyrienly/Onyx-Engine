use crate::types::{
    OnyxMemoryRegion, OnyxModuleEntry, OnyxPeImport, OnyxPeSection, OnyxProcessEntry,
};
use onyx_core::kernel::DbkDriver;
use onyx_core::process::{
    DbgHelpSymbolEngine, PeInfoParser, Process, ProcessAccessMode, ProcessWatchEvent,
    ProcessWatcher,
};
use std::ffi::{c_void, CStr};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex, OnceLock};

static GLOBAL_DBK: OnceLock<Mutex<Option<Arc<DbkDriver>>>> = OnceLock::new();

fn get_dbk_mutex() -> &'static Mutex<Option<Arc<DbkDriver>>> {
    GLOBAL_DBK.get_or_init(|| Mutex::new(DbkDriver::connect().ok().map(Arc::new)))
}

pub fn get_global_dbk() -> Option<Arc<DbkDriver>> {
    get_dbk_mutex().lock().ok().and_then(|guard| guard.clone())
}

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

#[no_mangle]
pub unsafe extern "C" fn onyx_process_attach(pid: u32) -> *mut Process {
    let dbk = get_global_dbk();
    let mode = if dbk.is_some() {
        ProcessAccessMode::KernelDbk
    } else {
        ProcessAccessMode::NtApi
    };

    match Process::attach_with_mode(pid, mode, dbk) {
        Ok(proc) => Box::into_raw(Box::new(proc)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_process_close(handle: *mut Process) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

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
                *out_modules.add(i) =
                    OnyxModuleEntry::new(mods[i].base, mods[i].size, &mods[i].name);
            }
            count as i32
        }
        Err(_) => -1,
    }
}

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
    (*engine)
        .load_module(path_str, base, size)
        .unwrap_or_default()
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

#[no_mangle]
pub unsafe extern "C" fn onyx_pe_parse_sections(
    handle: *mut Process,
    module_base: usize,
    out_sections: *mut OnyxPeSection,
    max_sections: u32,
    out_count: *mut u32,
) -> i32 {
    if handle.is_null() || out_sections.is_null() || max_sections == 0 {
        return -1;
    }

    match PeInfoParser::parse_process_module(&*handle, module_base) {
        Ok(info) => {
            if !out_count.is_null() {
                *out_count = info.sections.len() as u32;
            }
            let write_len = info.sections.len().min(max_sections as usize);
            for i in 0..write_len {
                let s = &info.sections[i];
                let mut entry = OnyxPeSection {
                    name: [0u8; 16],
                    virtual_address: s.virtual_address,
                    virtual_size: s.virtual_size,
                    raw_size: s.raw_size,
                    characteristics: s.characteristics,
                    is_executable: if s.is_executable { 1 } else { 0 },
                    is_writable: if s.is_writable { 1 } else { 0 },
                    is_readable: if s.is_readable { 1 } else { 0 },
                };
                let n_bytes = s.name.as_bytes();
                let n_len = n_bytes.len().min(15);
                entry.name[..n_len].copy_from_slice(&n_bytes[..n_len]);

                *out_sections.add(i) = entry;
            }
            write_len as i32
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pe_parse_imports(
    handle: *mut Process,
    module_base: usize,
    out_imports: *mut OnyxPeImport,
    max_imports: u32,
    out_count: *mut u32,
) -> i32 {
    if handle.is_null() || out_imports.is_null() || max_imports == 0 {
        return -1;
    }

    match PeInfoParser::parse_process_module(&*handle, module_base) {
        Ok(info) => {
            let mut flat_imports = Vec::new();
            for mod_entry in &info.imports {
                for fn_entry in &mod_entry.functions {
                    flat_imports.push((&mod_entry.module_name, fn_entry));
                }
            }

            if !out_count.is_null() {
                *out_count = flat_imports.len() as u32;
            }

            let write_len = flat_imports.len().min(max_imports as usize);
            for i in 0..write_len {
                let (dll_name, f) = flat_imports[i];
                let mut entry = OnyxPeImport {
                    module_name: [0u8; 128],
                    function_name: [0u8; 128],
                    ordinal: f.ordinal,
                    iat_address: f.iat_address,
                    resolved_address: f.resolved_address,
                };

                let dll_bytes = dll_name.as_bytes();
                let dll_len = dll_bytes.len().min(127);
                entry.module_name[..dll_len].copy_from_slice(&dll_bytes[..dll_len]);

                let fn_bytes = f.name.as_bytes();
                let fn_len = fn_bytes.len().min(127);
                entry.function_name[..fn_len].copy_from_slice(&fn_bytes[..fn_len]);

                *out_imports.add(i) = entry;
            }
            write_len as i32
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_kernel_connect(device_path: *const c_char) -> i32 {
    let res = if !device_path.is_null() {
        if let Ok(c_str) = CStr::from_ptr(device_path).to_str() {
            DbkDriver::connect_device(c_str)
        } else {
            DbkDriver::connect()
        }
    } else {
        DbkDriver::connect()
    };

    match res {
        Ok(driver) => {
            if let Ok(mut guard) = get_dbk_mutex().lock() {
                *guard = Some(Arc::new(driver));
            }
            1
        }
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn onyx_kernel_is_connected() -> i32 {
    if let Some(ref dbk) = get_global_dbk() {
        if dbk.test() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn onyx_kernel_hide_driver() -> i32 {
    if let Some(ref dbk) = get_global_dbk() {
        if dbk.hide_driver().is_ok() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn onyx_kernel_strip_callbacks(restore: i32) -> i32 {
    if let Some(ref dbk) = get_global_dbk() {
        match dbk.strip_callbacks(restore != 0) {
            Ok(count) => count as i32,
            Err(_) => -1,
        }
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn onyx_kernel_hide_process(pid: u32) -> i32 {
    if let Some(ref dbk) = get_global_dbk() {
        if dbk.hide_process(pid).is_ok() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn onyx_kernel_restore_process(pid: u32) -> i32 {
    if let Some(ref dbk) = get_global_dbk() {
        if dbk.restore_process(pid).is_ok() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn onyx_kernel_clean_traces() -> i32 {
    if let Some(ref dbk) = get_global_dbk() {
        if dbk.clean_traces().is_ok() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn onyx_kernel_set_protection(pid: u32, enable: i32) -> i32 {
    if let Some(ref dbk) = get_global_dbk() {
        if dbk.set_protection(pid, enable != 0).is_ok() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn onyx_kernel_freeze_process(pid: u32, freeze: i32) -> i32 {
    if let Some(ref dbk) = get_global_dbk() {
        if dbk.freeze_process(pid, freeze != 0).is_ok() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_kernel_cloak_symlink(new_symlink: *const c_char) -> i32 {
    if new_symlink.is_null() {
        return 0;
    }
    if let Ok(c_str) = CStr::from_ptr(new_symlink).to_str() {
        if let Some(ref dbk) = get_global_dbk() {
            if dbk.cloak_symlink(c_str).is_ok() {
                1
            } else {
                0
            }
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_kernel_enum_vad(
    pid: u32,
    out_modules: *mut OnyxModuleEntry,
    max_count: u32,
    out_total: *mut u32,
) -> i32 {
    if out_modules.is_null() || max_count == 0 {
        return -1;
    }

    if let Some(ref dbk) = get_global_dbk() {
        match dbk.enum_vad_modules(pid) {
            Ok(mods) => {
                if !out_total.is_null() {
                    *out_total = mods.len() as u32;
                }
                let write_count = mods.len().min(max_count as usize);
                for i in 0..write_count {
                    *out_modules.add(i) =
                        OnyxModuleEntry::new(mods[i].base, mods[i].size, &mods[i].name);
                }
                write_count as i32
            }
            Err(_) => -1,
        }
    } else {
        -1
    }
}
