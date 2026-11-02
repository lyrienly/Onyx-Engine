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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OnyxCallbackEntry {
    pub entry_address: u64,
    pub object_type: u32,
    pub operations: u32,
    pub enabled: u32,
    pub _pad: u32,
    pub pre_operation: u64,
    pub post_operation: u64,
    pub owner_module: [u8; 64],
}

#[no_mangle]
pub extern "C" fn onyx_kernel_strip_callbacks(mode: i32) -> i32 {
    if let Some(ref dbk) = get_global_dbk() {
        match dbk.strip_callbacks_mode(mode as u32) {
            Ok(count) => count as i32,
            Err(_) => -1,
        }
    } else {
        -1
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_kernel_enum_callbacks(
    out_callbacks: *mut OnyxCallbackEntry,
    max_count: u32,
    out_total: *mut u32,
) -> i32 {
    if let Some(ref dbk) = get_global_dbk() {
        match dbk.enum_callbacks() {
            Ok(cbs) => {
                if !out_total.is_null() {
                    *out_total = cbs.len() as u32;
                }
                if out_callbacks.is_null() || max_count == 0 {
                    return cbs.len() as i32;
                }
                let write_count = cbs.len().min(max_count as usize);
                for i in 0..write_count {
                    let entry = OnyxCallbackEntry {
                        entry_address: cbs[i].entry_address,
                        object_type: cbs[i].object_type as u32,
                        operations: cbs[i].operations,
                        enabled: cbs[i].enabled,
                        _pad: 0,
                        pre_operation: cbs[i].pre_operation,
                        post_operation: cbs[i].post_operation,
                        owner_module: cbs[i].owner_module,
                    };
                    *out_callbacks.add(i) = entry;
                }
                write_count as i32
            }
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
pub extern "C" fn onyx_kernel_cloak_page(pid: u32, address: u64) -> i32 {
    if let Some(ref dbk) = get_global_dbk() {
        if dbk.cloak_page(pid, address).is_ok() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn onyx_kernel_uncloak_page(pid: u32, address: u64) -> i32 {
    if let Some(ref dbk) = get_global_dbk() {
        if dbk.uncloak_page(pid, address).is_ok() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_kernel_write_cloaked(
    pid: u32,
    address: u64,
    buffer: *const u8,
    size: u32,
) -> i32 {
    if buffer.is_null() || size == 0 {
        return 0;
    }
    let data = std::slice::from_raw_parts(buffer, size as usize);
    if let Some(ref dbk) = get_global_dbk() {
        if dbk.write_cloaked(pid, address, data).is_ok() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_kernel_cloak_region(
    pid: u32,
    address: u64,
    buffer: *const u8,
    size: u32,
) -> i32 {
    if buffer.is_null() || size == 0 {
        return 0;
    }
    let data = std::slice::from_raw_parts(buffer, size as usize);
    if let Some(ref dbk) = get_global_dbk() {
        if dbk.cloak_region(pid, address, data).is_ok() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_kernel_get_dbvm_status(
    out_active: *mut u32,
    out_version: *mut u32,
) -> i32 {
    if let Some(ref dbk) = get_global_dbk() {
        match dbk.get_dbvm_status() {
            Ok((is_active, version)) => {
                if !out_active.is_null() {
                    *out_active = if is_active { 1 } else { 0 };
                }
                if !out_version.is_null() {
                    *out_version = version;
                }
                1
            }
            Err(_) => 0,
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

#[no_mangle]
pub extern "C" fn onyx_security_cloak_peb(pid: u32) -> i32 {
    #[cfg(target_os = "windows")]
    unsafe {
        use onyx_core::security::AntiDebug;
        use onyx_core::win32::{CloseHandle, GetCurrentProcess, OpenProcess, PROCESS_ALL_ACCESS};

        if pid == 0 {
            if AntiDebug::cloak_target_process(GetCurrentProcess()).is_ok() {
                1
            } else {
                0
            }
        } else {
            let handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if handle.is_null() {
                return 0;
            }
            let res = AntiDebug::cloak_target_process(handle);
            CloseHandle(handle);
            if res.is_ok() {
                1
            } else {
                0
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        0
    }
}

#[no_mangle]
pub extern "C" fn onyx_security_restore_peb(pid: u32) -> i32 {
    #[cfg(target_os = "windows")]
    unsafe {
        use onyx_core::security::AntiDebug;
        use onyx_core::win32::{CloseHandle, GetCurrentProcess, OpenProcess, PROCESS_ALL_ACCESS};

        if pid == 0 {
            if AntiDebug::restore_target_process(GetCurrentProcess()).is_ok() {
                1
            } else {
                0
            }
        } else {
            let handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if handle.is_null() {
                return 0;
            }
            let res = AntiDebug::restore_target_process(handle);
            CloseHandle(handle);
            if res.is_ok() {
                1
            } else {
                0
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        0
    }
}

#[no_mangle]
pub extern "C" fn onyx_security_anti_debug_audit() -> i32 {
    let report = onyx_core::security::AntiDebug::audit();
    if report.is_under_analysis() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_kernel_read_memory_cr3(
    pid: u32,
    address: u64,
    buffer: *mut u8,
    size: usize,
) -> i32 {
    if buffer.is_null() || size == 0 {
        return 0;
    }
    match onyx_core::process::kernel::OnyxDriver::connect() {
        Ok(driver) => match driver.read_memory_cr3(pid, address, size) {
            Ok(bytes) => {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len());
                bytes.len() as i32
            }
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_kernel_write_memory_cr3(
    pid: u32,
    address: u64,
    data: *const u8,
    size: usize,
) -> i32 {
    if data.is_null() || size == 0 {
        return 0;
    }
    let slice = std::slice::from_raw_parts(data, size);
    match onyx_core::process::kernel::OnyxDriver::connect() {
        Ok(driver) => match driver.write_memory_cr3(pid, address, slice) {
            Ok(written) => written as i32,
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_kernel_get_hvci_status(out_vbs: *mut u32, out_hvci: *mut u32) -> i32 {
    if !out_vbs.is_null() {
        *out_vbs = 0;
    }
    if !out_hvci.is_null() {
        *out_hvci = 0;
    }

    if let Ok(driver) = onyx_core::process::kernel::OnyxDriver::connect() {
        if let Ok(status) = driver.get_hvci_status() {
            if !out_vbs.is_null() {
                *out_vbs = status.vbs_enabled;
            }
            if !out_hvci.is_null() {
                *out_hvci = status.hvci_enabled;
            }
            return 1;
        }
    }

    let vbs = onyx_core::process::kernel::OnyxDriver::is_vbs_active();
    let hvci = onyx_core::process::kernel::OnyxDriver::is_hvci_active();
    if !out_vbs.is_null() {
        *out_vbs = if vbs { 1 } else { 0 };
    }
    if !out_hvci.is_null() {
        *out_hvci = if hvci { 1 } else { 0 };
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn onyx_ultimap2_setup(
    pid: u32,
    buffer_size: u32,
    range_start: u64,
    range_end: u64,
) -> i32 {
    let mut config = onyx_core::process::kernel::CeUltimap2Config::default();
    config.pid = pid;
    config.buffer_size = buffer_size;
    if range_start < range_end {
        config.range_count = 1;
        config.ranges[0].start_address = range_start;
        config.ranges[0].end_address = range_end;
        config.ranges[0].is_stop_address = 0;
    }
    match onyx_core::process::kernel::OnyxDriver::connect() {
        Ok(driver) => match driver.setup_ultimap2(&config) {
            Ok(_) => 1,
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_ultimap2_disable() -> i32 {
    match onyx_core::process::kernel::OnyxDriver::connect() {
        Ok(driver) => match driver.disable_ultimap2() {
            Ok(_) => 1,
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_ultimap2_pause() -> i32 {
    match onyx_core::process::kernel::OnyxDriver::connect() {
        Ok(driver) => match driver.pause_ultimap2() {
            Ok(_) => 1,
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_ultimap2_resume() -> i32 {
    match onyx_core::process::kernel::OnyxDriver::connect() {
        Ok(driver) => match driver.resume_ultimap2() {
            Ok(_) => 1,
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_ultimap2_get_trace_size(out_size: *mut u64) -> i32 {
    if out_size.is_null() {
        return 0;
    }
    match onyx_core::process::kernel::OnyxDriver::connect() {
        Ok(driver) => match driver.get_ultimap2_trace_size() {
            Ok(size) => {
                *out_size = size;
                1
            }
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_intel_pt_decode_stream(
    buffer: *const u8,
    size: usize,
    filter_start: u64,
    filter_end: u64,
) -> usize {
    if buffer.is_null() || size == 0 {
        return 0;
    }
    let slice = std::slice::from_raw_parts(buffer, size);
    let mut decoder = onyx_core::debugger::intel_pt::IntelPtDecoder::new();
    if filter_start < filter_end {
        decoder.add_filter_range(filter_start, filter_end);
    }
    let events = decoder.reconstruct_execution_flow(slice);
    events.len()
}
