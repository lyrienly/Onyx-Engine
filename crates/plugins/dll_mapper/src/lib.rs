#![allow(non_snake_case)]

mod imports;
mod mapper;
mod pe;
mod reloc;
mod stub;

use std::ffi::{c_char, CStr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

pub const ONYX_PLUGIN_API_VERSION: u32 = 1;

pub const ONYX_PLUGIN_OK: i32 = 0;
pub const ONYX_PLUGIN_ERR_INVALID_PARAM: i32 = -1;
pub const ONYX_PLUGIN_ERR_NOT_FOUND: i32 = -2;
pub const ONYX_PLUGIN_ERR_BUFFER_SMALL: i32 = -3;
pub const ONYX_PLUGIN_ERR_EXECUTION: i32 = -4;
pub const ONYX_PLUGIN_ERR_NOT_SUPPORTED: i32 = -5;

pub const ONYX_MAP_ERASE_HEADERS: u32 = 1;
pub const ONYX_MAP_PROTECT_SECTIONS: u32 = 2;
pub const ONYX_MAP_CALL_TLS: u32 = 4;
pub const ONYX_MAP_THREAD_HIJACK: u32 = 8;
pub const ONYX_MAP_USE_DRIVER: u32 = 16;
pub const ONYX_MAP_WIPE_STUB: u32 = 32;
pub const ONYX_MAP_MODULE_STOMP: u32 = 64;
pub const ONYX_MAP_RESOLVE_PEB: u32 = 128;
pub const ONYX_MAP_REGISTER_SEH: u32 = 256;
pub const ONYX_MAP_INIT_COOKIE: u32 = 512;
pub const ONYX_MAP_AUTO: u32 = 0x8000_0000;

#[repr(C)]
pub struct OnyxPluginInfo {
    pub api_version: u32,
    pub name: *const c_char,
    pub version: *const c_char,
    pub author: *const c_char,
    pub description: *const c_char,
}

#[repr(C)]
pub struct OnyxPluginHostAPI {
    pub struct_size: u32,
    pub get_target_pid: Option<unsafe extern "system" fn() -> u32>,
    pub get_target_handle: Option<unsafe extern "system" fn() -> *mut std::ffi::c_void>,
    pub read_memory:
        Option<unsafe extern "system" fn(u64, *mut std::ffi::c_void, usize, *mut usize) -> i32>,
    pub write_memory:
        Option<unsafe extern "system" fn(u64, *const std::ffi::c_void, usize, *mut usize) -> i32>,
    pub resolve_symbol: Option<unsafe extern "system" fn(u64, *mut c_char, usize, *mut u64) -> i32>,
    pub log_message: Option<unsafe extern "system" fn(i32, *const c_char)>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OnyxMapOptions {
    pub struct_size: u32,
    pub flags: u32,
    pub preferred_base: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OnyxMapResult {
    pub image_base: u64,
    pub entry_point: u64,
    pub dll_main_result: i32,
    pub flags_applied: u32,
    pub relocations: u32,
    pub imports: u32,
    pub error: [c_char; 256],
}

static PLUGIN_NAME: &[u8] = b"Onyx DLL Manual Mapper\0";
static PLUGIN_VERSION: &[u8] = b"1.2.0\0";
static PLUGIN_AUTHOR: &[u8] = b"OnyxEngine Team\0";
static PLUGIN_DESC: &[u8] =
    b"Manual (mapped) DLL injection with module stomping, VAD evasion, PEB EAT resolving, and thread hijacking\0";

static HOST: AtomicUsize = AtomicUsize::new(0);
static MAPPED: Mutex<Vec<u64>> = Mutex::new(Vec::new());

fn write_c_string(dest: &mut [c_char], src: &str) {
    let bytes = src.as_bytes();
    let max = dest.len().saturating_sub(1);
    let copy_len = bytes.len().min(max);
    for i in 0..copy_len {
        dest[i] = bytes[i] as c_char;
    }
    dest[copy_len] = 0;
}

fn clear_c_string(dest: &mut [c_char]) {
    for byte in dest.iter_mut() {
        *byte = 0;
    }
}

fn target_pid() -> u32 {
    let host = HOST.load(Ordering::SeqCst) as *const OnyxPluginHostAPI;
    if host.is_null() {
        return 0;
    }
    match unsafe { (*host).get_target_pid } {
        Some(get_pid) => unsafe { get_pid() },
        None => 0,
    }
}

fn parse_map_options(flags: u32) -> mapper::MapOptions {
    if flags == 0 || (flags & ONYX_MAP_AUTO != 0) {
        return mapper::MapOptions {
            erase_headers: true,
            protect_sections: true,
            call_tls: true,
            thread_hijack: true,
            use_driver: true,
            wipe_stub: true,
            module_stomp: flags & ONYX_MAP_MODULE_STOMP != 0,
            resolve_peb: true,
            register_seh: true,
            init_cookie: true,
            target_stomp_module: None,
        };
    }
    mapper::MapOptions {
        erase_headers: flags & ONYX_MAP_ERASE_HEADERS != 0,
        protect_sections: flags & ONYX_MAP_PROTECT_SECTIONS != 0,
        call_tls: flags & ONYX_MAP_CALL_TLS != 0,
        thread_hijack: flags & ONYX_MAP_THREAD_HIJACK != 0,
        use_driver: flags & ONYX_MAP_USE_DRIVER != 0,
        wipe_stub: flags & ONYX_MAP_WIPE_STUB != 0,
        module_stomp: flags & ONYX_MAP_MODULE_STOMP != 0,
        resolve_peb: flags & ONYX_MAP_RESOLVE_PEB != 0,
        register_seh: flags & ONYX_MAP_REGISTER_SEH != 0,
        init_cookie: flags & ONYX_MAP_INIT_COOKIE != 0,
        target_stomp_module: None,
    }
}

#[no_mangle]
pub unsafe extern "system" fn OnyxPlugin_GetInfo(out_info: *mut OnyxPluginInfo) -> i32 {
    if out_info.is_null() {
        return ONYX_PLUGIN_ERR_INVALID_PARAM;
    }

    (*out_info).api_version = ONYX_PLUGIN_API_VERSION;
    (*out_info).name = PLUGIN_NAME.as_ptr() as *const c_char;
    (*out_info).version = PLUGIN_VERSION.as_ptr() as *const c_char;
    (*out_info).author = PLUGIN_AUTHOR.as_ptr() as *const c_char;
    (*out_info).description = PLUGIN_DESC.as_ptr() as *const c_char;

    ONYX_PLUGIN_OK
}

#[no_mangle]
pub unsafe extern "system" fn OnyxPlugin_Init(host_api: *const OnyxPluginHostAPI) -> i32 {
    HOST.store(host_api as usize, Ordering::SeqCst);
    ONYX_PLUGIN_OK
}

#[no_mangle]
pub unsafe extern "system" fn OnyxPlugin_Shutdown() {
    HOST.store(0, Ordering::SeqCst);
}

#[no_mangle]
pub unsafe extern "system" fn OnyxPlugin_MapDllPid(
    target_pid: u32,
    dll_path: *const c_char,
    options: *const OnyxMapOptions,
    out_result: *mut OnyxMapResult,
) -> i32 {
    if dll_path.is_null() || out_result.is_null() {
        return ONYX_PLUGIN_ERR_INVALID_PARAM;
    }
    clear_c_string(&mut (*out_result).error);

    let path = match CStr::from_ptr(dll_path).to_str() {
        Ok(value) => value,
        Err(_) => {
            write_c_string(&mut (*out_result).error, "invalid UTF-8 path");
            return ONYX_PLUGIN_ERR_INVALID_PARAM;
        }
    };

    let flags = if options.is_null() {
        ONYX_MAP_PROTECT_SECTIONS
            | ONYX_MAP_CALL_TLS
            | ONYX_MAP_RESOLVE_PEB
            | ONYX_MAP_REGISTER_SEH
            | ONYX_MAP_INIT_COOKIE
    } else {
        (*options).flags
    };

    let pid = if target_pid != 0 {
        target_pid
    } else {
        self::target_pid()
    };
    if pid == 0 {
        write_c_string(&mut (*out_result).error, "no target process attached");
        return ONYX_PLUGIN_ERR_NOT_FOUND;
    }

    let map_options = parse_map_options(flags);

    match mapper::map_dll(pid, path, &map_options) {
        Ok(outcome) => {
            (*out_result).image_base = outcome.image_base as u64;
            (*out_result).entry_point = outcome.entry_point as u64;
            (*out_result).dll_main_result = outcome.dll_main_result;
            (*out_result).flags_applied = flags;
            (*out_result).relocations = outcome.relocations;
            (*out_result).imports = outcome.imports;
            if let Ok(mut mapped) = MAPPED.lock() {
                mapped.push(outcome.image_base as u64);
            }
            ONYX_PLUGIN_OK
        }
        Err(error) => {
            write_c_string(&mut (*out_result).error, &error);
            ONYX_PLUGIN_ERR_EXECUTION
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn OnyxPlugin_MapDll(
    dll_path: *const c_char,
    options: *const OnyxMapOptions,
    out_result: *mut OnyxMapResult,
) -> i32 {
    OnyxPlugin_MapDllPid(0, dll_path, options, out_result)
}

#[no_mangle]
pub unsafe extern "system" fn OnyxPlugin_MapDllNamed(
    target_name: *const c_char,
    dll_path: *const c_char,
    options: *const OnyxMapOptions,
    out_result: *mut OnyxMapResult,
) -> i32 {
    if target_name.is_null() || dll_path.is_null() || out_result.is_null() {
        return ONYX_PLUGIN_ERR_INVALID_PARAM;
    }
    clear_c_string(&mut (*out_result).error);

    let name = match CStr::from_ptr(target_name).to_str() {
        Ok(value) => value,
        Err(_) => {
            write_c_string(&mut (*out_result).error, "invalid UTF-8 target name");
            return ONYX_PLUGIN_ERR_INVALID_PARAM;
        }
    };

    let path = match CStr::from_ptr(dll_path).to_str() {
        Ok(value) => value,
        Err(_) => {
            write_c_string(&mut (*out_result).error, "invalid UTF-8 path");
            return ONYX_PLUGIN_ERR_INVALID_PARAM;
        }
    };

    let flags = if options.is_null() {
        ONYX_MAP_PROTECT_SECTIONS
            | ONYX_MAP_CALL_TLS
            | ONYX_MAP_RESOLVE_PEB
            | ONYX_MAP_REGISTER_SEH
            | ONYX_MAP_INIT_COOKIE
    } else {
        (*options).flags
    };

    let map_options = parse_map_options(flags);

    match mapper::map_dll_by_name(name, path, &map_options) {
        Ok(outcome) => {
            (*out_result).image_base = outcome.image_base as u64;
            (*out_result).entry_point = outcome.entry_point as u64;
            (*out_result).dll_main_result = outcome.dll_main_result;
            (*out_result).flags_applied = flags;
            (*out_result).relocations = outcome.relocations;
            (*out_result).imports = outcome.imports;
            if let Ok(mut mapped) = MAPPED.lock() {
                mapped.push(outcome.image_base as u64);
            }
            ONYX_PLUGIN_OK
        }
        Err(error) => {
            write_c_string(&mut (*out_result).error, &error);
            ONYX_PLUGIN_ERR_EXECUTION
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn OnyxPlugin_IsMapped(image_base: u64) -> i32 {
    match MAPPED.lock() {
        Ok(mapped) => {
            if mapped.contains(&image_base) {
                1
            } else {
                0
            }
        }
        Err(_) => 0,
    }
}
