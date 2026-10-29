use std::ffi::c_void;
use std::os::raw::c_char;

use onyx_hook::{Hook, HookEngine};

use crate::api::abi_util::{cstr_to_str, guard, ERR_INTERNAL, ERR_INVALID_UTF8, ERR_NULL, OK};

#[no_mangle]
pub unsafe extern "C" fn onyx_hook_create(
    target: *const c_void,
    hook_fn: *const c_void,
    out_hook: *mut *mut c_void,
) -> i32 {
    guard(|| {
        if target.is_null() || hook_fn.is_null() || out_hook.is_null() {
            return ERR_NULL;
        }
        match Hook::new(target as *const u8, hook_fn as *const u8) {
            Ok(h) => {
                let boxed = Box::new(h);
                *out_hook = Box::into_raw(boxed) as *mut c_void;
                OK
            }
            Err(_) => ERR_INTERNAL,
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn onyx_hook_original(hook: *mut c_void) -> *const c_void {
    if hook.is_null() {
        return std::ptr::null();
    }
    let h = &*(hook as *const Hook);
    h.original() as *const c_void
}

#[no_mangle]
pub unsafe extern "C" fn onyx_hook_remove(hook: *mut c_void) -> i32 {
    guard(|| {
        if hook.is_null() {
            return ERR_NULL;
        }
        let boxed: Box<Hook> = Box::from_raw(hook as *mut Hook);
        match boxed.remove() {
            Ok(()) => OK,
            Err(_) => ERR_INTERNAL,
        }
    })
}

#[no_mangle]
pub extern "C" fn onyx_hook_engine_new() -> *mut c_void {
    let engine = Box::new(HookEngine::new());
    Box::into_raw(engine) as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn onyx_hook_engine_free(engine: *mut c_void) {
    if engine.is_null() {
        return;
    }
    drop(Box::from_raw(engine as *mut HookEngine));
}

#[no_mangle]
pub unsafe extern "C" fn onyx_hook_engine_install(
    engine: *mut c_void,
    name: *const c_char,
    target: *const c_void,
    hook_fn: *const c_void,
    out_original: *mut *const c_void,
) -> i32 {
    guard(|| {
        if engine.is_null() || name.is_null() || target.is_null() || hook_fn.is_null() {
            return ERR_NULL;
        }
        let name_str = match cstr_to_str(name) {
            Some(s) => s,
            None => return ERR_INVALID_UTF8,
        };
        let eng = &mut *(engine as *mut HookEngine);
        match eng.install(name_str, target as *const u8, hook_fn as *const u8) {
            Ok(orig) => {
                if !out_original.is_null() {
                    *out_original = orig as *const c_void;
                }
                OK
            }
            Err(_) => ERR_INTERNAL,
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn onyx_hook_engine_remove_by_name(
    engine: *mut c_void,
    name: *const c_char,
) -> i32 {
    guard(|| {
        if engine.is_null() || name.is_null() {
            return ERR_NULL;
        }
        let name_str = match cstr_to_str(name) {
            Some(s) => s,
            None => return ERR_INVALID_UTF8,
        };
        let eng = &mut *(engine as *mut HookEngine);
        match eng.remove(name_str) {
            Ok(()) => OK,
            Err(_) => ERR_INTERNAL,
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn onyx_hook_engine_len(engine: *mut c_void) -> i32 {
    if engine.is_null() {
        return -1;
    }
    let eng = &*(engine as *const HookEngine);
    eng.len() as i32
}
