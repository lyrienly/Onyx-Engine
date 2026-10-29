use std::os::raw::c_char;

use crate::api::abi_util::ERR_NOT_IMPLEMENTED;

#[no_mangle]
pub extern "C" fn onyx_manual_map_dll(_target_pid: u32, _dll_path: *const c_char) -> i32 {
    ERR_NOT_IMPLEMENTED
}

#[no_mangle]
pub extern "C" fn onyx_manual_map_available() -> i32 {
    0
}
