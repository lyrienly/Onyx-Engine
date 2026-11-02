#![allow(
    non_snake_case,
    non_camel_case_types,
    dead_code,
    unsafe_op_in_unsafe_fn,
    static_mut_refs
)]

pub mod backend;
pub mod exports;
pub mod hooks;
pub mod manager;
pub mod pipe;
pub mod state;
pub mod vtable;

pub use exports::{
    D3DHook_ClearCommands, D3DHook_GetCommandCount, D3DHook_Initialize, D3DHook_Shutdown,
    RenderCommand,
};

use std::ffi::c_void;

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: *mut c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> i32 {
    match fdw_reason {
        1 => {
            D3DHook_Initialize();
        }
        0 => {
            D3DHook_Shutdown();
        }
        _ => {}
    }
    1
}
