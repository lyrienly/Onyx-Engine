// OnyxEngine Backend Native Dynamic Library (onyx_backend.dll)
// High-performance Rust backend engine for Pascal / Lazarus frontend

#![allow(unsafe_op_in_unsafe_fn, unused_mut, static_mut_refs, dead_code)]

pub mod types;
pub mod api;

pub use api::process::*;
pub use api::scanner::*;
pub use api::disasm::*;
pub use api::freezer::*;
pub use api::pointer::*;
pub use api::speedhack::*;
pub use api::mono::*;

/// Query backend version code (e.g. 100 for v1.0.0)
#[no_mangle]
pub extern "C" fn onyx_backend_version() -> u32 {
    100
}

/// Check if the backend is initialized and healthy
#[no_mangle]
pub extern "C" fn onyx_backend_ping() -> i32 {
    1
}

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(
    _hinst_dll: *mut std::ffi::c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut std::ffi::c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_PROCESS_DETACH: u32 = 0;

    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            // Initialization
        }
        DLL_PROCESS_DETACH => {
            // Cleanup
        }
        _ => {}
    }

    1
}
