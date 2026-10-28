
#![allow(unsafe_op_in_unsafe_fn, unused_mut, static_mut_refs, dead_code)]

pub mod types;
pub mod api;
pub mod loader;

pub use api::process::*;
pub use api::scanner::*;
pub use api::disasm::*;
pub use api::freezer::*;
pub use api::pointer::*;
pub use api::speedhack::*;
pub use api::mono::*;
pub use api::veh::*;
pub use api::tx::*;
pub use loader::*;

#[no_mangle]
pub extern "C" fn onyx_backend_version() -> u32 {
    100
}

#[no_mangle]
pub extern "C" fn onyx_backend_ping() -> i32 {
    1
}

#[no_mangle]
pub extern "C" fn onyx_security_cloak_self() -> i32 {
    let pid = std::process::id();
    let _ = onyx_core::security::activate_process_shield();
    if let Ok(driver) = onyx_core::process::kernel::DbkDriver::connect() {
        let _ = driver.hide_process(pid);
    }
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
            loader::init_modules();
        }
        DLL_PROCESS_DETACH => {
            loader::cleanup_modules();
        }
        _ => {}
    }

    1
}

