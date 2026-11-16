#![allow(unsafe_op_in_unsafe_fn, unused_mut, static_mut_refs, dead_code)]

pub mod api;
pub mod loader;
pub mod types;

pub use api::aa::*;
pub use api::abi_util::*;
pub use api::disasm::*;
pub use api::error::*;
pub use api::freezer::*;
pub use api::gdb::*;
pub use api::hook::*;
pub use api::manual_map::*;
pub use api::mono::*;
pub use api::pointer::*;
pub use api::process::*;
pub use api::scanner::*;
pub use api::speedhack::*;
pub use api::tx::*;
pub use api::veh::*;
pub use loader::*;

#[no_mangle]
pub extern "C" fn onyx_backend_version() -> u32 {
    loader::ensure_initialized();
    100
}

#[no_mangle]
pub extern "C" fn onyx_backend_ping() -> i32 {
    loader::ensure_initialized();
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
    _fdw_reason: u32,
    _lpv_reserved: *mut std::ffi::c_void,
) -> i32 {
    1
}
