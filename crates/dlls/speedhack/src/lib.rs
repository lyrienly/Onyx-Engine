#![allow(
    non_snake_case,
    non_camel_case_types,
    dead_code,
    unsafe_op_in_unsafe_fn,
    static_mut_refs
)]

pub mod clock;

#[cfg(windows)]
pub mod hooks;

#[cfg(windows)]
mod pipe;

#[cfg(windows)]
use std::ffi::c_void;

#[cfg(windows)]
type BOOL = i32;
#[cfg(windows)]
type DWORD = u32;
#[cfg(windows)]
type HMODULE = *mut c_void;
#[cfg(windows)]
type LPVOID = *mut c_void;

#[cfg(windows)]
const DLL_PROCESS_ATTACH: DWORD = 1;

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn DisableThreadLibraryCalls(hLibModule: HMODULE) -> BOOL;
}

// ============================================================================
// C ABI publica
// ============================================================================

/// Instala os hooks com a velocidade indicada. Retorna 0 em sucesso, codigo
/// negativo em erro. Idempotente: reinstalacoes retornam -2.
#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "system" fn speedhack_install(speed: f64) -> i32 {
    match hooks::install(speed) {
        Ok(()) => 0,
        Err(hooks::InstallError::AlreadyInstalled) => -2,
        Err(hooks::InstallError::MissingSymbol(_)) => -3,
        Err(hooks::InstallError::Hook(_)) => -4,
    }
}

#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "system" fn speedhack_set_speed(speed: f64) -> i32 {
    if !hooks::is_installed() {
        return -1;
    }
    hooks::set_speed(speed);
    0
}

#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "system" fn speedhack_uninstall() -> i32 {
    match hooks::uninstall() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

// ---------------------------------------------------------------------------
// API legada (compatibilidade com UI Pascal e injetores que ja chamam estes
// nomes). Mantemos o contrato f32.
// ---------------------------------------------------------------------------

#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "system" fn InitializeSpeedhack(speed: f32) {
    if hooks::is_installed() {
        hooks::set_speed(speed as f64);
    } else {
        let _ = hooks::install(speed as f64);
    }
}

#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "system" fn SetSpeed(speed: f32) {
    if hooks::is_installed() {
        hooks::set_speed(speed as f64);
    }
}

// ============================================================================
// DllMain
// ============================================================================

#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    hinstDLL: HMODULE,
    fdwReason: DWORD,
    _lpReserved: LPVOID,
) -> BOOL {
    if fdwReason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(hinstDLL);
        let _ = hooks::install(1.0);
        pipe::start_listener();
    }
    1
}
