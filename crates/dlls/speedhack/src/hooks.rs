//! Instalacao dos detours de temporizacao.
//!
//! Usa `onyx_hook::HookEngine` para patchar os prologos das APIs do
//! Windows: `QueryPerformanceCounter`, `GetTickCount`, `GetTickCount64` e
//! `timeGetTime`. Cada detour chama o original pelo trampolim (nunca o
//! simbolo nominal, que esta patchado) e aplica a conversao via
//! [`crate::clock`].
//!
//! `QueryPerformanceFrequency` NAO e hookado: alterar a frequencia quebra
//! toda normalizacao de delta em motores modernos.

#![cfg(windows)]
#![allow(non_snake_case, unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::sync::Mutex;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use onyx_hook::{HookEngine, HookError};

use crate::clock;

type BOOL = i32;
type DWORD = u32;
type HMODULE = *mut c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleA(lpModuleName: *const u8) -> HMODULE;
    fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> *mut c_void;
    fn LoadLibraryA(lpLibFileName: *const u8) -> HMODULE;
}

type FnQpc = unsafe extern "system" fn(*mut i64) -> BOOL;

static TRAMP_QPC: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static TRAMP_GTC: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static TRAMP_GTC64: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static TRAMP_TGT: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

static ENGINE: Mutex<Option<HookEngine>> = Mutex::new(None);
static INSTALL_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
pub enum InstallError {
    Hook(HookError),
    MissingSymbol(&'static str),
    AlreadyInstalled,
}

impl core::fmt::Display for InstallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InstallError::Hook(e) => write!(f, "hook: {}", e),
            InstallError::MissingSymbol(s) => write!(f, "simbolo ausente: {}", s),
            InstallError::AlreadyInstalled => write!(f, "ja instalado"),
        }
    }
}

/// Le o QPC real passando pelo trampolim quando disponivel.
#[inline]
fn real_qpc_now() -> i64 {
    let tp = TRAMP_QPC.load(Ordering::Acquire);
    if tp.is_null() {
        return clock::raw_qpc_now();
    }
    unsafe {
        let f: FnQpc = core::mem::transmute(tp);
        let mut v: i64 = 0;
        f(&mut v);
        v
    }
}

unsafe extern "system" fn hooked_qpc(out: *mut i64) -> BOOL {
    let real = real_qpc_now();
    if !out.is_null() {
        *out = clock::virtual_from_real(real);
    }
    1
}

unsafe extern "system" fn hooked_gtc() -> DWORD {
    let real = real_qpc_now();
    clock::virtual_ms_from_real(real) as DWORD
}

unsafe extern "system" fn hooked_gtc64() -> u64 {
    let real = real_qpc_now();
    clock::virtual_ms_from_real(real)
}

unsafe extern "system" fn hooked_tgt() -> DWORD {
    let real = real_qpc_now();
    clock::virtual_ms_from_real(real) as DWORD
}

/// Retorna todos os enderecos distintos do simbolo em kernel32 e kernelbase.
///
/// Em versoes modernas do Windows alguns exports (ex.: `GetTickCount64`) sao
/// implementados independentemente em cada DLL em vez de forwarder: patchar
/// apenas um nao basta. Retornamos dois ponteiros ja deduplicados.
unsafe fn resolve_kernel_all(name: &[u8]) -> [*const u8; 2] {
    debug_assert!(name.last() == Some(&0));
    let kb = GetModuleHandleA(b"kernelbase.dll\0".as_ptr());
    let k32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    let a = if !kb.is_null() {
        GetProcAddress(kb, name.as_ptr()) as *const u8
    } else {
        core::ptr::null()
    };
    let b = if !k32.is_null() {
        let p = GetProcAddress(k32, name.as_ptr()) as *const u8;
        if p == a { core::ptr::null() } else { p }
    } else {
        core::ptr::null()
    };
    [a, b]
}

unsafe fn resolve_kernel(name: &[u8]) -> *const u8 {
    let [a, b] = resolve_kernel_all(name);
    if !a.is_null() { a } else { b }
}

unsafe fn resolve_winmm(name: &[u8]) -> *const u8 {
    debug_assert!(name.last() == Some(&0));
    let mut h = GetModuleHandleA(b"winmm.dll\0".as_ptr());
    if h.is_null() {
        h = LoadLibraryA(b"winmm.dll\0".as_ptr());
    }
    if h.is_null() {
        return core::ptr::null();
    }
    let p = GetProcAddress(h, name.as_ptr());
    if p.is_null() {
        core::ptr::null()
    } else {
        p as *const u8
    }
}

/// Instala os detours. Idempotente por processo.
pub fn install(speed: f64) -> Result<(), InstallError> {
    let prev = INSTALL_COUNT.fetch_add(1, Ordering::SeqCst);
    if prev != 0 {
        INSTALL_COUNT.fetch_sub(1, Ordering::SeqCst);
        return Err(InstallError::AlreadyInstalled);
    }

    clock::init_with(clock::raw_qpc_now(), clock::raw_qpc_freq(), speed);

    let mut engine = HookEngine::new();

    unsafe {
        let p_qpc = resolve_kernel(b"QueryPerformanceCounter\0");
        if p_qpc.is_null() {
            clock::deinit();
            INSTALL_COUNT.store(0, Ordering::SeqCst);
            return Err(InstallError::MissingSymbol("QueryPerformanceCounter"));
        }
        let tramp = engine
            .install("QueryPerformanceCounter", p_qpc, hooked_qpc as *const u8)
            .map_err(InstallError::Hook)?;
        TRAMP_QPC.store(tramp as *mut c_void, Ordering::Release);

        for (i, p) in resolve_kernel_all(b"GetTickCount\0").iter().enumerate() {
            if p.is_null() { continue; }
            let name = if i == 0 { "GetTickCount@kernelbase" } else { "GetTickCount@kernel32" };
            match engine.install(name, *p, hooked_gtc as *const u8) {
                Ok(t) => {
                    if TRAMP_GTC.load(Ordering::Relaxed).is_null() {
                        TRAMP_GTC.store(t as *mut c_void, Ordering::Release);
                    }
                }
                Err(e) => eprintln!("[speedhack] {} hook falhou: {}", name, e),
            }
        }

        for (i, p) in resolve_kernel_all(b"GetTickCount64\0").iter().enumerate() {
            if p.is_null() { continue; }
            let name = if i == 0 { "GetTickCount64@kernelbase" } else { "GetTickCount64@kernel32" };
            match engine.install(name, *p, hooked_gtc64 as *const u8) {
                Ok(t) => {
                    if TRAMP_GTC64.load(Ordering::Relaxed).is_null() {
                        TRAMP_GTC64.store(t as *mut c_void, Ordering::Release);
                    }
                }
                Err(e) => eprintln!("[speedhack] {} hook falhou: {}", name, e),
            }
        }

        let p_tgt = resolve_winmm(b"timeGetTime\0");
        if !p_tgt.is_null() {
            match engine.install("timeGetTime", p_tgt, hooked_tgt as *const u8) {
                Ok(t) => TRAMP_TGT.store(t as *mut c_void, Ordering::Release),
                Err(e) => eprintln!("[speedhack] timeGetTime hook falhou: {}", e),
            }
        }
    }

    *ENGINE.lock().unwrap() = Some(engine);
    Ok(())
}

/// Remove todos os hooks ativos.
pub fn uninstall() -> Result<(), InstallError> {
    let mut guard = ENGINE.lock().unwrap();
    if let Some(mut engine) = guard.take() {
        let _ = engine.remove("timeGetTime");
        let _ = engine.remove("GetTickCount64@kernelbase");
        let _ = engine.remove("GetTickCount64@kernel32");
        let _ = engine.remove("GetTickCount@kernelbase");
        let _ = engine.remove("GetTickCount@kernel32");
        let _ = engine.remove("QueryPerformanceCounter");
    }
    TRAMP_TGT.store(core::ptr::null_mut(), Ordering::Release);
    TRAMP_GTC64.store(core::ptr::null_mut(), Ordering::Release);
    TRAMP_GTC.store(core::ptr::null_mut(), Ordering::Release);
    TRAMP_QPC.store(core::ptr::null_mut(), Ordering::Release);
    clock::deinit();
    INSTALL_COUNT.store(0, Ordering::SeqCst);
    Ok(())
}

pub fn set_speed(speed: f64) {
    let real = real_qpc_now();
    clock::set_speed_with(real, speed);
}

pub fn is_installed() -> bool {
    INSTALL_COUNT.load(Ordering::SeqCst) > 0
}
