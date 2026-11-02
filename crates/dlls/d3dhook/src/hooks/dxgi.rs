//! Hooks de `IDXGISwapChain::Present` e `IDXGISwapChain1::Present1`.
//!
//! Como DX10/11/12 todos apresentam frames via DXGI, hookar Present é a
//! forma mais universal de interceptar o pipeline de apresentação.
//!
//! Estratégia:
//! 1. Criar um dispositivo D3D11 + swap chain dummy em uma janela oculta.
//! 2. QueryInterface o swap chain para IDXGISwapChain1 (todos os sistemas
//!    com DX11.1+ suportam isso).
//! 3. Ler VTable[8] (Present) e VTable[22] (Present1) e patchar.
//! 4. No trampolim, chamar `state::try_capture_from_swap_chain` na primeira
//!    invocação para armazenar o device real do jogo.

use super::{HookError, HookResult};
use crate::state;
use crate::vtable::{patch_slot, vtable_of};
use parking_lot::Mutex;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use windows::Win32::Foundation::{BOOL, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CREATE_DEVICE_FLAG, D3D11_SDK_VERSION, D3D11CreateDeviceAndSwapChain,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_MODE_DESC, DXGI_RATIONAL, DXGI_SAMPLE_DESC,
};
use windows::Win32::Graphics::Dxgi::{
    DXGI_PRESENT_PARAMETERS, DXGI_SWAP_CHAIN_DESC, DXGI_SWAP_EFFECT_DISCARD,
    DXGI_USAGE_RENDER_TARGET_OUTPUT, IDXGISwapChain, IDXGISwapChain1,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, CreateWindowExA, DefWindowProcA, DestroyWindow,
    RegisterClassExA, UnregisterClassA, WINDOW_EX_STYLE, WNDCLASSEXA, WS_OVERLAPPEDWINDOW,
};
use windows::core::{HRESULT, Interface, PCSTR};

const PRESENT_VTABLE_INDEX: usize = 8;
const PRESENT1_VTABLE_INDEX: usize = 22;

type FnPresent =
    unsafe extern "system" fn(this: *mut c_void, sync_interval: u32, flags: u32) -> HRESULT;
type FnPresent1 = unsafe extern "system" fn(
    this: *mut c_void,
    sync_interval: u32,
    flags: u32,
    params: *const DXGI_PRESENT_PARAMETERS,
) -> HRESULT;

static ORIG_PRESENT: Mutex<Option<FnPresent>> = Mutex::new(None);
static PRESENT_SLOT: Mutex<Option<usize>> = Mutex::new(None);
static ORIG_PRESENT1: Mutex<Option<FnPresent1>> = Mutex::new(None);
static PRESENT1_SLOT: Mutex<Option<usize>> = Mutex::new(None);

/// Contador usado pelo PR #13 (unhook race-safe) — incrementado ao entrar
/// no trampolim e decrementado ao sair. uninstall() espera chegar a 0.
pub static IN_HOOK: AtomicU32 = AtomicU32::new(0);

unsafe extern "system" fn hook_present(
    swap_chain: *mut c_void,
    sync_interval: u32,
    flags: u32,
) -> HRESULT {
    IN_HOOK.fetch_add(1, Ordering::SeqCst);
    capture_on_first_present(swap_chain);
    // TODO(PR #12): render overlay ImGui aqui antes do Present original.
    let result = match *ORIG_PRESENT.lock() {
        Some(f) => f(swap_chain, sync_interval, flags),
        None => HRESULT(0),
    };
    IN_HOOK.fetch_sub(1, Ordering::SeqCst);
    result
}

unsafe extern "system" fn hook_present1(
    swap_chain: *mut c_void,
    sync_interval: u32,
    flags: u32,
    params: *const DXGI_PRESENT_PARAMETERS,
) -> HRESULT {
    IN_HOOK.fetch_add(1, Ordering::SeqCst);
    capture_on_first_present(swap_chain);
    // TODO(PR #12): render overlay ImGui aqui antes do Present1 original.
    let result = match *ORIG_PRESENT1.lock() {
        Some(f) => f(swap_chain, sync_interval, flags, params),
        None => HRESULT(0),
    };
    IN_HOOK.fetch_sub(1, Ordering::SeqCst);
    result
}

unsafe fn capture_on_first_present(swap_chain_raw: *mut c_void) {
    if state::is_captured() {
        return;
    }
    if let Some(sc) = IDXGISwapChain::from_raw_borrowed(&swap_chain_raw) {
        state::try_capture_from_swap_chain(sc);
    }
}

pub unsafe fn install() -> HookResult {
    let swap_chain = create_dummy_swap_chain()?;

    // Present (slot 8 de IDXGISwapChain)
    let vt = vtable_of(swap_chain.as_raw() as *mut c_void);
    let slot = vt.add(PRESENT_VTABLE_INDEX);
    let orig = patch_slot(slot, hook_present as *mut c_void);
    *ORIG_PRESENT.lock() = Some(std::mem::transmute::<*mut c_void, FnPresent>(orig));
    *PRESENT_SLOT.lock() = Some(slot as usize);

    // Present1 (slot 22 de IDXGISwapChain1) — opcional: só se QI tiver sucesso
    if let Ok(sc1) = swap_chain.cast::<IDXGISwapChain1>() {
        let vt1 = vtable_of(sc1.as_raw() as *mut c_void);
        let slot1 = vt1.add(PRESENT1_VTABLE_INDEX);
        let orig1 = patch_slot(slot1, hook_present1 as *mut c_void);
        *ORIG_PRESENT1.lock() = Some(std::mem::transmute::<*mut c_void, FnPresent1>(orig1));
        *PRESENT1_SLOT.lock() = Some(slot1 as usize);
    }

    Ok(())
}

pub unsafe fn uninstall() {
    if let (Some(slot_addr), Some(orig)) = (*PRESENT1_SLOT.lock(), *ORIG_PRESENT1.lock()) {
        let slot = slot_addr as *mut *mut c_void;
        patch_slot(slot, orig as *mut c_void);
    }
    *ORIG_PRESENT1.lock() = None;
    *PRESENT1_SLOT.lock() = None;

    if let (Some(slot_addr), Some(orig)) = (*PRESENT_SLOT.lock(), *ORIG_PRESENT.lock()) {
        let slot = slot_addr as *mut *mut c_void;
        patch_slot(slot, orig as *mut c_void);
    }
    *ORIG_PRESENT.lock() = None;
    *PRESENT_SLOT.lock() = None;
}

unsafe fn create_dummy_swap_chain() -> HookResult<IDXGISwapChain> {
    let class_name = b"OnyxDummyDxgi\0".as_ptr() as *const u8;
    let hmod = windows::Win32::System::LibraryLoader::GetModuleHandleA(PCSTR::null())
        .map_err(|_| HookError::DummyDeviceFailed)?;
    let hinstance: HINSTANCE = hmod.into();

    let wc = WNDCLASSEXA {
        cbSize: size_of::<WNDCLASSEXA>() as u32,
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(default_wndproc),
        hInstance: hinstance,
        lpszClassName: PCSTR(class_name),
        ..Default::default()
    };
    RegisterClassExA(&wc);

    let hwnd = CreateWindowExA(
        WINDOW_EX_STYLE(0),
        PCSTR(class_name),
        PCSTR(class_name),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        100,
        100,
        None,
        None,
        hinstance,
        None,
    )
    .map_err(|_| HookError::DummyDeviceFailed)?;

    let desc = DXGI_SWAP_CHAIN_DESC {
        BufferDesc: DXGI_MODE_DESC {
            Width: 100,
            Height: 100,
            RefreshRate: DXGI_RATIONAL { Numerator: 60, Denominator: 1 },
            Format: DXGI_FORMAT_R8G8B8A8_UNORM,
            ..Default::default()
        },
        SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
        BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
        BufferCount: 1,
        OutputWindow: hwnd,
        Windowed: BOOL(1),
        SwapEffect: DXGI_SWAP_EFFECT_DISCARD,
        ..Default::default()
    };

    let feature_levels = [D3D_FEATURE_LEVEL_11_0];
    let mut swap_chain = None;
    let mut device = None;
    let mut context = None;
    let mut level = D3D_FEATURE_LEVEL_11_0;

    let hr = D3D11CreateDeviceAndSwapChain(
        None,
        D3D_DRIVER_TYPE_HARDWARE,
        None,
        D3D11_CREATE_DEVICE_FLAG(0),
        Some(&feature_levels),
        D3D11_SDK_VERSION,
        Some(&desc),
        Some(&mut swap_chain),
        Some(&mut device),
        Some(&mut level),
        Some(&mut context),
    );

    let _ = DestroyWindow(hwnd);
    let _ = UnregisterClassA(PCSTR(class_name), hinstance);

    hr.map_err(|_| HookError::DummyDeviceFailed)?;
    swap_chain.ok_or(HookError::DummyDeviceFailed)
}

unsafe extern "system" fn default_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    DefWindowProcA(hwnd, msg, wparam, lparam)
}
