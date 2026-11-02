//! Hook de `IDXGISwapChain::Present` e `IDXGISwapChain1::Present1`.
//!
//! Estratégia: cria um dispositivo D3D11 + swap chain dummy em uma janela
//! oculta, lê os ponteiros Present/Present1 das VTables, patcha-os para
//! nossos trampolines, guarda os originais em [`ORIG_PRESENT`] / [`ORIG_PRESENT1`].
//! Compartilhado entre DX10/11/12 (todos apresentam via DXGI).

use super::{HookError, HookResult};
use crate::vtable::{patch_slot, vtable_of};
use parking_lot::Mutex;
use std::ffi::c_void;
use windows::Win32::Foundation::{BOOL, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_CREATE_DEVICE_FLAG, D3D11_SDK_VERSION, D3D11CreateDeviceAndSwapChain,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_MODE_DESC, DXGI_RATIONAL, DXGI_SAMPLE_DESC,
};
use windows::Win32::Graphics::Dxgi::{
    DXGI_SWAP_CHAIN_DESC, DXGI_SWAP_EFFECT_DISCARD, DXGI_USAGE_RENDER_TARGET_OUTPUT, IDXGISwapChain,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, CreateWindowExA, DefWindowProcA, DestroyWindow,
    RegisterClassExA, UnregisterClassA, WINDOW_EX_STYLE, WNDCLASSEXA, WS_OVERLAPPEDWINDOW,
};
use windows::core::{Interface, PCSTR};

const PRESENT_VTABLE_INDEX: usize = 8;
#[allow(dead_code)]
const PRESENT1_VTABLE_INDEX: usize = 22;

type FnPresent =
    unsafe extern "system" fn(*mut c_void, sync_interval: u32, flags: u32) -> windows::core::HRESULT;

static ORIG_PRESENT: Mutex<Option<FnPresent>> = Mutex::new(None);
static PRESENT_SLOT: Mutex<Option<usize>> = Mutex::new(None);

unsafe extern "system" fn hook_present(
    swap_chain: *mut c_void,
    sync_interval: u32,
    flags: u32,
) -> windows::core::HRESULT {
    // TODO(issue-8): disparar overlay backend (ImGui) antes do Present original.
    let orig = *ORIG_PRESENT.lock();
    match orig {
        Some(f) => f(swap_chain, sync_interval, flags),
        None => windows::core::HRESULT(0),
    }
}

pub unsafe fn install() -> HookResult {
    let swap_chain = create_dummy_swap_chain()?;
    let vt = vtable_of(swap_chain.as_raw() as *mut c_void);
    let slot = vt.add(PRESENT_VTABLE_INDEX);
    let original = patch_slot(slot, hook_present as *mut c_void);
    *ORIG_PRESENT.lock() = Some(std::mem::transmute::<*mut c_void, FnPresent>(original));
    *PRESENT_SLOT.lock() = Some(slot as usize);
    Ok(())
}

pub unsafe fn uninstall() {
    let (Some(slot_addr), Some(orig)) = (*PRESENT_SLOT.lock(), *ORIG_PRESENT.lock()) else {
        return;
    };
    let slot = slot_addr as *mut *mut c_void;
    patch_slot(slot, orig as *mut c_void);
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

    let mut desc = DXGI_SWAP_CHAIN_DESC {
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
    let _ = &mut desc;
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
