//! Resolucao do slot `IDXGISwapChain::Present` via criacao de um device DX11
//! descartavel. O endereco retornado e o ponteiro de funcao armazenado em
//! `vtable[8]` da swapchain, que pode ser detourado com `onyx_hook::Hook`.

use core::ffi::c_void;
use core::ptr::{null, null_mut};

use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExA, DefWindowProcA, DestroyWindow, RegisterClassExA, UnregisterClassA,
    WNDCLASSEXA, WS_OVERLAPPEDWINDOW,
};

use crate::dx::*;

pub use crate::dx::PRESENT_VTABLE_INDEX;

#[derive(Debug)]
pub enum ResolveError {
    WindowClass,
    Window,
    Device(HRESULT),
    NullVtable,
}

impl core::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ResolveError::WindowClass => write!(f, "falha ao registrar window class"),
            ResolveError::Window => write!(f, "falha ao criar janela cobaia"),
            ResolveError::Device(hr) => {
                write!(f, "D3D11CreateDeviceAndSwapChain falhou: {:#x}", hr)
            }
            ResolveError::NullVtable => write!(f, "vtable da swapchain invalida"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Resolve o endereco atual de `IDXGISwapChain::Present` extraindo
/// `vtable[PRESENT_VTABLE_INDEX]` de uma swapchain descartavel.
pub fn resolve_present_slot() -> Result<*const u8, ResolveError> {
    unsafe {
        let class_name = c"OnyxOverlayProbe".as_ptr() as *const u8;
        let wc = WNDCLASSEXA {
            cbSize: core::mem::size_of::<WNDCLASSEXA>() as u32,
            style: 0,
            lpfnWndProc: Some(DefWindowProcA),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: 0,
            hIcon: 0,
            hCursor: 0,
            hbrBackground: 0,
            lpszMenuName: null(),
            lpszClassName: class_name,
            hIconSm: 0,
        };
        // Ignora falha se classe ja registrada por chamada anterior.
        let _ = RegisterClassExA(&wc);

        let hwnd = CreateWindowExA(
            0,
            class_name,
            c"OnyxOverlayProbe".as_ptr() as *const u8,
            WS_OVERLAPPEDWINDOW,
            0,
            0,
            4,
            4,
            0,
            0,
            0,
            null(),
        );
        if hwnd == 0 {
            UnregisterClassA(class_name, 0);
            return Err(ResolveError::Window);
        }

        let hwnd_ptr = hwnd as *mut c_void;
        let desc = DXGI_SWAP_CHAIN_DESC {
            BufferDesc: DXGI_MODE_DESC {
                Width: 4,
                Height: 4,
                RefreshRate: DXGI_RATIONAL {
                    Numerator: 0,
                    Denominator: 1,
                },
                Format: DXGI_FORMAT_R8G8B8A8_UNORM,
                ScanlineOrdering: 0,
                Scaling: 0,
            },
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
            BufferCount: 1,
            OutputWindow: hwnd_ptr,
            Windowed: 1,
            SwapEffect: DXGI_SWAP_EFFECT_DISCARD,
            Flags: 0,
        };

        let feature_levels = [D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0];
        let mut swapchain: *mut IDXGISwapChain = null_mut();
        let mut device: *mut ID3D11Device = null_mut();
        let mut context: *mut ID3D11DeviceContext = null_mut();
        let mut obtained_level = 0u32;

        let mut hr = D3D11CreateDeviceAndSwapChain(
            null_mut(),
            D3D_DRIVER_TYPE_HARDWARE,
            null_mut(),
            0,
            feature_levels.as_ptr(),
            feature_levels.len() as u32,
            D3D11_SDK_VERSION,
            &desc,
            &mut swapchain,
            &mut device,
            &mut obtained_level,
            &mut context,
        );
        if hr < 0 {
            hr = D3D11CreateDeviceAndSwapChain(
                null_mut(),
                D3D_DRIVER_TYPE_WARP,
                null_mut(),
                0,
                feature_levels.as_ptr(),
                feature_levels.len() as u32,
                D3D11_SDK_VERSION,
                &desc,
                &mut swapchain,
                &mut device,
                &mut obtained_level,
                &mut context,
            );
        }
        if hr < 0 {
            DestroyWindow(hwnd);
            UnregisterClassA(class_name, 0);
            return Err(ResolveError::Device(hr));
        }

        let vtbl_ptr = *(swapchain as *const *const *const c_void);
        if vtbl_ptr.is_null() {
            release_com(swapchain);
            release_com(context);
            release_com(device);
            DestroyWindow(hwnd);
            UnregisterClassA(class_name, 0);
            return Err(ResolveError::NullVtable);
        }
        let present_fn = *vtbl_ptr.add(PRESENT_VTABLE_INDEX);

        release_com(swapchain);
        release_com(context);
        release_com(device);
        DestroyWindow(hwnd);
        UnregisterClassA(class_name, 0);

        if present_fn.is_null() {
            return Err(ResolveError::NullVtable);
        }
        Ok(present_fn as *const u8)
    }
}
