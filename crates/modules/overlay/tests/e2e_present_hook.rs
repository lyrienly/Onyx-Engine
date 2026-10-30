#![cfg(windows)]
#![allow(non_snake_case)]

use core::ffi::c_void;
use core::ptr::{null, null_mut};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use onyx_overlay::dx::*;
use onyx_overlay::OverlayEngine;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExA, DefWindowProcA, DestroyWindow, RegisterClassExA, UnregisterClassA,
    WNDCLASSEXA, WS_OVERLAPPEDWINDOW,
};

fn scratchpad_dir() -> PathBuf {
    let p = std::env::temp_dir().join("onyx_overlay_scratchpad");
    fs::create_dir_all(&p).ok();
    p
}

fn log(msg: &str) {
    let path = scratchpad_dir().join("overlay_e2e.log");
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{}", msg);
    }
    eprintln!("{}", msg);
}

#[test]
fn e2e_overlay_hook_presente_e_desenha() {
    unsafe {
        log("--- inicio e2e_overlay_hook_presente_e_desenha ---");
        let class_name = b"OnyxOverlayE2E\0".as_ptr();
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
        let _ = RegisterClassExA(&wc);

        let hwnd = CreateWindowExA(
            0,
            class_name,
            b"OnyxOverlayE2E\0".as_ptr(),
            WS_OVERLAPPEDWINDOW,
            0,
            0,
            320,
            240,
            0,
            0,
            0,
            null(),
        );
        assert!(hwnd != 0, "CreateWindowExA");

        let desc = DXGI_SWAP_CHAIN_DESC {
            BufferDesc: DXGI_MODE_DESC {
                Width: 320,
                Height: 240,
                RefreshRate: DXGI_RATIONAL {
                    Numerator: 60,
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
            OutputWindow: hwnd as usize as *mut c_void,
            Windowed: 1,
            SwapEffect: DXGI_SWAP_EFFECT_DISCARD,
            Flags: 0,
        };

        let feature_levels = [D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0];
        let mut swapchain: *mut IDXGISwapChain = null_mut();
        let mut device: *mut ID3D11Device = null_mut();
        let mut context: *mut ID3D11DeviceContext = null_mut();
        let mut got_level = 0u32;

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
            &mut got_level,
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
                &mut got_level,
                &mut context,
            );
        }
        assert!(hr >= 0, "D3D11CreateDeviceAndSwapChain hr={:#x}", hr);
        log(&format!(
            "device/swapchain criados hr={:#x} level={:#x}",
            hr, got_level
        ));

        OverlayEngine::install(device, context).expect("install overlay");
        OverlayEngine::set_clear_color(0.10, 0.80, 0.20, 1.0);

        static USER_CB_HITS: AtomicU64 = AtomicU64::new(0);
        OverlayEngine::set_draw(|_frame| {
            USER_CB_HITS.fetch_add(1, Ordering::SeqCst);
        });

        let sc_vtbl = *(swapchain as *const *const IDXGISwapChainVtbl);
        for _ in 0..30 {
            let _ = ((*sc_vtbl).present)(swapchain, 0, 0);
        }

        let hits = OverlayEngine::hit_count();
        log(&format!("hits apos 30 frames = {}", hits));
        assert!(hits >= 30, "hits insuficientes: {}", hits);
        assert!(
            USER_CB_HITS.load(Ordering::SeqCst) >= 30,
            "callback de usuario nao foi chamado"
        );

        // Staging texture para captura
        let dev_vtbl = *(device as *const *const ID3D11DeviceVtbl);
        let staging_desc = D3D11_TEXTURE2D_DESC {
            Width: 320,
            Height: 240,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_R8G8B8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ,
            MiscFlags: 0,
        };
        let mut staging: *mut ID3D11Texture2D = null_mut();
        let hr = ((*dev_vtbl).create_texture_2d)(device, &staging_desc, null(), &mut staging);
        assert!(
            hr >= 0 && !staging.is_null(),
            "CreateTexture2D hr={:#x}",
            hr
        );

        // Captura: callback copia o backbuffer PRE-Present original (apos clear do overlay)
        static CAPTURED: AtomicU64 = AtomicU64::new(0);
        static STAGING_PTR: AtomicPtr<ID3D11Texture2D> = AtomicPtr::new(null_mut());
        STAGING_PTR.store(staging, Ordering::SeqCst);

        OverlayEngine::set_draw(move |frame| {
            if CAPTURED.load(Ordering::SeqCst) == 0 {
                let ctx_vtbl = *(frame.context as *const *const ID3D11DeviceContextVtbl);
                let sc_vtbl2 = *(frame.swapchain as *const *const IDXGISwapChainVtbl);
                let mut bb: *mut c_void = null_mut();
                let hr =
                    ((*sc_vtbl2).get_buffer)(frame.swapchain, 0, &IID_ID3D11_TEXTURE2D, &mut bb);
                if hr >= 0 && !bb.is_null() {
                    let st = STAGING_PTR.load(Ordering::SeqCst);
                    ((*ctx_vtbl).copy_resource)(
                        frame.context,
                        st as *mut ID3D11Resource,
                        bb as *mut ID3D11Resource,
                    );
                    release_com(bb);
                    CAPTURED.store(1, Ordering::SeqCst);
                }
            }
        });

        for _ in 0..2 {
            let _ = ((*sc_vtbl).present)(swapchain, 0, 0);
        }
        assert_eq!(CAPTURED.load(Ordering::SeqCst), 1, "captura nao executou");

        let ctx_vtbl = *(context as *const *const ID3D11DeviceContextVtbl);
        let mut mapped = D3D11_MAPPED_SUBRESOURCE {
            pData: null_mut(),
            RowPitch: 0,
            DepthPitch: 0,
        };
        let hr = ((*ctx_vtbl).map)(
            context,
            staging as *mut ID3D11Resource,
            0,
            D3D11_MAP_READ,
            0,
            &mut mapped,
        );
        assert!(hr >= 0, "Map hr={:#x}", hr);

        let w = 320usize;
        let h = 240usize;
        let mut rgba = vec![0u8; w * h * 4];
        let row_pitch = mapped.RowPitch as usize;
        for y in 0..h {
            let src = (mapped.pData as *const u8).add(y * row_pitch);
            let dst = rgba.as_mut_ptr().add(y * w * 4);
            core::ptr::copy_nonoverlapping(src, dst, w * 4);
        }
        ((*ctx_vtbl).unmap)(context, staging as *mut ID3D11Resource, 0);

        let mut non_black = 0usize;
        let mut green_dominant = 0usize;
        for px in rgba.as_chunks::<4>().0 {
            if px[0] != 0 || px[1] != 0 || px[2] != 0 {
                non_black += 1;
            }
            if px[1] > 150 && px[1] > px[0] && px[1] > px[2] {
                green_dominant += 1;
            }
        }
        log(&format!(
            "pixels nao-pretos = {}/{} ; verde dominante = {}",
            non_black,
            w * h,
            green_dominant
        ));
        assert!(
            non_black > (w * h) / 2,
            "esperava backbuffer colorido pelo overlay"
        );
        assert!(green_dominant > (w * h) / 2, "overlay nao pintou de verde");

        let png_path = scratchpad_dir().join("overlay_e2e_frame.png");
        {
            let f = std::fs::File::create(&png_path).expect("criar png");
            let mut enc = png::Encoder::new(f, w as u32, h as u32);
            enc.set_color(png::ColorType::Rgba);
            enc.set_depth(png::BitDepth::Eight);
            let mut writer = enc.write_header().expect("png header");
            writer.write_image_data(&rgba).expect("png data");
        }
        log(&format!("png salvo em {}", png_path.display()));

        release_com(staging);

        let hits_before = OverlayEngine::hit_count();
        OverlayEngine::uninstall().expect("uninstall");
        for _ in 0..5 {
            let _ = ((*sc_vtbl).present)(swapchain, 0, 0);
        }
        let hits_after = OverlayEngine::hit_count();
        log(&format!(
            "hits antes uninstall = {}, apos 5 presents sem hook = {}",
            hits_before, hits_after
        ));
        assert_eq!(
            hits_before, hits_after,
            "detour continuou ativo apos uninstall"
        );

        release_com(swapchain);
        release_com(context);
        release_com(device);
        DestroyWindow(hwnd);
        UnregisterClassA(class_name, 0);
        log("--- fim e2e ok ---");
    }
}
