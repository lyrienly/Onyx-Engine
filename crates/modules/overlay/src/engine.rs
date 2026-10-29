//! Motor do overlay: instala um detour em `IDXGISwapChain::Present`, roteia o
//! callback de desenho do usuario e restaura o alvo original ao desinstalar.

use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use onyx_hook::{Hook, HookError};

use crate::dx::*;
use crate::present_hook::{resolve_present_slot, ResolveError};
use crate::renderer::Renderer;

/// Dados passados ao callback de desenho a cada frame.
pub struct OverlayFrame {
    pub swapchain: *mut IDXGISwapChain,
    pub device: *mut ID3D11Device,
    pub context: *mut ID3D11DeviceContext,
    pub frame_index: u64,
}

type DrawCallback = Box<dyn FnMut(&OverlayFrame) + Send>;

#[derive(Debug)]
pub enum OverlayError {
    Resolve(ResolveError),
    Hook(HookError),
    AlreadyInstalled,
    NotInstalled,
}

impl core::fmt::Display for OverlayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OverlayError::Resolve(e) => write!(f, "resolve: {}", e),
            OverlayError::Hook(e) => write!(f, "hook: {}", e),
            OverlayError::AlreadyInstalled => write!(f, "overlay ja instalado"),
            OverlayError::NotInstalled => write!(f, "overlay nao instalado"),
        }
    }
}

impl std::error::Error for OverlayError {}

type FnPresent =
    unsafe extern "system" fn(this: *mut IDXGISwapChain, sync_interval: u32, flags: u32) -> HRESULT;

// Estado global (unico detour ativo por processo).
static PRESENT_HIT_COUNT: AtomicU64 = AtomicU64::new(0);
static ORIG_PRESENT_PTR: AtomicUsize = AtomicUsize::new(0);
static DEVICE_PTR: AtomicPtr<ID3D11Device> = AtomicPtr::new(core::ptr::null_mut());
static CONTEXT_PTR: AtomicPtr<ID3D11DeviceContext> = AtomicPtr::new(core::ptr::null_mut());

static ENGINE_STATE: Mutex<Option<EngineState>> = Mutex::new(None);
static DRAW_CB: Mutex<Option<DrawCallback>> = Mutex::new(None);
static RENDERER: Mutex<Option<Renderer>> = Mutex::new(None);

struct EngineState {
    hook: Hook,
}

unsafe extern "system" fn present_detour(
    this: *mut IDXGISwapChain,
    sync_interval: u32,
    flags: u32,
) -> HRESULT {
    let frame_index = PRESENT_HIT_COUNT.fetch_add(1, Ordering::SeqCst);

    if let Ok(guard) = RENDERER.lock() {
        if let Some(renderer) = guard.as_ref() {
            let _ = renderer.render(this);
        }
    }

    if let Ok(mut guard) = DRAW_CB.lock() {
        if let Some(cb) = guard.as_mut() {
            let frame = OverlayFrame {
                swapchain: this,
                device: DEVICE_PTR.load(Ordering::SeqCst),
                context: CONTEXT_PTR.load(Ordering::SeqCst),
                frame_index,
            };
            cb(&frame);
        }
    }

    let orig = ORIG_PRESENT_PTR.load(Ordering::SeqCst);
    if orig == 0 {
        return 0;
    }
    let f: FnPresent = core::mem::transmute(orig);
    f(this, sync_interval, flags)
}

pub struct OverlayEngine;

impl OverlayEngine {
    pub fn install(
        device: *mut ID3D11Device,
        context: *mut ID3D11DeviceContext,
    ) -> Result<(), OverlayError> {
        let mut slot = ENGINE_STATE.lock().unwrap();
        if slot.is_some() {
            return Err(OverlayError::AlreadyInstalled);
        }

        let present = resolve_present_slot().map_err(OverlayError::Resolve)?;
        let hook = Hook::new(present, present_detour as *const u8).map_err(OverlayError::Hook)?;
        ORIG_PRESENT_PTR.store(hook.original() as usize, Ordering::SeqCst);
        PRESENT_HIT_COUNT.store(0, Ordering::SeqCst);
        DEVICE_PTR.store(device, Ordering::SeqCst);
        CONTEXT_PTR.store(context, Ordering::SeqCst);

        if !device.is_null() && !context.is_null() {
            *RENDERER.lock().unwrap() = Some(Renderer::new(device, context));
        }

        *slot = Some(EngineState { hook });
        Ok(())
    }

    pub fn set_draw<F>(callback: F)
    where
        F: FnMut(&OverlayFrame) + Send + 'static,
    {
        *DRAW_CB.lock().unwrap() = Some(Box::new(callback));
    }

    pub fn clear_draw() {
        *DRAW_CB.lock().unwrap() = None;
    }

    pub fn hit_count() -> u64 {
        PRESENT_HIT_COUNT.load(Ordering::SeqCst)
    }

    pub fn set_clear_color(r: f32, g: f32, b: f32, a: f32) {
        if let Ok(mut guard) = RENDERER.lock() {
            if let Some(renderer) = guard.as_mut() {
                renderer.set_clear_color(r, g, b, a);
            }
        }
    }

    pub fn uninstall() -> Result<(), OverlayError> {
        let mut slot = ENGINE_STATE.lock().unwrap();
        let state = slot.take().ok_or(OverlayError::NotInstalled)?;
        state.hook.remove().map_err(OverlayError::Hook)?;
        ORIG_PRESENT_PTR.store(0, Ordering::SeqCst);
        DEVICE_PTR.store(core::ptr::null_mut(), Ordering::SeqCst);
        CONTEXT_PTR.store(core::ptr::null_mut(), Ordering::SeqCst);
        *RENDERER.lock().unwrap() = None;
        *DRAW_CB.lock().unwrap() = None;
        Ok(())
    }
}
