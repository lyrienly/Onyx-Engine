//! Renderizador minimo do overlay: cria uma RTV para o backbuffer atual e
//! executa `ClearRenderTargetView` com a cor configurada. Suficiente para
//! evidenciar visualmente que o detour de `Present` executou render antes
//! do swap original.

use core::ptr::null_mut;

use crate::dx::*;

pub struct Renderer {
    device: *mut ID3D11Device,
    context: *mut ID3D11DeviceContext,
    clear_rgba: [f32; 4],
}

unsafe impl Send for Renderer {}
unsafe impl Sync for Renderer {}

impl Renderer {
    pub fn new(device: *mut ID3D11Device, context: *mut ID3D11DeviceContext) -> Self {
        Self {
            device,
            context,
            clear_rgba: [0.10, 0.50, 0.95, 1.0],
        }
    }

    pub fn set_clear_color(&mut self, r: f32, g: f32, b: f32, a: f32) {
        self.clear_rgba = [r, g, b, a];
    }

    pub unsafe fn render(&self, swapchain: *mut IDXGISwapChain) -> Result<(), HRESULT> {
        if swapchain.is_null() || self.device.is_null() || self.context.is_null() {
            return Err(-1);
        }

        let sc_vtbl = *(swapchain as *const *const IDXGISwapChainVtbl);
        let mut back: *mut core::ffi::c_void = null_mut();
        let hr = ((*sc_vtbl).get_buffer)(swapchain, 0, &IID_ID3D11_TEXTURE2D, &mut back);
        if hr < 0 || back.is_null() {
            return Err(hr);
        }

        let rtv_desc = D3D11_RENDER_TARGET_VIEW_DESC {
            Format: DXGI_FORMAT_R8G8B8A8_UNORM,
            ViewDimension: D3D11_RTV_DIMENSION_TEXTURE2D,
            Texture2D: D3D11_TEX2D_RTV { MipSlice: 0 },
        };

        let device_vtbl = *(self.device as *const *const ID3D11DeviceVtbl);
        let mut rtv: *mut ID3D11RenderTargetView = null_mut();
        let hr = ((*device_vtbl).create_render_target_view)(
            self.device,
            back as *mut ID3D11Resource,
            &rtv_desc,
            &mut rtv,
        );
        release_com(back);
        if hr < 0 || rtv.is_null() {
            return Err(hr);
        }

        let ctx_vtbl = *(self.context as *const *const ID3D11DeviceContextVtbl);
        ((*ctx_vtbl).clear_render_target_view)(self.context, rtv, &self.clear_rgba);

        release_com(rtv);
        Ok(())
    }
}
