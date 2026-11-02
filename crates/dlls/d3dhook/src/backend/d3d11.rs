//! Backend DX11: ImGui renderizado via `imgui-dx11-renderer`.
//!
//! Fluxo quando a integração ImGui for ativada:
//! 1. `init()`: lê `CapturedApi::D3D11 { device }`, chama
//!    `device.GetImmediateContext()`, instancia `imgui_dx11::Renderer`.
//! 2. `render_frame()`: pega back buffer do swap chain atual, define como
//!    render target no context, roda `ctx.new_frame()` → UI →
//!    `renderer.render(draw_data)`.
//! 3. `shutdown()`: solta ImmediateContext e Renderer antes do unhook.

use super::OverlayBackend;

#[derive(Default)]
pub struct D3D11Backend {
    initialized: bool,
    // TODO(imgui): manter imgui::Context + imgui_dx11::Renderer + ID3D11DeviceContext.
}

impl OverlayBackend for D3D11Backend {
    unsafe fn init(&mut self) -> bool {
        // TODO: instanciar imgui::Context, pegar ImmediateContext do device
        // capturado e construir imgui_dx11::Renderer.
        self.initialized = false;
        false
    }

    unsafe fn render_frame(&mut self) {
        if !self.initialized {
            return;
        }
        // TODO: ctx.new_frame() -> ui.show_demo_window() -> renderer.render(draw_data)
    }

    unsafe fn shutdown(&mut self) {
        self.initialized = false;
    }

    fn name(&self) -> &'static str {
        "D3D11"
    }
}
