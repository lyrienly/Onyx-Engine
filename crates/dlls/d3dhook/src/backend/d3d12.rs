//! Backend DX12: ImGui renderizado via renderer DX12 custom (não há crate
//! `imgui-dx12` oficial mantido em `crates.io`; usamos fork ou port manual).
//!
//! Fluxo quando a integração ImGui for ativada:
//! 1. `init()`: lê `CapturedApi::D3D12 { device, queue: Some(_) }`,
//!    cria descriptor heap SRV (para font atlas) + CBV_SRV_UAV, cria
//!    pipeline state object (root signature + PSO para quad texturizado),
//!    carrega texture atlas da ImGui.
//! 2. `render_frame()`: aloca command list, define render target no back
//!    buffer atual, grava draw calls do ImGui, chama
//!    `queue.ExecuteCommandLists(list)`. Sincroniza via fence.
//! 3. `shutdown()`: espera GPU idle (fence), libera PSO/heaps/texture.

use super::OverlayBackend;

#[derive(Default)]
pub struct D3D12Backend {
    initialized: bool,
    // TODO(imgui): descriptor heap, root signature, PSO, upload buffer,
    // font texture, fence, frame resources ring buffer (3x).
}

impl OverlayBackend for D3D12Backend {
    unsafe fn init(&mut self) -> bool {
        // TODO: criar descriptor heaps, PSO, carregar font atlas no upload
        // heap, copiar para default heap.
        self.initialized = false;
        false
    }

    unsafe fn render_frame(&mut self) {
        if !self.initialized {
            return;
        }
        // TODO: new_frame -> UI -> render -> record command list ->
        // ExecuteCommandLists -> fence signal.
    }

    unsafe fn shutdown(&mut self) {
        // TODO: WaitForGpuIdle (fence) antes de dropar os recursos.
        self.initialized = false;
    }

    fn name(&self) -> &'static str {
        "D3D12"
    }
}
