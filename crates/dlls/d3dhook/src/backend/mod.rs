//! Rendering backends do overlay — a camada que vai hospedar ImGui.
//!
//! Cada API gráfica tem um backend concreto que recebe os objetos capturados
//! pelos hooks (device, context, command queue) e desenha o overlay no mesmo
//! pipeline do jogo. A seleção acontece via `select_from_captured_state()`.
//!
//! A integração ImGui será adicionada em PR dedicado via `imgui = "0.12"`:
//! - `imgui-dx11` → `D3D11Backend`
//! - fork/manual DX12 renderer → `D3D12Backend`
//! - `imgui-rs-vulkan-renderer` → `VulkanBackend`
//!
//! Cada renderer precisa de 3 pontos de integração:
//! 1. **init:** cria texture atlas, upload de fontes, cria pipeline/PSO.
//! 2. **render_frame:** `ctx.new_frame()` → desenha a UI → `ctx.render()`
//!    → emite draw calls no device/queue capturado.
//! 3. **shutdown:** libera recursos GPU antes do unhook (ver PR #13).

use crate::state::{CAPTURED, CapturedApi};

pub mod d3d11;
pub mod d3d12;
pub mod vulkan;

/// Interface comum a todos os backends do overlay.
///
/// Chamada **sempre** da thread de render do jogo (dentro do trampolim de
/// Present / ExecuteCommandLists / vkQueuePresentKHR), nunca de outra thread.
pub trait OverlayBackend {
    /// Chamado uma única vez após captura dos handles do jogo. Deve criar
    /// pipelines, descritores, texture atlas das fontes ImGui.
    unsafe fn init(&mut self) -> bool;

    /// Chamado a cada frame do jogo, antes do Present original. Executa o
    /// ciclo ImGui `new_frame → draw UI → render` emitindo draw calls no
    /// device/queue capturado.
    unsafe fn render_frame(&mut self);

    /// Libera todos os recursos GPU alocados. Precisa rodar **antes** da DLL
    /// descarregar — ver `manager::uninstall_all`.
    unsafe fn shutdown(&mut self);

    /// Nome legível, usado em logs.
    fn name(&self) -> &'static str;
}

/// Escolhe o backend concreto a partir do estado capturado pelos hooks.
/// Retorna `None` se nenhuma API foi capturada ainda.
pub fn select_from_captured_state() -> Option<Box<dyn OverlayBackend + Send>> {
    match &*CAPTURED.lock() {
        CapturedApi::None => None,
        CapturedApi::D3D11 { .. } => Some(Box::new(d3d11::D3D11Backend::default())),
        CapturedApi::D3D12 { .. } => Some(Box::new(d3d12::D3D12Backend::default())),
        CapturedApi::Vulkan => Some(Box::new(vulkan::VulkanBackend::default())),
    }
}
