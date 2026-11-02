//! Rendering backends para o overlay (futuro ImGui).
//!
//! Cada API gráfica terá um backend que recebe o handle apresentado pelo hook
//! correspondente (swap chain DX11/DX12, VkQueue+VkSwapchainKHR etc.) e
//! desenha o overlay com ImGui.

pub mod d3d11;
pub mod d3d12;
pub mod vulkan;

pub trait OverlayBackend {
    unsafe fn init(&mut self) -> bool;
    unsafe fn render_frame(&mut self);
    unsafe fn shutdown(&mut self);
}
