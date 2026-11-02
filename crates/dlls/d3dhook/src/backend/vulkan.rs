//! Backend Vulkan: ImGui renderizado via `imgui-rs-vulkan-renderer`.
//!
//! Fluxo quando a integração ImGui for ativada (depende do hook de
//! `vkQueuePresentKHR` do PR Vulkan):
//! 1. `init()`: a partir do `VkInstance` capturado, resolve `VkDevice`,
//!    `VkQueue`, `VkSwapchainKHR`. Cria command pool + descriptor pool.
//!    Instancia `imgui_rs_vulkan_renderer::Renderer`.
//! 2. `render_frame()`: dentro do hook de vkQueuePresentKHR, aloca command
//!    buffer transient, grava draw calls do overlay no VkImage do swapchain,
//!    submete antes do present original.
//! 3. `shutdown()`: `vkDeviceWaitIdle` antes de liberar recursos.

use super::OverlayBackend;

#[derive(Default)]
pub struct VulkanBackend {
    initialized: bool,
    // TODO(imgui): instance/device/queue/swapchain handles, command pool,
    // descriptor pool, Renderer.
}

impl OverlayBackend for VulkanBackend {
    unsafe fn init(&mut self) -> bool {
        // TODO: capturar VkDevice/VkQueue a partir do VkInstance armazenado
        // em state, criar pools e Renderer.
        self.initialized = false;
        false
    }

    unsafe fn render_frame(&mut self) {
        if !self.initialized {
            return;
        }
        // TODO: new_frame -> UI -> render -> alloc cmd buffer -> submit.
    }

    unsafe fn shutdown(&mut self) {
        // TODO: vkDeviceWaitIdle antes de dropar.
        self.initialized = false;
    }

    fn name(&self) -> &'static str {
        "Vulkan"
    }
}
