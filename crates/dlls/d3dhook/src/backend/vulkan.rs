use super::OverlayBackend;

#[derive(Default)]
pub struct VulkanBackend;

impl OverlayBackend for VulkanBackend {
    unsafe fn init(&mut self) -> bool {
        // TODO(issue-8): bind imgui-rs-vulkan-renderer ao device + swapchain capturados.
        false
    }
    unsafe fn render_frame(&mut self) {}
    unsafe fn shutdown(&mut self) {}
}
