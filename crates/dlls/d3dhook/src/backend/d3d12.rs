use super::OverlayBackend;

#[derive(Default)]
pub struct D3D12Backend;

impl OverlayBackend for D3D12Backend {
    unsafe fn init(&mut self) -> bool {
        // TODO(issue-8): bind imgui-dx12 ao device + CommandQueue capturados.
        false
    }
    unsafe fn render_frame(&mut self) {}
    unsafe fn shutdown(&mut self) {}
}
