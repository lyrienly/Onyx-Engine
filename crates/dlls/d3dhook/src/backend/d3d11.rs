use super::OverlayBackend;

#[derive(Default)]
pub struct D3D11Backend;

impl OverlayBackend for D3D11Backend {
    unsafe fn init(&mut self) -> bool {
        // TODO(issue-8): bind imgui-dx11 ao device/context capturado pelo hook DXGI.
        false
    }
    unsafe fn render_frame(&mut self) {}
    unsafe fn shutdown(&mut self) {}
}
