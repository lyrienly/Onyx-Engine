pub mod d3d12;
pub mod dxgi;
pub mod vulkan;

#[derive(Debug)]
pub enum HookError {
    DummyDeviceFailed,
    VTableUnavailable,
    ModuleNotLoaded(&'static str),
    SymbolNotFound(&'static str),
    DetourFailed,
    Unimplemented,
}

pub type HookResult<T = ()> = Result<T, HookError>;
