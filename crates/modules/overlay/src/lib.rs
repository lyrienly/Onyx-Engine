//! Overlay in-game via hook de `IDXGISwapChain::Present`.
//!
//! Expoe uma API minima para instalar/desinstalar o overlay e registrar um
//! callback de desenho invocado a cada frame. O renderizador padrao limpa o
//! backbuffer com uma cor configuravel, suficiente para provar que o pipeline
//! de desenho foi exercitado durante os testes E2E.

#![cfg(windows)]
#![allow(clippy::missing_safety_doc)]

pub mod dx;
pub mod present_hook;
pub mod renderer;
pub mod engine;

pub use dx::PRESENT_VTABLE_INDEX;
pub use engine::{OverlayEngine, OverlayError, OverlayFrame};
pub use present_hook::resolve_present_slot;
pub use renderer::Renderer;
