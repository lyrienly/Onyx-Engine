//! Overlay de telemetria do OnyxEngine via [`hudhook`].
//!
//! A DLL é injetada no processo alvo (jogo). O macro `hudhook!` abaixo
//! define o `DllMain` que:
//! 1. Hooka o pipeline de apresentação DX11 (via `ImguiDx11Hooks`).
//! 2. Captura device/context/swap chain do jogo.
//! 3. Chama `OnyxOverlay::render` a cada frame antes do `Present` original.
//! 4. Restaura os hooks limpamente no `DLL_PROCESS_DETACH`.
//!
//! A ABI de `D3DHook_*` consumida pelo frontend Pascal fica preservada em
//! [`exports`] como stubs — o overlay roda sozinho sem precisar da chamada
//! do frontend.

#![allow(
    static_mut_refs,
    dead_code,
    non_snake_case,
    non_camel_case_types,
    unsafe_op_in_unsafe_fn
)]

use hudhook::hooks::dx11::ImguiDx11Hooks;
use hudhook::imgui::{self, Condition};
use hudhook::{ImguiRenderLoop, hudhook};
use std::time::Instant;

pub mod exports;
mod telemetry;

pub use exports::{
    D3DHook_ClearCommands, D3DHook_GetCommandCount, D3DHook_Initialize, D3DHook_Shutdown,
    RenderCommand,
};

pub struct OnyxOverlay {
    frame_count: u64,
    start: Instant,
}

impl Default for OnyxOverlay {
    fn default() -> Self {
        Self {
            frame_count: 0,
            start: Instant::now(),
        }
    }
}

impl ImguiRenderLoop for OnyxOverlay {
    fn render(&mut self, ui: &mut imgui::Ui) {
        self.frame_count += 1;

        ui.window("Onyx Telemetry")
            .position([20.0, 20.0], Condition::FirstUseEver)
            .size([320.0, 220.0], Condition::FirstUseEver)
            .build(|| {
                let io = ui.io();
                let fps = io.framerate;
                let frame_ms = if fps > 0.0 { 1000.0 / fps } else { 0.0 };

                ui.text(format!("FPS:        {:.1}", fps));
                ui.text(format!("Frame:      {:.2} ms", frame_ms));
                ui.text(format!("Frames:     {}", self.frame_count));
                ui.separator();

                let (mem_mb, peak_mb) = telemetry::process_memory_mb();
                ui.text(format!("Memory:     {} MB", mem_mb));
                ui.text(format!("Peak:       {} MB", peak_mb));
                ui.separator();

                let uptime = self.start.elapsed().as_secs_f32();
                ui.text(format!("Uptime:     {:.1}s", uptime));
                ui.separator();
                ui.text_colored([0.4, 0.9, 0.4, 1.0], "OnyxEngine Overlay");
            });
    }
}

hudhook!(ImguiDx11Hooks, OnyxOverlay::default());
