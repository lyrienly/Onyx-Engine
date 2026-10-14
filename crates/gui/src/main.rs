// OnyxEngine Native GUI Entrypoint
// Powered by egui + wgpu + winit hardware-accelerated rendering

#![windows_subsystem = "windows"]
#![allow(dead_code, unused_variables, unsafe_op_in_unsafe_fn, static_mut_refs)]

mod app;
mod state;
mod ui;

use app::OnyxEngineApp;
use eframe::egui::{self, Color32, Rounding, Stroke, Vec2};

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("OnyxEngine - Native Memory & Inspection Suite")
            .with_resizable(true)
            .with_inner_size([1260.0, 880.0])
            .with_min_inner_size([900.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        "OnyxEngine",
        native_options,
        Box::new(|cc| {
            // Configure modern dark aesthetic for egui + wgpu
            let mut visuals = egui::Visuals::dark();

            // Background palettes: Deep obsidian & carbon slate
            visuals.panel_fill = Color32::from_rgb(18, 20, 24);
            visuals.window_fill = Color32::from_rgb(23, 26, 32);
            visuals.faint_bg_color = Color32::from_rgb(28, 31, 39);
            visuals.extreme_bg_color = Color32::from_rgb(12, 14, 17);

            // Widget base strokes and rounded corners
            let border_stroke = Stroke::new(1.0_f32, Color32::from_rgb(46, 52, 64));
            visuals.widgets.noninteractive.bg_stroke = border_stroke;
            visuals.widgets.noninteractive.rounding = Rounding::same(6.0);

            visuals.widgets.inactive.bg_fill = Color32::from_rgb(30, 34, 43);
            visuals.widgets.inactive.bg_stroke = border_stroke;
            visuals.widgets.inactive.rounding = Rounding::same(6.0);

            visuals.widgets.hovered.bg_fill = Color32::from_rgb(42, 48, 60);
            visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(70, 85, 110));
            visuals.widgets.hovered.rounding = Rounding::same(6.0);

            visuals.widgets.active.bg_fill = Color32::from_rgb(48, 56, 72);
            visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(90, 115, 150));
            visuals.widgets.active.rounding = Rounding::same(6.0);

            visuals.widgets.open.rounding = Rounding::same(6.0);

            // Apply visuals and modern spacing
            cc.egui_ctx.set_visuals(visuals);

            let mut style = (*cc.egui_ctx.style()).clone();
            style.spacing.item_spacing = Vec2::new(8.0, 6.0);
            style.spacing.button_padding = Vec2::new(10.0, 5.0);
            style.spacing.window_margin = egui::Margin::same(12.0);
            cc.egui_ctx.set_style(style);

            Ok(Box::new(OnyxEngineApp::new(cc)))
        }),
    )
}
