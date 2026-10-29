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
            .with_title("OnyxEngine")
            .with_resizable(true)
            .with_inner_size([1260.0, 880.0])
            .with_min_inner_size([820.0, 560.0]),
        wgpu_options: eframe::egui_wgpu::WgpuConfiguration {
            present_mode: eframe::egui_wgpu::wgpu::PresentMode::AutoNoVsync,
            power_preference: eframe::egui_wgpu::wgpu::PowerPreference::HighPerformance,
            ..Default::default()
        },
        ..Default::default()
    };

    eframe::run_native(
        "CheatEngine",
        native_options,
        Box::new(|cc| {

            let mut visuals = egui::Visuals::dark();

            visuals.panel_fill = Color32::from_rgb(30, 33, 40);
            visuals.window_fill = Color32::from_rgb(34, 38, 46);
            visuals.faint_bg_color = Color32::from_rgb(25, 28, 35);
            visuals.extreme_bg_color = Color32::from_rgb(16, 18, 23);

            let border_stroke = Stroke::new(1.0_f32, Color32::from_rgb(55, 62, 75));
            visuals.widgets.noninteractive.bg_stroke = border_stroke;
            visuals.widgets.noninteractive.rounding = Rounding::same(3.0);

            visuals.widgets.inactive.bg_fill = Color32::from_rgb(38, 43, 53);
            visuals.widgets.inactive.bg_stroke = border_stroke;
            visuals.widgets.inactive.rounding = Rounding::same(3.0);

            visuals.widgets.hovered.bg_fill = Color32::from_rgb(50, 57, 70);
            visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(75, 95, 125));
            visuals.widgets.hovered.rounding = Rounding::same(3.0);

            visuals.widgets.active.bg_fill = Color32::from_rgb(58, 68, 85);
            visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(95, 120, 160));
            visuals.widgets.active.rounding = Rounding::same(3.0);

            visuals.widgets.open.rounding = Rounding::same(3.0);

            cc.egui_ctx.set_visuals(visuals);

            let mut style = (*cc.egui_ctx.style()).clone();
            style.spacing.item_spacing = Vec2::new(6.0, 4.0);
            style.spacing.button_padding = Vec2::new(8.0, 3.5);
            style.spacing.window_margin = egui::Margin::same(8.0);
            cc.egui_ctx.set_style(style);

            Ok(Box::new(OnyxEngineApp::new(cc)))
        }),
    )
}
