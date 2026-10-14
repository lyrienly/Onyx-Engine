// Plugin & Auxiliary DLL Injection Manager Modal for OnyxEngine

use eframe::egui::{self, Color32, RichText, Vec2};
use onyx_core::process::Process;
use crate::app::OnyxEngineApp;

pub fn render(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    if !app.show_plugins_modal {
        return;
    }

    egui::Window::new("Plugin & DLL Injection Manager")
        .collapsible(true)
        .resizable(true)
        .movable(true)
        .constrain(false)
        .default_size(Vec2::new(660.0, 420.0))
        .show(ctx, |ui| {
            ui.label(RichText::new("Auxiliary Engine DLLs").strong().color(Color32::from_rgb(120, 200, 255)));
            ui.label("Inject modular subsystems into the attached target process:");

            ui.separator();

            let dlls = [
                ("d3dhook_dll.dll", "Direct3D Overlay, In-Game HUD, Frame Counter"),
                ("speedhack_dll.dll", "High-Precision QPC / GetTickCount Time Scaler"),
                ("vehdebug_dll.dll", "Vectored Exception Handler Debugger Engine"),
                ("allochook_dll.dll", "Heap & VirtualAlloc Memory Allocator Interceptor"),
                ("luaclient_dll.dll", "Remote Lua IPC Client for Live Automation"),
            ];

            egui::Grid::new("dll_plugin_grid")
                .striped(true)
                .min_col_width(120.0)
                .spacing(Vec2::new(12.0, 8.0))
                .show(ui, |ui| {
                    ui.label(RichText::new("DLL Name").strong());
                    ui.label(RichText::new("Description").strong());
                    ui.label(RichText::new("Status / File").strong());
                    ui.label(RichText::new("Action").strong());
                    ui.end_row();

                    for (name, desc) in &dlls {
                        ui.label(RichText::new(*name).monospace().strong());
                        ui.label(*desc);

                        let resolved = Process::resolve_dll_path(name);
                        match resolved {
                            Ok(p) => {
                                let filename = p.file_name().unwrap_or_default().to_string_lossy();
                                ui.label(RichText::new(format!("[Found] {}", filename)).color(Color32::GREEN));
                            }
                            Err(_) => {
                                ui.label(RichText::new("[Missing]").color(Color32::RED));
                            }
                        }

                        if ui.button(RichText::new("[Inject]").color(Color32::from_rgb(100, 220, 255))).clicked() {
                            app.inject_aux_dll(name);
                        }
                        ui.end_row();
                    }
                });

            ui.separator();
            if ui.button("Close").clicked() {
                app.show_plugins_modal = false;
            }
        });
}
