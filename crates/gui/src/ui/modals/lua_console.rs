// Lua 5.3 Scripting Console Modal for OnyxEngine

use eframe::egui::{self, Color32, RichText, Vec2};
use crate::app::OnyxEngineApp;

pub fn render(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    if !app.show_lua_console {
        return;
    }

    egui::Window::new("Lua Scripting Engine (Lua 5.3)")
        .collapsible(true)
        .resizable(true)
        .movable(true)
        .constrain(false)
        .default_size(Vec2::new(600.0, 480.0))
        .show(ctx, |ui| {
            ui.label(RichText::new("Lua Code:").strong());
            ui.add(egui::TextEdit::multiline(&mut app.lua_script).code_editor().desired_rows(8).desired_width(f32::INFINITY));

            ui.horizontal(|ui| {
                if ui.button(RichText::new("[Run Lua]").strong().color(Color32::GREEN)).clicked() {
                    if let Some(lua) = &app.lua_engine {
                        match lua.execute(&app.lua_script) {
                            Ok(res) => app.lua_output.push(format!("[Out]: {}", res)),
                            Err(e) => app.lua_output.push(format!("[Err]: {}", e)),
                        }
                    }
                }
                if ui.button("Clear Log").clicked() {
                    app.lua_output.clear();
                }
                if ui.button("Close").clicked() {
                    app.show_lua_console = false;
                }
            });

            ui.separator();
            ui.label(RichText::new("Console Output:").strong());
            egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                for line in &app.lua_output {
                    ui.label(RichText::new(line).monospace());
                }
            });
        });
}
