use crate::app::OnyxEngineApp;
use eframe::egui::{self, Color32, RichText, Vec2};

pub fn render(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    if !app.show_lua_console {
        return;
    }

    let mut close_modal = false;

    ctx.show_viewport_immediate(
        egui::ViewportId::from_hash_of("ce_lua_engine_viewport"),
        egui::ViewportBuilder::default()
            .with_title("Lua Engine (Lua 5.3)")
            .with_inner_size([720.0, 520.0])
            .with_min_inner_size([480.0, 360.0])
            .with_resizable(true),
        |ctx, _class| {
            if ctx.input(|i| i.viewport().close_requested() || i.key_pressed(egui::Key::Escape)) {
                close_modal = true;
            }

            egui::CentralPanel::default()
                .frame(
                    egui::Frame::none()
                        .fill(Color32::from_rgb(26, 29, 36))
                        .inner_margin(egui::Margin::same(8.0)),
                )
                .show(ctx, |ui| {
                    let avail_h = ui.available_height();
                    let edit_h = (avail_h * 0.42).clamp(100.0, 240.0);
                    let output_h = (avail_h - edit_h - 85.0).max(100.0);

                    ui.label(RichText::new("Lua Code:").strong());
                    ui.add_sized(
                        Vec2::new(ui.available_width(), edit_h),
                        egui::TextEdit::multiline(&mut app.lua_script)
                            .code_editor()
                            .desired_width(f32::INFINITY),
                    );

                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui
                            .button(RichText::new("[Run Lua]").strong().color(Color32::GREEN))
                            .clicked()
                            && let Some(lua) = &app.lua_engine
                        {
                            match lua.execute(&app.lua_script) {
                                Ok(res) => app.lua_output.push(format!("[Out]: {}", res)),
                                Err(e) => app.lua_output.push(format!("[Err]: {}", e)),
                            }
                        }
                        if ui.button("Clear Log").clicked() {
                            app.lua_output.clear();
                        }
                        if ui.button("Close").clicked() {
                            close_modal = true;
                        }
                    });

                    ui.separator();
                    ui.label(RichText::new("Console Output:").strong());
                    egui::ScrollArea::vertical()
                        .id_salt("lua_console_scroll")
                        .max_height(output_h)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for line in &app.lua_output {
                                ui.label(RichText::new(line).monospace());
                            }
                        });
                });
        },
    );

    if close_modal {
        app.show_lua_console = false;
    }
}
