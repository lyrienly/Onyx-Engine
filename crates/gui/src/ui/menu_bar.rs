// OnyxEngine Top Menu Bar and Modern Header Subsystem
// Sleek, responsive layout with high-contrast status badges

use eframe::egui::{self, Color32, RichText, Rounding, Stroke, Vec2};
use onyx_core::ct_parser::CtParser;
use crate::app::OnyxEngineApp;

pub fn render_top_menu(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    egui::TopBottomPanel::top("top_menu_bar")
        .frame(egui::Frame::none()
            .fill(Color32::from_rgb(18, 20, 25))
            .inner_margin(egui::Margin::symmetric(10.0, 5.0))
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(32, 36, 45))))
        .show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button(RichText::new("File").strong(), |ui| {
                    if ui.button("Open Process...").clicked() {
                        app.refresh_proc_list();
                        app.show_proc_modal = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Save Cheat Table (.CT)").clicked() {
                        let mut ct = onyx_core::table::CheatTable::new();
                        for e in &app.cheat_table {
                            if e.offsets.is_empty() {
                                ct.add_simple(&e.description, e.address, e.val_type);
                            } else {
                                ct.add_pointer(&e.description, e.module_name.as_deref().unwrap_or(""), e.base_offset, e.offsets.clone(), e.val_type);
                            }
                        }
                        let _ = CtParser::save_ct_file(&ct, "onyx_table.CT");
                        app.status_msg = "Table saved to onyx_table.CT".to_string();
                        ui.close_menu();
                    }
                    if ui.button("Load Cheat Table (.CT)").clicked() {
                        if let Ok(table) = CtParser::load_ct_file("onyx_table.CT") {
                            for e in table.entries {
                                app.cheat_table.push(crate::state::GuiTableEntry {
                                    active: false,
                                    description: e.description,
                                    address: e.base_offset,
                                    module_name: e.module_name,
                                    base_offset: e.base_offset,
                                    offsets: e.offsets,
                                    val_type: e.val_type,
                                    current_val: "0".to_string(),
                                    target_val: "0".to_string(),
                                });
                            }
                            app.status_msg = "Table loaded successfully.".to_string();
                        }
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Clear Table").clicked() {
                        app.cheat_table.clear();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button(RichText::new("Process").strong(), |ui| {
                    if ui.button("Select Process...").clicked() {
                        app.refresh_proc_list();
                        app.show_proc_modal = true;
                        ui.close_menu();
                    }
                    if ui.button("Detach Process").clicked() {
                        app.attached_proc = None;
                        app.proc_name = "No process selected".to_string();
                        app.proc_pid = 0;
                        app.status_msg = "Detached from target process.".to_string();
                        ui.close_menu();
                    }
                });

                ui.menu_button(RichText::new("Tools").strong(), |ui| {
                    if ui.button("Memory Browser (Disassembler & Hex)").clicked() {
                        app.update_memory_view();
                        app.show_memory_view = true;
                        ui.close_menu();
                    }
                    if ui.button("Multilevel Pointer Scanner").clicked() {
                        app.show_pointer_scanner = true;
                        ui.close_menu();
                    }
                    if ui.button("Auto Assembler (Script Editor)").clicked() {
                        app.show_aa_modal = true;
                        ui.close_menu();
                    }
                    if ui.button("Lua Engine Console (5.3)").clicked() {
                        app.show_lua_console = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Plugin & DLL Manager").clicked() {
                        app.show_plugins_modal = true;
                        ui.close_menu();
                    }
                });

                ui.menu_button(RichText::new(".NET / Mono").strong(), |ui| {
                    if ui.button("Dissect Managed Code").clicked() {
                        if let Some(proc) = &app.attached_proc {
                            let _ = app.mono_dissector.dissect(proc);
                        }
                        app.show_mono_modal = true;
                        ui.close_menu();
                    }
                    if ui.button("Re-Scan Managed Runtime").clicked() {
                        if let Some(proc) = &app.attached_proc {
                            let _ = app.mono_dissector.attach(proc);
                            let _ = app.mono_dissector.dissect(proc);
                        }
                        ui.close_menu();
                    }
                });

                ui.menu_button(RichText::new("D3D Overlay").strong(), |ui| {
                    if ui.button("Inject Direct3D Overlay (d3dhook_dll.dll)").clicked() {
                        app.inject_aux_dll("d3dhook_dll.dll");
                        ui.close_menu();
                    }
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(4.0);
                    egui::Frame::none()
                        .fill(Color32::from_rgb(26, 32, 44))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(50, 65, 90)))
                        .rounding(Rounding::same(4.0))
                        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
                        .show(ui, |ui| {
                            ui.label(RichText::new("ONYX v1.0 | wgpu").size(11.0).color(Color32::from_rgb(120, 220, 160)).strong());
                        });
                });
            });
        });
}

pub fn render_bottom_bar(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    egui::TopBottomPanel::bottom("status_bar")
        .frame(egui::Frame::none()
            .fill(Color32::from_rgb(15, 17, 21))
            .inner_margin(egui::Margin::symmetric(12.0, 6.0))
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(30, 34, 42))))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("[>]").color(Color32::from_rgb(100, 180, 255)).monospace());
                ui.label(RichText::new(&app.status_msg).size(12.0).color(Color32::from_rgb(200, 205, 215)));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if app.attached_proc.is_some() {
                        egui::Frame::none()
                            .fill(Color32::from_rgb(20, 48, 28))
                            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(45, 120, 60)))
                            .rounding(Rounding::same(4.0))
                            .inner_margin(egui::Margin::symmetric(8.0, 2.0))
                            .show(ui, |ui| {
                                ui.label(RichText::new(format!("[ATTACHED] PID: 0x{:04X}", app.proc_pid)).size(11.0).color(Color32::from_rgb(120, 240, 140)).strong());
                            });
                    } else {
                        egui::Frame::none()
                            .fill(Color32::from_rgb(45, 22, 22))
                            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(110, 45, 45)))
                            .rounding(Rounding::same(4.0))
                            .inner_margin(egui::Margin::symmetric(8.0, 2.0))
                            .show(ui, |ui| {
                                ui.label(RichText::new("[NO TARGET]").size(11.0).color(Color32::from_rgb(240, 120, 120)).strong());
                            });
                    }

                    ui.label(RichText::new(format!("Table: {} | Found: {}", app.cheat_table.len(), app.found_count)).size(11.0).color(Color32::GRAY));
                });
            });
        });
}

pub fn render_header_bar(app: &mut OnyxEngineApp, ui: &mut egui::Ui) {
    egui::Frame::none()
        .fill(Color32::from_rgb(22, 25, 32))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(38, 43, 55)))
        .rounding(Rounding::same(8.0))
        .inner_margin(egui::Margin::symmetric(10.0, 8.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                // Attach button with dynamic pulse when idle
                let is_attached = app.attached_proc.is_some();
                let pulse = (ui.input(|i| i.time * 3.5).sin() * 0.5 + 0.5) as f32;

                let (btn_fill, stroke_color, btn_label) = if !is_attached {
                    let r = (25.0 + pulse * 40.0) as u8;
                    let g = (80.0 + pulse * 110.0) as u8;
                    let b = (35.0 + pulse * 45.0) as u8;
                    (Color32::from_rgb(r, g, b), Color32::from_rgb(60, 180, 80), "[ SELECT PROCESS ]")
                } else {
                    (Color32::from_rgb(30, 85, 45), Color32::from_rgb(45, 140, 70), "[ CHANGE PROCESS ]")
                };

                let proc_btn = egui::Button::new(RichText::new(btn_label).size(12.5).color(Color32::WHITE).strong())
                    .fill(btn_fill)
                    .stroke(Stroke::new(1.0_f32, stroke_color))
                    .min_size(Vec2::new(140.0, 30.0))
                    .rounding(Rounding::same(6.0));

                if ui.add(proc_btn).clicked() {
                    app.refresh_proc_list();
                    app.show_proc_modal = true;
                }

                ui.add_space(6.0);

                // Process Info Badge
                let target_bg = if is_attached { Color32::from_rgb(18, 32, 22) } else { Color32::from_rgb(30, 20, 22) };
                let target_stroke = if is_attached { Color32::from_rgb(40, 85, 50) } else { Color32::from_rgb(70, 35, 40) };

                egui::Frame::none()
                    .fill(target_bg)
                    .stroke(Stroke::new(1.0_f32, target_stroke))
                    .rounding(Rounding::same(6.0))
                    .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                    .show(ui, |ui| {
                        ui.set_min_width(260.0);
                        ui.horizontal(|ui| {
                            let dot_color = if is_attached { Color32::from_rgb(70, 220, 110) } else { Color32::from_rgb(220, 70, 70) };
                            let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                            ui.painter().circle_filled(rect.center(), 4.5, dot_color);
                            ui.add_space(2.0);
                            ui.label(RichText::new(&app.proc_name).size(13.0).color(Color32::WHITE).strong());
                        });
                    });

                // Right quick tool shortcuts with sleek pill styling
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let tool_btn = |text: &str, text_color: Color32, border_color: Color32| {
                        egui::Button::new(RichText::new(text).size(12.0).color(text_color).strong())
                            .fill(Color32::from_rgb(26, 30, 39))
                            .stroke(Stroke::new(1.0_f32, border_color))
                            .min_size(Vec2::new(95.0, 28.0))
                            .rounding(Rounding::same(6.0))
                    };

                    if ui.add(tool_btn("Memory View", Color32::from_rgb(130, 205, 255), Color32::from_rgb(45, 80, 120))).clicked() {
                        app.update_memory_view();
                        app.show_memory_view = true;
                    }

                    if ui.add(tool_btn("Pointer Scan", Color32::from_rgb(255, 195, 120), Color32::from_rgb(120, 85, 40))).clicked() {
                        app.show_pointer_scanner = true;
                    }

                    if ui.add(tool_btn(".NET / Mono", Color32::from_rgb(180, 235, 160), Color32::from_rgb(60, 110, 50))).clicked() {
                        if let Some(proc) = &app.attached_proc {
                            let _ = app.mono_dissector.dissect(proc);
                        }
                        app.show_mono_modal = true;
                    }

                    if ui.add(tool_btn("Auto Asm", Color32::from_rgb(255, 170, 200), Color32::from_rgb(110, 50, 75))).clicked() {
                        app.show_aa_modal = true;
                    }

                    if ui.add(tool_btn("Lua Console", Color32::from_rgb(180, 180, 255), Color32::from_rgb(65, 65, 120))).clicked() {
                        app.show_lua_console = true;
                    }

                    if ui.add(tool_btn("Plugins", Color32::from_rgb(210, 190, 255), Color32::from_rgb(80, 60, 120))).clicked() {
                        app.show_plugins_modal = true;
                    }
                });
            });
        });
}
