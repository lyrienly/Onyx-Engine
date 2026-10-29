use eframe::egui::{self, Color32, RichText, Rounding, Stroke, Vec2};
use onyx_core::ct_parser::CtParser;
use crate::app::OnyxEngineApp;

pub fn render_top_menu(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    egui::TopBottomPanel::top("top_menu_bar")
        .frame(egui::Frame::none()
            .fill(Color32::from_rgb(26, 29, 36))
            .inner_margin(egui::Margin::symmetric(6.0, 3.0))
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(46, 52, 65))))
        .show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {

                ui.menu_button(RichText::new("File").size(12.0), |ui| {
                    if ui.button("Open Process... [Ctrl+O]").clicked() {
                        app.refresh_proc_list();
                        app.show_proc_modal = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Open File [Ctrl+Shift+O]").clicked() {
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
                    if ui.button("Save [Ctrl+S]").clicked() {
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
                    if ui.button("Clear list").clicked() {
                        app.cheat_table.clear();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button(RichText::new("Edit").size(12.0), |ui| {
                    if ui.button("Settings [Ctrl+,]").clicked() {
                        app.show_settings_modal = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Clear Address List").clicked() {
                        app.cheat_table.clear();
                        ui.close_menu();
                    }
                });

                ui.menu_button(RichText::new("Table").size(12.0), |ui| {
                    if ui.button("Add Address Manually").clicked() {
                        app.show_add_addr_modal = true;
                        ui.close_menu();
                    }
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
                    let ghost_label = if app.ghost_mode {
                        "Disable Ghost Mode (Overlay) [F10]"
                    } else {
                        "Enable Ghost Mode (Overlay) [F10]"
                    };
                    if ui.button(ghost_label).clicked() {
                        app.ghost_mode = !app.ghost_mode;
                        ctx.send_viewport_cmd(egui::ViewportCommand::MousePassthrough(app.ghost_mode));
                        ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(if app.ghost_mode {
                            egui::WindowLevel::AlwaysOnTop
                        } else {
                            egui::WindowLevel::Normal
                        }));
                        ui.close_menu();
                    }
                });

                ui.menu_button(RichText::new("Dbi").size(12.0), |ui| {
                    if ui.button("Connect to DBK Driver (\\.\\DBK64)").clicked() {
                        app.try_connect_dbk();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Use NT Native API (ntdll)").clicked() {
                        app.set_access_mode(onyx_core::process::ProcessAccessMode::NtApi);
                        ui.close_menu();
                    }
                    if ui.button("Use Kernel DBK64 Driver").clicked() {
                        app.set_access_mode(onyx_core::process::ProcessAccessMode::KernelDbk);
                        ui.close_menu();
                    }
                    if ui.button("Use Win32 API (kernel32)").clicked() {
                        app.set_access_mode(onyx_core::process::ProcessAccessMode::Win32);
                        ui.close_menu();
                    }
                });

                if ui.button(RichText::new("Memory View").size(12.0)).clicked() {
                    app.update_memory_view();
                    app.show_memory_view = true;
                }

                ui.menu_button(RichText::new("Tools").size(12.0), |ui| {
                    if ui.button("Memory Browser (Disassembler & Hex) [Ctrl+M]").clicked() {
                        app.update_memory_view();
                        app.show_memory_view = true;
                        ui.close_menu();
                    }
                    if ui.button("Pointer Scanner [Ctrl+P]").clicked() {
                        app.show_pointer_scanner = true;
                        ui.close_menu();
                    }
                    if ui.button("Auto Assembler [Ctrl+A]").clicked() {
                        app.show_aa_modal = true;
                        ui.close_menu();
                    }
                    if ui.button("Lua Engine [Ctrl+L]").clicked() {
                        app.show_lua_console = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button(".NET / Mono Dissector").clicked() {
                        if let Some(proc) = &app.attached_proc {
                            let _ = app.mono_dissector.dissect(proc);
                        }
                        app.show_mono_modal = true;
                        ui.close_menu();
                    }
                    if ui.button("Plugins").clicked() {
                        app.show_plugins_modal = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Inject Direct3D Overlay (d3dhook_dll)").clicked() {
                        app.inject_aux_dll("d3dhook_dll.dll");
                        ui.close_menu();
                    }
                });

                ui.menu_button(RichText::new("Help").size(12.0), |ui| {
                    if ui.button("About OnyxEngine").clicked() {
                        app.status_msg = "OnyxEngine (Rust Edition) - High performance native memory suite.".to_string();
                        ui.close_menu();
                    }
                });
            });
        });
}

pub fn render_header_bar(app: &mut OnyxEngineApp, ui: &mut egui::Ui) {
    egui::Frame::none()
        .fill(Color32::from_rgb(28, 31, 38))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(46, 52, 65)))
        .rounding(Rounding::same(2.0))
        .inner_margin(egui::Margin::symmetric(6.0, 4.0))
        .show(ui, |ui| {
            let is_attached = app.attached_proc.is_some();
            let pulse = (ui.input(|i| i.time * 4.5).sin() * 0.5 + 0.5) as f32;

            ui.horizontal(|ui| {

                let (border_col, btn_fill) = if !is_attached {
                    let g = (140.0 + pulse * 115.0) as u8;
                    (Color32::from_rgb(40, g, 80), Color32::from_rgb(22, 45, 30))
                } else {
                    (Color32::from_rgb(55, 65, 80), Color32::from_rgb(26, 30, 38))
                };

                let proc_btn_resp = if let Some(ref icons) = app.icons {
                    let img = egui::Image::new(&icons.open_process).fit_to_exact_size(Vec2::splat(24.0));
                    ui.add(
                        egui::Button::image(img)
                            .fill(btn_fill)
                            .stroke(Stroke::new(if !is_attached { 2.0_f32 } else { 1.0_f32 }, border_col))
                            .min_size(Vec2::new(34.0, 30.0))
                            .rounding(Rounding::same(2.0)),
                    )
                } else {
                    let label = if !is_attached { "[ SELECT PROCESS ]" } else { "[ CHANGE PROCESS ]" };
                    ui.add(
                        egui::Button::new(RichText::new(label).strong())
                            .fill(btn_fill)
                            .stroke(Stroke::new(1.0_f32, border_col))
                            .min_size(Vec2::new(125.0, 30.0))
                            .rounding(Rounding::same(2.0)),
                    )
                };

                if proc_btn_resp.on_hover_text("Select a process to open (Ctrl+O)").clicked() {
                    app.refresh_proc_list();
                    app.show_proc_modal = true;
                }

                if let Some(ref icons) = app.icons {
                    let img = egui::Image::new(&icons.open).fit_to_exact_size(Vec2::splat(22.0));
                    let open_btn = egui::Button::image(img)
                        .fill(Color32::from_rgb(26, 30, 38))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(48, 54, 66)))
                        .min_size(Vec2::new(32.0, 30.0))
                        .rounding(Rounding::same(2.0));
                    if ui.add(open_btn).on_hover_text("Open Cheat Table (.CT)").clicked()
                        && let Ok(table) = CtParser::load_ct_file("onyx_table.CT") {
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

                    let save_img = egui::Image::new(&icons.save).fit_to_exact_size(Vec2::splat(22.0));
                    let save_btn = egui::Button::image(save_img)
                        .fill(Color32::from_rgb(26, 30, 38))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(48, 54, 66)))
                        .min_size(Vec2::new(32.0, 30.0))
                        .rounding(Rounding::same(2.0));
                    if ui.add(save_btn).on_hover_text("Save Cheat Table (.CT)").clicked() {
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
                    }
                }

                ui.add_space(8.0);

                let text_color = if is_attached { Color32::from_rgb(110, 240, 140) } else { Color32::from_rgb(220, 225, 235) };
                ui.horizontal(|ui| {
                    if is_attached
                        && let Some(ref proc) = app.attached_proc
                            && let Some(texture) = app.get_icon(&proc.name) {
                                ui.add(egui::Image::new(texture).fit_to_exact_size(Vec2::splat(16.0)));
                                ui.add_space(2.0);
                            }

                    ui.label(
                        RichText::new(&app.proc_name)
                            .monospace()
                            .size(13.0)
                            .color(text_color)
                            .strong(),
                    );
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {

                    if let Some(ref icons) = app.icons {
                        let logo_img = egui::Image::new(&icons.ce_logo).fit_to_exact_size(Vec2::new(36.0, 32.0));
                        ui.add(logo_img);
                        ui.add_space(4.0);
                    }

                    if let Some(ref icons) = app.icons {
                        let img = egui::Image::new(&icons.settings).fit_to_exact_size(Vec2::splat(18.0));
                        if ui.add(
                            egui::Button::image(img)
                                .fill(Color32::from_rgb(26, 30, 38))
                                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(48, 54, 66)))
                                .min_size(Vec2::new(28.0, 28.0))
                                .rounding(Rounding::same(2.0)),
                        ).on_hover_text("OnyxEngine Settings (Ctrl+,)").clicked() {
                            app.show_settings_modal = true;
                        }
                    }

                    let mode_badge = app.access_mode.badge();
                    let mode_col = match app.access_mode {
                        onyx_core::process::ProcessAccessMode::NtApi => Color32::from_rgb(100, 240, 140),
                        onyx_core::process::ProcessAccessMode::KernelDbk => Color32::from_rgb(255, 195, 80),
                        onyx_core::process::ProcessAccessMode::Win32 => Color32::from_rgb(120, 180, 255),
                    };

                    let mode_btn = egui::Button::new(RichText::new(mode_badge).monospace().size(11.0).color(mode_col).strong())
                        .fill(Color32::from_rgb(22, 25, 32))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(46, 52, 65)))
                        .min_size(Vec2::new(65.0, 24.0))
                        .rounding(Rounding::same(2.0));

                    if ui.add(mode_btn).on_hover_text("Switch Access Mode (NT Native API / Kernel DBK64 / Win32)").clicked() {
                        app.settings_tab = 3;
                        app.show_settings_modal = true;
                    }
                });
            });
        });
}

pub fn render_bottom_bar(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    egui::TopBottomPanel::bottom("bottom_status_bar")
        .frame(egui::Frame::none()
            .fill(Color32::from_rgb(24, 26, 32))
            .inner_margin(egui::Margin::symmetric(8.0, 3.0))
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(46, 52, 65))))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {

                let adv_btn = egui::Button::new(RichText::new("Advanced Options").size(11.0).color(Color32::from_rgb(200, 205, 215)))
                    .fill(Color32::from_rgb(28, 32, 40))
                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(48, 54, 68)))
                    .rounding(Rounding::same(2.0));
                if ui.add(adv_btn).on_hover_text("Auto Assembler & Code List").clicked() {
                    app.show_aa_modal = true;
                }

                ui.add_space(8.0);
                ui.label(RichText::new(&app.status_msg).size(11.5).color(Color32::from_rgb(200, 205, 215)));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {

                    let extras_btn = egui::Button::new(RichText::new("Table Extras").size(11.0).color(Color32::from_rgb(200, 205, 215)))
                        .fill(Color32::from_rgb(28, 32, 40))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(48, 54, 68)))
                        .rounding(Rounding::same(2.0));
                    if ui.add(extras_btn).on_hover_text("Open Lua Engine / Table Script").clicked() {
                        app.show_lua_console = true;
                    }

                    ui.add_space(6.0);
                    let dbk_col = if app.dbk_driver.is_some() {
                        Color32::from_rgb(100, 240, 140)
                    } else {
                        Color32::from_rgb(140, 145, 155)
                    };
                    let dbk_text = if app.dbk_driver.is_some() { "[DBK: ON]" } else { "[DBK: OFF]" };
                    ui.label(RichText::new(dbk_text).monospace().size(11.0).color(dbk_col));

                    ui.label(RichText::new("|").color(Color32::DARK_GRAY));

                    ui.label(RichText::new(format!("Table: {} | Found: {}", app.cheat_table.len(), app.found_count)).size(11.0).color(Color32::GRAY));
                });
            });
        });
}
