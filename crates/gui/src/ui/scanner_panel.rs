// OnyxEngine Scanner Workspace Panel
// High-performance candidate viewer and modern scan control station

use eframe::egui::{self, Color32, RichText, Rounding, Stroke, Vec2};
use crate::app::OnyxEngineApp;

pub fn render(app: &mut OnyxEngineApp, ui: &mut egui::Ui, upper_height: f32) {
    ui.allocate_ui_with_layout(Vec2::new(ui.available_width(), upper_height), egui::Layout::left_to_right(egui::Align::TOP), |ui| {
        // LEFT PANEL: Found Candidates List (44% - 48% responsive width)
        let left_width = (ui.available_width() * 0.44).clamp(300.0, 560.0);
        egui::Frame::none()
            .fill(Color32::from_rgb(20, 23, 29))
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(36, 42, 53)))
            .rounding(Rounding::same(8.0))
            .inner_margin(egui::Margin::same(8.0))
            .show(ui, |ui| {
                ui.set_width(left_width);
                ui.set_height(upper_height);

                let mut add_all_clicked = false;
                ui.horizontal(|ui| {
                    egui::Frame::none()
                        .fill(Color32::from_rgb(26, 36, 30))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(45, 90, 55)))
                        .rounding(Rounding::same(4.0))
                        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
                        .show(ui, |ui| {
                            ui.label(RichText::new(format!("Found: {}", app.found_count)).size(13.0).strong().color(Color32::from_rgb(110, 240, 140)));
                        });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let add_all_btn = egui::Button::new(RichText::new("+ Add Top 100").size(11.5).color(Color32::from_rgb(180, 220, 255)).strong())
                            .fill(Color32::from_rgb(28, 38, 52))
                            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(50, 75, 110)))
                            .rounding(Rounding::same(4.0));
                        if ui.add(add_all_btn).clicked() {
                            add_all_clicked = true;
                        }
                    });
                });

                if add_all_clicked {
                    let val_type = app.parse_val_type_from_idx();
                    let addrs: Vec<usize> = app.candidates.iter().take(100).map(|c| c.0).collect();
                    for addr in addrs {
                        app.add_candidate_to_table(addr, val_type);
                    }
                    app.status_msg = "Added top 100 candidates to Cheat Table.".to_string();
                }

                ui.add_space(4.0);

                let mut to_add: Option<usize> = None;
                let mut to_browse: Option<usize> = None;
                let mut to_disasm: Option<usize> = None;
                let mut to_copy: Option<String> = None;
                let mut to_ptr_scan: Option<usize> = None;

                egui::ScrollArea::vertical()
                    .id_salt("candidates_scroll_area")
                    .max_height(upper_height - 52.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        egui::Grid::new("candidates_grid_main")
                            .striped(true)
                            .min_col_width(90.0)
                            .spacing(Vec2::new(14.0, 4.0))
                            .show(ui, |ui| {
                                ui.label(RichText::new("Address").size(11.5).strong().color(Color32::from_rgb(140, 160, 190)));
                                ui.label(RichText::new("Value").size(11.5).strong().color(Color32::from_rgb(140, 160, 190)));
                                ui.label(RichText::new("Previous").size(11.5).strong().color(Color32::from_rgb(140, 160, 190)));
                                ui.end_row();

                                for (row_idx, (addr, val, prev)) in app.candidates.iter().enumerate() {
                                    let hex_str = format!("0x{:08X}", addr);
                                    let is_diff = val != prev;

                                    let addr_response = ui.add(
                                        egui::Button::new(RichText::new(&hex_str).monospace().size(12.0).color(Color32::from_rgb(120, 190, 255)))
                                            .fill(if row_idx % 2 == 0 { Color32::from_rgb(24, 28, 36) } else { Color32::from_rgb(20, 23, 30) })
                                            .stroke(Stroke::NONE)
                                            .rounding(Rounding::same(3.0))
                                    );

                                    if addr_response.clicked() {
                                        to_add = Some(*addr);
                                    }

                                    addr_response.context_menu(|ui| {
                                        if ui.button("Add to address list").clicked() {
                                            to_add = Some(*addr);
                                            ui.close_menu();
                                        }
                                        if ui.button("Browse in Hex Memory View").clicked() {
                                            to_browse = Some(*addr);
                                            ui.close_menu();
                                        }
                                        if ui.button("Disassemble this instruction").clicked() {
                                            to_disasm = Some(*addr);
                                            ui.close_menu();
                                        }
                                        if ui.button("Scan Pointers for this address").clicked() {
                                            to_ptr_scan = Some(*addr);
                                            ui.close_menu();
                                        }
                                        if ui.button("Copy address").clicked() {
                                            to_copy = Some(hex_str.clone());
                                            ui.close_menu();
                                        }
                                    });

                                    let val_color = if is_diff { Color32::from_rgb(255, 205, 100) } else { Color32::WHITE };
                                    ui.label(RichText::new(val).monospace().strong().color(val_color));
                                    ui.label(RichText::new(prev).monospace().color(Color32::from_rgb(120, 125, 135)));
                                    ui.end_row();
                                }
                            });
                    });

                let val_type = app.parse_val_type_from_idx();
                if let Some(addr) = to_add {
                    app.add_candidate_to_table(addr, val_type);
                    app.status_msg = format!("Added 0x{:08X} to Cheat Table.", addr);
                }
                if let Some(addr) = to_browse {
                    app.navigate_hex(addr);
                    app.show_memory_view = true;
                }
                if let Some(addr) = to_disasm {
                    app.navigate_disasm(addr);
                    app.show_memory_view = true;
                }
                if let Some(addr) = to_ptr_scan {
                    app.ptr_target_addr_text = format!("0x{:08X}", addr);
                    app.show_pointer_scanner = true;
                }
                if let Some(text) = to_copy {
                    ui.ctx().copy_text(text.clone());
                    app.status_msg = format!("Copied {} to clipboard.", text);
                }
            });

        ui.add_space(8.0);

        // RIGHT PANEL: Scan Controls & Options
        egui::ScrollArea::vertical()
            .id_salt("scan_controls_scroll_area")
            .max_height(upper_height)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    // 1. Primary Scan Action Buttons Card
                    egui::Frame::none()
                        .fill(Color32::from_rgb(22, 25, 32))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(38, 43, 55)))
                        .rounding(Rounding::same(8.0))
                        .inner_margin(egui::Margin::same(8.0))
                        .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let btn_new_text = if app.has_scanned { "New Scan" } else { "First Scan" };
                        let new_scan_btn = egui::Button::new(RichText::new(btn_new_text).size(13.0).color(Color32::WHITE).strong())
                            .fill(Color32::from_rgb(32, 135, 65))
                            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(45, 185, 90)))
                            .min_size(Vec2::new(110.0, 32.0))
                            .rounding(Rounding::same(6.0));

                        if ui.add(new_scan_btn).clicked() {
                            app.execute_first_scan();
                        }

                        let next_scan_btn = egui::Button::new(RichText::new("Next Scan").size(13.0).color(Color32::WHITE).strong())
                            .fill(if app.has_scanned { Color32::from_rgb(38, 95, 185) } else { Color32::from_rgb(35, 40, 50) })
                            .stroke(Stroke::new(1.0_f32, if app.has_scanned { Color32::from_rgb(60, 130, 240) } else { Color32::from_rgb(50, 55, 68) }))
                            .min_size(Vec2::new(110.0, 32.0))
                            .rounding(Rounding::same(6.0));

                        if ui.add_enabled(app.has_scanned, next_scan_btn).clicked() {
                            app.execute_next_scan();
                        }

                        let can_undo = !app.scanner.history.is_empty();
                        let undo_label = if can_undo { format!("Undo ({})", app.scanner.history.len()) } else { "Undo".to_string() };
                        let undo_btn = egui::Button::new(RichText::new(undo_label).size(12.0).color(Color32::WHITE).strong())
                            .fill(if can_undo { Color32::from_rgb(175, 95, 25) } else { Color32::from_rgb(35, 40, 50) })
                            .stroke(Stroke::new(1.0_f32, if can_undo { Color32::from_rgb(220, 130, 40) } else { Color32::from_rgb(50, 55, 68) }))
                            .min_size(Vec2::new(90.0, 32.0))
                            .rounding(Rounding::same(6.0));

                        if ui.add_enabled(can_undo, undo_btn).clicked() {
                            app.execute_undo_scan();
                        }
                    });
                });

            ui.add_space(4.0);

            // 2. Scan Value Input Box
            egui::Frame::none()
                .fill(Color32::from_rgb(20, 23, 29))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(36, 42, 53)))
                .rounding(Rounding::same(8.0))
                .inner_margin(egui::Margin::same(8.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Value:").size(12.5).strong().color(Color32::from_rgb(180, 205, 240)));
                        let val_input = ui.add(
                            egui::TextEdit::singleline(&mut app.scan_val_text)
                                .desired_width(160.0)
                                .font(egui::TextStyle::Monospace)
                        );
                        if val_input.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            if app.has_scanned {
                                app.execute_next_scan();
                            } else {
                                app.execute_first_scan();
                            }
                        }

                        if app.scan_type_idx == 3 {
                            ui.label("and:");
                            ui.add(egui::TextEdit::singleline(&mut app.scan_val_second_text).desired_width(90.0).font(egui::TextStyle::Monospace));
                        }

                        ui.add_space(6.0);
                        ui.checkbox(&mut app.is_hex, RichText::new("Hex").strong());
                    });
                });

            ui.add_space(4.0);

            // 3. Scan & Value Types
            egui::Frame::none()
                .fill(Color32::from_rgb(20, 23, 29))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(36, 42, 53)))
                .rounding(Rounding::same(8.0))
                .inner_margin(egui::Margin::same(8.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Scan Type:").size(12.0).color(Color32::LIGHT_GRAY));
                        let scan_types = [
                            "Exact Value",
                            "Bigger than...",
                            "Smaller than...",
                            "Value between...",
                            "Unknown initial value",
                            "Changed value",
                            "Unchanged value",
                            "Increased value by...",
                            "Decreased value by...",
                        ];
                        egui::ComboBox::from_id_salt("scan_type_selector")
                            .selected_text(scan_types[app.scan_type_idx.min(scan_types.len() - 1)])
                            .show_ui(ui, |ui| {
                                for (i, t) in scan_types.iter().enumerate() {
                                    ui.selectable_value(&mut app.scan_type_idx, i, *t);
                                }
                            });
                    });

                    ui.add_space(3.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Value Type:").size(12.0).color(Color32::LIGHT_GRAY));
                        let val_types = [
                            "1 Byte (i8)",
                            "1 Byte (u8)",
                            "2 Bytes (i16)",
                            "2 Bytes (u16)",
                            "4 Bytes (i32)",
                            "4 Bytes (u32)",
                            "8 Bytes (i64)",
                            "8 Bytes (u64)",
                            "Float (32-bit)",
                            "Double (64-bit)",
                            "String (ASCII)",
                            "Array of Byte (AOB)",
                        ];
                        egui::ComboBox::from_id_salt("val_type_selector")
                            .selected_text(val_types[app.val_type_idx.min(val_types.len() - 1)])
                            .show_ui(ui, |ui| {
                                for (i, t) in val_types.iter().enumerate() {
                                    ui.selectable_value(&mut app.val_type_idx, i, *t);
                                }
                            });
                    });
                });

            ui.add_space(4.0);

            // 4. Memory Scan Scope & Alignment
            egui::Frame::none()
                .fill(Color32::from_rgb(20, 23, 29))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(36, 42, 53)))
                .rounding(Rounding::same(8.0))
                .inner_margin(egui::Margin::same(8.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Memory Scan Options").size(11.5).strong().color(Color32::from_rgb(140, 185, 230)));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Reset Scope").clicked() {
                                app.start_addr_text = "0000000000000000".to_string();
                                app.stop_addr_text = "7FFFFFFFFFFFFFFF".to_string();
                            }
                        });
                    });

                    ui.horizontal(|ui| {
                        ui.label("Start:");
                        ui.add(egui::TextEdit::singleline(&mut app.start_addr_text).desired_width(125.0).font(egui::TextStyle::Monospace));
                        ui.label("Stop:");
                        ui.add(egui::TextEdit::singleline(&mut app.stop_addr_text).desired_width(125.0).font(egui::TextStyle::Monospace));
                    });

                    ui.horizontal(|ui| {
                        ui.checkbox(&mut app.fast_scan, "Fast Scan");
                        ui.add_space(8.0);
                        ui.label("Align:");
                        let aligns = ["4 Bytes", "1 Byte", "2 Bytes", "8 Bytes"];
                        egui::ComboBox::from_id_salt("align_selector")
                            .selected_text(aligns[app.alignment_idx.min(aligns.len() - 1)])
                            .show_ui(ui, |ui| {
                                for (i, a) in aligns.iter().enumerate() {
                                    ui.selectable_value(&mut app.alignment_idx, i, *a);
                                }
                            });
                    });

                    ui.horizontal(|ui| {
                        ui.checkbox(&mut app.writable_only, "Writable");
                        ui.checkbox(&mut app.executable, "Executable");
                        ui.checkbox(&mut app.copy_on_write, "CopyOnWrite");
                    });
                });

            ui.add_space(4.0);

            // 5. Speedhack Widget
            egui::Frame::none()
                .fill(Color32::from_rgb(20, 23, 29))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(36, 42, 53)))
                .rounding(Rounding::same(8.0))
                .inner_margin(egui::Margin::same(8.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if ui.checkbox(&mut app.speedhack_enabled, RichText::new("Enable Speedhack").size(12.0).strong()).changed() {
                            if let Some(proc) = &app.attached_proc {
                                let mult = if app.speedhack_enabled { app.speedhack_val } else { 1.0 };
                                let _ = app.speedhack_injector.enable_speedhack(proc, mult);
                                app.status_msg = format!("Speedhack set to {:.1}x", mult);
                            }
                        }

                        if app.speedhack_enabled {
                            ui.label(RichText::new(format!("{:.1}x", app.speedhack_val)).color(Color32::GREEN).strong());
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                for &p in &[10.0, 5.0, 2.0, 1.0, 0.5] {
                                    if ui.button(format!("{:.1}x", p)).clicked() {
                                        app.speedhack_val = p;
                                        if let Some(proc) = &app.attached_proc {
                                            let _ = app.speedhack_injector.enable_speedhack(proc, app.speedhack_val);
                                        }
                                    }
                                }
                            });
                        }
                    });

                    if app.speedhack_enabled {
                        if ui.add(egui::Slider::new(&mut app.speedhack_val, 0.1..=20.0).text("Multiplier")).changed() {
                            if let Some(proc) = &app.attached_proc {
                                let _ = app.speedhack_injector.enable_speedhack(proc, app.speedhack_val);
                            }
                        }
                    }
                });
            });
        });
    });
}
