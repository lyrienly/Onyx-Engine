// Cheat Engine 7.7 Scanner Workspace Panel (MainUnit upper area)
// Replicates official Found List (TListView) and Scan Controls (TGroupBox)

use eframe::egui::{self, Color32, RichText, Rounding, Stroke, Vec2};
use crate::app::OnyxEngineApp;

pub fn render(app: &mut OnyxEngineApp, ui: &mut egui::Ui, upper_height: f32) {
    ui.allocate_ui_with_layout(Vec2::new(ui.available_width(), upper_height), egui::Layout::left_to_right(egui::Align::TOP), |ui| {
        // LEFT PANEL: Authentic Cheat Engine Found List
        let left_width = (ui.available_width() * 0.44).clamp(280.0, 520.0);
        ui.vertical(|ui| {
            ui.set_width(left_width);
            ui.set_height(upper_height);

            // Label above list: "Found: X"
            ui.horizontal(|ui| {
                ui.label(RichText::new("Found:").size(12.0).color(Color32::from_rgb(180, 185, 195)));
                ui.label(RichText::new(format!("{}", app.found_count)).monospace().size(12.0).strong().color(Color32::from_rgb(100, 240, 140)));
            });

            ui.add_space(2.0);

            // Inset Win32 Table Container
            egui::Frame::none()
                .fill(Color32::from_rgb(20, 22, 28))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(46, 52, 65)))
                .rounding(Rounding::same(2.0))
                .inner_margin(egui::Margin::same(1.0))
                .show(ui, |ui| {
                    ui.set_width(left_width);
                    let list_h = upper_height - 24.0;

                    // Table Header Bar (Address | Value | Previous)
                    ui.horizontal(|ui| {
                        let col_btn = |ui: &mut egui::Ui, text: &str, w: f32| {
                            egui::Frame::none()
                                .fill(Color32::from_rgb(32, 36, 46))
                                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(48, 54, 68)))
                                .rounding(Rounding::same(1.0))
                                .inner_margin(egui::Margin::symmetric(6.0, 3.0))
                                .show(ui, |ui| {
                                    ui.set_width(w);
                                    ui.label(RichText::new(text).size(11.5).strong().color(Color32::from_rgb(200, 205, 215)));
                                });
                        };

                        col_btn(ui, "Address", 120.0);
                        col_btn(ui, "Value", 110.0);
                        col_btn(ui, "Previous", 100.0);
                    });

                    let mut to_add: Option<usize> = None;
                    let mut to_browse: Option<usize> = None;
                    let mut to_disasm: Option<usize> = None;
                    let mut to_copy: Option<String> = None;

                    egui::ScrollArea::vertical()
                        .id_salt("ce_candidates_scroll")
                        .max_height(list_h - 26.0)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.set_min_width(left_width - 8.0);
                            egui::Grid::new("ce_found_grid")
                                .striped(true)
                                .min_col_width(90.0)
                                .spacing(Vec2::new(8.0, 3.0))
                                .show(ui, |ui| {
                                    for (row_idx, (addr, val, prev)) in app.candidates.iter().enumerate() {
                                        let hex_str = format!("{:08X}", addr);
                                        let is_diff = val != prev;

                                        let row_bg = if row_idx % 2 == 0 {
                                            Color32::from_rgb(24, 27, 34)
                                        } else {
                                            Color32::from_rgb(20, 22, 28)
                                        };

                                        let addr_resp = ui.add(
                                            egui::Button::new(RichText::new(&hex_str).monospace().size(12.0).color(Color32::from_rgb(80, 200, 255)))
                                                .fill(row_bg)
                                                .stroke(Stroke::NONE)
                                                .rounding(Rounding::same(1.0)),
                                        );

                                        if addr_resp.double_clicked() {
                                            to_add = Some(*addr);
                                        }

                                        addr_resp.context_menu(|ui| {
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
                                            if ui.button("Copy address").clicked() {
                                                to_copy = Some(hex_str.clone());
                                                ui.close_menu();
                                            }
                                        });

                                        let val_color = if is_diff { Color32::from_rgb(255, 205, 100) } else { Color32::WHITE };
                                        ui.label(RichText::new(val).monospace().strong().color(val_color));
                                        ui.label(RichText::new(prev).monospace().color(Color32::from_rgb(140, 145, 155)));
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
                    if let Some(text) = to_copy {
                        ui.ctx().copy_text(text.clone());
                        app.status_msg = format!("Copied {} to clipboard.", text);
                    }
                });
        });

        ui.add_space(8.0);

        // RIGHT PANEL: Authentic Cheat Engine Scan Controls
        ui.vertical(|ui| {
            ui.set_width(ui.available_width());

            // 1. Scan Action Buttons: First Scan, Next Scan, New Scan, Undo
            ui.horizontal(|ui| {
                let first_scan_btn = egui::Button::new(RichText::new("First Scan").size(12.0).color(Color32::WHITE).strong())
                    .fill(if !app.has_scanned { Color32::from_rgb(32, 125, 60) } else { Color32::from_rgb(38, 42, 52) })
                    .stroke(Stroke::new(1.0_f32, if !app.has_scanned { Color32::from_rgb(48, 175, 85) } else { Color32::from_rgb(52, 58, 70) }))
                    .min_size(Vec2::new(95.0, 26.0))
                    .rounding(Rounding::same(2.0));

                if ui.add_enabled(!app.has_scanned, first_scan_btn).clicked() {
                    app.execute_first_scan();
                }

                let next_scan_btn = egui::Button::new(RichText::new("Next Scan").size(12.0).color(Color32::WHITE).strong())
                    .fill(if app.has_scanned { Color32::from_rgb(35, 95, 175) } else { Color32::from_rgb(38, 42, 52) })
                    .stroke(Stroke::new(1.0_f32, if app.has_scanned { Color32::from_rgb(55, 130, 235) } else { Color32::from_rgb(52, 58, 70) }))
                    .min_size(Vec2::new(95.0, 26.0))
                    .rounding(Rounding::same(2.0));

                if ui.add_enabled(app.has_scanned, next_scan_btn).clicked() {
                    app.execute_next_scan();
                }

                let new_scan_btn = egui::Button::new(RichText::new("New Scan").size(12.0).color(Color32::WHITE).strong())
                    .fill(if app.has_scanned { Color32::from_rgb(145, 45, 45) } else { Color32::from_rgb(38, 42, 52) })
                    .stroke(Stroke::new(1.0_f32, if app.has_scanned { Color32::from_rgb(195, 65, 65) } else { Color32::from_rgb(52, 58, 70) }))
                    .min_size(Vec2::new(85.0, 26.0))
                    .rounding(Rounding::same(2.0));

                if ui.add_enabled(app.has_scanned, new_scan_btn).on_hover_text("Start a fresh scan session").clicked() {
                    app.has_scanned = false;
                    app.candidates.clear();
                    app.found_count = 0;
                    app.scanner.candidates.clear();
                    app.status_msg = "Scan reset. Ready for First Scan.".to_string();
                }

                let can_undo = !app.scanner.history.is_empty();
                let undo_label = if can_undo { format!("Undo ({})", app.scanner.history.len()) } else { "Undo".to_string() };
                let undo_btn = egui::Button::new(RichText::new(undo_label).size(11.5).color(Color32::WHITE).strong())
                    .fill(if can_undo { Color32::from_rgb(155, 90, 25) } else { Color32::from_rgb(38, 42, 52) })
                    .stroke(Stroke::new(1.0_f32, if can_undo { Color32::from_rgb(205, 120, 35) } else { Color32::from_rgb(52, 58, 70) }))
                    .min_size(Vec2::new(75.0, 26.0))
                    .rounding(Rounding::same(2.0));

                if ui.add_enabled(can_undo, undo_btn).clicked() {
                    app.execute_undo_scan();
                }
            });

            ui.add_space(4.0);

            // 2. Value Input Row: Value: [      ] [ ] Hex
            ui.horizontal(|ui| {
                ui.label(RichText::new("Value:").size(12.0).color(Color32::from_rgb(200, 205, 215)));
                let val_w = if app.scan_type_idx == 3 { 90.0 } else { 160.0 };
                let val_input = ui.add(
                    egui::TextEdit::singleline(&mut app.scan_val_text)
                        .desired_width(val_w)
                        .font(egui::TextStyle::Monospace),
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
                    ui.add(egui::TextEdit::singleline(&mut app.scan_val_second_text).desired_width(val_w).font(egui::TextStyle::Monospace));
                }

                ui.checkbox(&mut app.is_hex, "Hex");
            });

            ui.add_space(4.0);

            // 3. Scan Type & Value Type Dropdowns
            ui.horizontal(|ui| {
                ui.label(RichText::new("Scan Type:").size(12.0).color(Color32::from_rgb(180, 185, 195)));
                let scan_types = [
                    "Exact Value",
                    "Bigger than...",
                    "Smaller than...",
                    "Value between...",
                    "Unknown initial value",
                    "Increased value",
                    "Decreased value",
                    "Changed value",
                    "Unchanged value",
                    "Same as first scan",
                ];
                egui::ComboBox::from_id_salt("ce_scan_type_combo")
                    .width(180.0)
                    .selected_text(*scan_types.get(app.scan_type_idx).unwrap_or(&"Exact Value"))
                    .show_ui(ui, |ui| {
                        for (idx, name) in scan_types.iter().enumerate() {
                            ui.selectable_value(&mut app.scan_type_idx, idx, *name);
                        }
                    });
            });

            ui.add_space(2.0);

            ui.horizontal(|ui| {
                ui.label(RichText::new("Value Type:").size(12.0).color(Color32::from_rgb(180, 185, 195)));
                let val_types = [
                    "Binary",
                    "Byte",
                    "2 Bytes",
                    "4 Bytes",
                    "8 Bytes",
                    "Float",
                    "Double",
                    "String",
                    "Array of byte",
                    "All",
                    "Grouped",
                    "AOB (CE 7.7 Notation)",
                ];
                egui::ComboBox::from_id_salt("ce_val_type_combo")
                    .width(180.0)
                    .selected_text(*val_types.get(app.val_type_idx).unwrap_or(&"4 Bytes"))
                    .show_ui(ui, |ui| {
                        for (idx, name) in val_types.iter().enumerate() {
                            ui.selectable_value(&mut app.val_type_idx, idx, *name);
                        }
                    });
            });

            ui.add_space(6.0);

            // 4. Memory Scan Options (Classic Framed GroupBox)
            ui.label(RichText::new("Memory Scan Options:").size(11.5).strong().color(Color32::from_rgb(140, 180, 240)));
            egui::Frame::none()
                .fill(Color32::from_rgb(22, 24, 30))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(46, 52, 65)))
                .rounding(Rounding::same(2.0))
                .inner_margin(egui::Margin::same(6.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Start");
                        ui.add(egui::TextEdit::singleline(&mut app.start_addr_text).desired_width(120.0).font(egui::TextStyle::Monospace));
                        ui.label("Stop");
                        ui.add(egui::TextEdit::singleline(&mut app.stop_addr_text).desired_width(120.0).font(egui::TextStyle::Monospace));
                    });

                    ui.horizontal(|ui| {
                        ui.checkbox(&mut app.fast_scan, "Fast Scan");
                        ui.label("Alignment:");
                        let alignments = ["4 Bytes", "1 Byte", "2 Bytes", "8 Bytes"];
                        egui::ComboBox::from_id_salt("ce_align_combo")
                            .width(85.0)
                            .selected_text(*alignments.get(app.alignment_idx).unwrap_or(&"4 Bytes"))
                            .show_ui(ui, |ui| {
                                for (idx, name) in alignments.iter().enumerate() {
                                    ui.selectable_value(&mut app.alignment_idx, idx, *name);
                                }
                            });
                    });

                    ui.horizontal(|ui| {
                        ui.checkbox(&mut app.writable_only, "Writable");
                        ui.checkbox(&mut app.copy_on_write, "CopyOnWrite");
                        ui.checkbox(&mut app.executable, "Executable");
                    });
                });
        });
    });
}
