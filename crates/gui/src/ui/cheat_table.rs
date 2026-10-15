// Cheat Engine 7.7 Cheat Table Subsystem (MainUnit lower area)
// Replicates official Address List (TTreeView) with Active [X] cross and Win32 table headers

use eframe::egui::{self, Color32, RichText, Rounding, Stroke, Vec2};
use onyx_core::ct_parser::CtParser;
use crate::app::OnyxEngineApp;
use crate::state::GuiTableEntry;

pub fn render(app: &mut OnyxEngineApp, ui: &mut egui::Ui, lower_height: f32) {
    egui::Frame::none()
        .fill(Color32::from_rgb(22, 24, 30))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(46, 52, 65)))
        .rounding(Rounding::same(2.0))
        .inner_margin(egui::Margin::same(4.0))
        .show(ui, |ui| {
            ui.set_height(lower_height);

            // Table Action Header
            ui.horizontal(|ui| {
                ui.label(RichText::new("Address List:").size(12.0).strong().color(Color32::from_rgb(180, 185, 195)));
                ui.label(RichText::new(format!("{} records", app.cheat_table.len())).size(11.5).color(Color32::GRAY));

                ui.add_space(8.0);

                let add_btn = egui::Button::new(RichText::new("+ Add Address").size(11.5).color(Color32::WHITE).strong())
                    .fill(Color32::from_rgb(30, 85, 45))
                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(45, 130, 70)))
                    .min_size(Vec2::new(90.0, 22.0))
                    .rounding(Rounding::same(2.0));
                if ui.add(add_btn).clicked() {
                    app.show_add_addr_modal = true;
                }

                if ui.button("Clear List").clicked() {
                    app.cheat_table.clear();
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Save .CT").clicked() {
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
                    if ui.button("Load .CT").clicked() {
                        if let Ok(table) = CtParser::load_ct_file("onyx_table.CT") {
                            for e in table.entries {
                                app.cheat_table.push(GuiTableEntry {
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
                            app.status_msg = "Table loaded.".to_string();
                        }
                    }
                });
            });

            ui.add_space(2.0);

            // Win32 Inset Container
            egui::Frame::none()
                .fill(Color32::from_rgb(18, 20, 26))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(42, 48, 60)))
                .rounding(Rounding::same(2.0))
                .inner_margin(egui::Margin::same(1.0))
                .show(ui, |ui| {
                    let table_scroll_h = (lower_height - 38.0).max(100.0);

                    // Table Header Bar (Active | Description | Address | Type | Value)
                    ui.horizontal(|ui| {
                        let th = |ui: &mut egui::Ui, text: &str, w: f32| {
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

                        th(ui, "Active", 50.0);
                        th(ui, "Description", 180.0);
                        th(ui, "Address", 160.0);
                        th(ui, "Type", 90.0);
                        th(ui, "Value", 120.0);
                    });

                    egui::ScrollArea::both()
                        .id_salt("ce_cheat_table_scroll")
                        .max_height(table_scroll_h - 26.0)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            egui::Grid::new("ce_cheat_table_grid")
                                .striped(true)
                                .min_col_width(60.0)
                                .spacing(Vec2::new(8.0, 3.0))
                                .show(ui, |ui| {
                                    let mut edit_click: Option<(usize, String)> = None;
                                    let mut delete_click: Option<usize> = None;
                                    let mut browse_click: Option<usize> = None;
                                    let mut disasm_click: Option<usize> = None;
                                    let mut ptr_scan_click: Option<usize> = None;

                                    for (idx, entry) in app.cheat_table.iter_mut().enumerate() {
                                        // Active Toggle (Classic CE [X] red cross)
                                        let (active_text, active_color) = if entry.active {
                                            ("[X]", Color32::from_rgb(255, 50, 50))
                                        } else {
                                            ("[ ]", Color32::from_rgb(130, 135, 150))
                                        };
                                        if ui.selectable_label(entry.active, RichText::new(active_text).monospace().strong().color(active_color)).clicked() {
                                            entry.active = !entry.active;
                                        }

                                        // Description (Editable inline)
                                        ui.add(egui::TextEdit::singleline(&mut entry.description).desired_width(180.0));

                                        // Address / Pointer Chain
                                        let is_ptr = !entry.offsets.is_empty();
                                        let addr_text = if !is_ptr {
                                            format!("{:08X}", entry.address)
                                        } else {
                                            let mod_str = entry.module_name.as_deref().unwrap_or("mem");
                                            let off_chain = entry.offsets.iter().map(|o| format!("+{:X}", o)).collect::<Vec<_>>().join("->");
                                            format!("P->[\"{}\"+{:X}]->{}", mod_str, entry.base_offset, off_chain)
                                        };

                                        let badge_color = if !is_ptr {
                                            Color32::from_rgb(80, 200, 255)
                                        } else {
                                            Color32::from_rgb(255, 195, 100)
                                        };

                                        let addr_btn = egui::Button::new(RichText::new(&addr_text).monospace().size(12.0).color(badge_color))
                                            .fill(Color32::from_rgb(24, 27, 34))
                                            .stroke(Stroke::NONE)
                                            .rounding(Rounding::same(2.0));

                                        let resp = ui.add(addr_btn);
                                        if resp.clicked() {
                                            browse_click = Some(entry.address);
                                        }

                                        resp.context_menu(|ui| {
                                            if ui.button("Browse Memory in Hex View").clicked() {
                                                browse_click = Some(entry.address);
                                                ui.close_menu();
                                            }
                                            if ui.button("Disassemble Memory Region").clicked() {
                                                disasm_click = Some(entry.address);
                                                ui.close_menu();
                                            }
                                            if ui.button("Pointer scan for this address").clicked() {
                                                ptr_scan_click = Some(entry.address);
                                                ui.close_menu();
                                            }
                                            ui.separator();
                                            if ui.button("Delete Record").clicked() {
                                                delete_click = Some(idx);
                                                ui.close_menu();
                                            }
                                        });

                                        // Type
                                        ui.label(RichText::new(entry.val_type.as_str()).size(11.5).color(Color32::from_rgb(160, 180, 205)));

                                        // Value (Click to edit)
                                        let val_resp = ui.add(
                                            egui::Button::new(RichText::new(&entry.current_val).monospace().strong().color(Color32::WHITE))
                                                .fill(Color32::from_rgb(26, 30, 40))
                                                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(45, 52, 68)))
                                                .rounding(Rounding::same(2.0)),
                                        );

                                        if val_resp.double_clicked() {
                                            edit_click = Some((idx, entry.current_val.clone()));
                                        }

                                        ui.end_row();
                                    }

                                    if let Some((idx, val)) = edit_click {
                                        app.edit_entry_idx = Some(idx);
                                        app.edit_val_text = val;
                                        app.show_edit_byte_modal = true;
                                    }
                                    if let Some(idx) = delete_click {
                                        if idx < app.cheat_table.len() {
                                            app.cheat_table.remove(idx);
                                        }
                                    }
                                    if let Some(addr) = browse_click {
                                        app.navigate_hex(addr);
                                        app.show_memory_view = true;
                                    }
                                    if let Some(addr) = disasm_click {
                                        app.navigate_disasm(addr);
                                        app.show_memory_view = true;
                                    }
                                    if let Some(addr) = ptr_scan_click {
                                        app.ptr_target_addr_text = format!("0x{:08X}", addr);
                                        app.show_pointer_scanner = true;
                                    }
                                });
                        });
                });
        });
}
