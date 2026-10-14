// OnyxEngine Cheat Table Subsystem
// Address list management, inline value modification, and real-time freeze engine

use eframe::egui::{self, Color32, RichText, Rounding, Stroke, Vec2};
use onyx_core::ct_parser::CtParser;
use crate::app::OnyxEngineApp;
use crate::state::GuiTableEntry;

pub fn render(app: &mut OnyxEngineApp, ui: &mut egui::Ui, lower_height: f32) {
    egui::Frame::none()
        .fill(Color32::from_rgb(20, 23, 29))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(36, 42, 53)))
        .rounding(Rounding::same(8.0))
        .inner_margin(egui::Margin::same(8.0))
        .show(ui, |ui| {
            ui.set_height(lower_height);
            ui.horizontal(|ui| {
                egui::Frame::none()
                    .fill(Color32::from_rgb(26, 32, 44))
                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(45, 65, 95)))
                    .rounding(Rounding::same(4.0))
                    .inner_margin(egui::Margin::symmetric(8.0, 3.0))
                    .show(ui, |ui| {
                        ui.label(RichText::new(format!("Address List ({})", app.cheat_table.len())).size(12.5).strong().color(Color32::from_rgb(140, 205, 255)));
                    });

                ui.add_space(8.0);

                let add_btn = egui::Button::new(RichText::new("+ Add Address").size(11.5).color(Color32::WHITE).strong())
                    .fill(Color32::from_rgb(35, 110, 60))
                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(50, 160, 85)))
                    .rounding(Rounding::same(4.0));
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

            ui.add_space(6.0);

            // Cheat Table Address Grid
            egui::ScrollArea::vertical()
                .id_salt("cheat_table_scroll_area")
                .max_height((lower_height - 52.0).max(100.0))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    egui::Grid::new("cheat_table_grid_main")
                        .striped(true)
                        .min_col_width(75.0)
                        .spacing(Vec2::new(14.0, 5.0))
                        .show(ui, |ui| {
                            ui.label(RichText::new("Active").size(11.5).strong().color(Color32::from_rgb(140, 160, 190)));
                            ui.label(RichText::new("Description").size(11.5).strong().color(Color32::from_rgb(140, 160, 190)));
                            ui.label(RichText::new("Address / Pointer Chain").size(11.5).strong().color(Color32::from_rgb(140, 160, 190)));
                            ui.label(RichText::new("Type").size(11.5).strong().color(Color32::from_rgb(140, 160, 190)));
                            ui.label(RichText::new("Value").size(11.5).strong().color(Color32::from_rgb(140, 160, 190)));
                            ui.label(RichText::new("Actions").size(11.5).strong().color(Color32::from_rgb(140, 160, 190)));
                            ui.end_row();

                            let mut edit_click: Option<(usize, String)> = None;
                            let mut delete_click: Option<usize> = None;
                            let mut browse_click: Option<usize> = None;
                            let mut disasm_click: Option<usize> = None;
                            let mut ptr_scan_click: Option<usize> = None;

                            for (idx, entry) in app.cheat_table.iter_mut().enumerate() {
                                // Active Toggle Pill
                                let active_text = if entry.active { "[FROZEN]" } else { "[  ]" };
                                let active_color = if entry.active { Color32::from_rgb(100, 240, 120) } else { Color32::GRAY };
                                if ui.selectable_label(entry.active, RichText::new(active_text).monospace().strong().color(active_color)).clicked() {
                                    entry.active = !entry.active;
                                }

                                // Description (Editable inline)
                                ui.add(egui::TextEdit::singleline(&mut entry.description).desired_width(180.0));

                                // Address / Pointer Chain
                                let is_ptr = !entry.offsets.is_empty();
                                let addr_text = if !is_ptr {
                                    format!("0x{:08X}", entry.address)
                                } else {
                                    let mod_str = entry.module_name.as_deref().unwrap_or("mem");
                                    let off_chain = entry.offsets.iter().map(|o| format!("+{:X}", o)).collect::<Vec<_>>().join("->");
                                    format!("P->[\"{}\"+{:X}]->{}", mod_str, entry.base_offset, off_chain)
                                };

                                let (badge_color, border_color) = if !is_ptr {
                                    (Color32::from_rgb(120, 190, 255), Color32::from_rgb(45, 80, 120))
                                } else {
                                    (Color32::from_rgb(255, 195, 100), Color32::from_rgb(120, 85, 40))
                                };

                                let addr_btn = egui::Button::new(RichText::new(&addr_text).monospace().size(12.0).color(badge_color))
                                    .fill(Color32::from_rgb(24, 28, 36))
                                    .stroke(Stroke::new(1.0_f32, border_color))
                                    .rounding(Rounding::same(4.0));

                                let resp = ui.add(addr_btn);
                                if resp.clicked() {
                                    browse_click = Some(entry.address);
                                }

                                resp.context_menu(|ui| {
                                    if ui.button("Browse in Hex Memory View").clicked() {
                                        browse_click = Some(entry.address);
                                        ui.close_menu();
                                    }
                                    if ui.button("Disassemble this address").clicked() {
                                        disasm_click = Some(entry.address);
                                        ui.close_menu();
                                    }
                                    if ui.button("Scan Pointers for this address").clicked() {
                                        ptr_scan_click = Some(entry.address);
                                        ui.close_menu();
                                    }
                                    if ui.button("Change Value").clicked() {
                                        edit_click = Some((idx, entry.current_val.clone()));
                                        ui.close_menu();
                                    }
                                    if ui.button("Delete from list").clicked() {
                                        delete_click = Some(idx);
                                        ui.close_menu();
                                    }
                                });

                                // Type Badge
                                let type_name = match entry.val_type {
                                    onyx_core::scanner::ValType::I8 => "i8",
                                    onyx_core::scanner::ValType::U8 => "u8",
                                    onyx_core::scanner::ValType::I16 => "i16",
                                    onyx_core::scanner::ValType::U16 => "u16",
                                    onyx_core::scanner::ValType::I32 => "i32",
                                    onyx_core::scanner::ValType::U32 => "u32",
                                    onyx_core::scanner::ValType::I64 => "i64",
                                    onyx_core::scanner::ValType::U64 => "u64",
                                    onyx_core::scanner::ValType::Float => "Float",
                                    onyx_core::scanner::ValType::Double => "Double",
                                    onyx_core::scanner::ValType::Str => "Str",
                                    onyx_core::scanner::ValType::Aob => "AOB",
                                };
                                ui.label(RichText::new(format!("[{}]", type_name)).size(11.0).color(Color32::from_rgb(170, 185, 215)));

                                // Value Button (Click to edit)
                                let val_btn = egui::Button::new(RichText::new(&entry.current_val).monospace().strong().size(12.5).color(Color32::WHITE))
                                    .fill(Color32::from_rgb(28, 33, 44))
                                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(45, 55, 75)))
                                    .min_size(Vec2::new(75.0, 22.0))
                                    .rounding(Rounding::same(4.0));

                                if ui.add(val_btn).clicked() {
                                    edit_click = Some((idx, entry.current_val.clone()));
                                }

                                // Delete button
                                if ui.button(RichText::new("[x]").color(Color32::from_rgb(240, 100, 100))).clicked() {
                                    delete_click = Some(idx);
                                }

                                ui.end_row();
                            }

                            if let Some((idx, val)) = edit_click {
                                app.edit_entry_idx = Some(idx);
                                app.edit_val_text = val;
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

                            if let Some(idx) = delete_click {
                                if idx < app.cheat_table.len() {
                                    app.cheat_table.remove(idx);
                                }
                            }
                        });
                });
        });

    // Modal: Edit Table Entry Value
    if let Some(idx) = app.edit_entry_idx {
        let mut close_edit = false;
        egui::Window::new("Change Value")
            .collapsible(false)
            .resizable(false)
            .movable(true)
            .constrain(false)
            .default_size(Vec2::new(300.0, 130.0))
            .show(ui.ctx(), |ui| {
                ui.label(RichText::new("Enter new value:").size(12.5).color(Color32::LIGHT_GRAY));
                let te = ui.add(egui::TextEdit::singleline(&mut app.edit_val_text).desired_width(260.0).font(egui::TextStyle::Monospace));
                if te.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    let text = app.edit_val_text.clone();
                    app.write_table_entry_value(idx, &text);
                    close_edit = true;
                }

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let ok_btn = egui::Button::new(RichText::new("Confirm").strong().color(Color32::WHITE))
                        .fill(Color32::from_rgb(35, 125, 65))
                        .rounding(Rounding::same(4.0));
                    if ui.add(ok_btn).clicked() {
                        let text = app.edit_val_text.clone();
                        app.write_table_entry_value(idx, &text);
                        close_edit = true;
                    }

                    if ui.button("Cancel").clicked() {
                        close_edit = true;
                    }
                });
            });

        if close_edit {
            app.edit_entry_idx = None;
        }
    }
}
