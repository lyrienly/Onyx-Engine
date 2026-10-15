use eframe::egui::{self, Color32, RichText};
use crate::app::OnyxEngineApp;
use crate::state::GuiTableEntry;

pub fn render(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    if !app.show_add_addr_modal {
        return;
    }

    let mut close_modal = false;

    ctx.show_viewport_immediate(
        egui::ViewportId::from_hash_of("ce_add_address_viewport"),
        egui::ViewportBuilder::default()
            .with_title("Add Address Manually")
            .with_inner_size([460.0, 380.0])
            .with_min_inner_size([360.0, 300.0])
            .with_resizable(true),
        |ctx, _class| {
            if ctx.input(|i| i.viewport().close_requested() || i.key_pressed(egui::Key::Escape)) {
                close_modal = true;
            }

            egui::CentralPanel::default()
                .frame(egui::Frame::none().fill(Color32::from_rgb(26, 29, 36)).inner_margin(egui::Margin::same(8.0)))
                .show(ctx, |ui| {
                    ui.checkbox(&mut app.manual_is_pointer, RichText::new("Pointer").strong());

                    if !app.manual_is_pointer {
                        ui.label("Address (Hex):");
                        ui.add(egui::TextEdit::singleline(&mut app.manual_addr_text).desired_width((ui.available_width() - 20.0).max(180.0)).font(egui::TextStyle::Monospace));
                    } else {
                        ui.group(|ui| {
                            ui.label(RichText::new("Base Pointer:").strong());
                            ui.horizontal(|ui| {
                                ui.label("Module:");
                                ui.add(egui::TextEdit::singleline(&mut app.manual_module_text).desired_width(120.0));
                                ui.label("Offset:");
                                ui.add(egui::TextEdit::singleline(&mut app.manual_base_offset_text).desired_width(80.0).font(egui::TextStyle::Monospace));
                            });

                            ui.separator();
                            ui.label("Offsets Chain:");
                            let mut remove_idx: Option<usize> = None;
                            for (i, off_str) in app.manual_offsets.iter_mut().enumerate() {
                                ui.horizontal(|ui| {
                                    ui.label(format!("Offset {}:", i));
                                    ui.add(egui::TextEdit::singleline(off_str).desired_width(80.0).font(egui::TextStyle::Monospace));
                                    if ui.button("[x]").clicked() {
                                        remove_idx = Some(i);
                                    }
                                });
                            }
                            if let Some(r_idx) = remove_idx {
                                app.manual_offsets.remove(r_idx);
                            }
                            if ui.button("+ Add Offset").clicked() {
                                app.manual_offsets.push("0x0".to_string());
                            }
                        });
                    }

                    ui.label("Description:");
                    ui.add(egui::TextEdit::singleline(&mut app.manual_desc_text).desired_width((ui.available_width() - 20.0).max(180.0)));

                    ui.label("Type:");
                    let val_types = [
                        "1 Byte (i8)",
                        "1 Byte (u8)",
                        "2 Bytes (i16)",
                        "2 Bytes (u16)",
                        "4 Bytes (i32)",
                        "4 Bytes (u32)",
                        "8 Bytes (i64)",
                        "8 Bytes (u64)",
                        "Float",
                        "Double",
                        "String",
                        "Array of Byte (AOB)",
                    ];
                    egui::ComboBox::from_id_salt("manual_type_combo")
                        .selected_text(val_types[app.manual_type_idx.min(val_types.len() - 1)])
                        .show_ui(ui, |ui| {
                            for (i, t) in val_types.iter().enumerate() {
                                ui.selectable_value(&mut app.manual_type_idx, i, *t);
                            }
                        });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("Add").strong().color(Color32::GREEN)).clicked() {
                            let val_type = app.parse_manual_val_type();

                            if !app.manual_is_pointer {
                                let addr = OnyxEngineApp::parse_hex_addr(&app.manual_addr_text, 0);
                                let cur_val = if let Some(proc) = &app.attached_proc {
                                    proc.read::<i32>(addr).map(|v| v.to_string()).unwrap_or("???".to_string())
                                } else {
                                    "???".to_string()
                                };

                                app.cheat_table.push(GuiTableEntry {
                                    active: false,
                                    description: app.manual_desc_text.clone(),
                                    address: addr,
                                    module_name: None,
                                    base_offset: addr,
                                    offsets: Vec::new(),
                                    val_type,
                                    current_val: cur_val.clone(),
                                    target_val: cur_val,
                                });
                            } else {
                                let base_offset = OnyxEngineApp::parse_hex_addr(&app.manual_base_offset_text, 0);
                                let offsets: Vec<usize> = app.manual_offsets
                                    .iter()
                                    .map(|s| OnyxEngineApp::parse_hex_addr(s, 0))
                                    .collect();

                                app.cheat_table.push(GuiTableEntry {
                                    active: false,
                                    description: app.manual_desc_text.clone(),
                                    address: 0,
                                    module_name: Some(app.manual_module_text.clone()),
                                    base_offset,
                                    offsets,
                                    val_type,
                                    current_val: "???".to_string(),
                                    target_val: "0".to_string(),
                                });
                            }

                            close_modal = true;
                        }

                        if ui.button("Cancel").clicked() {
                            close_modal = true;
                        }
                    });
                });
        },
    );

    if close_modal {
        app.show_add_addr_modal = false;
    }
}
