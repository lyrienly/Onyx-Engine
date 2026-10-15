// Mono & .NET CLR Runtime Dissector Modal for OnyxEngine
// In-depth inspection of assemblies, classes, live field values, and JIT compiled methods

use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use onyx_core::mono::MonoDissector;
use onyx_core::scanner::ValType;
use crate::app::OnyxEngineApp;
use crate::state::GuiTableEntry;

pub fn render(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    if !app.show_mono_modal {
        return;
    }

    ctx.show_viewport_immediate(
        egui::ViewportId::from_hash_of("onyx_mono_dissector_viewport"),
        egui::ViewportBuilder::default()
            .with_title("Mono & .NET Dissector - OnyxEngine")
            .with_inner_size([1120.0, 720.0])
            .with_min_inner_size([760.0, 480.0])
            .with_resizable(true),
        |ctx, _class| {
            if ctx.input(|i| i.viewport().close_requested()) {
                app.show_mono_modal = false;
            }

            // 1. Header Toolbar
            egui::TopBottomPanel::top("mono_top_bar").show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let rt_name = app.mono_dissector.runtime_type.as_str();
                    let is_attached = app.mono_dissector.is_attached;
                    let rt_color = if is_attached { Color32::GREEN } else { Color32::GRAY };
                    ui.label(RichText::new(format!("[*] {}", rt_name)).strong().color(rt_color));

                    ui.add_space(10.0);
                    ui.label("Search:");
                    ui.add(egui::TextEdit::singleline(&mut app.mono_search_text).hint_text("Filter classes & fields...").desired_width(220.0));

                    ui.add_space(6.0);
                    if ui.button("[Re-Dissect]").clicked() {
                        if let Some(proc) = &app.attached_proc {
                            let _ = app.mono_dissector.dissect(proc);
                        }
                    }

                    if ui.button("[Copy Report]").clicked() {
                        let rep = app.mono_dissector.generate_report();
                        ctx.copy_text(rep);
                        app.status_msg = "Copied .NET/Mono Report to clipboard.".to_string();
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("[Close]").clicked() {
                            app.show_mono_modal = false;
                        }
                    });
                });
                ui.add_space(4.0);
            });

            // 2. Bottom Status Bar
            egui::TopBottomPanel::bottom("mono_bottom_bar").show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let a_count = app.mono_dissector.assemblies.len();
                    let c_count: usize = app.mono_dissector.assemblies.iter().map(|a| a.classes.len()).sum();
                    ui.label(RichText::new(format!("Runtime: {} | Assemblies: {} | Classes: {} | Target: {}", app.mono_dissector.runtime_type.as_str(), a_count, c_count, app.proc_name)).color(Color32::LIGHT_GRAY));

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button(RichText::new("Close Dissector").strong()).clicked() {
                            app.show_mono_modal = false;
                        }
                    });
                });
                ui.add_space(4.0);
            });

            // 3. Central Working Area
            egui::CentralPanel::default().show(ctx, |ui| {
                let avail = ui.available_size();
                let left_w = (avail.x * 0.30).clamp(260.0, 360.0);
                let right_w = (avail.x - left_w - 10.0).max(300.0);
                let full_h = avail.y;

                ui.horizontal(|ui| {
                    // LEFT MASTER PANEL
                    ui.vertical(|ui| {
                        ui.set_width(left_w);
                        let asm_h = (full_h * 0.38).clamp(100.0, 220.0);
                        let cls_h = (full_h - asm_h - 14.0).max(120.0);

                        // Card 1: Assemblies
                        egui::Frame::group(ui.style())
                            .fill(Color32::from_rgb(22, 26, 34))
                            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(44, 52, 66)))
                            .rounding(egui::Rounding::same(4.0))
                            .show(ui, |ui| {
                                ui.set_width(left_w);
                                ui.set_height(asm_h);
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(format!("[Assemblies] ({})", app.mono_dissector.assemblies.len())).strong().color(Color32::from_rgb(120, 200, 255)));
                                });
                                ui.separator();

                                egui::ScrollArea::vertical()
                                    .id_salt("mono_asm_scroll")
                                    .max_height(asm_h - 36.0)
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        for (idx, asm) in app.mono_dissector.assemblies.iter().enumerate() {
                                            let is_sel = app.selected_assembly_idx == Some(idx);
                                            let label_text = format!("{} ({})", asm.name, asm.classes.len());
                                            if ui.selectable_label(is_sel, RichText::new(label_text).monospace()).clicked() {
                                                app.selected_assembly_idx = Some(idx);
                                                app.selected_class_idx = None;
                                            }
                                        }
                                    });
                            });

                        ui.add_space(6.0);

                        // Card 2: Classes
                        let search_lower = app.mono_search_text.trim().to_lowercase();
                        let sel_asm = app.selected_assembly_idx.and_then(|idx| app.mono_dissector.assemblies.get(idx));
                        let class_count = sel_asm.map(|a| a.classes.len()).unwrap_or(0);

                        egui::Frame::group(ui.style())
                            .fill(Color32::from_rgb(22, 26, 34))
                            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(44, 52, 66)))
                            .rounding(egui::Rounding::same(4.0))
                            .show(ui, |ui| {
                                ui.set_width(left_w);
                                ui.set_height(cls_h);
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(format!("[Classes] ({})", class_count)).strong().color(Color32::from_rgb(255, 200, 100)));
                                });
                                ui.separator();

                                egui::ScrollArea::vertical()
                                    .id_salt("mono_classes_scroll")
                                    .max_height(cls_h - 36.0)
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        if let Some(asm) = sel_asm {
                                            for (idx, cls) in asm.classes.iter().enumerate() {
                                                if search_lower.is_empty()
                                                    || cls.full_name.to_lowercase().contains(&search_lower)
                                                    || cls.fields.iter().any(|f| f.name.to_lowercase().contains(&search_lower))
                                                    || cls.methods.iter().any(|m| m.name.to_lowercase().contains(&search_lower))
                                                {
                                                    let is_sel = app.selected_class_idx == Some(idx);
                                                    let short_name = cls.name.as_str();
                                                    let label_resp = ui.selectable_label(is_sel, RichText::new(short_name).monospace().strong());
                                                    if label_resp.clicked() {
                                                        app.selected_class_idx = Some(idx);
                                                    }
                                                    if label_resp.hovered() {
                                                        label_resp.on_hover_text(&cls.full_name);
                                                    }
                                                }
                                            }
                                        } else {
                                            ui.label(RichText::new("Select an assembly above").color(Color32::GRAY));
                                        }
                                    });
                            });
                    });

                    ui.add_space(8.0);

                    // RIGHT DETAIL PANEL
                    ui.vertical(|ui| {
                        ui.set_width(right_w);
                        egui::Frame::group(ui.style())
                            .fill(Color32::from_rgb(22, 26, 34))
                            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(44, 52, 66)))
                            .rounding(egui::Rounding::same(4.0))
                            .show(ui, |ui| {
                                ui.set_width(right_w);
                                ui.set_height(full_h - 4.0);

                                let mut to_add_field: Option<(String, usize, ValType)> = None;
                                let mut to_disasm_method: Option<usize> = None;
                                let mut to_hook_method: Option<(String, usize)> = None;

                                let sel_cls = app.selected_assembly_idx
                                    .and_then(|a_idx| app.mono_dissector.assemblies.get(a_idx))
                                    .and_then(|asm| app.selected_class_idx.and_then(|c_idx| asm.classes.get(c_idx)));

                                if let Some(cls) = sel_cls {
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new(&cls.full_name).size(15.0).strong().color(Color32::WHITE));
                                        if let Some(p) = &cls.parent_class {
                                            ui.label(RichText::new(format!(": {}", p)).color(Color32::from_rgb(140, 180, 220)));
                                        }
                                    });

                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new("Instance Pointer (Hex):").color(Color32::LIGHT_GRAY));
                                        ui.add(egui::TextEdit::singleline(&mut app.mono_instance_addr_text).hint_text("0x00000000").desired_width(170.0).font(egui::TextStyle::Monospace));

                                        if ui.button("Paste from Table").clicked() {
                                            if let Some(entry) = app.cheat_table.first() {
                                                app.mono_instance_addr_text = format!("0x{:08X}", entry.address);
                                            }
                                        }
                                        if ui.button("Clear").clicked() {
                                            app.mono_instance_addr_text.clear();
                                        }
                                        ui.label(RichText::new("[Live values read from memory]").color(Color32::GRAY));
                                    });

                                    ui.separator();

                                    let inst_addr = OnyxEngineApp::parse_hex_addr(&app.mono_instance_addr_text, 0);
                                    let rem_h = ui.available_height() - 20.0;
                                    let fields_h = (rem_h * 0.58).max(120.0);
                                    let methods_h = (rem_h - fields_h - 28.0).max(100.0);

                                    // Fields
                                    ui.label(RichText::new(format!("Fields ({})", cls.fields.len())).strong().color(Color32::from_rgb(120, 210, 255)));
                                    egui::ScrollArea::vertical()
                                        .id_salt("mono_fields_scroll")
                                        .max_height(fields_h)
                                        .auto_shrink([false, false])
                                        .show(ui, |ui| {
                                            egui::Grid::new("mono_fields_grid")
                                                .striped(true)
                                                .min_col_width(70.0)
                                                .spacing(Vec2::new(12.0, 3.0))
                                                .show(ui, |ui| {
                                                    ui.label(RichText::new("Offset").strong().color(Color32::LIGHT_GRAY));
                                                    ui.label(RichText::new("Field Name").strong().color(Color32::LIGHT_GRAY));
                                                    ui.label(RichText::new("Data Type").strong().color(Color32::LIGHT_GRAY));
                                                    ui.label(RichText::new("Live Value").strong().color(Color32::LIGHT_GRAY));
                                                    ui.label(RichText::new("Actions").strong().color(Color32::LIGHT_GRAY));
                                                    ui.end_row();

                                                    for f in &cls.fields {
                                                        let off_str = format!("+0x{:04X}", f.offset);
                                                        ui.label(RichText::new(off_str).monospace().color(Color32::from_rgb(110, 190, 255)));
                                                        ui.label(RichText::new(&f.name).monospace().strong());
                                                        ui.label(RichText::new(&f.type_name).monospace().color(Color32::from_rgb(190, 170, 240)));

                                                        let live_str = if let Some(proc) = &app.attached_proc {
                                                            MonoDissector::read_field_value(proc, inst_addr, f)
                                                        } else {
                                                            "-".to_string()
                                                        };

                                                        let val_color = if live_str.starts_with('"') {
                                                            Color32::from_rgb(255, 215, 120)
                                                        } else if live_str == "true" {
                                                            Color32::GREEN
                                                        } else if live_str == "false" {
                                                            Color32::RED
                                                        } else if live_str != "-" && live_str != "???" && live_str != "null" {
                                                            Color32::from_rgb(140, 240, 140)
                                                        } else {
                                                            Color32::GRAY
                                                        };
                                                        ui.label(RichText::new(live_str).monospace().strong().color(val_color));

                                                        if ui.button("+ Add").clicked() {
                                                            let vt = match f.type_name.as_str() {
                                                                "System.Single" | "float" => ValType::Float,
                                                                "System.Double" | "double" => ValType::Double,
                                                                "System.Int64" | "long" => ValType::I64,
                                                                "System.UInt64" | "ulong" => ValType::U64,
                                                                "System.Int32" | "int" => ValType::I32,
                                                                "System.UInt32" | "uint" => ValType::U32,
                                                                "System.Int16" | "short" => ValType::I16,
                                                                "System.Boolean" | "bool" => ValType::U8,
                                                                "System.Byte" | "byte" => ValType::U8,
                                                                _ => ValType::I32,
                                                            };
                                                            let base_target = if inst_addr != 0 { inst_addr } else { cls.class_address };
                                                            to_add_field = Some((format!("{}::{}", cls.name, f.name), base_target + f.offset, vt));
                                                        }
                                                        ui.end_row();
                                                    }
                                                });
                                        });

                                    ui.add_space(4.0);
                                    ui.separator();

                                    // Methods
                                    ui.label(RichText::new(format!("Methods ({})", cls.methods.len())).strong().color(Color32::from_rgb(255, 170, 170)));
                                    egui::ScrollArea::vertical()
                                        .id_salt("mono_methods_scroll")
                                        .max_height(methods_h)
                                        .auto_shrink([false, false])
                                        .show(ui, |ui| {
                                            egui::Grid::new("mono_methods_grid")
                                                .striped(true)
                                                .min_col_width(70.0)
                                                .spacing(Vec2::new(12.0, 3.0))
                                                .show(ui, |ui| {
                                                    ui.label(RichText::new("Method Name").strong().color(Color32::LIGHT_GRAY));
                                                    ui.label(RichText::new("Entry Address").strong().color(Color32::LIGHT_GRAY));
                                                    ui.label(RichText::new("Return Type").strong().color(Color32::LIGHT_GRAY));
                                                    ui.label(RichText::new("Actions").strong().color(Color32::LIGHT_GRAY));
                                                    ui.end_row();

                                                    for m in &cls.methods {
                                                        ui.label(RichText::new(&m.name).monospace().strong());
                                                        ui.label(RichText::new(format!("0x{:08X}", m.address)).monospace().color(Color32::from_rgb(110, 200, 255)));
                                                        ui.label(RichText::new(&m.return_type).monospace().color(Color32::LIGHT_GRAY));

                                                        ui.horizontal(|ui| {
                                                            if ui.button("Disasm").clicked() {
                                                                to_disasm_method = Some(m.address);
                                                            }
                                                            if ui.button("Hook").clicked() {
                                                                to_hook_method = Some((format!("{}::{}", cls.name, m.name), m.address));
                                                            }
                                                        });
                                                        ui.end_row();
                                                    }
                                                });
                                        });
                                } else {
                                    ui.vertical_centered(|ui| {
                                        ui.add_space(80.0);
                                        ui.label(RichText::new("Select an Assembly and Class from the left to inspect fields and methods.").size(14.0).color(Color32::GRAY));
                                        ui.label(RichText::new("Entering an Instance Pointer enables real-time memory value inspection.").color(Color32::DARK_GRAY));
                                    });
                                }

                                if let Some((desc, target_addr, vt)) = to_add_field {
                                    app.cheat_table.push(GuiTableEntry {
                                        active: false,
                                        description: desc,
                                        address: target_addr,
                                        module_name: app.mono_dissector.module_name.clone(),
                                        base_offset: target_addr,
                                        offsets: Vec::new(),
                                        val_type: vt,
                                        current_val: "0".to_string(),
                                        target_val: "0".to_string(),
                                    });
                                    app.status_msg = format!("Added managed field to Cheat Table (0x{:X})", target_addr);
                                }

                                if let Some(addr) = to_disasm_method {
                                    app.navigate_disasm(addr);
                                    app.show_memory_view = true;
                                }

                                if let Some((name, addr)) = to_hook_method {
                                    app.aa_script = MonoDissector::generate_method_hook_script(&name, addr);
                                    app.show_aa_modal = true;
                                }
                            });
                    });
                });
            });
        },
    );
}
