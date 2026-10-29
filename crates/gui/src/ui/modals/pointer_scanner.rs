use std::time::Instant;
use eframe::egui::{self, Color32, RichText, Vec2};
use onyx_core::pointer_scanner::{PointerPath, PointerScanner};
use onyx_core::scanner::ValType;
use crate::app::OnyxEngineApp;

pub fn render(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    if !app.show_pointer_scanner {
        return;
    }

    ctx.show_viewport_immediate(
        egui::ViewportId::from_hash_of("onyx_pointer_scanner_viewport"),
        egui::ViewportBuilder::default()
            .with_title("Multilevel Pointer Scanner - OnyxEngine")
            .with_inner_size([920.0, 640.0])
            .with_min_inner_size([640.0, 420.0])
            .with_resizable(true),
        |ctx, _class| {
            if ctx.input(|i| i.viewport().close_requested()) {
                app.show_pointer_scanner = false;
            }

            egui::TopBottomPanel::bottom("ptr_scanner_bottom_bar").show(ctx, |ui| {
                ui.add_space(3.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&app.ptr_status).color(Color32::from_rgb(200, 200, 100)));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button(RichText::new("Close Scanner").strong()).clicked() {
                            app.show_pointer_scanner = false;
                        }
                    });
                });
                ui.add_space(3.0);
            });

            egui::CentralPanel::default().show(ctx, |ui| {
                ui.label(RichText::new("Target Address to Find Pointers:").strong().color(Color32::from_rgb(120, 200, 255)));

                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut app.ptr_target_addr_text).desired_width(180.0).font(egui::TextStyle::Monospace));

                    if ui.button("Paste Target from Table").clicked()
                        && let Some(entry) = app.cheat_table.first() {
                            app.ptr_target_addr_text = format!("0x{:08X}", entry.address);
                        }
                });

                ui.add_space(4.0);

                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("Max Depth / Level:");
                        ui.add(egui::Slider::new(&mut app.ptr_max_depth, 1..=7));

                        ui.add_space(10.0);
                        ui.label("Max Offset:");
                        ui.add(egui::Slider::new(&mut app.ptr_max_offset, 256..=16384));
                    });
                });

                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    let map_btn_text = if app.ptr_map_nodes > 0 {
                        format!("1. Regenerate Map ({} indexed)", app.ptr_map_nodes)
                    } else {
                        "1. Generate Pointer Map".to_string()
                    };

                    if ui.button(RichText::new(map_btn_text).color(Color32::WHITE).strong()).clicked() {
                        if let Some(proc) = &app.attached_proc {
                            let start = Instant::now();
                            match app.pointer_scanner.generate_map(proc) {
                                Ok(nodes) => {
                                    app.ptr_map_nodes = nodes;
                                    app.ptr_status = format!("Generated pointer map with {} nodes in {:.2?}", nodes, start.elapsed());
                                }
                                Err(e) => {
                                    app.ptr_status = format!("Map generation failed: {}", e);
                                }
                            }
                        } else {
                            app.ptr_status = "Attach to a process first.".to_string();
                        }
                    }

                    if ui.button(RichText::new("2. Scan for Pointers").color(Color32::GREEN).strong()).clicked()
                        && let Some(proc) = &app.attached_proc {
                            if app.ptr_map_nodes == 0 {
                                let _ = app.pointer_scanner.generate_map(proc);
                            }
                            let target_addr = OnyxEngineApp::parse_hex_addr(&app.ptr_target_addr_text, 0);
                            let start = Instant::now();
                            match app.pointer_scanner.scan_paths(proc, target_addr, app.ptr_max_depth, app.ptr_max_offset) {
                                Ok(paths) => {
                                    app.ptr_results = paths;
                                    app.ptr_status = format!("Found {} pointer paths in {:.2?}", app.ptr_results.len(), start.elapsed());
                                }
                                Err(e) => {
                                    app.ptr_status = format!("Pointer scan failed: {}", e);
                                }
                            }
                        }

                    ui.separator();
                    ui.label("Rescan Filter Address:");
                    ui.add(egui::TextEdit::singleline(&mut app.ptr_rescan_addr_text).desired_width(120.0).font(egui::TextStyle::Monospace));

                    if ui.button("Rescan").clicked()
                        && let Some(proc) = &app.attached_proc {
                            let new_target = OnyxEngineApp::parse_hex_addr(&app.ptr_rescan_addr_text, 0);
                            let filtered = PointerScanner::rescan_paths(proc, &app.ptr_results, new_target);
                            app.ptr_status = format!("Rescan complete: {} of {} survived.", filtered.len(), app.ptr_results.len());
                            app.ptr_results = filtered;
                        }
                });

                ui.label(RichText::new(&app.ptr_status).color(Color32::from_rgb(200, 200, 100)));
                ui.separator();

                ui.label(RichText::new(format!("Pointer Results ({})", app.ptr_results.len())).strong());

                let mut add_ptr: Option<PointerPath> = None;

                egui::ScrollArea::vertical()
                    .id_salt("ptr_results_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        egui::Grid::new("ptr_results_grid")
                            .striped(true)
                            .min_col_width(90.0)
                            .spacing(Vec2::new(10.0, 4.0))
                            .show(ui, |ui| {
                                ui.label(RichText::new("Base Module + Offset").strong().color(Color32::LIGHT_GRAY));
                                ui.label(RichText::new("Offset Chain").strong().color(Color32::LIGHT_GRAY));
                                ui.label(RichText::new("Points To").strong().color(Color32::LIGHT_GRAY));
                                ui.label(RichText::new("Live Value").strong().color(Color32::LIGHT_GRAY));
                                ui.label(RichText::new("Action").strong().color(Color32::LIGHT_GRAY));
                                ui.end_row();

                                for path in &app.ptr_results {
                                    let base_text = format!("\"{}\"+0x{:X}", path.module_name, path.base_offset);
                                    ui.label(RichText::new(base_text).monospace().color(Color32::from_rgb(120, 180, 255)));

                                    let off_chain = path.offsets.iter().map(|o| format!("+{:X}", o)).collect::<Vec<_>>().join(" -> ");
                                    ui.label(RichText::new(off_chain).monospace());

                                    let live_val_str = if let Some(proc) = &app.attached_proc {
                                        if let Ok(resolved) = PointerScanner::evaluate_path(proc, path) {
                                            ui.label(RichText::new(format!("0x{:08X}", resolved)).monospace().color(Color32::GREEN));
                                            proc.read::<i32>(resolved).map(|v| v.to_string()).unwrap_or("???".to_string())
                                        } else {
                                            ui.label(RichText::new("Broken").color(Color32::RED));
                                            "???".to_string()
                                        }
                                    } else {
                                        ui.label(RichText::new(format!("0x{:08X}", path.final_address)).monospace());
                                        "???".to_string()
                                    };

                                    ui.label(RichText::new(live_val_str).monospace().strong());

                                    if ui.button(RichText::new("+ Add to Table").color(Color32::GREEN)).clicked() {
                                        add_ptr = Some(path.clone());
                                    }

                                    ui.end_row();
                                }
                            });
                    });

                if let Some(path) = add_ptr {
                    app.add_pointer_to_table(&path, ValType::I32);
                }
            });
        },
    );
}
