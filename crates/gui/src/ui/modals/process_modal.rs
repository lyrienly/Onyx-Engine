// Process Selection Modal for Cheat Engine 7.7
// Authentic 3-tab layout: Applications, Processes, Windows, with native 16x16 icons

use eframe::egui::{self, Color32, RichText, Rounding, Stroke, Vec2};
use crate::app::OnyxEngineApp;

pub fn render(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    if !app.show_proc_modal {
        return;
    }

    let mut attach_target: Option<(u32, String)> = None;
    let mut close_modal = false;

    ctx.show_viewport_immediate(
        egui::ViewportId::from_hash_of("ce_process_list_viewport"),
        egui::ViewportBuilder::default()
            .with_title("Process List")
            .with_inner_size([580.0, 580.0])
            .with_min_inner_size([420.0, 380.0])
            .with_resizable(true),
        |ctx, _class| {
            if ctx.input(|i| i.viewport().close_requested() || i.key_pressed(egui::Key::Escape)) {
                close_modal = true;
            }

            egui::CentralPanel::default()
                .frame(egui::Frame::none().fill(Color32::from_rgb(26, 29, 36)).inner_margin(egui::Margin::same(8.0)))
                .show(ctx, |ui| {

            // 1. Cheat Engine 3-Tab Header
            ui.horizontal(|ui| {
                let tab_btn = |ui: &mut egui::Ui, title: &str, idx: usize, current: usize| -> bool {
                    let is_active = idx == current;
                    let (bg, border, text_color) = if is_active {
                        (Color32::from_rgb(38, 52, 75), Color32::from_rgb(70, 115, 180), Color32::WHITE)
                    } else {
                        (Color32::from_rgb(26, 28, 35), Color32::from_rgb(46, 52, 65), Color32::from_rgb(180, 185, 195))
                    };

                    let btn = egui::Button::new(RichText::new(title).size(12.0).color(text_color).strong())
                        .fill(bg)
                        .stroke(Stroke::new(1.0_f32, border))
                        .min_size(Vec2::new(100.0, 26.0))
                        .rounding(Rounding::same(3.0));

                    ui.add(btn).clicked()
                };

                if tab_btn(ui, "Applications", 0, app.proc_modal_tab) {
                    app.proc_modal_tab = 0;
                }
                if tab_btn(ui, "Processes", 1, app.proc_modal_tab) {
                    app.proc_modal_tab = 1;
                }
                if tab_btn(ui, "Windows", 2, app.proc_modal_tab) {
                    app.proc_modal_tab = 2;
                }
            });

            ui.add_space(4.0);

            // 2. Search Filter & Refresh
            ui.horizontal(|ui| {
                ui.label(RichText::new("Filter:").size(12.0).color(Color32::from_rgb(200, 205, 215)).strong());
                let filter_w = (ui.available_width() - 85.0).max(120.0);
                ui.add(egui::TextEdit::singleline(&mut app.proc_filter).desired_width(filter_w));
                if ui.button("[Refresh]").clicked() {
                    app.refresh_proc_list();
                }
            });

            ui.separator();

            let filter_lower = app.proc_filter.to_lowercase();

            // Filter entries according to active tab
            let filtered: Vec<(u32, String)> = app.proc_list
                .iter()
                .filter(|p| {
                    if !filter_lower.is_empty() && !p.name.to_lowercase().contains(&filter_lower) {
                        return false;
                    }
                    match app.proc_modal_tab {
                        // Applications tab: prioritize non-svchost user binaries
                        0 => {
                            let n = p.name.to_lowercase();
                            !n.starts_with("svchost")
                                && !n.starts_with("conhost")
                                && !n.starts_with("system")
                                && !n.starts_with("smss")
                                && !n.starts_with("csrss")
                                && !n.starts_with("wininit")
                                && !n.starts_with("services")
                                && !n.starts_with("lsass")
                                && !n.starts_with("fontdrvhost")
                        }
                        // Processes tab: all processes
                        _ => true,
                    }
                })
                .map(|p| (p.pid, p.name.clone()))
                .collect();

            // Preload icons for visible items
            for (pid, name) in &filtered {
                app.ensure_proc_icon(ctx, *pid, name);
            }

            // 3. Process Table (Address List Style)
            let scroll_h = (ui.available_height() - 50.0).max(200.0);
            egui::ScrollArea::vertical()
                .id_salt("ce_proc_list_scroll")
                .max_height(scroll_h)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    egui::Grid::new("ce_proc_list_grid")
                        .striped(true)
                        .min_col_width(24.0)
                        .spacing(Vec2::new(8.0, 4.0))
                        .show(ui, |ui| {
                            // Column Headers
                            ui.label(RichText::new("PID").monospace().color(Color32::from_rgb(140, 160, 185)).strong());
                            ui.label(RichText::new("").monospace());
                            ui.label(RichText::new("Process Name").color(Color32::from_rgb(140, 160, 185)).strong());
                            ui.end_row();

                            for (pid, name) in &filtered {
                                let pid_text = format!("{:08X}", pid);
                                let is_selected = app.selected_proc_item.as_ref().map(|(p, _)| *p == *pid).unwrap_or(false);

                                let row_bg = if is_selected {
                                    Color32::from_rgb(35, 65, 110)
                                } else {
                                    Color32::TRANSPARENT
                                };

                                // PID button
                                let pid_btn = ui.add(
                                    egui::Button::new(RichText::new(&pid_text).monospace().color(Color32::from_rgb(120, 205, 255)))
                                        .fill(row_bg)
                                        .stroke(Stroke::NONE)
                                        .rounding(Rounding::same(2.0)),
                                );

                                // Native 16x16 Executable Icon
                                let icon_resp = if let Some(texture) = app.get_icon(name) {
                                    ui.add(egui::Image::new(texture).fit_to_exact_size(Vec2::splat(16.0)))
                                } else {
                                    ui.allocate_response(Vec2::splat(16.0), egui::Sense::click())
                                };

                                // Process Name Label
                                let name_lbl = ui.add(
                                    egui::SelectableLabel::new(
                                        is_selected,
                                        RichText::new(name).color(if is_selected { Color32::WHITE } else { Color32::from_rgb(220, 225, 235) }).strong(),
                                    ),
                                );
                                ui.end_row();

                                // Selection & Double-click Handling
                                if pid_btn.clicked() || icon_resp.clicked() || name_lbl.clicked() {
                                    app.selected_proc_item = Some((*pid, name.clone()));
                                }
                                if pid_btn.double_clicked() || icon_resp.double_clicked() || name_lbl.double_clicked() {
                                    attach_target = Some((*pid, name.clone()));
                                }
                            }
                        });
                });

            ui.separator();

            // 4. Bottom Action Bar: Open, Cancel, Attach debugger
            ui.horizontal(|ui| {
                let can_open = app.selected_proc_item.is_some() || !filtered.is_empty();

                let open_btn = egui::Button::new(RichText::new("Open").size(12.5).color(Color32::WHITE).strong())
                    .fill(if can_open { Color32::from_rgb(32, 110, 55) } else { Color32::from_rgb(40, 45, 55) })
                    .stroke(Stroke::new(1.0_f32, if can_open { Color32::from_rgb(50, 160, 80) } else { Color32::from_rgb(55, 60, 72) }))
                    .min_size(Vec2::new(90.0, 28.0))
                    .rounding(Rounding::same(3.0));

                if ui.add_enabled(can_open, open_btn).clicked() || ctx.input(|i| i.key_pressed(egui::Key::Enter)) {
                    if let Some(ref target) = app.selected_proc_item {
                        attach_target = Some(target.clone());
                    } else if let Some(first) = filtered.first() {
                        attach_target = Some(first.clone());
                    }
                }

                if ui.button("Cancel").clicked() {
                    close_modal = true;
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(format!("{} items", filtered.len())).color(Color32::GRAY).small());
                });
            });

                if let Some((pid, name)) = attach_target.take() {
                    app.attach_to_proc(pid, name);
                    close_modal = true;
                }
            });
        },
    );

    if close_modal {
        app.show_proc_modal = false;
    }
}
