// Process Selection Modal for OnyxEngine
// Lists all running processes with PID, icon/name, and search filter

use eframe::egui::{self, Color32, RichText, Vec2};
use crate::app::OnyxEngineApp;

pub fn render(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    if !app.show_proc_modal {
        return;
    }

    egui::Window::new("Select Target Process")
        .collapsible(true)
        .resizable(true)
        .movable(true)
        .constrain(false)
        .default_size(Vec2::new(480.0, 520.0))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.add(egui::TextEdit::singleline(&mut app.proc_filter).desired_width(260.0));
                if ui.button("[Refresh]").clicked() {
                    app.refresh_proc_list();
                }
            });

            ui.separator();

            let filter_lower = app.proc_filter.to_lowercase();
            let mut selected_pid: Option<(u32, String)> = None;

            egui::ScrollArea::vertical().max_height(380.0).show(ui, |ui| {
                egui::Grid::new("proc_list_grid").striped(true).min_col_width(80.0).show(ui, |ui| {
                    for p in &app.proc_list {
                        if filter_lower.is_empty() || p.name.to_lowercase().contains(&filter_lower) {
                            let pid_text = format!("{:08X}", p.pid);
                            let btn = ui.button(RichText::new(&pid_text).monospace().color(Color32::from_rgb(120, 200, 255)));
                            ui.label(RichText::new(&p.name).strong());
                            ui.end_row();

                            if btn.clicked() {
                                selected_pid = Some((p.pid, p.name.clone()));
                            }
                        }
                    }
                });
            });

            ui.separator();
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    app.show_proc_modal = false;
                }
            });

            if let Some((pid, name)) = selected_pid {
                app.attach_to_proc(pid, name);
            }
        });
}
