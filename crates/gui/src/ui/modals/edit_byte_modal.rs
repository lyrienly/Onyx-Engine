// In-Place Hex Byte Editor Modal for OnyxEngine

use eframe::egui::{self, Color32, RichText};
use crate::app::OnyxEngineApp;

pub fn render(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    if !app.show_edit_byte_modal {
        return;
    }

    let mut close_modal = false;
    let title = format!("Edit Byte at 0x{:08X}", app.edit_byte_addr);

    ctx.show_viewport_immediate(
        egui::ViewportId::from_hash_of("ce_edit_byte_viewport"),
        egui::ViewportBuilder::default()
            .with_title(title)
            .with_inner_size([300.0, 140.0])
            .with_min_inner_size([240.0, 120.0])
            .with_resizable(false),
        |ctx, _class| {
            if ctx.input(|i| i.viewport().close_requested() || i.key_pressed(egui::Key::Escape)) {
                close_modal = true;
            }

            egui::CentralPanel::default()
                .frame(egui::Frame::none().fill(Color32::from_rgb(26, 29, 36)).inner_margin(egui::Margin::same(8.0)))
                .show(ctx, |ui| {
                    ui.label("Hex Value (00 - FF):");
                    let te = ui.add(egui::TextEdit::singleline(&mut app.edit_byte_val_text).desired_width(80.0).font(egui::TextStyle::Monospace));

                    let mut submit = te.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("Write").strong().color(Color32::GREEN)).clicked() {
                            submit = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_modal = true;
                        }
                    });

                    if submit {
                        if let Ok(b) = u8::from_str_radix(app.edit_byte_val_text.trim(), 16) {
                            if let Some(proc) = &app.attached_proc {
                                let _ = proc.protect(app.edit_byte_addr, 1, 0x40); // PAGE_EXECUTE_READWRITE
                                let _ = proc.write_raw(app.edit_byte_addr, &[b]);
                                app.update_memory_view();
                            }
                        }
                        close_modal = true;
                    }
                });
        },
    );

    if close_modal {
        app.show_edit_byte_modal = false;
    }
}
