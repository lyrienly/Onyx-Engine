// In-Place Hex Byte Editor Modal for OnyxEngine

use eframe::egui::{self, Color32, RichText, Vec2};
use crate::app::OnyxEngineApp;

pub fn render(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    if !app.show_edit_byte_modal {
        return;
    }

    let mut close_modal = false;
    egui::Window::new(format!("Edit Byte at 0x{:08X}", app.edit_byte_addr))
        .collapsible(false)
        .resizable(false)
        .movable(true)
        .constrain(false)
        .default_size(Vec2::new(240.0, 110.0))
        .show(ctx, |ui| {
            ui.label("Hex Value (00 - FF):");
            ui.add(egui::TextEdit::singleline(&mut app.edit_byte_val_text).desired_width(80.0).font(egui::TextStyle::Monospace));

            ui.horizontal(|ui| {
                if ui.button(RichText::new("Write").strong().color(Color32::GREEN)).clicked() {
                    if let Ok(b) = u8::from_str_radix(app.edit_byte_val_text.trim(), 16) {
                        if let Some(proc) = &app.attached_proc {
                            let _ = proc.protect(app.edit_byte_addr, 1, 0x40); // PAGE_EXECUTE_READWRITE
                            let _ = proc.write_raw(app.edit_byte_addr, &[b]);
                            app.update_memory_view();
                        }
                    }
                    close_modal = true;
                }
                if ui.button("Cancel").clicked() {
                    close_modal = true;
                }
            });
        });

    if close_modal {
        app.show_edit_byte_modal = false;
    }
}
