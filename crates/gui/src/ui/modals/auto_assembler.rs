// Auto Assembler Modal for OnyxEngine
// Code cave allocation, AOB patching, label resolution, hook generation

use eframe::egui::{self, Color32, RichText, Vec2};
use onyx_core::autoassembler::AutoAssembler;
use crate::app::OnyxEngineApp;

pub fn render(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    if !app.show_aa_modal {
        return;
    }

    egui::Window::new("Auto Assembler")
        .collapsible(true)
        .resizable(true)
        .movable(true)
        .constrain(false)
        .default_size(Vec2::new(600.0, 500.0))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Script Editor ([ENABLE] / [DISABLE]):").strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Template: Code Cave").clicked() {
                        app.aa_script = r#"[ENABLE]
alloc(newmem, 2048)
label(returnhere)
label(originalcode)

newmem:
// Custom code here
nop

originalcode:
// Restored instructions
ret

[DISABLE]
dealloc(newmem)
"#.to_string();
                    }
                });
            });

            ui.add(egui::TextEdit::multiline(&mut app.aa_script).code_editor().desired_rows(16).desired_width(f32::INFINITY));

            ui.horizontal(|ui| {
                if ui.button(RichText::new("[Execute Script]").strong().color(Color32::GREEN)).clicked() {
                    if let Some(proc) = &app.attached_proc {
                        let mut aa = AutoAssembler::new();
                        match aa.execute(proc, &app.aa_script, true) {
                            Ok(_) => app.aa_status = "[+] Auto Assembler script executed successfully!".to_string(),
                            Err(e) => app.aa_status = format!("[-] Script error: {}", e),
                        }
                    } else {
                        app.aa_status = "No process attached.".to_string();
                    }
                }
                if ui.button("Close").clicked() {
                    app.show_aa_modal = false;
                }
            });

            if !app.aa_status.is_empty() {
                ui.label(RichText::new(&app.aa_status).color(Color32::YELLOW));
            }
        });
}
