// Auto Assembler Modal for OnyxEngine
// Code cave allocation, AOB patching, label resolution, hook generation

use eframe::egui::{self, Color32, RichText, Vec2};
use onyx_core::autoassembler::AutoAssembler;
use crate::app::OnyxEngineApp;

pub fn render(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    if !app.show_aa_modal {
        return;
    }

    let mut close_modal = false;

    ctx.show_viewport_immediate(
        egui::ViewportId::from_hash_of("ce_auto_assembler_viewport"),
        egui::ViewportBuilder::default()
            .with_title("Auto Assembler")
            .with_inner_size([720.0, 540.0])
            .with_min_inner_size([480.0, 360.0])
            .with_resizable(true),
        |ctx, _class| {
            if ctx.input(|i| i.viewport().close_requested() || i.key_pressed(egui::Key::Escape)) {
                close_modal = true;
            }

            egui::CentralPanel::default()
                .frame(egui::Frame::none().fill(Color32::from_rgb(26, 29, 36)).inner_margin(egui::Margin::same(8.0)))
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

                    let editor_h = (ui.available_height() - 70.0).max(180.0);
                    ui.add_sized(
                        Vec2::new(ui.available_width(), editor_h),
                        egui::TextEdit::multiline(&mut app.aa_script).code_editor().desired_width(f32::INFINITY)
                    );

                    ui.add_space(4.0);
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
                            close_modal = true;
                        }
                    });

                    if !app.aa_status.is_empty() {
                        ui.label(RichText::new(&app.aa_status).color(Color32::YELLOW));
                    }
                });
        },
    );

    if close_modal {
        app.show_aa_modal = false;
    }
}
