
use eframe::egui::{self, Color32, RichText, Rounding, Stroke, Vec2};
use onyx_core::process::ProcessAccessMode;
use crate::app::OnyxEngineApp;

pub fn render(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    if !app.show_settings_modal {
        return;
    }

    let mut close_modal = false;

    ctx.show_viewport_immediate(
        egui::ViewportId::from_hash_of("ce_settings_viewport"),
        egui::ViewportBuilder::default()
            .with_title("Cheat Engine settings")
            .with_inner_size([780.0, 540.0])
            .with_min_inner_size([600.0, 400.0])
            .with_resizable(true),
        |ctx, _class| {
            if ctx.input(|i| i.viewport().close_requested() || i.key_pressed(egui::Key::Escape)) {
                close_modal = true;
            }

            egui::CentralPanel::default()
                .frame(egui::Frame::none().fill(Color32::from_rgb(26, 29, 36)).inner_margin(egui::Margin::same(8.0)))
                .show(ctx, |ui| {

            let total_h = ui.available_height() - 36.0;

            ui.horizontal_top(|ui| {

                let sidebar_w = 170.0;
                ui.vertical(|ui| {
                    ui.set_width(sidebar_w);
                    egui::Frame::none()
                        .fill(Color32::from_rgb(24, 26, 32))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(48, 54, 66)))
                        .rounding(Rounding::same(2.0))
                        .inner_margin(egui::Margin::symmetric(4.0, 4.0))
                        .show(ui, |ui| {
                            ui.set_height(total_h);
                            let categories = [
                                "General Settings",
                                "Scan Settings",
                                "Debugger Options",
                                "Kernel & DBK",
                                "Hotkeys",
                                "Plugins",
                                "Lua Engine",
                                "Extra",
                            ];

                            for (idx, name) in categories.iter().enumerate() {
                                let is_sel = app.settings_tab == idx;
                                let bg = if is_sel {
                                    Color32::from_rgb(38, 70, 120)
                                } else {
                                    Color32::TRANSPARENT
                                };
                                let text_col = if is_sel { Color32::WHITE } else { Color32::from_rgb(210, 215, 225) };

                                let btn = egui::Button::new(RichText::new(*name).size(12.0).color(text_col))
                                    .fill(bg)
                                    .stroke(Stroke::NONE)
                                    .min_size(Vec2::new(sidebar_w - 12.0, 22.0))
                                    .rounding(Rounding::same(2.0));

                                if ui.add(btn).clicked() {
                                    app.settings_tab = idx;
                                }
                            }
                        });
                });

                ui.add_space(6.0);

                let content_w = ui.available_width() - 4.0;
                ui.vertical(|ui| {
                    ui.set_width(content_w);
                    egui::Frame::none()
                        .fill(Color32::from_rgb(28, 31, 38))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(48, 54, 66)))
                        .rounding(Rounding::same(2.0))
                        .inner_margin(egui::Margin::same(10.0))
                        .show(ui, |ui| {
                            ui.set_height(total_h);
                            egui::ScrollArea::vertical()
                                .id_salt("ce_settings_scroll")
                                .max_height(total_h - 16.0)
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    match app.settings_tab {
                                        0 => render_general_settings(app, ui),
                                        1 => render_scan_settings(app, ui),
                                        2 => render_debugger_options(app, ui),
                                        3 => render_kernel_dbk_tab(app, ui),
                                        4 => render_hotkeys_tab(app, ui),
                                        5 => render_plugins_tab(app, ui),
                                        6 => render_lua_tab(app, ui),
                                        _ => render_extra_tab(app, ui),
                                    }
                                });
                        });
                });
            });

            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(
                        egui::Button::new(RichText::new("Cancel").size(12.0))
                            .min_size(Vec2::new(75.0, 24.0))
                            .rounding(Rounding::same(2.0)),
                    ).clicked() {
                        close_modal = true;
                    }

                    if ui.add(
                        egui::Button::new(RichText::new("OK").size(12.0).strong())
                            .fill(Color32::from_rgb(35, 75, 125))
                            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(60, 110, 180)))
                            .min_size(Vec2::new(75.0, 24.0))
                            .rounding(Rounding::same(2.0)),
                    ).clicked() || ctx.input(|i| i.key_pressed(egui::Key::Enter)) {
                        close_modal = true;
                    }
                });
            });
        });
    },
);

    if close_modal {
        app.show_settings_modal = false;
    }
}

fn render_group_box(ui: &mut egui::Ui, title: &str, content: impl FnOnce(&mut egui::Ui)) {
    ui.add_space(4.0);
    ui.label(RichText::new(title).size(11.5).strong().color(Color32::from_rgb(140, 180, 240)));
    egui::Frame::none()
        .fill(Color32::from_rgb(22, 24, 30))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(46, 52, 64)))
        .rounding(Rounding::same(2.0))
        .inner_margin(egui::Margin::same(8.0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            content(ui);
        });
    ui.add_space(4.0);
}

fn render_general_settings(app: &mut OnyxEngineApp, ui: &mut egui::Ui) {
    render_group_box(ui, "Update and Freeze Intervals", |ui| {
        ui.horizontal(|ui| {
            ui.label("Update interval:");
            ui.label(RichText::new("150").monospace());
            ui.label("ms");
        });
        ui.horizontal(|ui| {
            ui.label("Freeze interval:");
            if ui.add(egui::Slider::new(&mut app.freeze_interval_ms, 10..=500).text("ms")).changed() {
                if let Some(ref proc) = app.attached_proc {
                    app.freezer.stop();
                    app.freezer.start(proc, app.freeze_interval_ms);
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("Found address list update interval:");
            ui.label(RichText::new("250").monospace());
            ui.label("ms");
        });
    });

    render_group_box(ui, "Process List and Display", |ui| {
        let mut show_proc_list_on_start = true;
        let mut center_popups = true;
        let mut show_undo = true;
        ui.checkbox(&mut show_proc_list_on_start, "Show process list on start");
        ui.checkbox(&mut center_popups, "Center popup windows on Cheat Engine");
        ui.checkbox(&mut show_undo, "Show undo button");
        ui.horizontal(|ui| {
            ui.label("Address list max string length:");
            ui.label(RichText::new("1000 chars (CE 7.7 standard)").color(Color32::from_rgb(100, 220, 140)));
        });
    });

    render_group_box(ui, "Cheat Table File Association", |ui| {
        ui.label("Cheat Tables are saved and loaded in standard Cheat Engine XML (.CT) format.");
        ui.label(RichText::new("Compatible with Cheat Engine 7.0 - 7.7 tables.").color(Color32::GRAY));
    });
}

fn render_scan_settings(app: &mut OnyxEngineApp, ui: &mut egui::Ui) {
    render_group_box(ui, "Fast Scan & Alignment", |ui| {
        ui.checkbox(&mut app.fast_scan, "Fast Scan enabled by default");
        ui.horizontal(|ui| {
            ui.label("Default alignment:");
            ui.radio_value(&mut app.alignment_idx, 0, "4 Bytes");
            ui.radio_value(&mut app.alignment_idx, 1, "1 Byte");
            ui.radio_value(&mut app.alignment_idx, 2, "2 Bytes");
            ui.radio_value(&mut app.alignment_idx, 3, "8 Bytes");
        });
    });

    render_group_box(ui, "Memory Scanner Options", |ui| {
        ui.checkbox(&mut app.writable_only, "Scan writable memory only");
        ui.checkbox(&mut app.executable, "Scan executable memory");
        ui.checkbox(&mut app.copy_on_write, "Scan copy-on-write memory");
    });

    render_group_box(ui, "Cheat Engine 7.7 Enhancements", |ui| {
        let mut no_globalalloc_save = true;
        let mut low_mem_leak_fix = true;
        let mut binary_aob_notation = true;
        ui.checkbox(&mut no_globalalloc_save, "globalalloc symbols do not save in tables (CE 7.7)");
        ui.checkbox(&mut low_mem_leak_fix, "Memory scanner leak fix on repeated scans (CE 7.7)");
        ui.checkbox(&mut binary_aob_notation, "Bit-level binary notation in AOB scans (|010**010|)");
    });
}

fn render_debugger_options(app: &mut OnyxEngineApp, ui: &mut egui::Ui) {
    render_group_box(ui, "Debugger Interface", |ui| {
        ui.radio_value(&mut app.access_mode, ProcessAccessMode::NtApi, "Use VEH Debugger (Vectored Exception Handling)");
        ui.radio_value(&mut app.access_mode, ProcessAccessMode::KernelDbk, "Use DBVM / Kernel-mode Debugger (DBK64)");
        ui.radio_value(&mut app.access_mode, ProcessAccessMode::Win32, "Use Windows Debugger API");
    });

    render_group_box(ui, "Exceptions & Breakpoints (CE 7.7)", |ui| {
        let mut break_unexpected = true;
        let mut avx_state = true;
        let mut trace_exit = true;
        ui.checkbox(&mut break_unexpected, "Fix break on unexpected breakpoints");
        ui.checkbox(&mut avx_state, "AVX state save/restore fix (CE 7.7)");
        ui.checkbox(&mut trace_exit, "Break and trace: trace until initial function exit");
    });
}

fn render_kernel_dbk_tab(app: &mut OnyxEngineApp, ui: &mut egui::Ui) {
    render_group_box(ui, "Kernel Mode Driver (DBK64)", |ui| {
        let dbk_online = app.dbk_driver.is_some();
        let (status_text, status_col) = if dbk_online {
            ("DBK64 Driver: ONLINE (Connected)", Color32::from_rgb(100, 240, 140))
        } else {
            ("DBK64 Driver: OFFLINE (Driver not loaded or access denied)", Color32::from_rgb(240, 100, 100))
        };
        ui.label(RichText::new(status_text).strong().color(status_col));

        ui.add_space(4.0);
        if ui.button("Connect to DBK Driver (\\.\\DBK64 / \\.\\CEDRIVER77)").clicked() {
            app.try_connect_dbk();
        }
    });

    render_group_box(ui, "Memory Access Method", |ui| {
        if ui.radio(app.access_mode == ProcessAccessMode::NtApi, "[NT API] Native NT System Calls (NtReadVirtualMemory / NtWriteVirtualMemory)").clicked() {
            app.set_access_mode(ProcessAccessMode::NtApi);
        }
        if ui.radio(app.access_mode == ProcessAccessMode::KernelDbk, "[DBK64] Kernel Mode Driver (IOCTL_CE_READMEMORY / CR3 Physical)").clicked() {
            app.set_access_mode(ProcessAccessMode::KernelDbk);
        }
        if ui.radio(app.access_mode == ProcessAccessMode::Win32, "[WIN32] Standard Win32 (ReadProcessMemory / WriteProcessMemory)").clicked() {
            app.set_access_mode(ProcessAccessMode::Win32);
        }
    });
}

fn render_hotkeys_tab(app: &mut OnyxEngineApp, ui: &mut egui::Ui) {
    render_group_box(ui, "Global Shortcuts", |ui| {
        ui.label("Ctrl+O: Open Process List");
        ui.label("Ctrl+M: Memory Browser (Disassembler & Hex View)");
        ui.label("Ctrl+P: Pointer Scanner");
        ui.label("Ctrl+A: Auto Assembler");
        ui.label("Ctrl+L: Lua Engine Console");
        ui.label("Ctrl+,: Cheat Engine Settings");
    });

    render_group_box(ui, "Ghost Mode (CE 7.7)", |ui| {
        let mut ghost = app.ghost_mode;
        if ui.checkbox(&mut ghost, "Enable Ghost Mode (Click-Through Overlay)").changed() {
            app.ghost_mode = ghost;
        }
        ui.label(RichText::new("Hotkey: F10 or Ctrl+Shift+G").color(Color32::GRAY));
    });

    render_group_box(ui, "Speedhack", |ui| {
        ui.label(RichText::new("Hotkey: F11 (Toggle Speedhack)").color(Color32::WHITE));
        ui.horizontal(|ui| {
            ui.label("Speed multiplier:");
            ui.add(egui::Slider::new(&mut app.speedhack_val, 0.1..=50.0).text("x"));
        });
    });
}

fn render_plugins_tab(app: &mut OnyxEngineApp, ui: &mut egui::Ui) {
    render_group_box(ui, "Installed Plugins & DLLs", |ui| {
        ui.label("allochook_dll.dll - Hook preferred allocation engine (CE 7.7)");
        ui.label("vehdebug_dll.dll - 32-bit & 64-bit VEH debugger engine");
        ui.label("speedhack_dll.dll - Kernel & QueryPerformanceCounter speed modifier");
        ui.label("d3dhook_dll.dll - Direct3D 9/11/12 overlay engine");
        ui.label("luaclient_dll.dll - Lua pipe bridge");
    });
}

fn render_lua_tab(app: &mut OnyxEngineApp, ui: &mut egui::Ui) {
    render_group_box(ui, "Lua Engine 5.3 (CE 7.7)", |ui| {
        ui.label("CE 7.7 Lua Improvements:");
        ui.label("- Results property for direct memscan results without foundlist helper");
        ui.label("- stacktrace command");
        ui.label("- OrderedList methods for History object");
        ui.label("- LuaEngine dialogs own independent lua_State");
        ui.label("- json lua library integrated");
    });
}

fn render_extra_tab(app: &mut OnyxEngineApp, ui: &mut egui::Ui) {
    render_group_box(ui, "Extra Options", |ui| {
        ui.label("CE 7.7 Custom Types: 64-bit integer variant & internalOnly property");
        ui.label("ARM64 memory access support");
        ui.label("Mono / IL2CPP generic method and parameter lookup");
    });
}

