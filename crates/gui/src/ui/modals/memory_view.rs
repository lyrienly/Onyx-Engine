// Memory Viewer Native Window for OnyxEngine
// Faithful recreation of Cheat Engine 7.5 Memory Viewer (Disassembler & Hex Dump)

use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use onyx_core::disasm::format_symbol;
use crate::app::OnyxEngineApp;

fn get_mnemonic_description(mnemonic: &str) -> &'static str {
    match mnemonic.to_lowercase().as_str() {
        "sub" => "subtract",
        "add" => "add",
        "call" => "call procedure",
        "jmp" => "jump",
        "ret" => "return from procedure",
        "mov" => "move",
        "cmp" => "compare two operands",
        "test" => "logical compare",
        "lea" => "load effective address",
        "xor" => "logical exclusive OR",
        "and" => "logical AND",
        "or" => "logical inclusive OR",
        "push" => "push value onto stack",
        "pop" => "pop value from stack",
        "nop" => "no operation",
        "inc" => "increment by 1",
        "dec" => "decrement by 1",
        "je" | "jz" => "jump if equal / zero",
        "jne" | "jnz" => "jump if not equal / not zero",
        "ja" | "jnbe" => "jump if above (unsigned)",
        "jae" | "jnb" => "jump if above or equal",
        "jb" | "jnae" => "jump if below",
        "jbe" | "jna" => "jump if below or equal",
        "jg" | "jnle" => "jump if greater (signed)",
        "jge" | "jnl" => "jump if greater or equal",
        "jl" | "jnge" => "jump if less",
        "jle" | "jng" => "jump if less or equal",
        "int 3" | "int3" => "breakpoint interrupt",
        _ => "execute instruction",
    }
}

pub fn render(app: &mut OnyxEngineApp, ctx: &egui::Context) {
    if !app.show_memory_view {
        return;
    }

    ctx.show_viewport_immediate(
        egui::ViewportId::from_hash_of("onyx_memory_viewer_viewport"),
        egui::ViewportBuilder::default()
            .with_title("Memory Viewer")
            .with_inner_size([1040.0, 720.0])
            .with_min_inner_size([720.0, 480.0])
            .with_resizable(true),
        |ctx, _class| {
            if ctx.input(|i| i.viewport().close_requested()) {
                app.show_memory_view = false;
            }

            // 1. Top Menu Bar (File, Search, View, Debug, Tools, Kernel tools)
            egui::TopBottomPanel::top("mem_view_menu")
                .frame(egui::Frame::none().fill(Color32::from_rgb(26, 26, 26)).inner_margin(egui::Margin::symmetric(8.0, 3.0)))
                .show(ctx, |ui| {
                    egui::menu::bar(ui, |ui| {
                        ui.menu_button("File", |ui| {
                            if ui.button("Save Memory to File").clicked() {
                                ui.close_menu();
                            }
                            if ui.button("Load Memory from File").clicked() {
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("Close Window").clicked() {
                                app.show_memory_view = false;
                            }
                        });

                        ui.menu_button("Search", |ui| {
                            if ui.button("Find Memory...").clicked() {
                                ui.close_menu();
                            }
                            if ui.button("Find Assembly Code...").clicked() {
                                ui.close_menu();
                            }
                        });

                        ui.menu_button("View", |ui| {
                            if ui.button("Goto Address...").clicked() {
                                ui.close_menu();
                            }
                            if ui.button("Data / Value Inspector").clicked() {
                                app.show_data_inspector = !app.show_data_inspector;
                                ui.close_menu();
                            }
                        });

                        ui.menu_button("Debug", |ui| {
                            if ui.button("Break").clicked() {
                                ui.close_menu();
                            }
                            if ui.button("Step Into (F7)").clicked() {
                                ui.close_menu();
                            }
                            if ui.button("Step Over (F8)").clicked() {
                                ui.close_menu();
                            }
                        });

                        ui.menu_button("Tools", |ui| {
                            if ui.button("Auto Assembler (Ctrl+A)").clicked() {
                                app.show_aa_modal = true;
                                ui.close_menu();
                            }
                            if ui.button("Dissect Code").clicked() {
                                app.show_mono_modal = true;
                                ui.close_menu();
                            }
                        });

                        ui.menu_button("Kernel tools", |ui| {
                            ui.label("Kernel Mode DBK Driver required");
                        });
                    });
                });

            // 2. Subheader Bar (Centered Current Address / Symbol)
            egui::TopBottomPanel::top("mem_view_sub_header")
                .frame(egui::Frame::none().fill(Color32::from_rgb(32, 32, 32)).inner_margin(egui::Margin::symmetric(10.0, 4.0)))
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        let header_text = if let Some(proc) = &app.attached_proc {
                            let cur_addr = OnyxEngineApp::parse_hex_addr(&app.mem_addr_text, 0);
                            let modules = proc.modules().unwrap_or_default();
                            format_symbol(cur_addr, &modules)
                        } else {
                            "Please open a process first".to_string()
                        };
                        ui.label(RichText::new(header_text).size(13.0).color(Color32::WHITE).strong());
                    });
                });

            // 3. Bottom Status Bar (Advanced Options / Table Extras)
            egui::TopBottomPanel::bottom("mem_view_status_bar")
                .frame(egui::Frame::none().fill(Color32::from_rgb(26, 26, 26)).inner_margin(egui::Margin::symmetric(10.0, 4.0)))
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Advanced Options").size(11.0).color(Color32::LIGHT_GRAY));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(RichText::new("Table Extras").size(11.0).color(Color32::LIGHT_GRAY));
                        });
                    });
                });

            // 4. Central Split Workspace: Top = Disassembler, Bottom = Hex Dump
            egui::CentralPanel::default()
                .frame(egui::Frame::none().fill(Color32::from_rgb(20, 20, 20)))
                .show(ctx, |ui| {
                    let total_h = ui.available_height();
                    let disasm_h = (total_h * 0.48).max(160.0);
                    let hex_h = total_h - disasm_h - 28.0;

                    let mut selected_op_desc = "instruction";

                    // === TOP PANE: Disassembler View ===
                    egui::Frame::none()
                        .fill(Color32::from_rgb(18, 18, 18))
                        .show(ui, |ui| {
                            ui.set_height(disasm_h);

                            // Disassembler Columns Header
                            ui.horizontal(|ui| {
                                ui.set_min_height(20.0);
                                ui.add_space(8.0);
                                ui.label(RichText::new("Address").size(11.5).strong().color(Color32::from_rgb(160, 160, 160)));
                                ui.add_space(110.0);
                                ui.label(RichText::new("Bytes").size(11.5).strong().color(Color32::from_rgb(160, 160, 160)));
                                ui.add_space(80.0);
                                ui.label(RichText::new("Opcode").size(11.5).strong().color(Color32::from_rgb(160, 160, 160)));
                                ui.add_space(160.0);
                                ui.label(RichText::new("Comment").size(11.5).strong().color(Color32::from_rgb(160, 160, 160)));
                            });

                            ui.separator();

                            let mut sel_addr_click: Option<usize> = None;
                            let mut nop_click: Option<(usize, usize)> = None;
                            let mut hex_click: Option<usize> = None;
                            let mut copy_click: Option<usize> = None;

                            let modules = app.attached_proc.as_ref().and_then(|p| p.modules().ok()).unwrap_or_default();

                            egui::ScrollArea::vertical()
                                .id_salt("ce_disasm_scroll")
                                .max_height(disasm_h - 26.0)
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    if app.disasm_instructions.is_empty() {
                                        ui.vertical_centered(|ui| {
                                            ui.add_space(40.0);
                                            ui.label(RichText::new("No assembly instructions loaded. Open a process or navigate to an address.").color(Color32::GRAY));
                                        });
                                    } else {
                                        for insn in &app.disasm_instructions {
                                            let is_sel = app.selected_disasm_addr == Some(insn.address);
                                            if is_sel {
                                                selected_op_desc = get_mnemonic_description(&insn.mnemonic);
                                            }

                                            let row_bg = if is_sel {
                                                Color32::from_rgb(0, 120, 215) // Cheat Engine solid blue selection
                                            } else {
                                                Color32::TRANSPARENT
                                            };

                                            let text_color = if is_sel { Color32::WHITE } else { Color32::from_rgb(220, 220, 220) };

                                            let addr_str = format_symbol(insn.address, &modules);
                                            let bytes_str = insn.bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                                            let opcode_str = format!("{} {}", insn.mnemonic, insn.operands);

                                            let resp = ui.allocate_ui_with_layout(
                                                Vec2::new(ui.available_width(), 18.0),
                                                egui::Layout::left_to_right(egui::Align::Center),
                                                |ui| {
                                                    egui::Frame::none().fill(row_bg).show(ui, |ui| {
                                                        ui.add_space(8.0);
                                                        ui.add_sized([180.0, 18.0], egui::Label::new(RichText::new(&addr_str).monospace().size(12.0).color(if is_sel { Color32::WHITE } else { Color32::from_rgb(120, 190, 255) })));
                                                        ui.add_sized([140.0, 18.0], egui::Label::new(RichText::new(&bytes_str).monospace().size(12.0).color(text_color)));

                                                        // Syntax highlighted opcode
                                                        let op_color = if is_sel {
                                                            Color32::WHITE
                                                        } else if insn.mnemonic.starts_with('j') || insn.mnemonic == "call" {
                                                            Color32::from_rgb(60, 220, 120)
                                                        } else if insn.mnemonic == "ret" {
                                                            Color32::from_rgb(255, 120, 120)
                                                        } else {
                                                            Color32::from_rgb(100, 200, 255)
                                                        };

                                                        ui.add_sized([220.0, 18.0], egui::Label::new(RichText::new(&opcode_str).monospace().size(12.0).strong().color(op_color)));

                                                        let comment_str = if insn.operands.contains("rsp") || insn.operands.contains("rbp") {
                                                            "stack frame"
                                                        } else {
                                                            ""
                                                        };
                                                        ui.add_sized([120.0, 18.0], egui::Label::new(RichText::new(comment_str).size(11.0).color(Color32::GRAY)));
                                                    });
                                                },
                                            ).response;

                                            if resp.clicked() {
                                                sel_addr_click = Some(insn.address);
                                            }

                                            resp.context_menu(|ui| {
                                                if ui.button("NOP instruction").clicked() {
                                                    nop_click = Some((insn.address, insn.length));
                                                    ui.close_menu();
                                                }
                                                if ui.button("Follow in Hex View").clicked() {
                                                    hex_click = Some(insn.address);
                                                    ui.close_menu();
                                                }
                                                if ui.button("Copy Address").clicked() {
                                                    copy_click = Some(insn.address);
                                                    ui.close_menu();
                                                }
                                            });
                                        }
                                    }
                                });

                            if let Some(addr) = sel_addr_click {
                                app.selected_disasm_addr = Some(addr);
                            }
                            if let Some((addr, len)) = nop_click {
                                app.patch_instruction_nop(addr, len);
                            }
                            if let Some(addr) = hex_click {
                                app.navigate_hex(addr);
                            }
                            if let Some(addr) = copy_click {
                                ctx.copy_text(format!("0x{:016X}", addr));
                                app.status_msg = format!("Copied 0x{:X}", addr);
                            }
                        });

                    // === CENTER SPLITTER: Instruction Mnemonic Description ===
                    egui::Frame::none()
                        .fill(Color32::from_rgb(28, 28, 28))
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(45, 45, 45)))
                        .inner_margin(egui::Margin::symmetric(10.0, 4.0))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.vertical_centered(|ui| {
                                ui.label(RichText::new(selected_op_desc).size(12.0).color(Color32::WHITE).strong());
                            });
                        });

                    // === BOTTOM PANE: Hex Dump View with Authentic Cheat Engine Framing ===
                    egui::Frame::none()
                        .fill(Color32::from_rgb(18, 18, 18))
                        .show(ui, |ui| {
                            ui.set_height(hex_h);

                            // Region Info Bar (Protect, AllocationBase, Base, Size, Module)
                            let cur_hex = OnyxEngineApp::parse_hex_addr(&app.hex_addr_text, 0);
                            let region_info = if let Some(proc) = &app.attached_proc {
                                if let Ok(regs) = proc.regions(false) {
                                    if let Some(r) = regs.into_iter().find(|reg| cur_hex >= reg.base && cur_hex < reg.base + reg.size) {
                                        let prot_str = if r.is_writable() && r.is_executable() {
                                            "Execute/Read/Write"
                                        } else if r.is_writable() {
                                            "Read/Write"
                                        } else if r.is_executable() {
                                            "Execute/Read"
                                        } else {
                                            "ReadOnly"
                                        };
                                        let mod_name = proc.modules().ok()
                                            .and_then(|mods| mods.into_iter().find(|m| cur_hex >= m.base && cur_hex < m.base + m.size))
                                            .map(|m| m.name)
                                            .unwrap_or_else(|| "none".to_string());
                                        format!("Protect:{}   AllocationBase={:08X}   Base={:08X}   Size={:X}   Module={}", prot_str, r.base, r.base, r.size, mod_name)
                                    } else {
                                        format!("Protect:Unknown   Base={:016X}", cur_hex)
                                    }
                                } else {
                                    "Memory unavailable".to_string()
                                }
                            } else {
                                "Protect: None   AllocationBase=00000000   Base=00000000   Size=0".to_string()
                            };

                            ui.horizontal(|ui| {
                                ui.add_space(8.0);
                                ui.label(RichText::new(region_info).size(11.0).monospace().color(Color32::LIGHT_GRAY));
                            });

                            // Hex Column Header
                            ui.horizontal(|ui| {
                                ui.add_space(8.0);
                                ui.label(RichText::new("address").monospace().size(11.5).color(Color32::from_rgb(160, 160, 160)));
                                ui.add_space(20.0);
                                ui.label(RichText::new("00 01 02 03 04 05 06 07").monospace().size(11.5).color(Color32::from_rgb(160, 160, 160)));
                                ui.add_space(8.0);
                                ui.label(RichText::new("08 09 0A 0B 0C 0D 0E 0F").monospace().size(11.5).color(Color32::from_rgb(255, 230, 100)));
                                ui.add_space(14.0);
                                ui.label(RichText::new("0123456789ABCDEF").monospace().size(11.5).color(Color32::from_rgb(160, 160, 160)));
                            });

                            ui.separator();

                            let mut edit_target: Option<(usize, u8)> = None;

                            egui::ScrollArea::vertical()
                                .id_salt("ce_hex_scroll")
                                .max_height(hex_h - 50.0)
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    if app.hex_dump_bytes.is_empty() {
                                        ui.vertical_centered(|ui| {
                                            ui.add_space(40.0);
                                            ui.label(RichText::new("No memory dump loaded. Open a process to view memory.").color(Color32::GRAY));
                                        });
                                    } else {
                                        for (row_idx, chunk) in app.hex_dump_bytes.chunks(16).enumerate() {
                                            let row_addr = app.hex_dump_base + (row_idx * 16);

                                            ui.horizontal(|ui| {
                                                ui.add_space(8.0);
                                                // Address column
                                                ui.label(RichText::new(format!("{:012X}", row_addr)).monospace().size(12.0).color(Color32::WHITE));
                                                ui.add_space(12.0);

                                                // First 8 Bytes (00 .. 07)
                                                ui.horizontal(|ui| {
                                                    ui.spacing_mut().item_spacing = Vec2::new(4.0, 0.0);
                                                    for (b_idx, &b) in chunk.iter().take(8).enumerate() {
                                                        let b_addr = row_addr + b_idx;
                                                        let b_text = format!("{:02X}", b);
                                                        let b_resp = ui.add(egui::Label::new(RichText::new(b_text).monospace().size(12.0).color(Color32::from_rgb(0, 210, 0))).sense(egui::Sense::click()));
                                                        if b_resp.double_clicked() || (b_resp.clicked() && ui.input(|i| i.modifiers.ctrl)) {
                                                            edit_target = Some((b_addr, b));
                                                        }
                                                        b_resp.context_menu(|ui| {
                                                            if ui.button("Edit Byte (Hex)").clicked() {
                                                                edit_target = Some((b_addr, b));
                                                                ui.close_menu();
                                                            }
                                                        });
                                                    }
                                                });

                                                ui.add_space(4.0);

                                                // Second 8 Bytes (08 .. 0F) with Yellow Frame Accent
                                                egui::Frame::none()
                                                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(220, 200, 60)))
                                                    .inner_margin(egui::Margin::symmetric(3.0, 0.0))
                                                    .show(ui, |ui| {
                                                        ui.horizontal(|ui| {
                                                            ui.spacing_mut().item_spacing = Vec2::new(4.0, 0.0);
                                                            for (b_idx, &b) in chunk.iter().skip(8).take(8).enumerate() {
                                                                let b_addr = row_addr + 8 + b_idx;
                                                                let b_text = format!("{:02X}", b);
                                                                let b_resp = ui.add(egui::Label::new(RichText::new(b_text).monospace().size(12.0).color(Color32::from_rgb(0, 210, 0))).sense(egui::Sense::click()));
                                                                if b_resp.double_clicked() || (b_resp.clicked() && ui.input(|i| i.modifiers.ctrl)) {
                                                                    edit_target = Some((b_addr, b));
                                                                }
                                                                b_resp.context_menu(|ui| {
                                                                    if ui.button("Edit Byte (Hex)").clicked() {
                                                                        edit_target = Some((b_addr, b));
                                                                        ui.close_menu();
                                                                    }
                                                                });
                                                            }
                                                        });
                                                    });

                                                ui.add_space(10.0);

                                                // ASCII Text Column
                                                let ascii_text: String = chunk.iter().map(|&b| if b >= 0x20 && b <= 0x7E { b as char } else { '.' }).collect();
                                                ui.label(RichText::new(ascii_text).monospace().size(12.0).color(Color32::from_rgb(140, 220, 140)));
                                            });
                                        }
                                    }
                                });

                            if let Some((addr, byte)) = edit_target {
                                app.edit_byte_addr = addr;
                                app.edit_byte_val_text = format!("{:02X}", byte);
                                app.show_edit_byte_modal = true;
                            }
                        });
                });
        },
    );
}
