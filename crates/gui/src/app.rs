use eframe::egui::{self, Color32, RichText, Rounding, Stroke, Vec2};
use onyx_core::disasm::Disassembler;
use onyx_core::freeze::Freezer;
use onyx_core::kernel::OnyxDriver;
use onyx_core::lua_api::CeLuaEngine;
use onyx_core::mono::{MonoDissector, RuntimeType};
use onyx_core::pointer_scanner::{PointerPath, PointerScanner};
use onyx_core::process::{Process, ProcessAccessMode, ProcessEntry};
use onyx_core::scanner::{ScanCondition, ScanValue, Scanner, ValType};
use onyx_core::speedhack::SpeedhackInjector;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::state::GuiTableEntry;
use crate::ui;

pub struct OnyxEngineApp {
    pub attached_proc: Option<Process>,
    pub proc_name: String,
    pub proc_pid: u32,
    pub proc_list: Vec<ProcessEntry>,
    pub proc_filter: String,
    pub show_proc_modal: bool,
    pub proc_modal_tab: usize,
    pub selected_proc_item: Option<(u32, String)>,
    pub icon_cache: HashMap<String, egui::TextureHandle>,
    pub icons: Option<crate::ui::CeIcons>,

    pub last_table_update: Instant,

    pub scanner: Scanner,
    pub scan_val_text: String,
    pub scan_val_second_text: String,
    pub scan_type_idx: usize,
    pub val_type_idx: usize,
    pub is_hex: bool,
    pub candidates: Vec<(usize, String, String)>,
    pub found_count: usize,
    pub has_scanned: bool,
    pub status_msg: String,

    pub start_addr_text: String,
    pub stop_addr_text: String,
    pub fast_scan: bool,
    pub alignment_idx: usize,
    pub writable_only: bool,
    pub executable: bool,
    pub copy_on_write: bool,

    pub cheat_table: Vec<GuiTableEntry>,
    pub freezer: Freezer,

    pub show_memory_view: bool,
    pub show_pointer_scanner: bool,
    pub show_lua_console: bool,
    pub show_aa_modal: bool,
    pub show_plugins_modal: bool,
    pub show_add_addr_modal: bool,
    pub show_settings_modal: bool,
    pub settings_tab: usize,

    pub access_mode: ProcessAccessMode,
    pub dbk_driver: Option<Arc<OnyxDriver>>,
    pub dbk_status_msg: String,
    pub freeze_interval_ms: u64,

    pub ghost_mode: bool,

    pub pointer_scanner: PointerScanner,
    pub ptr_target_addr_text: String,
    pub ptr_max_depth: usize,
    pub ptr_max_offset: usize,
    pub ptr_results: Vec<PointerPath>,
    pub ptr_rescan_addr_text: String,
    pub ptr_status: String,
    pub ptr_map_nodes: usize,
    pub ptr_is_busy: bool,

    pub mem_addr_text: String,
    pub hex_addr_text: String,
    pub mem_history: Vec<usize>,
    pub mem_history_idx: usize,
    pub disasm_lines: Vec<(usize, usize, String)>,
    pub disasm_instructions: Vec<onyx_core::disasm::DecodedInsn>,
    pub hex_dump_bytes: Vec<u8>,
    pub hex_dump_base: usize,
    pub hex_view_mode: usize,
    pub hex_text_mode: usize,
    pub selected_disasm_addr: Option<usize>,
    pub selected_hex_addr: Option<usize>,
    pub bookmarks: [Option<usize>; 10],
    pub show_edit_byte_modal: bool,
    pub edit_byte_addr: usize,
    pub edit_byte_val_text: String,
    pub mem_is_maximized: bool,
    pub show_data_inspector: bool,

    pub aa_script: String,
    pub aa_status: String,

    pub lua_engine: Option<CeLuaEngine>,
    pub lua_script: String,
    pub lua_output: Vec<String>,

    pub speedhack_enabled: bool,
    pub speedhack_val: f32,
    pub speedhack_injector: SpeedhackInjector,

    pub edit_entry_idx: Option<usize>,
    pub edit_val_text: String,

    pub manual_addr_text: String,
    pub manual_desc_text: String,
    pub manual_type_idx: usize,
    pub manual_is_pointer: bool,
    pub manual_module_text: String,
    pub manual_base_offset_text: String,
    pub manual_offsets: Vec<String>,

    pub mono_dissector: MonoDissector,
    pub show_mono_modal: bool,
    pub mono_search_text: String,
    pub mono_instance_addr_text: String,
    pub selected_assembly_idx: Option<usize>,
    pub selected_class_idx: Option<usize>,
}

impl OnyxEngineApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            attached_proc: None,
            proc_name: "No process selected".to_string(),
            proc_pid: 0,
            proc_list: Vec::new(),
            proc_filter: String::new(),
            show_proc_modal: false,
            proc_modal_tab: 0,
            selected_proc_item: None,
            icon_cache: HashMap::new(),
            icons: None,

            last_table_update: Instant::now(),

            scanner: Scanner::new(ValType::I32),
            scan_val_text: "100".to_string(),
            scan_val_second_text: "200".to_string(),
            scan_type_idx: 0,
            val_type_idx: 4,
            is_hex: false,
            candidates: Vec::new(),
            found_count: 0,
            has_scanned: false,
            status_msg: "OnyxEngine Ready. Select a process to begin.".to_string(),

            start_addr_text: "0000000000000000".to_string(),
            stop_addr_text: "7FFFFFFFFFFFFFFF".to_string(),
            fast_scan: true,
            alignment_idx: 0,
            writable_only: true,
            executable: false,
            copy_on_write: false,

            cheat_table: Vec::new(),
            freezer: Freezer::new(),

            show_memory_view: false,
            show_pointer_scanner: false,
            show_lua_console: false,
            show_aa_modal: false,
            show_plugins_modal: false,
            show_add_addr_modal: false,
            show_settings_modal: false,
            settings_tab: 0,

            access_mode: ProcessAccessMode::NtApi,
            dbk_driver: OnyxDriver::connect().ok().map(Arc::new),
            dbk_status_msg: String::new(),
            freeze_interval_ms: 50,
            ghost_mode: false,

            pointer_scanner: PointerScanner::new(),
            ptr_target_addr_text: "0x7FF700000000".to_string(),
            ptr_max_depth: 4,
            ptr_max_offset: 4096,
            ptr_results: Vec::new(),
            ptr_rescan_addr_text: String::new(),
            ptr_status: "Pointer Scanner ready.".to_string(),
            ptr_map_nodes: 0,
            ptr_is_busy: false,

            mem_addr_text: "0x7FF700001000".to_string(),
            hex_addr_text: "0x7FF700000000".to_string(),
            mem_history: Vec::new(),
            mem_history_idx: 0,
            disasm_lines: Vec::new(),
            disasm_instructions: Vec::new(),
            hex_dump_bytes: Vec::new(),
            hex_dump_base: 0,
            hex_view_mode: 0,
            hex_text_mode: 0,
            selected_disasm_addr: None,
            selected_hex_addr: None,
            bookmarks: [None; 10],
            show_edit_byte_modal: false,
            edit_byte_addr: 0,
            edit_byte_val_text: "00".to_string(),
            mem_is_maximized: false,
            show_data_inspector: true,

            aa_script: r#"[ENABLE]
// Alloc memory for code cave
alloc(newmem, 2048)
label(returnhere)
label(originalcode)

newmem:
// Custom assembly here
nop

originalcode:
// Restored instruction
ret

[DISABLE]
dealloc(newmem)
"#
            .to_string(),
            aa_status: String::new(),

            lua_engine: CeLuaEngine::init().ok(),
            lua_script: r#"print("OnyxEngine Lua Runtime Ready")
"#
            .to_string(),
            lua_output: vec!["Lua Engine 5.3 Ready.".to_string()],

            speedhack_enabled: false,
            speedhack_val: 1.0,
            speedhack_injector: SpeedhackInjector::new(),

            edit_entry_idx: None,
            edit_val_text: String::new(),

            manual_addr_text: "0x7FF700000000".to_string(),
            manual_desc_text: "Manual Entry".to_string(),
            manual_type_idx: 4,
            manual_is_pointer: false,
            manual_module_text: "main.exe".to_string(),
            manual_base_offset_text: "0x1000".to_string(),
            manual_offsets: vec!["0x10".to_string(), "0x28".to_string()],

            mono_dissector: MonoDissector::new(),
            show_mono_modal: false,
            mono_search_text: String::new(),
            mono_instance_addr_text: String::new(),
            selected_assembly_idx: None,
            selected_class_idx: None,
        }
    }

    pub fn try_connect_dbk(&mut self) {
        match OnyxDriver::connect() {
            Ok(driver) => {
                let arc = Arc::new(driver);
                self.dbk_status_msg = format!("Connected to driver: {}", arc.device_name);
                self.dbk_driver = Some(arc.clone());
                if let Some(ref mut proc) = self.attached_proc {
                    proc.set_dbk(Some(arc));
                }
                self.status_msg = "OnyxDriver (Stealth Ring-0) connected.".to_string();
            }
            Err(e) => {
                self.dbk_status_msg = format!("Driver connection failed: {}", e);
                self.dbk_driver = None;
            }
        }
    }

    pub fn set_access_mode(&mut self, mode: ProcessAccessMode) {
        self.access_mode = mode;
        if let Some(ref mut proc) = self.attached_proc {
            proc.set_access_mode(mode);
            proc.set_dbk(self.dbk_driver.clone());
        }
        self.status_msg = format!("Process access mode switched to {}", mode.badge());
    }

    pub fn refresh_proc_list(&mut self) {
        if let Ok(mut list) = Process::list_all() {
            list.sort_by_key(|a| a.name.to_lowercase());
            self.proc_list = list;
        }
    }

    pub fn ensure_proc_icon(&mut self, ctx: &egui::Context, pid: u32, name: &str) {
        let key = name.to_lowercase();
        if self.icon_cache.contains_key(&key) {
            return;
        }

        let icon_data = onyx_core::process::ProcessIconExtractor::get_process_icon(pid, name)
            .or_else(onyx_core::process::ProcessIconExtractor::extract_default_exe_icon);

        if let Some((w, h, pixels)) = icon_data {
            let color_image =
                egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &pixels);
            let texture = ctx.load_texture(
                format!("proc_icon_{}", key),
                color_image,
                egui::TextureOptions::LINEAR,
            );
            self.icon_cache.insert(key, texture);
        }
    }

    pub fn get_icon(&self, name: &str) -> Option<&egui::TextureHandle> {
        self.icon_cache.get(&name.to_lowercase())
    }

    pub fn attach_to_proc(&mut self, pid: u32, _name: String) {
        match Process::attach_with_mode(pid, self.access_mode, self.dbk_driver.clone()) {
            Ok(p) => {
                self.proc_name = format!("{:08X} - {}", p.pid, p.name);
                self.proc_pid = p.pid;
                self.status_msg = format!(
                    "Attached to {} (PID: 0x{:X}) | Mode: {}",
                    p.name,
                    p.pid,
                    p.access_mode.badge()
                );

                self.freezer.stop();
                self.freezer.start(&p, self.freeze_interval_ms);

                if let Some(lua) = &self.lua_engine {
                    lua.set_active_process(&p);
                }

                if let Ok(mods) = p.modules()
                    && let Some(main_mod) = mods.first()
                {
                    self.mem_addr_text = format!("0x{:016X}", main_mod.base + 0x1000);
                    self.hex_addr_text = format!("0x{:016X}", main_mod.base);
                    self.manual_module_text = main_mod.name.clone();
                }

                let (rt, _) = MonoDissector::detect_runtime(&p);
                if rt != RuntimeType::None {
                    let _ = self.mono_dissector.attach(&p);
                    let _ = self.mono_dissector.dissect(&p);
                    self.status_msg = format!(
                        "Attached to {} (PID: 0x{:X}) | {} active",
                        p.name,
                        p.pid,
                        rt.as_str()
                    );
                }

                self.attached_proc = Some(p);
                self.show_proc_modal = false;
            }
            Err(e) => {
                self.status_msg = format!("Failed to attach: {}", e);
            }
        }
    }

    pub fn parse_val_type_from_idx(&self) -> ValType {
        match self.val_type_idx {
            0 => ValType::U8,
            1 => ValType::I8,
            2 => ValType::I16,
            3 => ValType::I32,
            4 => ValType::I64,
            5 => ValType::Float,
            6 => ValType::Double,
            7 => ValType::Str,
            8 => ValType::Aob,
            9 => ValType::All,
            10 => ValType::Group,
            11 => ValType::Aob,
            _ => ValType::I32,
        }
    }

    pub fn parse_manual_val_type(&self) -> ValType {
        match self.manual_type_idx {
            0 => ValType::I8,
            1 => ValType::U8,
            2 => ValType::I16,
            3 => ValType::U16,
            4 => ValType::I32,
            5 => ValType::U32,
            6 => ValType::I64,
            7 => ValType::U64,
            8 => ValType::Float,
            9 => ValType::Double,
            10 => ValType::Str,
            11 => ValType::Aob,
            _ => ValType::I32,
        }
    }

    pub fn parse_hex_addr(text: &str, default: usize) -> usize {
        let t = text.trim();
        let s = if t.starts_with("0x") || t.starts_with("0X") {
            &t[2..]
        } else {
            t
        };
        usize::from_str_radix(s, 16).unwrap_or(default)
    }

    pub fn configure_scanner_params(&mut self) {
        self.scanner.start_addr = Self::parse_hex_addr(&self.start_addr_text, 0);
        self.scanner.stop_addr = Self::parse_hex_addr(&self.stop_addr_text, 0x7FFFFFFFFFFF);
        self.scanner.writable_only = self.writable_only;
        self.scanner.executable = self.executable;
        self.scanner.copy_on_write = self.copy_on_write;
        self.scanner.fast_scan = self.fast_scan;
        let align = match self.alignment_idx {
            0 => 4,
            1 => 1,
            2 => 2,
            3 => 8,
            _ => 4,
        };
        self.scanner.set_alignment(align);
    }

    pub fn execute_first_scan(&mut self) {
        if self.attached_proc.is_none() {
            self.status_msg = "Please attach to a process first.".to_string();
            return;
        }

        let val_type = self.parse_val_type_from_idx();
        self.scanner.val_type = val_type;
        self.configure_scanner_params();

        let proc = self.attached_proc.as_ref().unwrap();

        let condition = match self.scan_type_idx {
            3 => {
                let v1 = match ScanValue::parse(val_type, self.scan_val_text.trim()) {
                    Ok(v) => v,
                    Err(e) => {
                        self.status_msg = format!("Value 1 error: {}", e);
                        return;
                    }
                };
                let v2 = match ScanValue::parse(val_type, self.scan_val_second_text.trim()) {
                    Ok(v) => v,
                    Err(e) => {
                        self.status_msg = format!("Value 2 error: {}", e);
                        return;
                    }
                };
                ScanCondition::Between(v1, v2)
            }
            4 => ScanCondition::UnknownInitial,
            _ => {
                let val_str = if self.is_hex && !self.scan_val_text.starts_with("0x") {
                    format!("0x{}", self.scan_val_text.trim())
                } else {
                    self.scan_val_text.trim().to_string()
                };

                match ScanValue::parse(val_type, &val_str) {
                    Ok(v) => match self.scan_type_idx {
                        1 => ScanCondition::BiggerThan(v),
                        2 => ScanCondition::SmallerThan(v),
                        _ => ScanCondition::Exact(v),
                    },
                    Err(e) => {
                        self.status_msg = format!("Value parse error: {}", e);
                        return;
                    }
                }
            }
        };

        let start = Instant::now();
        match self.scanner.first_scan(proc, condition) {
            Ok(count) => {
                self.found_count = count;
                self.has_scanned = true;
                self.status_msg = format!("First Scan: {} found in {:.2?}", count, start.elapsed());
                self.refresh_candidates_cache();
            }
            Err(e) => {
                self.status_msg = format!("Scan failed: {}", e);
            }
        }
    }

    pub fn execute_next_scan(&mut self) {
        let proc = match &self.attached_proc {
            Some(p) => p,
            None => return,
        };

        let val_type = self.scanner.val_type;
        let val_str = if self.is_hex && !self.scan_val_text.starts_with("0x") {
            format!("0x{}", self.scan_val_text.trim())
        } else {
            self.scan_val_text.trim().to_string()
        };

        let condition = match self.scan_type_idx {
            0 => match ScanValue::parse(val_type, &val_str) {
                Ok(v) => ScanCondition::Exact(v),
                Err(e) => {
                    self.status_msg = format!("Value parse error: {}", e);
                    return;
                }
            },
            1 => ScanCondition::Increased,
            2 => ScanCondition::Decreased,
            3 => {
                let v1 = match ScanValue::parse(val_type, self.scan_val_text.trim()) {
                    Ok(v) => v,
                    Err(e) => {
                        self.status_msg = format!("Value 1 error: {}", e);
                        return;
                    }
                };
                let v2 = match ScanValue::parse(val_type, self.scan_val_second_text.trim()) {
                    Ok(v) => v,
                    Err(e) => {
                        self.status_msg = format!("Value 2 error: {}", e);
                        return;
                    }
                };
                ScanCondition::Between(v1, v2)
            }
            4 => ScanCondition::UnknownInitial,
            5 => ScanCondition::Changed,
            6 => ScanCondition::Unchanged,
            7 => match ScanValue::parse(val_type, &val_str) {
                Ok(v) => ScanCondition::IncreasedBy(v),
                Err(e) => {
                    self.status_msg = format!("Error: {}", e);
                    return;
                }
            },
            8 => match ScanValue::parse(val_type, &val_str) {
                Ok(v) => ScanCondition::DecreasedBy(v),
                Err(e) => {
                    self.status_msg = format!("Error: {}", e);
                    return;
                }
            },
            _ => ScanCondition::Exact(ScanValue::I32(0)),
        };

        let start = Instant::now();
        match self.scanner.next_scan(proc, condition) {
            Ok(count) => {
                self.found_count = count;
                self.status_msg =
                    format!("Next Scan: {} remaining in {:.2?}", count, start.elapsed());
                self.refresh_candidates_cache();
            }
            Err(e) => {
                self.status_msg = format!("Next scan failed: {}", e);
            }
        }
    }

    pub fn execute_undo_scan(&mut self) {
        if self.scanner.undo_scan() {
            self.found_count = self.scanner.candidates.len();
            self.has_scanned = !self.scanner.candidates.is_empty();
            self.status_msg = format!("Undid scan. Restored {} candidates.", self.found_count);
            self.refresh_candidates_cache();
        } else {
            self.status_msg = "No previous scan history to undo.".to_string();
        }
    }

    pub fn refresh_candidates_cache(&mut self) {
        let sample = self.scanner.results(150);
        self.candidates = sample
            .iter()
            .map(|c| {
                (
                    c.address,
                    c.current_value.to_display_string(),
                    c.previous_value.to_display_string(),
                )
            })
            .collect();
    }

    pub fn add_candidate_to_table(&mut self, addr: usize, val_type: ValType) {
        let cur_val = if let Some(proc) = &self.attached_proc {
            match val_type {
                ValType::I8 => proc
                    .read::<i8>(addr)
                    .map(|v| v.to_string())
                    .unwrap_or("???".to_string()),
                ValType::U8 => proc
                    .read::<u8>(addr)
                    .map(|v| v.to_string())
                    .unwrap_or("???".to_string()),
                ValType::I16 => proc
                    .read::<i16>(addr)
                    .map(|v| v.to_string())
                    .unwrap_or("???".to_string()),
                ValType::U16 => proc
                    .read::<u16>(addr)
                    .map(|v| v.to_string())
                    .unwrap_or("???".to_string()),
                ValType::I32 => proc
                    .read::<i32>(addr)
                    .map(|v| v.to_string())
                    .unwrap_or("???".to_string()),
                ValType::U32 => proc
                    .read::<u32>(addr)
                    .map(|v| v.to_string())
                    .unwrap_or("???".to_string()),
                ValType::I64 => proc
                    .read::<i64>(addr)
                    .map(|v| v.to_string())
                    .unwrap_or("???".to_string()),
                ValType::U64 => proc
                    .read::<u64>(addr)
                    .map(|v| v.to_string())
                    .unwrap_or("???".to_string()),
                ValType::Float => proc
                    .read::<f32>(addr)
                    .map(|v| format!("{:.2}", v))
                    .unwrap_or("???".to_string()),
                ValType::Double => proc
                    .read::<f64>(addr)
                    .map(|v| format!("{:.4}", v))
                    .unwrap_or("???".to_string()),
                _ => proc
                    .read::<i32>(addr)
                    .map(|v| v.to_string())
                    .unwrap_or("???".to_string()),
            }
        } else {
            "???".to_string()
        };

        self.cheat_table.push(GuiTableEntry {
            active: false,
            description: format!("Address 0x{:08X}", addr),
            address: addr,
            module_name: None,
            base_offset: addr,
            offsets: Vec::new(),
            val_type,
            current_val: cur_val.clone(),
            target_val: cur_val,
        });
    }

    pub fn add_pointer_to_table(&mut self, path: &PointerPath, val_type: ValType) {
        let cur_val = if let Some(proc) = &self.attached_proc {
            if let Ok(resolved) = PointerScanner::evaluate_path(proc, path) {
                proc.read::<i32>(resolved)
                    .map(|v| v.to_string())
                    .unwrap_or("???".to_string())
            } else {
                "???".to_string()
            }
        } else {
            "???".to_string()
        };

        self.cheat_table.push(GuiTableEntry {
            active: false,
            description: format!(
                "Pointer [\"{}\"+0x{:X}]",
                path.module_name, path.base_offset
            ),
            address: path.final_address,
            module_name: Some(path.module_name.clone()),
            base_offset: path.base_offset,
            offsets: path.offsets.clone(),
            val_type,
            current_val: cur_val.clone(),
            target_val: cur_val,
        });
        self.status_msg = format!("Added pointer to {} to Cheat Table.", path.module_name);
    }

    pub fn update_table_values(&mut self) {
        if let Some(proc) = &self.attached_proc {
            for entry in &mut self.cheat_table {
                if !entry.offsets.is_empty() {
                    let mut cur = match &entry.module_name {
                        Some(name) => {
                            if let Some(m) = proc.find_module(name) {
                                m.base + entry.base_offset
                            } else {
                                0
                            }
                        }
                        None => entry.base_offset,
                    };

                    if cur != 0 {
                        let mut broken = false;
                        for &off in &entry.offsets {
                            match proc.read::<usize>(cur) {
                                Ok(next_ptr) if next_ptr != 0 => {
                                    cur = next_ptr + off;
                                }
                                _ => {
                                    broken = true;
                                    break;
                                }
                            }
                        }
                        if !broken {
                            entry.address = cur;
                        }
                    }
                }

                entry.current_val = match entry.val_type {
                    ValType::I8 => proc
                        .read::<i8>(entry.address)
                        .map(|v| v.to_string())
                        .unwrap_or("???".to_string()),
                    ValType::U8 => proc
                        .read::<u8>(entry.address)
                        .map(|v| v.to_string())
                        .unwrap_or("???".to_string()),
                    ValType::I16 => proc
                        .read::<i16>(entry.address)
                        .map(|v| v.to_string())
                        .unwrap_or("???".to_string()),
                    ValType::U16 => proc
                        .read::<u16>(entry.address)
                        .map(|v| v.to_string())
                        .unwrap_or("???".to_string()),
                    ValType::I32 => proc
                        .read::<i32>(entry.address)
                        .map(|v| v.to_string())
                        .unwrap_or("???".to_string()),
                    ValType::U32 => proc
                        .read::<u32>(entry.address)
                        .map(|v| v.to_string())
                        .unwrap_or("???".to_string()),
                    ValType::I64 => proc
                        .read::<i64>(entry.address)
                        .map(|v| v.to_string())
                        .unwrap_or("???".to_string()),
                    ValType::U64 => proc
                        .read::<u64>(entry.address)
                        .map(|v| v.to_string())
                        .unwrap_or("???".to_string()),
                    ValType::Float => proc
                        .read::<f32>(entry.address)
                        .map(|v| format!("{:.2}", v))
                        .unwrap_or("???".to_string()),
                    ValType::Double => proc
                        .read::<f64>(entry.address)
                        .map(|v| format!("{:.4}", v))
                        .unwrap_or("???".to_string()),
                    ValType::Str => match proc.read_string(entry.address, 1001, false) {
                        Ok(s) => {
                            if s.chars().count() > 1000 {
                                s.chars().take(1000).collect()
                            } else {
                                s
                            }
                        }
                        Err(_) => "???".to_string(),
                    },
                    _ => proc
                        .read::<i32>(entry.address)
                        .map(|v| v.to_string())
                        .unwrap_or("???".to_string()),
                };

                if entry.active {
                    match entry.val_type {
                        ValType::I32 => {
                            if let Ok(v) = entry.target_val.parse::<i32>() {
                                let _ = proc.write(entry.address, &v);
                            }
                        }
                        ValType::Float => {
                            if let Ok(v) = entry.target_val.parse::<f32>() {
                                let _ = proc.write(entry.address, &v);
                            }
                        }
                        ValType::I64 => {
                            if let Ok(v) = entry.target_val.parse::<i64>() {
                                let _ = proc.write(entry.address, &v);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    pub fn write_table_entry_value(&mut self, idx: usize, new_val_str: &str) {
        if idx >= self.cheat_table.len() {
            return;
        }
        let entry = &mut self.cheat_table[idx];
        if let Some(proc) = &self.attached_proc {
            match entry.val_type {
                ValType::I8 => {
                    if let Ok(v) = new_val_str.parse::<i8>() {
                        let _ = proc.write(entry.address, &v);
                        entry.target_val = v.to_string();
                    }
                }
                ValType::U8 => {
                    if let Ok(v) = new_val_str.parse::<u8>() {
                        let _ = proc.write(entry.address, &v);
                        entry.target_val = v.to_string();
                    }
                }
                ValType::I16 => {
                    if let Ok(v) = new_val_str.parse::<i16>() {
                        let _ = proc.write(entry.address, &v);
                        entry.target_val = v.to_string();
                    }
                }
                ValType::U16 => {
                    if let Ok(v) = new_val_str.parse::<u16>() {
                        let _ = proc.write(entry.address, &v);
                        entry.target_val = v.to_string();
                    }
                }
                ValType::I32 => {
                    if let Ok(v) = new_val_str.parse::<i32>() {
                        let _ = proc.write(entry.address, &v);
                        entry.target_val = v.to_string();
                    }
                }
                ValType::U32 => {
                    if let Ok(v) = new_val_str.parse::<u32>() {
                        let _ = proc.write(entry.address, &v);
                        entry.target_val = v.to_string();
                    }
                }
                ValType::Float => {
                    if let Ok(v) = new_val_str.parse::<f32>() {
                        let _ = proc.write(entry.address, &v);
                        entry.target_val = v.to_string();
                    }
                }
                ValType::I64 => {
                    if let Ok(v) = new_val_str.parse::<i64>() {
                        let _ = proc.write(entry.address, &v);
                        entry.target_val = v.to_string();
                    }
                }
                ValType::Double => {
                    if let Ok(v) = new_val_str.parse::<f64>() {
                        let _ = proc.write(entry.address, &v);
                        entry.target_val = v.to_string();
                    }
                }
                ValType::Str => {
                    let mut raw = new_val_str.as_bytes().to_vec();
                    raw.push(0);
                    let _ = proc.write_raw(entry.address, &raw);
                    entry.target_val = new_val_str.to_string();
                }
                _ => {}
            }
        }
    }

    pub fn update_disasm_view(&mut self) {
        let addr = Self::parse_hex_addr(&self.mem_addr_text, 0);
        if let Some(proc) = &self.attached_proc {
            let mut buf = [0u8; 512];
            if let Ok(bytes_read) = proc.read_raw(addr, &mut buf) {
                let instrs = Disassembler::disassemble_block(addr, &buf[..bytes_read], 40);
                let modules = proc.modules().unwrap_or_default();
                self.disasm_lines = instrs
                    .iter()
                    .map(|i| (i.address, i.length, i.to_symbolic_string(&modules)))
                    .collect();
                self.disasm_instructions = instrs;
            }
        }
    }

    pub fn update_hex_view(&mut self) {
        let addr = Self::parse_hex_addr(&self.hex_addr_text, 0);
        if let Some(proc) = &self.attached_proc {
            let mut buf = [0u8; 512];
            if let Ok(bytes_read) = proc.read_raw(addr, &mut buf) {
                self.hex_dump_bytes = buf[..bytes_read].to_vec();
                self.hex_dump_base = addr;
            }
        }
    }

    pub fn update_memory_view(&mut self) {
        self.update_disasm_view();
        self.update_hex_view();
    }

    pub fn navigate_disasm(&mut self, addr: usize) {
        self.mem_history.push(addr);
        self.mem_history_idx = self.mem_history.len().saturating_sub(1);
        self.mem_addr_text = format!("0x{:016X}", addr);
        self.update_disasm_view();
    }

    pub fn navigate_hex(&mut self, addr: usize) {
        self.hex_addr_text = format!("0x{:016X}", addr);
        self.update_hex_view();
    }

    pub fn patch_instruction_nop(&mut self, addr: usize, len: usize) {
        if let Some(proc) = &self.attached_proc {
            let nops = vec![0x90u8; len];
            let _ = proc.protect(addr, len, 0x40);
            if proc.write_raw(addr, &nops).is_ok() {
                self.status_msg = format!("Replaced {} bytes at 0x{:X} with NOPs.", len, addr);
                self.update_disasm_view();
                self.update_hex_view();
            }
        }
    }

    pub fn inject_aux_dll(&mut self, dll_name: &str) {
        if let Some(proc) = &self.attached_proc {
            match proc.inject_dll(dll_name) {
                Ok(addr) => self.status_msg = format!("Injected {} at 0x{:016X}", dll_name, addr),
                Err(e) => self.status_msg = format!("Injection failed ({}): {}", dll_name, e),
            }
        } else {
            self.status_msg = "Attach to a process first before injecting DLLs.".to_string();
        }
    }
}

impl eframe::App for OnyxEngineApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.icons.is_none() {
            self.icons = Some(crate::ui::CeIcons::load(ctx));
        }

        if self.last_table_update.elapsed() >= std::time::Duration::from_millis(150) {
            self.update_table_values();
            self.last_table_update = Instant::now();
        }

        if self.attached_proc.is_none() {
            ctx.request_repaint_after(std::time::Duration::from_millis(16));
        } else {
            ctx.request_repaint_after(std::time::Duration::from_millis(33));
        }

        if ctx.input(|i| {
            (i.modifiers.ctrl && i.key_pressed(egui::Key::Comma)) || i.key_pressed(egui::Key::F2)
        }) {
            self.show_settings_modal = !self.show_settings_modal;
        }
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::O)) {
            self.refresh_proc_list();
            self.show_proc_modal = true;
        }
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::M)) {
            self.update_memory_view();
            self.show_memory_view = true;
        }
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::P)) {
            self.show_pointer_scanner = true;
        }
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::L)) {
            self.show_lua_console = true;
        }
        if ctx.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::A)) {
            self.show_aa_modal = true;
        }
        if ctx.input(|i| i.key_pressed(egui::Key::F11)) {
            self.speedhack_enabled = !self.speedhack_enabled;
            if let Some(proc) = &self.attached_proc {
                let mult = if self.speedhack_enabled {
                    self.speedhack_val
                } else {
                    1.0
                };
                let _ = self.speedhack_injector.enable_speedhack(proc, mult);
                self.status_msg = format!("Speedhack toggled: {:.1}x", mult);
            }
        }

        if ctx.input(|i| {
            i.key_pressed(egui::Key::F10)
                || (i.modifiers.ctrl && i.modifiers.shift && i.key_pressed(egui::Key::G))
        }) {
            self.ghost_mode = !self.ghost_mode;
            self.status_msg = if self.ghost_mode {
                "Ghost Mode [ON]: Window is click-through (overlay). Press F10 to disable."
                    .to_string()
            } else {
                "Ghost Mode [OFF]: Window interaction restored.".to_string()
            };
            ctx.send_viewport_cmd(egui::ViewportCommand::MousePassthrough(self.ghost_mode));
            ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(if self.ghost_mode {
                egui::WindowLevel::AlwaysOnTop
            } else {
                egui::WindowLevel::Normal
            }));
        }

        ui::render_top_menu(self, ctx);

        ui::render_bottom_bar(self, ctx);

        egui::CentralPanel::default().show(ctx, |ui| {
            ui::render_header_bar(self, ui);

            ui.add_space(4.0);

            let available_h = ui.available_height().max(420.0);
            let divider_h = 36.0;
            let spacing_h = 16.0;
            let content_h = (available_h - divider_h - spacing_h).max(320.0);

            let upper_h = (content_h * 0.52).clamp(240.0, 560.0);
            let lower_h = (content_h - upper_h).max(160.0);

            ui::scanner_panel::render(self, ui, upper_h);

            ui.add_space(4.0);

            let mut add_top_candidate = false;
            egui::Frame::none()
                .fill(Color32::from_rgb(22, 25, 32))
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(38, 43, 55)))
                .rounding(Rounding::same(6.0))
                .inner_margin(egui::Margin::symmetric(10.0, 4.0))
                .show(ui, |ui| {
                    ui.set_height(28.0);
                    let total_w = ui.available_width();
                    ui.horizontal(|ui| {
                        let mem_btn_resp = if let Some(ref icons) = self.icons {
                            let img = egui::Image::new(&icons.memory_view)
                                .fit_to_exact_size(Vec2::splat(18.0));
                            ui.add(
                                egui::Button::image_and_text(
                                    img,
                                    RichText::new("Memory View")
                                        .size(12.0)
                                        .color(Color32::WHITE)
                                        .strong(),
                                )
                                .fill(Color32::from_rgb(32, 42, 58))
                                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(52, 72, 105)))
                                .min_size(Vec2::new(120.0, 26.0))
                                .rounding(Rounding::same(3.0)),
                            )
                        } else {
                            ui.add(
                                egui::Button::new(
                                    RichText::new("Memory View")
                                        .size(12.0)
                                        .color(Color32::WHITE)
                                        .strong(),
                                )
                                .fill(Color32::from_rgb(32, 42, 58))
                                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(52, 72, 105)))
                                .min_size(Vec2::new(105.0, 26.0))
                                .rounding(Rounding::same(3.0)),
                            )
                        };

                        if mem_btn_resp.clicked() {
                            self.update_memory_view();
                            self.show_memory_view = true;
                        }

                        let arrow_w = 40.0;
                        let mem_w = 120.0;
                        let space_to_center =
                            ((total_w / 2.0) - mem_w - (arrow_w / 2.0) - 8.0).max(8.0);
                        ui.add_space(space_to_center);

                        let arrow_btn_resp = if let Some(ref icons) = self.icons {
                            let img = egui::Image::new(&icons.arrow_down)
                                .fit_to_exact_size(Vec2::splat(22.0));
                            ui.add(
                                egui::Button::image(img)
                                    .fill(Color32::from_rgb(180, 35, 35))
                                    .stroke(Stroke::new(1.0_f32, Color32::from_rgb(230, 60, 60)))
                                    .min_size(Vec2::new(arrow_w, 26.0))
                                    .rounding(Rounding::same(3.0)),
                            )
                        } else {
                            ui.add(
                                egui::Button::new(
                                    RichText::new("  \\/  ")
                                        .size(13.0)
                                        .color(Color32::WHITE)
                                        .strong(),
                                )
                                .fill(Color32::from_rgb(180, 35, 35))
                                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(230, 60, 60)))
                                .min_size(Vec2::new(arrow_w, 26.0))
                                .rounding(Rounding::same(3.0)),
                            )
                        };

                        if arrow_btn_resp
                            .on_hover_text("Copy selected / top candidate to Cheat Table")
                            .clicked()
                        {
                            add_top_candidate = true;
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let manual_btn = egui::Button::new(
                                RichText::new("+ Add Address Manually")
                                    .size(12.0)
                                    .color(Color32::WHITE)
                                    .strong(),
                            )
                            .fill(Color32::from_rgb(28, 70, 42))
                            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(45, 120, 70)))
                            .min_size(Vec2::new(145.0, 26.0))
                            .rounding(Rounding::same(3.0));

                            if ui.add(manual_btn).clicked() {
                                self.show_add_addr_modal = true;
                            }
                        });
                    });
                });

            if add_top_candidate && let Some(first) = self.candidates.first() {
                let addr = first.0;
                let val_type = self.parse_val_type_from_idx();
                self.add_candidate_to_table(addr, val_type);
                self.status_msg = format!("Added 0x{:08X} to Cheat Table.", addr);
            }

            ui.add_space(4.0);

            ui::cheat_table::render(self, ui, lower_h);
        });

        ui::modals::render_all_modals(self, ctx);
    }
}
