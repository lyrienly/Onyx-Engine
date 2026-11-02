//! Native Plugin Host and Dynamic Dispatcher
//! Manages external C-ABI plugins (onyx_aob_tool.dll, onyx_dll_mapper.dll)
//! with fallback to core engine implementations.

use onyx_core::debugger::disasm::Disassembler;
use onyx_core::injection::manual_map::{ManualMapOptions, ManualMapper};
use onyx_core::memory::scanner::AobByte;
use onyx_core::memory::signature_maker::SignatureMaker;
use onyx_core::process::Process;
use onyx_core::win32::{GetProcAddress, LoadLibraryW, HMODULE};
use std::ffi::{c_char, CStr, CString};
use std::path::PathBuf;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OnyxMapOptions {
    pub struct_size: u32,
    pub flags: u32,
    pub preferred_base: u64,
}

#[repr(C)]
pub struct OnyxMapResult {
    pub image_base: u64,
    pub entry_point: u64,
    pub dll_main_result: i32,
    pub flags_applied: u32,
    pub relocations: u32,
    pub imports: u32,
    pub error: [c_char; 256],
}

#[repr(C)]
pub struct OnyxAobMatchResult {
    pub address: u64,
    pub match_count: u32,
    pub is_unique: u32,
    pub module_name: [c_char; 128],
    pub module_base: u64,
    pub module_offset: u64,
    pub function_name: [c_char; 256],
    pub function_start: u64,
    pub function_offset: i64,
    pub disasm_preview: [c_char; 512],
}

type FnValidateAob = unsafe extern "system" fn(u32, *const c_char, *const c_char, *mut OnyxAobMatchResult) -> i32;
type FnGenerateAob = unsafe extern "system" fn(u32, u64, u32, *mut c_char, u32) -> i32;
type FnMapDllPid = unsafe extern "system" fn(u32, *const c_char, *const OnyxMapOptions, *mut OnyxMapResult) -> i32;

pub struct PluginManager;

impl PluginManager {
    fn find_plugin_dll(dll_name: &str) -> Option<PathBuf> {
        let candidates = [
            PathBuf::from("bin/plugins").join(dll_name),
            PathBuf::from("UI/bin/plugins").join(dll_name),
            PathBuf::from("../bin/plugins").join(dll_name),
            PathBuf::from("../../bin/plugins").join(dll_name),
            PathBuf::from("plugins").join(dll_name),
            PathBuf::from(dll_name),
        ];

        for c in &candidates {
            if c.exists() {
                return std::fs::canonicalize(c).ok();
            }
        }
        None
    }

    fn load_library_safe(dll_name: &str) -> Option<HMODULE> {
        let path = Self::find_plugin_dll(dll_name)?;
        let wide: Vec<u16> = path.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe { LoadLibraryW(wide.as_ptr()) };
        if !handle.is_null() {
            Some(handle)
        } else {
            None
        }
    }

    pub fn validate_aob(proc: &Process, pattern_str: &str, module_filter: &str) -> Result<serde_json::Value, String> {
        if let Some(h_mod) = Self::load_library_safe("onyx_aob_tool.dll") {
            let proc_addr = unsafe { GetProcAddress(h_mod, b"OnyxPlugin_ValidateAOB\0".as_ptr()) };
            if !proc_addr.is_null() {
                let func: FnValidateAob = unsafe { std::mem::transmute(proc_addr) };
                let c_pat = CString::new(pattern_str).map_err(|e| e.to_string())?;
                let c_mod = CString::new(module_filter).map_err(|e| e.to_string())?;
                let mut out_res: OnyxAobMatchResult = unsafe { std::mem::zeroed() };

                let rc = unsafe {
                    func(
                        proc.pid,
                        c_pat.as_ptr(),
                        if module_filter.is_empty() { std::ptr::null() } else { c_mod.as_ptr() },
                        &mut out_res,
                    )
                };

                if rc == 0 {
                    let mod_name = unsafe { CStr::from_ptr(out_res.module_name.as_ptr()) }.to_string_lossy();
                    let func_name = unsafe { CStr::from_ptr(out_res.function_name.as_ptr()) }.to_string_lossy();
                    let disasm = unsafe { CStr::from_ptr(out_res.disasm_preview.as_ptr()) }.to_string_lossy();

                    return Ok(serde_json::json!({
                        "plugin": "onyx_aob_tool.dll (dynamic)",
                        "status": "match_found",
                        "first_address": format!("0x{:X}", out_res.address),
                        "match_count": out_res.match_count,
                        "is_unique": out_res.is_unique == 1,
                        "module_name": mod_name,
                        "module_offset": format!("0x{:X}", out_res.module_offset),
                        "function_name": func_name,
                        "preview": disasm
                    }));
                }
            }
        }

        // Native Core Fallback
        Self::validate_aob_core(proc, pattern_str, module_filter)
    }

    pub fn generate_aob(proc: &Process, target_address: usize, max_len: u32) -> Result<serde_json::Value, String> {
        if let Some(h_mod) = Self::load_library_safe("onyx_aob_tool.dll") {
            let proc_addr = unsafe { GetProcAddress(h_mod, b"OnyxPlugin_GenerateAOB\0".as_ptr()) };
            if !proc_addr.is_null() {
                let func: FnGenerateAob = unsafe { std::mem::transmute(proc_addr) };
                let mut buf = vec![0 as c_char; 512];
                let rc = unsafe {
                    func(
                        proc.pid,
                        target_address as u64,
                        max_len,
                        buf.as_mut_ptr(),
                        buf.len() as u32,
                    )
                };
                if rc == 0 {
                    let sig = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy();
                    return Ok(serde_json::json!({
                        "plugin": "onyx_aob_tool.dll (dynamic)",
                        "target_address": format!("0x{:X}", target_address),
                        "unique_signature": sig
                    }));
                }
            }
        }

        // Native Core Fallback
        let modules = proc.modules().unwrap_or_default();
        let enclosing_mod = modules.iter().find(|m| {
            target_address >= m.base && target_address < (m.base + m.size)
        });

        let (scan_start, scan_stop) = if let Some(m) = enclosing_mod {
            (m.base, m.base + m.size)
        } else {
            (target_address.saturating_sub(64 * 1024), target_address + 64 * 1024)
        };

        let max_sig = if max_len == 0 { 64 } else { (max_len as usize).min(256) };
        let sig = SignatureMaker::generate_signature(proc, target_address, scan_start, scan_stop, max_sig)?;

        Ok(serde_json::json!({
            "plugin": "onyx_core::signature_maker (internal)",
            "target_address": format!("0x{:X}", target_address),
            "unique_signature": sig.pattern
        }))
    }

    pub fn manual_map(proc: &Process, dll_path: &str, erase_headers: bool) -> Result<serde_json::Value, String> {
        if let Some(h_mod) = Self::load_library_safe("onyx_dll_mapper.dll") {
            let proc_addr = unsafe { GetProcAddress(h_mod, b"OnyxPlugin_MapDllPid\0".as_ptr()) };
            if !proc_addr.is_null() {
                let func: FnMapDllPid = unsafe { std::mem::transmute(proc_addr) };
                let c_path = CString::new(dll_path).map_err(|e| e.to_string())?;

                let mut options: OnyxMapOptions = unsafe { std::mem::zeroed() };
                options.struct_size = std::mem::size_of::<OnyxMapOptions>() as u32;
                options.flags = 2 | 4 | 128 | 256 | 512;
                if erase_headers {
                    options.flags |= 1;
                }

                let mut result: OnyxMapResult = unsafe { std::mem::zeroed() };
                let rc = unsafe {
                    func(proc.pid, c_path.as_ptr(), &options, &mut result)
                };

                if rc == 0 {
                    return Ok(serde_json::json!({
                        "plugin": "onyx_dll_mapper.dll (dynamic)",
                        "status": "manual_map_success",
                        "image_base": format!("0x{:X}", result.image_base),
                        "entry_point": format!("0x{:X}", result.entry_point),
                        "dll_main_result": result.dll_main_result,
                        "relocations": result.relocations,
                        "imports": result.imports
                    }));
                } else {
                    let err_msg = unsafe { CStr::from_ptr(result.error.as_ptr()) }.to_string_lossy();
                    return Err(format!("Manual map plugin error: {}", err_msg));
                }
            }
        }

        // Native Core Fallback
        let bytes = std::fs::read(dll_path).map_err(|e| format!("Falha ao ler arquivo DLL: {}", e))?;
        let mut options = ManualMapOptions::default();
        options.wipe_headers = erase_headers;

        let outcome = ManualMapper::inject(proc, &bytes, &options)?;
        Ok(serde_json::json!({
            "plugin": "onyx_core::injection::manual_map (internal)",
            "status": "manual_map_success",
            "image_base": format!("0x{:X}", outcome.base_address),
            "entry_point": format!("0x{:X}", outcome.entry_point),
            "size_of_image": outcome.size_of_image,
            "sections_mapped": outcome.sections_mapped,
            "tls_callbacks_executed": outcome.tls_callbacks_executed
        }))
    }

    fn validate_aob_core(proc: &Process, pattern_str: &str, module_filter: &str) -> Result<serde_json::Value, String> {
        let mut parsed_aob = Vec::new();
        for token in pattern_str.split_whitespace() {
            if !token.is_empty() {
                parsed_aob.push(AobByte::parse(token)?);
            }
        }
        if parsed_aob.is_empty() {
            return Err("Padrão AOB não pode ser vazio.".to_string());
        }

        let modules = proc.modules().unwrap_or_default();
        let target_modules: Vec<_> = if !module_filter.is_empty() {
            modules.into_iter().filter(|m| m.name.to_lowercase().contains(&module_filter.to_lowercase())).collect()
        } else {
            modules
        };

        let mut total_matches = 0usize;
        let mut first_match_addr = 0usize;
        let mut first_match_mod = String::new();
        let mut first_match_base = 0usize;

        for module in &target_modules {
            if module.size == 0 { continue; }
            let scan_len = module.size.min(32 * 1024 * 1024);
            if let Ok(mod_bytes) = proc.read_bytes(module.base, scan_len) {
                let m_count = SignatureMaker::count_matches_in_buffer(&mod_bytes, &parsed_aob);
                if m_count > 0 {
                    if total_matches == 0 {
                        let pat_len = parsed_aob.len();
                        let max_idx = mod_bytes.len().saturating_sub(pat_len);
                        for i in 0..=max_idx {
                            let mut ok = true;
                            for (p_idx, p_byte) in parsed_aob.iter().enumerate() {
                                if !p_byte.matches(mod_bytes[i + p_idx]) {
                                    ok = false;
                                    break;
                                }
                            }
                            if ok {
                                first_match_addr = module.base + i;
                                first_match_mod = module.name.clone();
                                first_match_base = module.base;
                                break;
                            }
                        }
                    }
                    total_matches += m_count;
                }
            }
        }

        if total_matches == 0 {
            return Err("Nenhuma ocorrência encontrada para o padrão AOB especificado.".to_string());
        }

        let mut disasm_lines = Vec::new();
        if let Ok(code_slice) = proc.read_bytes(first_match_addr, 48) {
            let mut off = 0;
            for _ in 0..5 {
                if off >= code_slice.len() { break; }
                let curr_addr = first_match_addr + off;
                let insn = Disassembler::decode_one(curr_addr, &code_slice[off..]);
                let len = insn.length.max(1);
                disasm_lines.push(format!("0x{:X}: {} {}", curr_addr, insn.mnemonic, insn.operands));
                off += len;
            }
        }

        Ok(serde_json::json!({
            "plugin": "onyx_core (internal)",
            "status": "match_found",
            "first_address": format!("0x{:X}", first_match_addr),
            "match_count": total_matches,
            "is_unique": total_matches == 1,
            "module_name": first_match_mod,
            "module_offset": format!("0x{:X}", first_match_addr.saturating_sub(first_match_base)),
            "preview": disasm_lines.join("\n")
        }))
    }
}
