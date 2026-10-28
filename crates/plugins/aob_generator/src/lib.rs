use std::ffi::{c_char, CStr};
use std::slice;

use onyx_core::debugger::disasm::Disassembler;
use onyx_core::memory::scanner::AobByte;
use onyx_core::memory::signature_maker::SignatureMaker;
use onyx_core::process::pdb::DbgHelpSymbolEngine;
use onyx_core::process::process::Process;

pub const ONYX_PLUGIN_API_VERSION: u32 = 1;

pub const ONYX_PLUGIN_OK: i32 = 0;
pub const ONYX_PLUGIN_ERR_INVALID_PARAM: i32 = -1;
pub const ONYX_PLUGIN_ERR_NOT_FOUND: i32 = -2;
pub const ONYX_PLUGIN_ERR_BUFFER_SMALL: i32 = -3;
pub const ONYX_PLUGIN_ERR_EXECUTION: i32 = -4;

#[repr(C)]
pub struct OnyxPluginInfo {
    pub api_version: u32,
    pub name: *const c_char,
    pub version: *const c_char,
    pub author: *const c_char,
    pub description: *const c_char,
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

#[repr(C)]
pub struct OnyxPluginHostAPI {
    pub struct_size: u32,
    pub get_target_pid: Option<unsafe extern "system" fn() -> u32>,
    pub get_target_handle: Option<unsafe extern "system" fn() -> *mut std::ffi::c_void>,
    pub read_memory: Option<
        unsafe extern "system" fn(
            u64,
            *mut std::ffi::c_void,
            usize,
            *mut usize,
        ) -> i32,
    >,
    pub write_memory: Option<
        unsafe extern "system" fn(
            u64,
            *const std::ffi::c_void,
            usize,
            *mut usize,
        ) -> i32,
    >,
    pub resolve_symbol: Option<
        unsafe extern "system" fn(u64, *mut c_char, usize, *mut u64) -> i32,
    >,
    pub log_message: Option<unsafe extern "system" fn(i32, *const c_char)>,
}

static PLUGIN_NAME: &[u8] = b"Onyx SigMaker & AOB Validator\0";
static PLUGIN_VERSION: &[u8] = b"1.0.0\0";
static PLUGIN_AUTHOR: &[u8] = b"OnyxEngine Team\0";
static PLUGIN_DESC: &[u8] =
    b"AOB Pattern validator, unique signature generator, and symbol function resolver\0";

#[no_mangle]
pub unsafe extern "system" fn OnyxPlugin_GetInfo(out_info: *mut OnyxPluginInfo) -> i32 {
    if out_info.is_null() {
        return ONYX_PLUGIN_ERR_INVALID_PARAM;
    }

    (*out_info).api_version = ONYX_PLUGIN_API_VERSION;
    (*out_info).name = PLUGIN_NAME.as_ptr() as *const c_char;
    (*out_info).version = PLUGIN_VERSION.as_ptr() as *const c_char;
    (*out_info).author = PLUGIN_AUTHOR.as_ptr() as *const c_char;
    (*out_info).description = PLUGIN_DESC.as_ptr() as *const c_char;

    ONYX_PLUGIN_OK
}

#[no_mangle]
pub unsafe extern "system" fn OnyxPlugin_Init(_host_api: *const OnyxPluginHostAPI) -> i32 {
    ONYX_PLUGIN_OK
}

#[no_mangle]
pub unsafe extern "system" fn OnyxPlugin_Shutdown() {
}

fn write_c_string(dest: &mut [c_char], src: &str) {
    let bytes = src.as_bytes();
    let max = dest.len().saturating_sub(1);
    let copy_len = bytes.len().min(max);
    for i in 0..copy_len {
        dest[i] = bytes[i] as c_char;
    }
    dest[copy_len] = 0;
}

pub fn parse_aob_pattern_str(pattern_str: &str) -> Result<Vec<AobByte>, String> {
    let mut pattern_bytes = Vec::new();
    for token in pattern_str.split_whitespace() {
        if token.is_empty() {
            continue;
        }
        let byte = AobByte::parse(token)?;
        pattern_bytes.push(byte);
    }
    if pattern_bytes.is_empty() {
        return Err("AOB pattern cannot be empty".to_string());
    }
    Ok(pattern_bytes)
}

#[no_mangle]
pub unsafe extern "system" fn OnyxPlugin_ValidateAOB(
    pid: u32,
    pattern_ptr: *const c_char,
    module_filter_ptr: *const c_char,
    out_result: *mut OnyxAobMatchResult,
) -> i32 {
    if pattern_ptr.is_null() || out_result.is_null() {
        return ONYX_PLUGIN_ERR_INVALID_PARAM;
    }

    let pattern_str = match CStr::from_ptr(pattern_ptr).to_str() {
        Ok(s) => s.trim(),
        Err(_) => return ONYX_PLUGIN_ERR_INVALID_PARAM,
    };

    let module_filter = if !module_filter_ptr.is_null() {
        CStr::from_ptr(module_filter_ptr).to_str().unwrap_or("").trim()
    } else {
        ""
    };

    let parsed_aob = match parse_aob_pattern_str(pattern_str) {
        Ok(a) => a,
        Err(_) => return ONYX_PLUGIN_ERR_INVALID_PARAM,
    };

    let proc = if pid == 0 {
        match Process::attach_current() {
            Ok(p) => p,
            Err(_) => return ONYX_PLUGIN_ERR_EXECUTION,
        }
    } else {
        match Process::attach(pid) {
            Ok(p) => p,
            Err(_) => return ONYX_PLUGIN_ERR_EXECUTION,
        }
    };

    let modules = match proc.modules() {
        Ok(m) => m,
        Err(_) => Vec::new(),
    };

    let target_modules: Vec<_> = if !module_filter.is_empty() {
        modules
            .into_iter()
            .filter(|m| m.name.to_lowercase().contains(&module_filter.to_lowercase()))
            .collect()
    } else {
        modules
    };

    let mut total_matches = 0usize;
    let mut first_match_addr = 0usize;
    let mut first_match_mod_name = String::new();
    let mut first_match_mod_base = 0usize;

    for module in &target_modules {
        if module.size == 0 {
            continue;
        }

        let chunk_size = 32 * 1024 * 1024;
        let scan_len = module.size.min(chunk_size);
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
                            first_match_mod_name = module.name.clone();
                            first_match_mod_base = module.base;
                            break;
                        }
                    }
                }
                total_matches += m_count;
            }
        }
    }

    if total_matches == 0 && target_modules.is_empty() {
        if let Ok(regions) = proc.regions(false) {
            for r in regions {
                if r.is_committed() && r.is_readable() && r.size <= 64 * 1024 * 1024 {
                    if let Ok(bytes) = proc.read_bytes(r.base, r.size) {
                        let cnt = SignatureMaker::count_matches_in_buffer(&bytes, &parsed_aob);
                        if cnt > 0 {
                            if total_matches == 0 {
                                let pat_len = parsed_aob.len();
                                let max_idx = bytes.len().saturating_sub(pat_len);
                                for i in 0..=max_idx {
                                    let mut ok = true;
                                    for (p_idx, p_byte) in parsed_aob.iter().enumerate() {
                                        if !p_byte.matches(bytes[i + p_idx]) {
                                            ok = false;
                                            break;
                                        }
                                    }
                                    if ok {
                                        first_match_addr = r.base + i;
                                        break;
                                    }
                                }
                            }
                            total_matches += cnt;
                        }
                    }
                }
            }
        }
    }

    (*out_result).address = first_match_addr as u64;
    (*out_result).match_count = total_matches as u32;
    (*out_result).is_unique = if total_matches == 1 { 1 } else { 0 };
    (*out_result).module_base = first_match_mod_base as u64;
    (*out_result).module_offset = if first_match_addr >= first_match_mod_base {
        (first_match_addr - first_match_mod_base) as u64
    } else {
        0
    };

    write_c_string(&mut (*out_result).module_name, &first_match_mod_name);

    let mut func_name = String::new();
    let mut func_start = 0u64;
    let mut func_disp = 0i64;

    if first_match_addr != 0 {
        if let Ok(dbg) = DbgHelpSymbolEngine::new(proc.handle) {
            if let Some((name, disp)) = dbg.resolve_address(first_match_addr) {
                func_name = name;
                func_disp = disp as i64;
                func_start = (first_match_addr as i64 - func_disp) as u64;
            }
        }

        if func_name.is_empty() {
            if !first_match_mod_name.is_empty() {
                func_name = format!("{}+0x{:X}", first_match_mod_name, (*out_result).module_offset);
                func_start = first_match_addr as u64;
                func_disp = 0;
            } else {
                func_name = format!("sub_{:X}", first_match_addr);
                func_start = first_match_addr as u64;
                func_disp = 0;
            }
        }

        let mut disasm_lines = Vec::new();
        if let Ok(code_slice) = proc.read_bytes(first_match_addr, 48) {
            let mut off = 0;
            for _ in 0..5 {
                if off >= code_slice.len() {
                    break;
                }
                let curr_addr = first_match_addr + off;
                let insn = Disassembler::decode_one(curr_addr, &code_slice[off..]);
                let len = insn.length.max(1);
                disasm_lines.push(format!("0x{:X}: {} {}", curr_addr, insn.mnemonic, insn.operands));
                off += len;
            }
        }

        let disasm_str = disasm_lines.join("\n");
        write_c_string(&mut (*out_result).disasm_preview, &disasm_str);
    }

    (*out_result).function_start = func_start;
    (*out_result).function_offset = func_disp;
    write_c_string(&mut (*out_result).function_name, &func_name);

    if total_matches == 0 {
        ONYX_PLUGIN_ERR_NOT_FOUND
    } else {
        ONYX_PLUGIN_OK
    }
}

#[no_mangle]
pub unsafe extern "system" fn OnyxPlugin_GenerateAOB(
    pid: u32,
    target_address: u64,
    max_len: u32,
    out_pattern_buf: *mut c_char,
    buf_size: u32,
) -> i32 {
    if target_address == 0 || out_pattern_buf.is_null() || buf_size == 0 {
        return ONYX_PLUGIN_ERR_INVALID_PARAM;
    }

    let proc = if pid == 0 {
        match Process::attach_current() {
            Ok(p) => p,
            Err(_) => return ONYX_PLUGIN_ERR_EXECUTION,
        }
    } else {
        match Process::attach(pid) {
            Ok(p) => p,
            Err(_) => return ONYX_PLUGIN_ERR_EXECUTION,
        }
    };

    let modules = proc.modules().unwrap_or_default();
    let enclosing_mod = modules
        .iter()
        .find(|m| (target_address as usize) >= m.base && (target_address as usize) < (m.base + m.size));

    let (scan_start, scan_stop) = if let Some(m) = enclosing_mod {
        (m.base, m.base + m.size)
    } else {
        (
            (target_address as usize).saturating_sub(64 * 1024),
            (target_address as usize) + 64 * 1024,
        )
    };

    let max_sig = if max_len == 0 { 64 } else { (max_len as usize).min(256) };

    match SignatureMaker::generate_signature(
        &proc,
        target_address as usize,
        scan_start,
        scan_stop,
        max_sig,
    ) {
        Ok(sig) => {
            let out_slice = slice::from_raw_parts_mut(out_pattern_buf, buf_size as usize);
            write_c_string(out_slice, &sig.pattern);
            ONYX_PLUGIN_OK
        }
        Err(_) => ONYX_PLUGIN_ERR_EXECUTION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_info_exports() {
        let mut info: OnyxPluginInfo = unsafe { std::mem::zeroed() };
        let rc = unsafe { OnyxPlugin_GetInfo(&mut info) };
        assert_eq!(rc, ONYX_PLUGIN_OK);
        assert_eq!(info.api_version, ONYX_PLUGIN_API_VERSION);

        let name = unsafe { CStr::from_ptr(info.name) }.to_str().unwrap();
        assert!(name.contains("Onyx SigMaker"));
    }

    #[test]
    fn test_parse_aob_pattern_str() {
        let pat = "48 89 5C 24 ?? 48 83 EC 20";
        let parsed = parse_aob_pattern_str(pat).unwrap();
        assert_eq!(parsed.len(), 9);
        assert_eq!(parsed[0].value, 0x48);
        assert_eq!(parsed[4].mask, 0x00);
    }
}
