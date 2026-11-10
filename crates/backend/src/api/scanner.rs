use crate::types::{
    OnyxAobValidation, OnyxCodecaveEntry, OnyxRipRelativeMatch, OnyxScanCandidate,
    OnyxSignatureResult,
};
use onyx_core::debugger::rip_scanner::RipRelativeScanner;
use onyx_core::memory::aob_validator::AobValidator;
use onyx_core::memory::codecave::{CaveByteType, CodecaveScanner};
use onyx_core::memory::signature_maker::SignatureMaker;
use onyx_core::process::Process;
use onyx_core::scanner::{ScanCondition, ScanValue, Scanner, ValType};
use std::ffi::CStr;
use std::os::raw::c_char;

fn map_val_type(idx: i32) -> ValType {
    match idx {
        0 => ValType::I8,
        1 => ValType::I16,
        2 => ValType::I32,
        3 => ValType::I64,
        4 => ValType::Float,
        5 => ValType::Double,
        6 | 7 | 16 => ValType::Str,
        8 | 15 => ValType::Aob,
        10 => ValType::All,
        14 => ValType::Group,
        _ => ValType::I32,
    }
}

fn parse_c_str(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(ptr).to_string_lossy().to_string() }
    }
}

fn resolve_condition(s: &Scanner, scan_type: i32, v1: &str, v2: &str) -> Option<ScanCondition> {
    match scan_type {
        0 => Some(ScanCondition::UnknownInitial),

        1 => ScanValue::parse(s.val_type, v1)
            .ok()
            .map(ScanCondition::Exact),

        2 => {
            let p1 = ScanValue::parse(s.val_type, v1).ok()?;
            let p2 = ScanValue::parse(s.val_type, v2).ok()?;
            Some(ScanCondition::Between(p1, p2))
        }

        3 => ScanValue::parse(s.val_type, v1)
            .ok()
            .map(ScanCondition::BiggerThan),

        4 => ScanValue::parse(s.val_type, v1)
            .ok()
            .map(ScanCondition::SmallerThan),

        5 => Some(ScanCondition::Increased),

        6 => ScanValue::parse(s.val_type, v1)
            .ok()
            .map(ScanCondition::IncreasedBy),

        7 => Some(ScanCondition::Decreased),

        8 => ScanValue::parse(s.val_type, v1)
            .ok()
            .map(ScanCondition::DecreasedBy),

        9 => Some(ScanCondition::Changed),

        10 => Some(ScanCondition::Unchanged),
        _ => None,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_scanner_create(val_type_idx: i32) -> *mut Scanner {
    let vt = map_val_type(val_type_idx);
    Box::into_raw(Box::new(Scanner::new(vt)))
}

#[no_mangle]
pub unsafe extern "C" fn onyx_scanner_destroy(scanner: *mut Scanner) {
    if !scanner.is_null() {
        drop(Box::from_raw(scanner));
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_scanner_first_scan(
    scanner: *mut Scanner,
    process: *mut Process,
    scan_type: i32,
    val1_str: *const c_char,
    val2_str: *const c_char,
    is_hex: i32,
    fast_scan: i32,
    alignment: usize,
    start_addr: usize,
    stop_addr: usize,
    writable_only: i32,
    executable: i32,
    copy_on_write: i32,
) -> i64 {
    if scanner.is_null() || process.is_null() {
        return -1;
    }

    let s = &mut *scanner;
    let proc = &*process;

    let v1_raw = parse_c_str(val1_str);
    let v2_raw = parse_c_str(val2_str);

    let v1 = if is_hex != 0 && !v1_raw.starts_with("0x") {
        format!("0x{}", v1_raw.trim())
    } else {
        v1_raw.trim().to_string()
    };

    let condition = match resolve_condition(s, scan_type, &v1, &v2_raw) {
        Some(c) => c,
        None => return -1,
    };

    s.fast_scan = fast_scan != 0;
    s.alignment = if alignment == 0 { 4 } else { alignment };
    s.start_addr = start_addr;
    s.stop_addr = if stop_addr == 0 {
        onyx_core::memory::MAX_USER_ADDRESS
    } else {
        stop_addr
    };
    s.writable_only = writable_only != 0;
    s.executable = executable != 0;
    s.copy_on_write = copy_on_write != 0;

    match s.first_scan(proc, condition) {
        Ok(count) => count as i64,
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_scanner_next_scan(
    scanner: *mut Scanner,
    process: *mut Process,
    scan_type: i32,
    val1_str: *const c_char,
    val2_str: *const c_char,
    is_hex: i32,
) -> i64 {
    if scanner.is_null() || process.is_null() {
        return -1;
    }

    let s = &mut *scanner;
    let proc = &*process;

    let v1_raw = parse_c_str(val1_str);
    let v2_raw = parse_c_str(val2_str);

    let v1 = if is_hex != 0 && !v1_raw.starts_with("0x") {
        format!("0x{}", v1_raw.trim())
    } else {
        v1_raw.trim().to_string()
    };

    let condition = match resolve_condition(s, scan_type, &v1, &v2_raw) {
        Some(c) => c,
        None => return -1,
    };

    match s.next_scan(proc, condition) {
        Ok(count) => count as i64,
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_scanner_undo(scanner: *mut Scanner) -> i32 {
    if scanner.is_null() {
        return 0;
    }
    let s = &mut *scanner;
    if s.undo_scan() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_scanner_get_count(scanner: *mut Scanner) -> i64 {
    if scanner.is_null() {
        return 0;
    }
    let s = &*scanner;
    s.candidates.len() as i64
}

#[no_mangle]
pub unsafe extern "C" fn onyx_scanner_get_results(
    scanner: *mut Scanner,
    out_candidates: *mut OnyxScanCandidate,
    max_count: u32,
) -> i64 {
    if scanner.is_null() || out_candidates.is_null() || max_count == 0 {
        return 0;
    }

    let s = &*scanner;
    let sample = s.results(max_count as usize);
    let count = sample.len();

    for (i, c) in sample.iter().enumerate() {
        let mut entry = OnyxScanCandidate {
            address: c.address,
            current_val: [0u8; 64],
            previous_val: [0u8; 64],
        };

        let cur_str = c.current_value.to_display_string();
        let prev_str = c.previous_value.to_display_string();

        let cur_bytes = cur_str.as_bytes();
        let cur_len = cur_bytes.len().min(63);
        entry.current_val[..cur_len].copy_from_slice(&cur_bytes[..cur_len]);

        let prev_bytes = prev_str.as_bytes();
        let prev_len = prev_bytes.len().min(63);
        entry.previous_val[..prev_len].copy_from_slice(&prev_bytes[..prev_len]);

        *out_candidates.add(i) = entry;
    }

    count as i64
}

#[no_mangle]
pub unsafe extern "C" fn onyx_scanner_save_results_file(
    scanner: *mut Scanner,
    file_path: *const c_char,
) -> i64 {
    if scanner.is_null() || file_path.is_null() {
        return -1;
    }

    let s = &*scanner;
    let path = parse_c_str(file_path);
    if path.is_empty() {
        return -1;
    }

    use std::fs::File;
    use std::io::{BufWriter, Write};

    let file = match File::create(&path) {
        Ok(f) => f,
        Err(_) => return -1,
    };
    let mut writer = BufWriter::with_capacity(512 * 1024, file);

    let header: [u8; 7] = [6, b'N', b'O', b'R', b'M', b'A', b'L'];
    if writer.write_all(&header).is_err() {
        return -1;
    }

    if s.val_type == ValType::Group {
        let offset_count = s
            .candidates
            .first()
            .map(|c| c.group_offsets.len() as u32)
            .unwrap_or(0);

        if writer.write_all(&offset_count.to_le_bytes()).is_err() {
            return -1;
        }

        for c in &s.candidates {
            let addr_u64 = c.address as u64;
            if writer.write_all(&addr_u64.to_le_bytes()).is_err() {
                return -1;
            }
            for off in &c.group_offsets {
                if writer.write_all(&off.to_le_bytes()).is_err() {
                    return -1;
                }
            }
        }

        if writer.flush().is_err() {
            return -1;
        }

        return s.candidates.len() as i64;
    }

    let is_bit_address = s.val_type == ValType::All;

    for c in &s.candidates {
        let addr_u64 = c.address as u64;
        if writer.write_all(&addr_u64.to_le_bytes()).is_err() {
            return -1;
        }
        if is_bit_address {
            let extra_u64 = c.extra_type as u64;
            if writer.write_all(&extra_u64.to_le_bytes()).is_err() {
                return -1;
            }
        }
    }

    if writer.flush().is_err() {
        return -1;
    }

    s.candidates.len() as i64
}

#[no_mangle]
pub unsafe extern "C" fn onyx_scan_codecaves(
    handle: *mut Process,
    start: usize,
    stop: usize,
    min_size: usize,
    byte_type: i32,
    exec_only: i32,
    out_entries: *mut OnyxCodecaveEntry,
    max_entries: u32,
    out_count: *mut u32,
) -> i32 {
    if handle.is_null() || out_entries.is_null() || max_entries == 0 {
        return -1;
    }

    let cave_type = match byte_type {
        0 => CaveByteType::Int3,
        1 => CaveByteType::Nop,
        2 => CaveByteType::Zero,
        _ => CaveByteType::AnyPadding,
    };

    match CodecaveScanner::scan_process(&*handle, start, stop, min_size, cave_type, exec_only != 0)
    {
        Ok(caves) => {
            if !out_count.is_null() {
                *out_count = caves.len() as u32;
            }
            let write_len = caves.len().min(max_entries as usize);
            for i in 0..write_len {
                *out_entries.add(i) = OnyxCodecaveEntry {
                    address: caves[i].address,
                    size: caves[i].size,
                    byte_value: caves[i].byte_value,
                };
            }
            write_len as i32
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_scan_rip_relative(
    handle: *mut Process,
    start: usize,
    stop: usize,
    target_address: usize,
    has_target_filter: i32,
    out_matches: *mut OnyxRipRelativeMatch,
    max_matches: u32,
    out_count: *mut u32,
) -> i32 {
    if handle.is_null() || out_matches.is_null() || max_matches == 0 {
        return -1;
    }

    let filter = if has_target_filter != 0 {
        Some(target_address)
    } else {
        None
    };

    match RipRelativeScanner::scan_range(&*handle, start, stop, filter) {
        Ok(matches) => {
            if !out_count.is_null() {
                *out_count = matches.len() as u32;
            }
            let write_len = matches.len().min(max_matches as usize);
            for i in 0..write_len {
                let mut m_entry = OnyxRipRelativeMatch {
                    instruction_address: matches[i].instruction_address,
                    target_address: matches[i].target_address,
                    mnemonic: [0u8; 32],
                    operands: [0u8; 96],
                };
                let m_bytes = matches[i].mnemonic.as_bytes();
                let m_len = m_bytes.len().min(31);
                m_entry.mnemonic[..m_len].copy_from_slice(&m_bytes[..m_len]);

                let op_bytes = matches[i].operands.as_bytes();
                let op_len = op_bytes.len().min(95);
                m_entry.operands[..op_len].copy_from_slice(&op_bytes[..op_len]);

                *out_matches.add(i) = m_entry;
            }
            write_len as i32
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_generate_aob_signature(
    handle: *mut Process,
    target_address: usize,
    scan_start: usize,
    scan_stop: usize,
    max_len: usize,
    out_result: *mut OnyxSignatureResult,
) -> i32 {
    if handle.is_null() || out_result.is_null() || max_len == 0 {
        return -1;
    }

    match SignatureMaker::generate_signature(
        &*handle,
        target_address,
        scan_start,
        scan_stop,
        max_len,
    ) {
        Ok(sig) => {
            let mut res = OnyxSignatureResult {
                pattern: [0u8; 256],
                length: sig.length,
                match_count: sig.match_count,
                is_unique: if sig.is_unique { 1 } else { 0 },
            };

            let p_bytes = sig.pattern.as_bytes();
            let p_len = p_bytes.len().min(255);
            res.pattern[..p_len].copy_from_slice(&p_bytes[..p_len]);

            *out_result = res;
            1
        }
        Err(_) => -1,
    }
}

fn build_aob_validation(pattern: &str, buffer: &[u8]) -> OnyxAobValidation {
    let v = AobValidator::validate(pattern, buffer);
    let mut result = OnyxAobValidation {
        valid: if v.valid { 1 } else { 0 },
        byte_len: v.byte_len as u32,
        wildcard_count: v.wildcard_count as u32,
        match_count: v.match_count,
        is_unique: if v.is_unique { 1 } else { 0 },
        error_index: v.error.as_ref().map(|e| e.token_index as i32).unwrap_or(-1),
        warning_flags: v.warning_flags(),
        first_match: v.match_offsets.first().copied().unwrap_or(usize::MAX),
        message: [0u8; 160],
    };

    if let Some(err) = &v.error {
        let text = format!("token {} ({}): {}", err.token_index, err.token, err.message);
        let bytes = text.as_bytes();
        let len = bytes.len().min(159);
        result.message[..len].copy_from_slice(&bytes[..len]);
    }

    result
}

#[no_mangle]
pub unsafe extern "C" fn onyx_validate_aob(
    pattern: *const u8,
    pattern_len: usize,
    buffer: *const u8,
    buffer_len: usize,
    out_result: *mut OnyxAobValidation,
) -> i32 {
    if out_result.is_null() {
        return -1;
    }

    let pattern_str = if pattern.is_null() || pattern_len == 0 {
        String::new()
    } else {
        String::from_utf8_lossy(std::slice::from_raw_parts(pattern, pattern_len)).to_string()
    };

    let buffer_slice: &[u8] = if buffer.is_null() || buffer_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(buffer, buffer_len)
    };

    *out_result = build_aob_validation(&pattern_str, buffer_slice);
    1
}

#[no_mangle]
pub unsafe extern "C" fn onyx_validate_aob_in_process(
    handle: *mut Process,
    pattern: *const u8,
    pattern_len: usize,
    start: usize,
    stop: usize,
    out_result: *mut OnyxAobValidation,
) -> i32 {
    if handle.is_null() || out_result.is_null() {
        return -1;
    }

    let pattern_str = if pattern.is_null() || pattern_len == 0 {
        String::new()
    } else {
        String::from_utf8_lossy(std::slice::from_raw_parts(pattern, pattern_len)).to_string()
    };

    let len = stop.saturating_sub(start).min(64 * 1024 * 1024);
    let buffer = match (*handle).read_bytes(start, len) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };

    *out_result = build_aob_validation(&pattern_str, &buffer);
    1
}
