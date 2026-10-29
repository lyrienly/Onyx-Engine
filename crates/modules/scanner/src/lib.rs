
pub mod pattern;
pub mod smart;

use std::ffi::CStr;
use std::os::raw::c_char;
use onyx_core::process::Process;
use onyx_core::scanner::{ScanCondition, ScanValue, Scanner, ValType};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OnyxScanCandidate {
    pub address: usize,
    pub current_val: [u8; 64],
    pub previous_val: [u8; 64],
}

impl Default for OnyxScanCandidate {
    fn default() -> Self {
        Self {
            address: 0,
            current_val: [0u8; 64],
            previous_val: [0u8; 64],
        }
    }
}

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
        1 => ScanValue::parse(s.val_type, v1).ok().map(ScanCondition::Exact),
        2 => {
            let p1 = ScanValue::parse(s.val_type, v1).ok()?;
            let p2 = ScanValue::parse(s.val_type, v2).ok()?;
            Some(ScanCondition::Between(p1, p2))
        }
        3 => ScanValue::parse(s.val_type, v1).ok().map(ScanCondition::BiggerThan),
        4 => ScanValue::parse(s.val_type, v1).ok().map(ScanCondition::SmallerThan),
        5 => Some(ScanCondition::Increased),
        6 => ScanValue::parse(s.val_type, v1).ok().map(ScanCondition::IncreasedBy),
        7 => Some(ScanCondition::Decreased),
        8 => ScanValue::parse(s.val_type, v1).ok().map(ScanCondition::DecreasedBy),
        9 => Some(ScanCondition::Changed),
        10 => Some(ScanCondition::Unchanged),
        _ => None,
    }
}

#[no_mangle]
pub extern "C" fn onyx_scanner_module_ping() -> i32 {
    1
}

#[no_mangle]
pub extern "C" fn onyx_scanner_create(val_type_idx: i32) -> *mut Scanner {
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
    _is_hex: i32,
    _fast_scan: i32,
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
    let p = &*process;

    let v1 = parse_c_str(val1_str);
    let v2 = parse_c_str(val2_str);

    let cond = match resolve_condition(s, scan_type, &v1, &v2) {
        Some(c) => c,
        None => return -2,
    };

    if alignment > 0 {
        s.alignment = alignment;
    }
    if start_addr > 0 {
        s.start_addr = start_addr;
    }
    if stop_addr > 0 {
        s.stop_addr = stop_addr;
    }
    s.writable_only = writable_only != 0;
    s.executable = executable != 0;
    s.copy_on_write = copy_on_write != 0;

    match s.first_scan(p, cond) {
        Ok(count) => count as i64,
        Err(_) => -3,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_scanner_next_scan(
    scanner: *mut Scanner,
    process: *mut Process,
    scan_type: i32,
    val1_str: *const c_char,
    val2_str: *const c_char,
    _is_hex: i32,
) -> i64 {
    if scanner.is_null() || process.is_null() {
        return -1;
    }

    let s = &mut *scanner;
    let p = &*process;

    let v1 = parse_c_str(val1_str);
    let v2 = parse_c_str(val2_str);

    let cond = match resolve_condition(s, scan_type, &v1, &v2) {
        Some(c) => c,
        None => return -2,
    };

    match s.next_scan(p, cond) {
        Ok(count) => count as i64,
        Err(_) => -3,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_scanner_undo(scanner: *mut Scanner) -> i32 {
    if scanner.is_null() {
        return 0;
    }
    let s = &mut *scanner;
    if s.undo_scan() { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_scanner_get_count(scanner: *mut Scanner) -> i64 {
    if scanner.is_null() {
        return 0;
    }
    (*scanner).count() as i64
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
        let offset_count = s.candidates.first()
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

    let total = s.candidates.len();
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

    total as i64
}

