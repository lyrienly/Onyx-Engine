// OnyxEngine Memory Scanner Backend API
// Ultra high-speed scanning engine exposed to Pascal / Lazarus

use std::ffi::CStr;
use std::os::raw::c_char;
use onyx_core::process::Process;
use onyx_core::scanner::{ScanCondition, ScanValue, Scanner, ValType};
use crate::types::OnyxScanCandidate;

fn map_val_type(idx: i32) -> ValType {
    match idx {
        // Direct CE TVariableType enum ordinals
        0 => ValType::I8,     // vtByte = 0
        1 => ValType::I16,    // vtWord = 1
        2 => ValType::I32,    // vtDword = 2
        3 => ValType::I64,    // vtQword = 3
        4 => ValType::Float,  // vtSingle = 4
        5 => ValType::Double, // vtDouble = 5
        6 | 7 | 16 => ValType::Str, // vtString = 6, vtUnicodeString = 7, vtCodePageString = 16
        8 | 15 => ValType::Aob,     // vtByteArray = 8, vtByteArrays = 15
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
        // CE TScanOption ordinals:
        // 0: soUnknownValue
        0 => Some(ScanCondition::UnknownInitial),
        // 1: soExactValue
        1 => ScanValue::parse(s.val_type, v1).ok().map(ScanCondition::Exact),
        // 2: soValueBetween
        2 => {
            let p1 = ScanValue::parse(s.val_type, v1).ok()?;
            let p2 = ScanValue::parse(s.val_type, v2).ok()?;
            Some(ScanCondition::Between(p1, p2))
        }
        // 3: soBiggerThan
        3 => ScanValue::parse(s.val_type, v1).ok().map(ScanCondition::BiggerThan),
        // 4: soSmallerThan
        4 => ScanValue::parse(s.val_type, v1).ok().map(ScanCondition::SmallerThan),
        // 5: soIncreasedValue
        5 => Some(ScanCondition::Increased),
        // 6: soIncreasedValueBy
        6 => ScanValue::parse(s.val_type, v1).ok().map(ScanCondition::IncreasedBy),
        // 7: soDecreasedValue
        7 => Some(ScanCondition::Decreased),
        // 8: soDecreasedValueBy
        8 => ScanValue::parse(s.val_type, v1).ok().map(ScanCondition::DecreasedBy),
        // 9: soChanged
        9 => Some(ScanCondition::Changed),
        // 10: soUnchanged
        10 => Some(ScanCondition::Unchanged),
        _ => None,
    }
}

/// Create a new scanner instance for a specific data type
#[no_mangle]
pub unsafe extern "C" fn onyx_scanner_create(val_type_idx: i32) -> *mut Scanner {
    let vt = map_val_type(val_type_idx);
    Box::into_raw(Box::new(Scanner::new(vt)))
}

/// Destroy a scanner instance
#[no_mangle]
pub unsafe extern "C" fn onyx_scanner_destroy(scanner: *mut Scanner) {
    if !scanner.is_null() {
        drop(Box::from_raw(scanner));
    }
}

/// Perform First Scan
/// Returns the number of found addresses, or -1 on error
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
    s.stop_addr = if stop_addr == 0 { 0x7FFFFFFFFFFFFFFF } else { stop_addr };
    s.writable_only = writable_only != 0;
    s.executable = executable != 0;
    s.copy_on_write = copy_on_write != 0;

    match s.first_scan(proc, condition) {
        Ok(count) => count as i64,
        Err(_) => -1,
    }
}

/// Perform Next Scan
/// Returns the number of found addresses remaining, or -1 on error
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

/// Undo previous scan
/// Returns 1 on success, 0 if no undo history available
#[no_mangle]
pub unsafe extern "C" fn onyx_scanner_undo(scanner: *mut Scanner) -> i32 {
    if scanner.is_null() {
        return 0;
    }
    let s = &mut *scanner;
    if s.undo_scan() { 1 } else { 0 }
}

/// Get total number of candidates found
#[no_mangle]
pub unsafe extern "C" fn onyx_scanner_get_count(scanner: *mut Scanner) -> i64 {
    if scanner.is_null() {
        return 0;
    }
    let s = &*scanner;
    s.candidates.len() as i64
}

/// Fetch found candidates into buffer
/// Returns number of items written
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

/// Save scanner results in Cheat Engine's native ADDRESSES.TMP format
/// Format: 7 bytes header [6, 'N', 'O', 'R', 'M', 'A', 'L'] followed by raw array of u64 addresses
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

    // 7-byte Pascal ShortString header: length byte (6) + "NORMAL"
    let header: [u8; 7] = [6, b'N', b'O', b'R', b'M', b'A', b'L'];
    if writer.write_all(&header).is_err() {
        return -1;
    }

    // Write all candidate addresses as raw 64-bit integers
    for c in &s.candidates {
        let addr_u64 = c.address as u64;
        if writer.write_all(&addr_u64.to_ne_bytes()).is_err() {
            return -1;
        }
    }

    if writer.flush().is_err() {
        return -1;
    }

    s.candidates.len() as i64
}
