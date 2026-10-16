// language: Rust, file: scanner.rs, target: Windows 11, MSVC
// High-performance multi-threaded Cheat Engine memory scanner

use std::sync::{Arc, Mutex};
use std::thread;
use crate::process::{MemoryRegion, Process};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValType {
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    Float,
    Double,
    Str,
    Aob,
}

impl ValType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ValType::I8 => "Byte",
            ValType::U8 => "Byte (unsigned)",
            ValType::I16 => "2 Bytes",
            ValType::U16 => "2 Bytes (unsigned)",
            ValType::I32 => "4 Bytes",
            ValType::U32 => "4 Bytes (unsigned)",
            ValType::I64 => "8 Bytes",
            ValType::U64 => "8 Bytes (unsigned)",
            ValType::Float => "Float",
            ValType::Double => "Double",
            ValType::Str => "String",
            ValType::Aob => "Array of byte",
        }
    }

    pub fn size(&self) -> usize {
        match self {
            ValType::I8 | ValType::U8 => 1,
            ValType::I16 | ValType::U16 => 2,
            ValType::I32 | ValType::U32 | ValType::Float => 4,
            ValType::I64 | ValType::U64 | ValType::Double => 8,
            ValType::Str | ValType::Aob => 1,
        }
    }

    pub fn default_alignment(&self) -> usize {
        match self {
            ValType::I8 | ValType::U8 | ValType::Str | ValType::Aob => 1,
            ValType::I16 | ValType::U16 => 2,
            ValType::I32 | ValType::U32 | ValType::Float => 4,
            ValType::I64 | ValType::U64 | ValType::Double => 4, // CE default for 8-byte is often 4
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AobByte {
    pub value: u8,
    pub mask: u8,
}

impl AobByte {
    pub fn exact(b: u8) -> Self {
        AobByte { value: b, mask: 0xFF }
    }

    pub fn wildcard() -> Self {
        AobByte { value: 0, mask: 0x00 }
    }

    pub fn matches(&self, b: u8) -> bool {
        (b & self.mask) == (self.value & self.mask)
    }

    pub fn parse(token: &str) -> Result<Self, String> {
        let t = token.trim();
        if t == "?" || t == "??" {
            return Ok(Self::wildcard());
        }

        // CE 7.7 binary notation: |010**010|
        if t.starts_with('|') && t.ends_with('|') && t.len() >= 3 {
            let bits = &t[1..t.len() - 1];
            if bits.len() != 8 {
                return Err(format!("Binary AOB token must be exactly 8 bits, got: {}", t));
            }
            let mut value: u8 = 0;
            let mut mask: u8 = 0;
            for ch in bits.chars() {
                value <<= 1;
                mask <<= 1;
                match ch {
                    '1' => {
                        value |= 1;
                        mask |= 1;
                    }
                    '0' => {
                        mask |= 1;
                    }
                    '*' | '?' | 'x' | 'X' => {
                        // wildcard bit
                    }
                    _ => return Err(format!("Invalid char in binary token '{}' in {}", ch, t)),
                }
            }
            return Ok(AobByte { value, mask });
        }

        let hex_str = if t.starts_with("0x") || t.starts_with("0X") {
            &t[2..]
        } else {
            t
        };
        let b = u8::from_str_radix(hex_str, 16)
            .map_err(|_| format!("Invalid hex byte: {}", token))?;
        Ok(Self::exact(b))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScanValue {
    I8(i8),
    U8(u8),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    Float(f32),
    Double(f64),
    Str(String),
    Aob(Vec<AobByte>),
}

impl ScanValue {
    pub fn val_type(&self) -> ValType {
        match self {
            ScanValue::I8(_) => ValType::I8,
            ScanValue::U8(_) => ValType::U8,
            ScanValue::I16(_) => ValType::I16,
            ScanValue::U16(_) => ValType::U16,
            ScanValue::I32(_) => ValType::I32,
            ScanValue::U32(_) => ValType::U32,
            ScanValue::I64(_) => ValType::I64,
            ScanValue::U64(_) => ValType::U64,
            ScanValue::Float(_) => ValType::Float,
            ScanValue::Double(_) => ValType::Double,
            ScanValue::Str(_) => ValType::Str,
            ScanValue::Aob(_) => ValType::Aob,
        }
    }

    pub fn byte_len(&self) -> usize {
        match self {
            ScanValue::I8(_) | ScanValue::U8(_) => 1,
            ScanValue::I16(_) | ScanValue::U16(_) => 2,
            ScanValue::I32(_) | ScanValue::U32(_) | ScanValue::Float(_) => 4,
            ScanValue::I64(_) | ScanValue::U64(_) | ScanValue::Double(_) => 8,
            ScanValue::Str(s) => s.len(),
            ScanValue::Aob(v) => v.len(),
        }
    }

    pub fn parse(val_type: ValType, text: &str) -> Result<Self, String> {
        let trimmed = text.trim();
        let hex_stripped = if trimmed.starts_with('$') {
            Some(&trimmed[1..])
        } else if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
            Some(&trimmed[2..])
        } else {
            None
        };

        match val_type {
            ValType::I8 => {
                if let Some(h) = hex_stripped {
                    i8::from_str_radix(h, 16).map(ScanValue::I8).map_err(|e| e.to_string())
                } else {
                    trimmed.parse::<i8>().map(ScanValue::I8).map_err(|e| e.to_string())
                }
            }
            ValType::U8 => {
                if let Some(h) = hex_stripped {
                    u8::from_str_radix(h, 16).map(ScanValue::U8).map_err(|e| e.to_string())
                } else {
                    trimmed.parse::<u8>().map(ScanValue::U8).map_err(|e| e.to_string())
                }
            }
            ValType::I16 => {
                if let Some(h) = hex_stripped {
                    i16::from_str_radix(h, 16).map(ScanValue::I16).map_err(|e| e.to_string())
                } else {
                    trimmed.parse::<i16>().map(ScanValue::I16).map_err(|e| e.to_string())
                }
            }
            ValType::U16 => {
                if let Some(h) = hex_stripped {
                    u16::from_str_radix(h, 16).map(ScanValue::U16).map_err(|e| e.to_string())
                } else {
                    trimmed.parse::<u16>().map(ScanValue::U16).map_err(|e| e.to_string())
                }
            }
            ValType::I32 => {
                if let Some(h) = hex_stripped {
                    i32::from_str_radix(h, 16).map(ScanValue::I32).map_err(|e| e.to_string())
                } else {
                    trimmed.parse::<i32>().map(ScanValue::I32).map_err(|e| e.to_string())
                }
            }
            ValType::U32 => {
                if let Some(h) = hex_stripped {
                    u32::from_str_radix(h, 16).map(ScanValue::U32).map_err(|e| e.to_string())
                } else {
                    trimmed.parse::<u32>().map(ScanValue::U32).map_err(|e| e.to_string())
                }
            }
            ValType::I64 => {
                if let Some(h) = hex_stripped {
                    i64::from_str_radix(h, 16).map(ScanValue::I64).map_err(|e| e.to_string())
                } else {
                    trimmed.parse::<i64>().map(ScanValue::I64).map_err(|e| e.to_string())
                }
            }
            ValType::U64 => {
                if let Some(h) = hex_stripped {
                    u64::from_str_radix(h, 16).map(ScanValue::U64).map_err(|e| e.to_string())
                } else {
                    trimmed.parse::<u64>().map(ScanValue::U64).map_err(|e| e.to_string())
                }
            }
            ValType::Float => trimmed.parse::<f32>().map(ScanValue::Float).map_err(|e| e.to_string()),
            ValType::Double => trimmed.parse::<f64>().map(ScanValue::Double).map_err(|e| e.to_string()),
            ValType::Str => Ok(ScanValue::Str(trimmed.to_string())),
            ValType::Aob => {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                let mut pattern = Vec::new();
                for p in parts {
                    pattern.push(AobByte::parse(p)?);
                }
                if pattern.is_empty() {
                    return Err("Empty AOB pattern".to_string());
                }
                Ok(ScanValue::Aob(pattern))
            }
        }
    }

    pub fn read_from_bytes(val_type: ValType, buf: &[u8]) -> Option<Self> {
        if buf.len() < val_type.size() {
            return None;
        }
        match val_type {
            ValType::I8 => Some(ScanValue::I8(buf[0] as i8)),
            ValType::U8 => Some(ScanValue::U8(buf[0])),
            ValType::I16 => Some(ScanValue::I16(i16::from_ne_bytes([buf[0], buf[1]]))),
            ValType::U16 => Some(ScanValue::U16(u16::from_ne_bytes([buf[0], buf[1]]))),
            ValType::I32 => Some(ScanValue::I32(i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]))),
            ValType::U32 => Some(ScanValue::U32(u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]))),
            ValType::I64 => Some(ScanValue::I64(i64::from_ne_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]))),
            ValType::U64 => Some(ScanValue::U64(u64::from_ne_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]))),
            ValType::Float => Some(ScanValue::Float(f32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]))),
            ValType::Double => Some(ScanValue::Double(f64::from_ne_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]))),
            ValType::Str => Some(ScanValue::Str(String::from_utf8_lossy(buf).to_string())),
            ValType::Aob => Some(ScanValue::Aob(buf.iter().map(|&b| AobByte::exact(b)).collect())),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            ScanValue::I8(v) => vec![*v as u8],
            ScanValue::U8(v) => vec![*v],
            ScanValue::I16(v) => v.to_ne_bytes().to_vec(),
            ScanValue::U16(v) => v.to_ne_bytes().to_vec(),
            ScanValue::I32(v) => v.to_ne_bytes().to_vec(),
            ScanValue::U32(v) => v.to_ne_bytes().to_vec(),
            ScanValue::I64(v) => v.to_ne_bytes().to_vec(),
            ScanValue::U64(v) => v.to_ne_bytes().to_vec(),
            ScanValue::Float(v) => v.to_ne_bytes().to_vec(),
            ScanValue::Double(v) => v.to_ne_bytes().to_vec(),
            ScanValue::Str(s) => s.as_bytes().to_vec(),
            ScanValue::Aob(v) => v.iter().map(|b| b.value).collect(),
        }
    }

    pub fn to_display_string(&self) -> String {
        match self {
            ScanValue::I8(v) => format!("{}", v),
            ScanValue::U8(v) => format!("{} (0x{:02X})", v, v),
            ScanValue::I16(v) => format!("{}", v),
            ScanValue::U16(v) => format!("{} (0x{:04X})", v, v),
            ScanValue::I32(v) => format!("{} (0x{:08X})", v, v),
            ScanValue::U32(v) => format!("{} (0x{:08X})", v, v),
            ScanValue::I64(v) => format!("{} (0x{:016X})", v, v),
            ScanValue::U64(v) => format!("{} (0x{:016X})", v, v),
            ScanValue::Float(v) => format!("{:.4}", v),
            ScanValue::Double(v) => format!("{:.6}", v),
            ScanValue::Str(s) => format!("\"{}\"", s),
            ScanValue::Aob(p) => {
                let bytes: Vec<String> = p.iter().map(|b| {
                    if b.mask == 0xFF {
                        format!("{:02X}", b.value)
                    } else if b.mask == 0x00 {
                        "??".to_string()
                    } else {
                        let mut s = String::with_capacity(10);
                        s.push('|');
                        for bit in (0..8).rev() {
                            if (b.mask & (1 << bit)) == 0 {
                                s.push('*');
                            } else if (b.value & (1 << bit)) != 0 {
                                s.push('1');
                            } else {
                                s.push('0');
                            }
                        }
                        s.push('|');
                        s
                    }
                }).collect();
                bytes.join(" ")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ScanCondition {
    Exact(ScanValue),
    Increased,
    Decreased,
    Changed,
    Unchanged,
    IncreasedBy(ScanValue),
    DecreasedBy(ScanValue),
    BiggerThan(ScanValue),
    SmallerThan(ScanValue),
    Between(ScanValue, ScanValue),
    UnknownInitial,
}

#[derive(Debug, Clone)]
pub struct ScanCandidate {
    pub address: usize,
    pub current_value: ScanValue,
    pub previous_value: ScanValue,
}

pub struct Scanner {
    pub val_type: ValType,
    pub alignment: usize,
    pub candidates: Vec<ScanCandidate>,
    pub history: Vec<Vec<ScanCandidate>>,
    pub scan_count: usize,
    pub start_addr: usize,
    pub stop_addr: usize,
    pub writable_only: bool,
    pub executable: bool,
    pub copy_on_write: bool,
    pub fast_scan: bool,
}

impl Scanner {
    pub fn new(val_type: ValType) -> Self {
        let align = val_type.default_alignment();
        Scanner {
            val_type,
            alignment: align,
            candidates: Vec::new(),
            history: Vec::new(),
            scan_count: 0,
            start_addr: 0x0000000000000000,
            stop_addr: 0x7FFFFFFFFFFF,
            writable_only: true,
            executable: false,
            copy_on_write: false,
            fast_scan: true,
        }
    }

    pub fn set_alignment(&mut self, align: usize) {
        self.alignment = align.max(1);
    }

    pub fn undo_scan(&mut self) -> bool {
        if let Some(prev) = self.history.pop() {
            self.candidates = prev;
            self.scan_count = self.scan_count.saturating_sub(1);
            true
        } else {
            false
        }
    }

    pub fn first_scan(&mut self, proc: &Process, condition: ScanCondition) -> Result<usize, String> {
        let all_regions = proc.regions(self.writable_only)?;
        let start = self.start_addr;
        let stop = if self.stop_addr == 0 { usize::MAX } else { self.stop_addr };

        let regions: Vec<MemoryRegion> = all_regions
            .into_iter()
            .filter(|r| {
                let r_end = r.base.saturating_add(r.size);
                if r_end <= start || r.base >= stop {
                    return false;
                }
                if !self.executable && r.is_executable() && !r.is_writable() {
                    return false;
                }
                true
            })
            .collect();

        let val_type = self.val_type;
        let alignment = if self.fast_scan { self.alignment } else { 1 };
        let cond = condition.clone();

        let results = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();

        let num_cpus = thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        let chunks: Vec<Vec<MemoryRegion>> = regions
            .chunks((regions.len() / num_cpus).max(1))
            .map(|c| c.to_vec())
            .collect();

        let proc_handle = proc.handle as usize;
        let proc_pid = proc.pid;
        let proc_mode = proc.access_mode;
        let proc_dbk = proc.dbk.clone();

        for chunk in chunks {
            let res_clone = Arc::clone(&results);
            let cond_clone = cond.clone();
            let chunk_dbk = proc_dbk.clone();

            let handle = thread::spawn(move || {
                let dummy_proc = Process {
                    pid: proc_pid,
                    handle: proc_handle as crate::win32::HANDLE,
                    name: String::new(),
                    access_mode: proc_mode,
                    dbk: chunk_dbk,
                };

                let mut local_candidates = Vec::new();
                for region in chunk {
                    // Read in 512KB chunks
                    let chunk_size = 512 * 1024;
                    let mut offset = 0;

                    while offset < region.size {
                        let cur_size = (region.size - offset).min(chunk_size);
                        let cur_addr = region.base + offset;

                        let mut buf = vec![0u8; cur_size];
                        if let Ok(bytes_read) = dummy_proc.read_raw(cur_addr, &mut buf) {
                            if bytes_read >= val_type.size() {
                                scan_buffer(
                                    cur_addr,
                                    &buf[..bytes_read],
                                    val_type,
                                    alignment,
                                    &cond_clone,
                                    &mut local_candidates,
                                );
                            }
                        }
                        offset += cur_size;
                    }
                }

                // Prevent drop closing handle
                std::mem::forget(dummy_proc);

                let mut lock = res_clone.lock().unwrap();
                lock.extend(local_candidates);
            });
            handles.push(handle);
        }

        for h in handles {
            let _ = h.join();
        }

        let mut collected = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
        collected.sort_by_key(|c| c.address);

        self.history.push(std::mem::take(&mut self.candidates));
        self.candidates = collected;
        self.scan_count = 1;
        Ok(self.candidates.len())
    }

    pub fn next_scan(&mut self, proc: &Process, condition: ScanCondition) -> Result<usize, String> {
        if self.candidates.is_empty() {
            return Err("No candidates available for Next Scan. Run First Scan first.".to_string());
        }

        let val_size = self.val_type.size();
        let val_type = self.val_type;
        let num_cpus = thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        let chunk_size = (self.candidates.len() / num_cpus).max(1);
        let chunks: Vec<Vec<ScanCandidate>> = self.candidates
            .chunks(chunk_size)
            .map(|c| c.to_vec())
            .collect();

        let proc_handle = proc.handle as usize;
        let proc_pid = proc.pid;
        let proc_mode = proc.access_mode;
        let proc_dbk = proc.dbk.clone();
        let cond = condition.clone();

        let results = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();

        for chunk in chunks {
            let res_clone = Arc::clone(&results);
            let cond_clone = cond.clone();
            let chunk_dbk = proc_dbk.clone();

            let handle = thread::spawn(move || {
                let dummy_proc = Process {
                    pid: proc_pid,
                    handle: proc_handle as crate::win32::HANDLE,
                    name: String::new(),
                    access_mode: proc_mode,
                    dbk: chunk_dbk,
                };

                let mut local = Vec::new();
                let mut page_buf = vec![0u8; 64 * 1024];
                let mut cached_page_base: usize = usize::MAX;
                let mut cached_page_len: usize = 0;

                for cand in &chunk {
                    let addr = cand.address;
                    let in_cache = addr >= cached_page_base
                        && (addr + val_size) <= (cached_page_base + cached_page_len);

                    if !in_cache {
                        let page_base = addr & !0xFFF;
                        if let Ok(bytes_read) = dummy_proc.read_raw(page_base, &mut page_buf) {
                            cached_page_base = page_base;
                            cached_page_len = bytes_read;
                        } else {
                            let mut single_buf = vec![0u8; val_size];
                            if dummy_proc.read_raw(addr, &mut single_buf).is_ok() {
                                if let Some(new_val) = ScanValue::read_from_bytes(val_type, &single_buf) {
                                    if matches_next_condition(&cand.current_value, &new_val, &cond_clone) {
                                        local.push(ScanCandidate {
                                            address: cand.address,
                                            current_value: new_val,
                                            previous_value: cand.current_value.clone(),
                                        });
                                    }
                                }
                            }
                            continue;
                        }
                    }

                    if addr >= cached_page_base && (addr + val_size) <= (cached_page_base + cached_page_len) {
                        let offset = addr - cached_page_base;
                        if let Some(new_val) = ScanValue::read_from_bytes(val_type, &page_buf[offset..offset + val_size]) {
                            if matches_next_condition(&cand.current_value, &new_val, &cond_clone) {
                                local.push(ScanCandidate {
                                    address: cand.address,
                                    current_value: new_val,
                                    previous_value: cand.current_value.clone(),
                                });
                            }
                        }
                    }
                }

                std::mem::forget(dummy_proc);
                let mut lock = res_clone.lock().unwrap();
                lock.extend(local);
            });
            handles.push(handle);
        }

        for h in handles {
            let _ = h.join();
        }

        let mut filtered = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
        filtered.sort_by_key(|c| c.address);

        self.history.push(self.candidates.clone());
        self.candidates = filtered;
        self.scan_count += 1;
        Ok(self.candidates.len())
    }

    pub fn results(&self, limit: usize) -> &[ScanCandidate] {
        let count = self.candidates.len().min(limit);
        &self.candidates[..count]
    }

    pub fn count(&self) -> usize {
        self.candidates.len()
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_i32_exact_avx2(
    base_addr: usize,
    buf: &[u8],
    target: i32,
    alignment: usize,
    val_type: ValType,
    out: &mut Vec<ScanCandidate>,
) {
    use core::arch::x86_64::*;

    let target_v = _mm256_set1_epi32(target);
    let len = buf.len();
    let mut i = 0;

    if alignment == 4 {
        while i + 32 <= len {
            let chunk_v = unsafe {
                let chunk_ptr = buf.as_ptr().add(i) as *const __m256i;
                _mm256_loadu_si256(chunk_ptr)
            };
            let cmp = _mm256_cmpeq_epi32(chunk_v, target_v);
            let mask = _mm256_movemask_epi8(cmp) as u32;

            if mask != 0 {
                for k in 0..8 {
                    if (mask & (0xF << (k * 4))) == (0xF << (k * 4)) {
                        let addr = base_addr + i + k * 4;
                        let cand_val = if val_type == ValType::U32 {
                            ScanValue::U32(target as u32)
                        } else {
                            ScanValue::I32(target)
                        };
                        out.push(ScanCandidate {
                            address: addr,
                            current_value: cand_val.clone(),
                            previous_value: cand_val,
                        });
                    }
                }
            }
            i += 32;
        }
    }

    while i + 4 <= len {
        let v = i32::from_ne_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        if v == target {
            let cand_val = if val_type == ValType::U32 {
                ScanValue::U32(target as u32)
            } else {
                ScanValue::I32(target)
            };
            out.push(ScanCandidate {
                address: base_addr + i,
                current_value: cand_val.clone(),
                previous_value: cand_val,
            });
        }
        i += alignment;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_float_exact_avx2(
    base_addr: usize,
    buf: &[u8],
    target: f32,
    alignment: usize,
    out: &mut Vec<ScanCandidate>,
) {
    use core::arch::x86_64::*;

    let target_v = _mm256_set1_ps(target);
    let epsilon_v = _mm256_set1_ps(0.0001);
    let sign_mask = _mm256_set1_ps(-0.0);
    let len = buf.len();
    let mut i = 0;

    if alignment == 4 {
        while i + 32 <= len {
            let chunk_v = unsafe {
                let chunk_ptr = buf.as_ptr().add(i) as *const f32;
                _mm256_loadu_ps(chunk_ptr)
            };
            let diff = _mm256_sub_ps(chunk_v, target_v);
            let abs_diff = _mm256_andnot_ps(sign_mask, diff);
            let cmp = _mm256_cmp_ps(abs_diff, epsilon_v, _CMP_LT_OQ);
            let mask = _mm256_movemask_ps(cmp);

            if mask != 0 {
                for k in 0..8 {
                    if (mask & (1 << k)) != 0 {
                        let addr = base_addr + i + k * 4;
                        let cand_val = ScanValue::Float(target);
                        out.push(ScanCandidate {
                            address: addr,
                            current_value: cand_val.clone(),
                            previous_value: cand_val,
                        });
                    }
                }
            }
            i += 32;
        }
    }

    while i + 4 <= len {
        let v = f32::from_ne_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        if (v - target).abs() < 0.0001 {
            let cand_val = ScanValue::Float(v);
            out.push(ScanCandidate {
                address: base_addr + i,
                current_value: cand_val.clone(),
                previous_value: cand_val,
            });
        }
        i += alignment;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_u8_exact_avx2(
    base_addr: usize,
    buf: &[u8],
    target: u8,
    alignment: usize,
    val_type: ValType,
    out: &mut Vec<ScanCandidate>,
) {
    use core::arch::x86_64::*;

    let target_v = _mm256_set1_epi8(target as i8);
    let len = buf.len();
    let mut i = 0;

    if alignment == 1 {
        while i + 32 <= len {
            let chunk_v = unsafe {
                let chunk_ptr = buf.as_ptr().add(i) as *const __m256i;
                _mm256_loadu_si256(chunk_ptr)
            };
            let cmp = _mm256_cmpeq_epi8(chunk_v, target_v);
            let mut mask = _mm256_movemask_epi8(cmp) as u32;

            while mask != 0 {
                let tz = mask.trailing_zeros() as usize;
                let addr = base_addr + i + tz;
                let cand_val = if val_type == ValType::I8 {
                    ScanValue::I8(target as i8)
                } else {
                    ScanValue::U8(target)
                };
                out.push(ScanCandidate {
                    address: addr,
                    current_value: cand_val.clone(),
                    previous_value: cand_val,
                });
                mask &= mask - 1;
            }
            i += 32;
        }
    }

    while i < len {
        if buf[i] == target {
            let cand_val = if val_type == ValType::I8 {
                ScanValue::I8(target as i8)
            } else {
                ScanValue::U8(target)
            };
            out.push(ScanCandidate {
                address: base_addr + i,
                current_value: cand_val.clone(),
                previous_value: cand_val,
            });
        }
        i += alignment;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_aob_exact_avx2(
    base_addr: usize,
    buf: &[u8],
    pattern: &[AobByte],
    alignment: usize,
    out: &mut Vec<ScanCandidate>,
) {
    use core::arch::x86_64::*;

    let pat_len = pattern.len();
    let len = buf.len();
    if len < pat_len {
        return;
    }

    let max_idx = len - pat_len;

    // Find the first non-wildcard byte to use as anchor
    let anchor_info = pattern.iter().enumerate().find(|(_, b)| b.mask == 0xFF);

    if let (Some((anchor_idx, anchor_byte)), 1) = (anchor_info, alignment) {
        let anchor_v = _mm256_set1_epi8(anchor_byte.value as i8);
        let mut i = 0;

        while i + 32 <= len {
            let chunk_ptr = unsafe { buf.as_ptr().add(i) as *const __m256i };
            let chunk_v = unsafe { _mm256_loadu_si256(chunk_ptr) };
            let cmp = _mm256_cmpeq_epi8(chunk_v, anchor_v);
            let mut mask = _mm256_movemask_epi8(cmp) as u32;

            while mask != 0 {
                let tz = mask.trailing_zeros() as usize;
                let cand_idx = i + tz;
                if cand_idx >= anchor_idx {
                    let start_idx = cand_idx - anchor_idx;
                    if start_idx <= max_idx {
                        let mut matched = true;
                        for (p_idx, pat_byte) in pattern.iter().enumerate() {
                            if !pat_byte.matches(buf[start_idx + p_idx]) {
                                matched = false;
                                break;
                            }
                        }
                        if matched {
                            let cand_bytes: Vec<AobByte> = buf[start_idx..start_idx + pat_len]
                                .iter()
                                .map(|&b| AobByte::exact(b))
                                .collect();
                            let cand_val = ScanValue::Aob(cand_bytes);
                            out.push(ScanCandidate {
                                address: base_addr + start_idx,
                                current_value: cand_val.clone(),
                                previous_value: cand_val,
                            });
                        }
                    }
                }
                mask &= mask - 1;
            }
            i += 32;
        }

        // Tail bytes
        let mut tail_idx = if len >= 32 { len - 32 } else { 0 };
        if tail_idx <= max_idx {
            while tail_idx <= max_idx {
                let mut matched = true;
                for (p_idx, pat_byte) in pattern.iter().enumerate() {
                    if !pat_byte.matches(buf[tail_idx + p_idx]) {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    let addr = base_addr + tail_idx;
                    if !out.iter().any(|c| c.address == addr) {
                        let cand_bytes: Vec<AobByte> = buf[tail_idx..tail_idx + pat_len]
                            .iter()
                            .map(|&b| AobByte::exact(b))
                            .collect();
                        let cand_val = ScanValue::Aob(cand_bytes);
                        out.push(ScanCandidate {
                            address: addr,
                            current_value: cand_val.clone(),
                            previous_value: cand_val,
                        });
                    }
                }
                tail_idx += alignment;
            }
        }
        return;
    }

    // Fallback scalar loop
    let mut i = 0;
    while i <= max_idx {
        let mut matched = true;
        for (p_idx, pat_byte) in pattern.iter().enumerate() {
            if !pat_byte.matches(buf[i + p_idx]) {
                matched = false;
                break;
            }
        }
        if matched {
            let cand_bytes: Vec<AobByte> = buf[i..i + pat_len]
                .iter()
                .map(|&b| AobByte::exact(b))
                .collect();
            let cand_val = ScanValue::Aob(cand_bytes);
            out.push(ScanCandidate {
                address: base_addr + i,
                current_value: cand_val.clone(),
                previous_value: cand_val,
            });
        }
        i += alignment;
    }
}

fn scan_buffer(
    base_addr: usize,
    buf: &[u8],
    val_type: ValType,
    alignment: usize,
    cond: &ScanCondition,
    out: &mut Vec<ScanCandidate>,
) {
    if let ScanCondition::Exact(ScanValue::Aob(pattern)) = cond {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") {
                unsafe {
                    scan_aob_exact_avx2(base_addr, buf, pattern, alignment, out);
                }
                return;
            }
        }

        let pat_len = pattern.len();
        if buf.len() < pat_len {
            return;
        }
        let max_idx = buf.len() - pat_len;
        let mut i = 0;
        while i <= max_idx {
            let mut matched = true;
            for (p_idx, pat_byte) in pattern.iter().enumerate() {
                if !pat_byte.matches(buf[i + p_idx]) {
                    matched = false;
                    break;
                }
            }
            if matched {
                let cand_bytes: Vec<AobByte> = buf[i..i + pat_len].iter().map(|&b| AobByte::exact(b)).collect();
                let cand_val = ScanValue::Aob(cand_bytes);
                out.push(ScanCandidate {
                    address: base_addr + i,
                    current_value: cand_val.clone(),
                    previous_value: cand_val,
                });
            }
            i += alignment;
        }
        return;
    }

    // SIMD AVX2 acceleration for Exact scans
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            match cond {
                ScanCondition::Exact(ScanValue::I32(v)) if val_type == ValType::I32 => {
                    unsafe { scan_i32_exact_avx2(base_addr, buf, *v, alignment, val_type, out); }
                    return;
                }
                ScanCondition::Exact(ScanValue::U32(v)) if val_type == ValType::U32 => {
                    unsafe { scan_i32_exact_avx2(base_addr, buf, *v as i32, alignment, val_type, out); }
                    return;
                }
                ScanCondition::Exact(ScanValue::Float(v)) if val_type == ValType::Float => {
                    unsafe { scan_float_exact_avx2(base_addr, buf, *v, alignment, out); }
                    return;
                }
                ScanCondition::Exact(ScanValue::U8(v)) if val_type == ValType::U8 => {
                    unsafe { scan_u8_exact_avx2(base_addr, buf, *v, alignment, val_type, out); }
                    return;
                }
                ScanCondition::Exact(ScanValue::I8(v)) if val_type == ValType::I8 => {
                    unsafe { scan_u8_exact_avx2(base_addr, buf, *v as u8, alignment, val_type, out); }
                    return;
                }
                _ => {}
            }
        }
    }

    let size = val_type.size();
    if buf.len() < size {
        return;
    }

    let max_idx = buf.len() - size;
    let mut i = 0;

    while i <= max_idx {
        if let Some(val) = ScanValue::read_from_bytes(val_type, &buf[i..i + size]) {
            if matches_first_condition(&val, cond) {
                out.push(ScanCandidate {
                    address: base_addr + i,
                    current_value: val.clone(),
                    previous_value: val,
                });
            }
        }
        i += alignment;
    }
}

fn matches_first_condition(val: &ScanValue, cond: &ScanCondition) -> bool {
    match cond {
        ScanCondition::Exact(target) => values_equal(val, target),
        ScanCondition::BiggerThan(target) => value_cmp(val, target) > 0,
        ScanCondition::SmallerThan(target) => value_cmp(val, target) < 0,
        ScanCondition::Between(low, high) => value_cmp(val, low) >= 0 && value_cmp(val, high) <= 0,
        ScanCondition::UnknownInitial => true,
        _ => false,
    }
}

fn matches_next_condition(old: &ScanValue, cur: &ScanValue, cond: &ScanCondition) -> bool {
    match cond {
        ScanCondition::Exact(target) => values_equal(cur, target),
        ScanCondition::Increased => value_cmp(cur, old) > 0,
        ScanCondition::Decreased => value_cmp(cur, old) < 0,
        ScanCondition::Changed => !values_equal(cur, old),
        ScanCondition::Unchanged => values_equal(cur, old),
        ScanCondition::BiggerThan(target) => value_cmp(cur, target) > 0,
        ScanCondition::SmallerThan(target) => value_cmp(cur, target) < 0,
        ScanCondition::Between(low, high) => value_cmp(cur, low) >= 0 && value_cmp(cur, high) <= 0,
        ScanCondition::IncreasedBy(diff) => matches_diff(old, cur, diff, true),
        ScanCondition::DecreasedBy(diff) => matches_diff(old, cur, diff, false),
        ScanCondition::UnknownInitial => true,
    }
}

fn values_equal(a: &ScanValue, b: &ScanValue) -> bool {
    match (a, b) {
        (ScanValue::I8(x), ScanValue::I8(y)) => x == y,
        (ScanValue::U8(x), ScanValue::U8(y)) => x == y,
        (ScanValue::I16(x), ScanValue::I16(y)) => x == y,
        (ScanValue::U16(x), ScanValue::U16(y)) => x == y,
        (ScanValue::I32(x), ScanValue::I32(y)) => x == y,
        (ScanValue::U32(x), ScanValue::U32(y)) => x == y,
        (ScanValue::I64(x), ScanValue::I64(y)) => x == y,
        (ScanValue::U64(x), ScanValue::U64(y)) => x == y,
        (ScanValue::Float(x), ScanValue::Float(y)) => (x - y).abs() < 0.0001,
        (ScanValue::Double(x), ScanValue::Double(y)) => (x - y).abs() < 0.000001,
        (ScanValue::Str(x), ScanValue::Str(y)) => x == y,
        (ScanValue::Aob(x), ScanValue::Aob(y)) => {
            if x.len() != y.len() {
                return false;
            }
            for (bx, by) in x.iter().zip(y.iter()) {
                let mask = bx.mask & by.mask;
                if (bx.value & mask) != (by.value & mask) {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

fn value_cmp(a: &ScanValue, b: &ScanValue) -> i32 {
    match (a, b) {
        (ScanValue::I8(x), ScanValue::I8(y)) => x.cmp(y) as i32,
        (ScanValue::U8(x), ScanValue::U8(y)) => x.cmp(y) as i32,
        (ScanValue::I16(x), ScanValue::I16(y)) => x.cmp(y) as i32,
        (ScanValue::U16(x), ScanValue::U16(y)) => x.cmp(y) as i32,
        (ScanValue::I32(x), ScanValue::I32(y)) => x.cmp(y) as i32,
        (ScanValue::U32(x), ScanValue::U32(y)) => x.cmp(y) as i32,
        (ScanValue::I64(x), ScanValue::I64(y)) => x.cmp(y) as i32,
        (ScanValue::U64(x), ScanValue::U64(y)) => x.cmp(y) as i32,
        (ScanValue::Float(x), ScanValue::Float(y)) => {
            if (x - y).abs() < 0.0001 { 0 } else if x > y { 1 } else { -1 }
        }
        (ScanValue::Double(x), ScanValue::Double(y)) => {
            if (x - y).abs() < 0.000001 { 0 } else if x > y { 1 } else { -1 }
        }
        _ => 0,
    }
}

fn matches_diff(old: &ScanValue, cur: &ScanValue, diff: &ScanValue, is_increase: bool) -> bool {
    match (old, cur, diff) {
        (ScanValue::I32(o), ScanValue::I32(c), ScanValue::I32(d)) => {
            if is_increase { c - o == *d } else { o - c == *d }
        }
        (ScanValue::U32(o), ScanValue::U32(c), ScanValue::U32(d)) => {
            if is_increase { c.wrapping_sub(*o) == *d } else { o.wrapping_sub(*c) == *d }
        }
        (ScanValue::Float(o), ScanValue::Float(c), ScanValue::Float(d)) => {
            let actual = if is_increase { c - o } else { o - c };
            (actual - d).abs() < 0.001
        }
        (ScanValue::Double(o), ScanValue::Double(c), ScanValue::Double(d)) => {
            let actual = if is_increase { c - o } else { o - c };
            (actual - d).abs() < 0.0001
        }
        _ => false,
    }
}
