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
    All,
    Group,
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
            ValType::All => "All",
            ValType::Group => "Grouped",
        }
    }

    pub fn size(&self) -> usize {
        match self {
            ValType::I8 | ValType::U8 | ValType::All | ValType::Group => 1,
            ValType::I16 | ValType::U16 => 2,
            ValType::I32 | ValType::U32 | ValType::Float => 4,
            ValType::I64 | ValType::U64 | ValType::Double => 8,
            ValType::Str | ValType::Aob => 1,
        }
    }

    pub fn default_alignment(&self) -> usize {
        match self {
            ValType::I8 | ValType::U8 | ValType::Str | ValType::Aob | ValType::All => 1,
            ValType::I16 | ValType::U16 => 2,
            ValType::I32 | ValType::U32 | ValType::Float | ValType::Group => 4,
            ValType::I64 | ValType::U64 | ValType::Double => 4,
        }
    }

    pub fn ce_type_ordinal(&self) -> u32 {
        match self {
            ValType::I8 | ValType::U8 => 0,
            ValType::I16 | ValType::U16 => 1,
            ValType::I32 | ValType::U32 => 2,
            ValType::I64 | ValType::U64 => 3,
            ValType::Float => 4,
            ValType::Double => 5,
            ValType::Str => 6,
            ValType::Aob => 8,
            ValType::All => 10,
            ValType::Group => 14,
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

    pub fn is_exact(&self) -> bool {
        self.mask == 0xFF
    }

    pub fn is_wildcard(&self) -> bool {
        self.mask == 0x00
    }

    fn nibble_hex(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    fn is_wild_char(c: u8) -> bool {
        c == b'?' || c == b'*'
    }

    pub fn parse(token: &str) -> Result<Self, String> {
        let t = token.trim();
        if t == "?" || t == "??" || t == "*" {
            return Ok(Self::wildcard());
        }

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

                    }
                    _ => return Err(format!("Invalid char in binary token '{}' in {}", ch, t)),
                }
            }
            return Ok(AobByte { value, mask });
        }

        if t.len() == 2 {
            let b = t.as_bytes();
            match (Self::is_wild_char(b[0]), Self::is_wild_char(b[1])) {
                (true, true) => return Ok(Self::wildcard()),
                (true, false) => {
                    let low = Self::nibble_hex(b[1])
                        .ok_or_else(|| format!("Invalid nibble wildcard: {}", t))?;
                    return Ok(AobByte { value: low, mask: 0x0F });
                }
                (false, true) => {
                    let high = Self::nibble_hex(b[0])
                        .ok_or_else(|| format!("Invalid nibble wildcard: {}", t))?;
                    return Ok(AobByte { value: high << 4, mask: 0xF0 });
                }
                (false, false) => {}
            }
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

    pub fn to_pattern_token(&self) -> String {
        match self.mask {
            0xFF => format!("{:02X}", self.value),
            0x00 => "??".to_string(),
            0xF0 => format!("{:X}?", self.value >> 4),
            0x0F => format!("?{:X}", self.value & 0x0F),
            _ => {
                let mut bits = String::from("|");
                for i in (0..8).rev() {
                    if (self.mask >> i) & 1 == 0 {
                        bits.push('?');
                    } else if (self.value >> i) & 1 == 1 {
                        bits.push('1');
                    } else {
                        bits.push('0');
                    }
                }
                bits.push('|');
                bits
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AllTargets {
    pub i8_val: Option<i8>,
    pub u8_val: Option<u8>,
    pub i16_val: Option<i16>,
    pub u16_val: Option<u16>,
    pub i32_val: Option<i32>,
    pub u32_val: Option<u32>,
    pub i64_val: Option<i64>,
    pub u64_val: Option<u64>,
    pub f32_val: Option<f32>,
    pub f64_val: Option<f64>,
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
    All(AllTargets),
    Group(crate::memory::group_scan::GroupScanConfig),
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
            ScanValue::All(_) => ValType::All,
            ScanValue::Group(_) => ValType::Group,
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
            ScanValue::All(_) => 1,
            ScanValue::Group(g) => g.blocksize,
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
            ValType::All => {
                let (i8_val, u8_val) = if let Some(h) = hex_stripped {
                    (i8::from_str_radix(h, 16).ok(), u8::from_str_radix(h, 16).ok())
                } else {
                    (trimmed.parse::<i8>().ok(), trimmed.parse::<u8>().ok())
                };

                let (i16_val, u16_val) = if let Some(h) = hex_stripped {
                    (i16::from_str_radix(h, 16).ok(), u16::from_str_radix(h, 16).ok())
                } else {
                    (trimmed.parse::<i16>().ok(), trimmed.parse::<u16>().ok())
                };

                let (i32_val, u32_val) = if let Some(h) = hex_stripped {
                    (i32::from_str_radix(h, 16).ok(), u32::from_str_radix(h, 16).ok())
                } else {
                    (trimmed.parse::<i32>().ok(), trimmed.parse::<u32>().ok())
                };

                let (i64_val, u64_val) = if let Some(h) = hex_stripped {
                    (i64::from_str_radix(h, 16).ok(), u64::from_str_radix(h, 16).ok())
                } else {
                    (trimmed.parse::<i64>().ok(), trimmed.parse::<u64>().ok())
                };

                let f32_val = if hex_stripped.is_some() {
                    None
                } else {
                    trimmed.parse::<f32>().ok().filter(|f| !f.is_nan() && !f.is_infinite())
                };

                let f64_val = if hex_stripped.is_some() {
                    None
                } else {
                    trimmed.parse::<f64>().ok().filter(|d| !d.is_nan() && !d.is_infinite())
                };

                if i8_val.is_none() && u8_val.is_none() && i16_val.is_none() && u16_val.is_none()
                    && i32_val.is_none() && u32_val.is_none() && i64_val.is_none() && u64_val.is_none()
                    && f32_val.is_none() && f64_val.is_none()
                {
                    return Err(format!("Cannot parse '{}' for All types scan", text));
                }

                Ok(ScanValue::All(AllTargets {
                    i8_val,
                    u8_val,
                    i16_val,
                    u16_val,
                    i32_val,
                    u32_val,
                    i64_val,
                    u64_val,
                    f32_val,
                    f64_val,
                }))
            }
            ValType::Group => {
                crate::memory::group_scan::GroupScanConfig::parse(text)
                    .map(ScanValue::Group)
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
            ValType::All => Some(ScanValue::U8(buf[0])),
            ValType::Group => None,
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
            ScanValue::All(_) | ScanValue::Group(_) => Vec::new(),
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
            ScanValue::All(_) => "All".to_string(),
            ScanValue::Group(g) => format!("Grouped ({} elements, blocksize {})", g.elements.len(), g.blocksize),
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
    pub extra_type: u32,
    pub group_offsets: Vec<u32>,
}

impl ScanCandidate {
    pub fn new(address: usize, current_value: ScanValue, extra_type: u32) -> Self {
        Self {
            address,
            previous_value: current_value.clone(),
            current_value,
            extra_type,
            group_offsets: Vec::new(),
        }
    }

    pub fn with_offsets(address: usize, current_value: ScanValue, extra_type: u32, group_offsets: Vec<u32>) -> Self {
        Self {
            address,
            previous_value: current_value.clone(),
            current_value,
            extra_type,
            group_offsets,
        }
    }
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
                let chunk_size = 512 * 1024;
                let mut buf = vec![0u8; chunk_size];

                let overlap = if let ScanCondition::Exact(ScanValue::Group(ref g)) = cond_clone {
                    g.blocksize.saturating_sub(1)
                } else {
                    0
                };

                for region in chunk {
                    let mut offset = 0;

                    while offset < region.size {
                        let cur_size = (region.size - offset).min(chunk_size);
                        let cur_addr = region.base + offset;

                        if let Ok(bytes_read) = dummy_proc.read_raw(cur_addr, &mut buf[..cur_size])
                            && bytes_read >= val_type.size() {
                                scan_buffer(
                                    cur_addr,
                                    &buf[..bytes_read],
                                    val_type,
                                    alignment,
                                    &cond_clone,
                                    &mut local_candidates,
                                );
                            }
                        if offset + cur_size < region.size {
                            offset += cur_size.saturating_sub(overlap);
                        } else {
                            break;
                        }
                    }
                }

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
                    let (cand_size, cand_val_type) = if val_type == ValType::All {
                        match cand.extra_type {
                            0 => (1, ValType::U8),
                            1 => (2, ValType::U16),
                            2 => (4, ValType::U32),
                            3 => (8, ValType::U64),
                            4 => (4, ValType::Float),
                            5 => (8, ValType::Double),
                            _ => (val_size, val_type),
                        }
                    } else {
                        (val_size, val_type)
                    };

                    let in_cache = addr >= cached_page_base
                        && (addr + cand_size) <= (cached_page_base + cached_page_len);

                    if !in_cache {
                        let page_base = addr & !0xFFF;
                        if let Ok(bytes_read) = dummy_proc.read_raw(page_base, &mut page_buf) {
                            cached_page_base = page_base;
                            cached_page_len = bytes_read;
                        } else {
                            let mut single_buf = vec![0u8; cand_size];
                            if dummy_proc.read_raw(addr, &mut single_buf).is_ok()
                                && let Some(new_val) = ScanValue::read_from_bytes(cand_val_type, &single_buf)
                                    && check_candidate_condition(cand, &new_val, &cond_clone, val_type) {
                                        local.push(ScanCandidate {
                                            address: cand.address,
                                            current_value: new_val,
                                            previous_value: cand.current_value.clone(),
                                            extra_type: cand.extra_type,
                                            group_offsets: cand.group_offsets.clone(),
                                        });
                                    }
                            continue;
                        }
                    }

                    if addr >= cached_page_base && (addr + cand_size) <= (cached_page_base + cached_page_len) {
                        let offset = addr - cached_page_base;
                        if let Some(new_val) = ScanValue::read_from_bytes(cand_val_type, &page_buf[offset..offset + cand_size])
                            && check_candidate_condition(cand, &new_val, &cond_clone, val_type) {
                                local.push(ScanCandidate {
                                    address: cand.address,
                                    current_value: new_val,
                                    previous_value: cand.current_value.clone(),
                                    extra_type: cand.extra_type,
                                    group_offsets: cand.group_offsets.clone(),
                                });
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
                        out.push(ScanCandidate::new(addr, cand_val, val_type.ce_type_ordinal()));
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
            out.push(ScanCandidate::new(base_addr + i, cand_val, val_type.ce_type_ordinal()));
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
                        out.push(ScanCandidate::new(addr, cand_val, 4));
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
            out.push(ScanCandidate::new(base_addr + i, cand_val, 4));
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
                out.push(ScanCandidate::new(addr, cand_val, val_type.ce_type_ordinal()));
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
            out.push(ScanCandidate::new(base_addr + i, cand_val, val_type.ce_type_ordinal()));
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
                            out.push(ScanCandidate::new(base_addr + start_idx, cand_val, 8));
                        }
                    }
                }
                mask &= mask - 1;
            }
            i += 32;
        }

        let mut tail_idx = len.saturating_sub(32);
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
                        out.push(ScanCandidate::new(addr, cand_val, 8));
                    }
                }
                tail_idx += alignment;
            }
        }
        return;
    }

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
            out.push(ScanCandidate::new(base_addr + i, cand_val, 8));
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
    if val_type == ValType::All {
        scan_buffer_all(base_addr, buf, alignment, cond, out);
        return;
    }

    if val_type == ValType::Group {
        if let ScanCondition::Exact(ScanValue::Group(cfg)) = cond {
            scan_buffer_group(base_addr, buf, cfg, out);
        }
        return;
    }

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
                out.push(ScanCandidate::new(base_addr + i, cand_val, 8));
            }
            i += alignment;
        }
        return;
    }

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
        if let Some(val) = ScanValue::read_from_bytes(val_type, &buf[i..i + size])
            && matches_first_condition(&val, cond) {
                out.push(ScanCandidate::new(base_addr + i, val, val_type.ce_type_ordinal()));
            }
        i += alignment;
    }
}

fn scan_buffer_group(
    base_addr: usize,
    buf: &[u8],
    cfg: &crate::memory::group_scan::GroupScanConfig,
    out: &mut Vec<ScanCandidate>,
) {
    if buf.len() < cfg.blocksize {
        return;
    }
    let max_idx = buf.len() - cfg.blocksize;
    let step = cfg.blockalignment.max(1);
    let mut i = 0;
    let mut offsets = Vec::with_capacity(cfg.elements.len());

    while i <= max_idx {
        if cfg.matches_block(&buf[i..], &mut offsets) {
            out.push(ScanCandidate::with_offsets(
                base_addr + i,
                ScanValue::Group(cfg.clone()),
                14,
                offsets.clone(),
            ));
        }
        i += step;
    }
}

fn scan_buffer_all(
    base_addr: usize,
    buf: &[u8],
    alignment: usize,
    cond: &ScanCondition,
    out: &mut Vec<ScanCandidate>,
) {
    let len = buf.len();
    let step = alignment.max(1);
    let mut i = 0;

    match cond {
        ScanCondition::Exact(ScanValue::All(targets)) => {
            while i < len {
                let addr = base_addr + i;
                let div2 = addr.is_multiple_of(2);
                let div4 = addr.is_multiple_of(4);

                if let Some(target) = targets.u8_val {
                    if buf[i] == target {
                        out.push(ScanCandidate::new(addr, ScanValue::U8(target), 0));
                    }
                } else if let Some(target) = targets.i8_val
                    && buf[i] as i8 == target {
                        out.push(ScanCandidate::new(addr, ScanValue::I8(target), 0));
                    }

                if div2 && i + 2 <= len {
                    let w = u16::from_ne_bytes([buf[i], buf[i + 1]]);
                    if let Some(target) = targets.u16_val {
                        if w == target {
                            out.push(ScanCandidate::new(addr, ScanValue::U16(target), 1));
                        }
                    } else if let Some(target) = targets.i16_val
                        && (w as i16) == target {
                            out.push(ScanCandidate::new(addr, ScanValue::I16(target), 1));
                        }
                }

                if div4 && i + 4 <= len {
                    let d = u32::from_ne_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
                    if let Some(target) = targets.u32_val {
                        if d == target {
                            out.push(ScanCandidate::new(addr, ScanValue::U32(target), 2));
                        }
                    } else if let Some(target) = targets.i32_val
                        && (d as i32) == target {
                            out.push(ScanCandidate::new(addr, ScanValue::I32(target), 2));
                        }

                    if let Some(target_f) = targets.f32_val {
                        let f = f32::from_ne_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
                        if !f.is_nan() && !f.is_infinite() && (f - target_f).abs() < 0.001 {
                            out.push(ScanCandidate::new(addr, ScanValue::Float(f), 4));
                        }
                    }
                }

                if div4 && i + 8 <= len {
                    let q = u64::from_ne_bytes([
                        buf[i], buf[i + 1], buf[i + 2], buf[i + 3],
                        buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7],
                    ]);
                    if let Some(target) = targets.u64_val {
                        if q == target {
                            out.push(ScanCandidate::new(addr, ScanValue::U64(target), 3));
                        }
                    } else if let Some(target) = targets.i64_val
                        && (q as i64) == target {
                            out.push(ScanCandidate::new(addr, ScanValue::I64(target), 3));
                        }

                    if let Some(target_d) = targets.f64_val {
                        let d = f64::from_ne_bytes([
                            buf[i], buf[i + 1], buf[i + 2], buf[i + 3],
                            buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7],
                        ]);
                        if !d.is_nan() && !d.is_infinite() && (d - target_d).abs() < 0.00001 {
                            out.push(ScanCandidate::new(addr, ScanValue::Double(d), 5));
                        }
                    }
                }

                i += step;
            }
        }
        ScanCondition::UnknownInitial => {
            while i < len {
                let addr = base_addr + i;
                let div2 = addr.is_multiple_of(2);
                let div4 = addr.is_multiple_of(4);

                let b = buf[i];
                out.push(ScanCandidate::new(addr, ScanValue::U8(b), 0));

                if div2 && i + 2 <= len {
                    let w = u16::from_ne_bytes([buf[i], buf[i + 1]]);
                    out.push(ScanCandidate::new(addr, ScanValue::U16(w), 1));
                }

                if div4 && i + 4 <= len {
                    let d = u32::from_ne_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
                    out.push(ScanCandidate::new(addr, ScanValue::U32(d), 2));

                    let f = f32::from_ne_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
                    if !f.is_nan() && !f.is_infinite() {
                        out.push(ScanCandidate::new(addr, ScanValue::Float(f), 4));
                    }
                }

                if div4 && i + 8 <= len {
                    let q = u64::from_ne_bytes([
                        buf[i], buf[i + 1], buf[i + 2], buf[i + 3],
                        buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7],
                    ]);
                    out.push(ScanCandidate::new(addr, ScanValue::U64(q), 3));

                    let d = f64::from_ne_bytes([
                        buf[i], buf[i + 1], buf[i + 2], buf[i + 3],
                        buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7],
                    ]);
                    if !d.is_nan() && !d.is_infinite() {
                        out.push(ScanCandidate::new(addr, ScanValue::Double(d), 5));
                    }
                }

                i += step;
            }
        }
        _ => {}
    }
}

fn check_candidate_condition(
    cand: &ScanCandidate,
    new_val: &ScanValue,
    cond: &ScanCondition,
    scan_val_type: ValType,
) -> bool {
    if scan_val_type == ValType::All
        && let ScanCondition::Exact(ScanValue::All(targets)) = cond {
            return match cand.extra_type {
                0 => {
                    if let Some(t) = targets.u8_val {
                        *new_val == ScanValue::U8(t)
                    } else if let Some(t) = targets.i8_val {
                        *new_val == ScanValue::I8(t)
                    } else {
                        false
                    }
                }
                1 => {
                    if let Some(t) = targets.u16_val {
                        *new_val == ScanValue::U16(t)
                    } else if let Some(t) = targets.i16_val {
                        *new_val == ScanValue::I16(t)
                    } else {
                        false
                    }
                }
                2 => {
                    if let Some(t) = targets.u32_val {
                        *new_val == ScanValue::U32(t)
                    } else if let Some(t) = targets.i32_val {
                        *new_val == ScanValue::I32(t)
                    } else {
                        false
                    }
                }
                3 => {
                    if let Some(t) = targets.u64_val {
                        *new_val == ScanValue::U64(t)
                    } else if let Some(t) = targets.i64_val {
                        *new_val == ScanValue::I64(t)
                    } else {
                        false
                    }
                }
                4 => {
                    if let Some(t) = targets.f32_val {
                        if let ScanValue::Float(f) = new_val {
                            (f - t).abs() < 0.001
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                5 => {
                    if let Some(t) = targets.f64_val {
                        if let ScanValue::Double(d) = new_val {
                            (d - t).abs() < 0.00001
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                _ => false,
            };
        }
    matches_next_condition(&cand.current_value, new_val, cond)
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
        (ScanValue::All(_), ScanValue::All(_)) => true,
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
        (ScanValue::I8(o), ScanValue::I8(c), ScanValue::I8(d)) => {
            let actual = if is_increase { c.wrapping_sub(*o) } else { o.wrapping_sub(*c) };
            actual == *d
        }
        (ScanValue::U8(o), ScanValue::U8(c), ScanValue::U8(d)) => {
            let actual = if is_increase { c.wrapping_sub(*o) } else { o.wrapping_sub(*c) };
            actual == *d
        }
        (ScanValue::I16(o), ScanValue::I16(c), ScanValue::I16(d)) => {
            let actual = if is_increase { c.wrapping_sub(*o) } else { o.wrapping_sub(*c) };
            actual == *d
        }
        (ScanValue::U16(o), ScanValue::U16(c), ScanValue::U16(d)) => {
            let actual = if is_increase { c.wrapping_sub(*o) } else { o.wrapping_sub(*c) };
            actual == *d
        }
        (ScanValue::I32(o), ScanValue::I32(c), ScanValue::I32(d)) => {
            let actual = if is_increase { c.wrapping_sub(*o) } else { o.wrapping_sub(*c) };
            actual == *d
        }
        (ScanValue::U32(o), ScanValue::U32(c), ScanValue::U32(d)) => {
            let actual = if is_increase { c.wrapping_sub(*o) } else { o.wrapping_sub(*c) };
            actual == *d
        }
        (ScanValue::I64(o), ScanValue::I64(c), ScanValue::I64(d)) => {
            let actual = if is_increase { c.wrapping_sub(*o) } else { o.wrapping_sub(*c) };
            actual == *d
        }
        (ScanValue::U64(o), ScanValue::U64(c), ScanValue::U64(d)) => {
            let actual = if is_increase { c.wrapping_sub(*o) } else { o.wrapping_sub(*c) };
            actual == *d
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aob_nibble_wildcards() {
        let high = AobByte::parse("A?").expect("A? should parse");
        assert_eq!(high.mask, 0xF0);
        assert_eq!(high.value, 0xA0);
        assert!(high.matches(0xA5));
        assert!(!high.matches(0x5A));
        assert!(!high.matches(0xB5));

        let low = AobByte::parse("?3").expect("?3 should parse");
        assert_eq!(low.mask, 0x0F);
        assert_eq!(low.value, 0x03);
        assert!(low.matches(0x13));
        assert!(!low.matches(0x31));

        assert!(AobByte::parse("?").unwrap().is_wildcard());
        assert!(AobByte::parse("??").unwrap().is_wildcard());
        assert!(AobByte::parse("*").unwrap().is_wildcard());
        assert!(AobByte::parse("FF").unwrap().is_exact());
    }

    #[test]
    fn test_aob_pattern_token_roundtrip() {
        let cases = vec![
            "FF", "00", "??", "A?", "?A", "|1?0?1?0?|", "|11110000|",
        ];
        for case in cases {
            let byte = AobByte::parse(case).unwrap_or_else(|e| panic!("failed {}: {}", case, e));
            let token = byte.to_pattern_token();
            let reparsed = AobByte::parse(&token).expect("roundtrip parse failed");
            assert_eq!(byte.value, reparsed.value, "value mismatch for {}", case);
            assert_eq!(byte.mask, reparsed.mask, "mask mismatch for {}", case);
        }
    }

    #[test]
    fn test_aob_pattern_matches_in_scan() {
        let pattern = ScanValue::parse(ValType::Aob, "A? ?3 FF").expect("pattern");
        if let ScanValue::Aob(bytes) = &pattern {
            assert_eq!(bytes.len(), 3);
            assert!(bytes[0].matches(0xAB));
            assert!(bytes[1].matches(0x53));
            assert!(bytes[2].matches(0xFF));
        } else {
            panic!("expected AOB value");
        }
    }

    #[test]
    fn test_val_type_all_parse() {
        let v = ScanValue::parse(ValType::All, "100").expect("Should parse 100 as All");
        if let ScanValue::All(targets) = v {
            assert_eq!(targets.u8_val, Some(100));
            assert_eq!(targets.u16_val, Some(100));
            assert_eq!(targets.u32_val, Some(100));
            assert_eq!(targets.u64_val, Some(100));
            assert_eq!(targets.f32_val, Some(100.0));
            assert_eq!(targets.f64_val, Some(100.0));
        } else {
            panic!("Expected ScanValue::All");
        }
    }

    #[test]
    fn test_scan_buffer_all_candidates() {

        let mut buf = vec![0u8; 32];
        let val_u32: u32 = 100;
        buf[0..4].copy_from_slice(&val_u32.to_ne_bytes());
        buf[8] = 100;

        let cond = ScanCondition::Exact(ScanValue::parse(ValType::All, "100").unwrap());
        let mut candidates = Vec::new();
        scan_buffer_all(0x1000, &buf, 1, &cond, &mut candidates);

        let addr_0_cands: Vec<_> = candidates.iter().filter(|c| c.address == 0x1000).collect();
        assert!(addr_0_cands.iter().any(|c| c.extra_type == 0));
        assert!(addr_0_cands.iter().any(|c| c.extra_type == 1));
        assert!(addr_0_cands.iter().any(|c| c.extra_type == 2));

        let addr_8_cands: Vec<_> = candidates.iter().filter(|c| c.address == 0x1008).collect();
        assert!(addr_8_cands.iter().any(|c| c.extra_type == 0));
    }

    #[test]
    fn test_group_scan_buffer_execution() {
        let cmd = "BA:4 4:100 4:200 4:300";
        let val = ScanValue::parse(ValType::Group, cmd).expect("Should parse group scan");
        let cond = ScanCondition::Exact(val);

        let mut buf = vec![0u8; 64];
        buf[8..12].copy_from_slice(&100u32.to_ne_bytes());
        buf[12..16].copy_from_slice(&200u32.to_ne_bytes());
        buf[16..20].copy_from_slice(&300u32.to_ne_bytes());

        let mut candidates = Vec::new();
        scan_buffer(0x5000, &buf, ValType::Group, 4, &cond, &mut candidates);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].address, 0x5000 + 8);
        assert_eq!(candidates[0].extra_type, 14);
        assert_eq!(candidates[0].group_offsets, vec![0, 4, 8]);
    }

    #[test]
    fn test_matches_diff_i32_extreme_values_do_not_overflow() {
        let old = ScanValue::I32(i32::MIN);
        let cur = ScanValue::I32(i32::MAX);
        assert!(!matches_diff(&old, &cur, &ScanValue::I32(1), true));
        assert!(!matches_diff(&cur, &old, &ScanValue::I32(1), false));

        assert!(matches_diff(
            &ScanValue::I32(10),
            &ScanValue::I32(12),
            &ScanValue::I32(2),
            true
        ));
        assert!(matches_diff(
            &ScanValue::I32(12),
            &ScanValue::I32(10),
            &ScanValue::I32(2),
            false
        ));
    }

    #[test]
    fn test_matches_diff_supports_all_integer_widths() {
        macro_rules! assert_diff {
            ($variant:ident, $v:expr) => {{
                let base = $v;
                let next = base + 5;
                assert!(matches_diff(
                    &ScanValue::$variant(base),
                    &ScanValue::$variant(next),
                    &ScanValue::$variant(5),
                    true
                ));
                assert!(matches_diff(
                    &ScanValue::$variant(next),
                    &ScanValue::$variant(base),
                    &ScanValue::$variant(5),
                    false
                ));
                assert!(!matches_diff(
                    &ScanValue::$variant(base),
                    &ScanValue::$variant(next),
                    &ScanValue::$variant(6),
                    true
                ));
            }};
        }

        assert_diff!(I8, 10i8);
        assert_diff!(U8, 10u8);
        assert_diff!(I16, 10i16);
        assert_diff!(U16, 10u16);
        assert_diff!(I32, 10i32);
        assert_diff!(U32, 10u32);
        assert_diff!(I64, 10i64);
        assert_diff!(U64, 10u64);
    }
}
