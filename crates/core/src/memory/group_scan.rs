use crate::memory::scanner::ValType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupScanType {
    Byte,
    Word,
    Dword,
    Qword,
    Float,
    Double,
    Str,
    Pointer,
    Wildcard,
}

impl GroupScanType {
    pub fn size(&self, ptr_size: usize) -> usize {
        match self {
            GroupScanType::Byte => 1,
            GroupScanType::Word => 2,
            GroupScanType::Dword | GroupScanType::Float => 4,
            GroupScanType::Qword | GroupScanType::Double => 8,
            GroupScanType::Pointer => ptr_size,
            GroupScanType::Str | GroupScanType::Wildcard => 1,
        }
    }

    pub fn alignment(&self, ptr_size: usize) -> usize {
        match self {
            GroupScanType::Byte | GroupScanType::Str | GroupScanType::Wildcard => 1,
            GroupScanType::Word => 2,
            GroupScanType::Dword | GroupScanType::Float => 4,
            GroupScanType::Qword | GroupScanType::Double | GroupScanType::Pointer => ptr_size.min(8),
        }
    }

    pub fn to_val_type(&self) -> ValType {
        match self {
            GroupScanType::Byte => ValType::U8,
            GroupScanType::Word => ValType::U16,
            GroupScanType::Dword => ValType::U32,
            GroupScanType::Qword => ValType::U64,
            GroupScanType::Float => ValType::Float,
            GroupScanType::Double => ValType::Double,
            GroupScanType::Str => ValType::Str,
            GroupScanType::Pointer => ValType::U64,
            GroupScanType::Wildcard => ValType::U8,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GroupElement {
    pub scan_type: GroupScanType,
    pub wildcard: bool,
    pub picked: bool,
    pub range: bool,
    pub signed: bool,
    pub offset: usize,
    pub bytesize: usize,
    pub value_int: u64,
    pub value_int2: u64,
    pub value_float: f64,
    pub value_float2: f64,
    pub value_str: String,
}

impl GroupElement {
    pub fn matches(&self, buf: &[u8]) -> bool {
        if self.wildcard {
            return true;
        }
        if buf.len() < self.bytesize {
            return false;
        }

        match self.scan_type {
            GroupScanType::Byte => {
                let v = buf[0];
                if self.range {
                    if self.signed {
                        let sv = v as i8;
                        sv >= self.value_int as i8 && sv <= self.value_int2 as i8
                    } else {
                        v >= self.value_int as u8 && v <= self.value_int2 as u8
                    }
                } else {
                    v == self.value_int as u8
                }
            }
            GroupScanType::Word => {
                let v = u16::from_ne_bytes([buf[0], buf[1]]);
                if self.range {
                    if self.signed {
                        let sv = v as i16;
                        sv >= self.value_int as i16 && sv <= self.value_int2 as i16
                    } else {
                        v >= self.value_int as u16 && v <= self.value_int2 as u16
                    }
                } else {
                    v == self.value_int as u16
                }
            }
            GroupScanType::Dword => {
                let v = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
                if self.range {
                    if self.signed {
                        let sv = v as i32;
                        sv >= self.value_int as i32 && sv <= self.value_int2 as i32
                    } else {
                        v >= self.value_int as u32 && v <= self.value_int2 as u32
                    }
                } else {
                    v == self.value_int as u32
                }
            }
            GroupScanType::Qword | GroupScanType::Pointer => {
                if buf.len() < 8 {
                    return false;
                }
                let v = u64::from_ne_bytes([
                    buf[0], buf[1], buf[2], buf[3],
                    buf[4], buf[5], buf[6], buf[7],
                ]);
                if self.range {
                    if self.signed {
                        let sv = v as i64;
                        sv >= self.value_int as i64 && sv <= self.value_int2 as i64
                    } else {
                        v >= self.value_int && v <= self.value_int2
                    }
                } else {
                    v == self.value_int
                }
            }
            GroupScanType::Float => {
                let v = f32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
                if v.is_nan() || v.is_infinite() {
                    return false;
                }
                if self.range {
                    v as f64 >= self.value_float && v as f64 <= self.value_float2
                } else {
                    (v as f64 - self.value_float).abs() < 0.001
                }
            }
            GroupScanType::Double => {
                if buf.len() < 8 {
                    return false;
                }
                let v = f64::from_ne_bytes([
                    buf[0], buf[1], buf[2], buf[3],
                    buf[4], buf[5], buf[6], buf[7],
                ]);
                if v.is_nan() || v.is_infinite() {
                    return false;
                }
                if self.range {
                    v >= self.value_float && v <= self.value_float2
                } else {
                    (v - self.value_float).abs() < 0.00001
                }
            }
            GroupScanType::Str => {
                let str_bytes = self.value_str.as_bytes();
                if buf.len() < str_bytes.len() {
                    return false;
                }
                &buf[..str_bytes.len()] == str_bytes
            }
            GroupScanType::Wildcard => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GroupScanConfig {
    pub elements: Vec<GroupElement>,
    pub blocksize: usize,
    pub blockalignment: usize,
    pub out_of_order: bool,
    pub type_aligned: bool,
}

impl GroupScanConfig {
    pub fn parse(command: &str) -> Result<Self, String> {
        let ptr_size = std::mem::size_of::<usize>();
        let mut blocksize = 0;
        let mut blockalignment = 4;
        let mut out_of_order = false;
        let mut type_aligned = true;
        let mut elements = Vec::new();
        let mut calculated_offset = 0;

        let tokens = command.split_whitespace();

        for token in tokens {
            let t = token.trim();
            if t.is_empty() {
                continue;
            }

            let colon_idx = match t.find(':') {
                Some(idx) => idx,
                None => continue,
            };

            let cmd_part = t[..colon_idx].to_uppercase();
            let val_part = &t[colon_idx + 1..];

            if cmd_part == "BA" {
                blockalignment = val_part.parse::<usize>().unwrap_or(4).max(1);
                continue;
            } else if cmd_part == "BS" {
                blocksize = val_part.parse::<usize>().unwrap_or(0);
                continue;
            } else if cmd_part == "OOO" {
                out_of_order = true;
                type_aligned = val_part.to_uppercase() != "U";
                continue;
            }

            let first_char = cmd_part.chars().next().ok_or("Empty command")?;
            let (scan_type, mut bytesize) = match first_char {
                '1' | 'B' => (GroupScanType::Byte, 1),
                '2' | 'W' => (GroupScanType::Word, 2),
                '4' | 'D' if cmd_part.starts_with('D') && (cmd_part == "D" || cmd_part.starts_with("DR") || cmd_part.starts_with("DP")) => {
                    (GroupScanType::Double, 8)
                }
                '4' => (GroupScanType::Dword, 4),
                '8' | 'Q' => (GroupScanType::Qword, 8),
                'F' => (GroupScanType::Float, 4),
                'P' => (GroupScanType::Pointer, ptr_size),
                'S' => (GroupScanType::Str, val_part.len()),
                _ => return Err(format!("Unknown group scan token type: {}", cmd_part)),
            };

            let mut picked = false;
            let mut range = false;

            for ch in cmd_part.chars().skip(1) {
                match ch {
                    'P' => picked = true,
                    'R' => range = true,
                    _ => {}
                }
            }

            let wildcard = val_part.is_empty() || val_part == "*" || val_part == "?";
            let mut signed = false;
            let mut value_int = 0u64;
            let mut value_int2 = 0u64;
            let mut value_float = 0.0f64;
            let mut value_float2 = 0.0f64;
            let mut value_str = String::new();

            if !wildcard {
                if range {
                    let parts: Vec<&str> = val_part.split('-').collect();
                    if parts.len() == 2 {
                        let p1 = parts[0].trim();
                        let p2 = parts[1].trim();
                        signed = p1.starts_with('-') || p2.starts_with('-');

                        match scan_type {
                            GroupScanType::Float | GroupScanType::Double => {
                                value_float = p1.parse::<f64>().unwrap_or(0.0);
                                value_float2 = p2.parse::<f64>().unwrap_or(0.0);
                            }
                            _ => {
                                if signed {
                                    value_int = p1.parse::<i64>().unwrap_or(0) as u64;
                                    value_int2 = p2.parse::<i64>().unwrap_or(0) as u64;
                                } else {
                                    value_int = parse_int(p1).unwrap_or(0);
                                    value_int2 = parse_int(p2).unwrap_or(0);
                                }
                            }
                        }
                    }
                } else {
                    match scan_type {
                        GroupScanType::Float | GroupScanType::Double => {
                            value_float = val_part.parse::<f64>().unwrap_or(0.0);
                        }
                        GroupScanType::Str => {
                            value_str = val_part.trim_matches('\'').trim_matches('"').to_string();
                            bytesize = value_str.len();
                        }
                        _ => {
                            if val_part.starts_with('-') {
                                signed = true;
                                value_int = val_part.parse::<i64>().unwrap_or(0) as u64;
                            } else {
                                value_int = parse_int(val_part).unwrap_or(0);
                            }
                        }
                    }
                }
            }

            elements.push(GroupElement {
                scan_type,
                wildcard,
                picked,
                range,
                signed,
                offset: calculated_offset,
                bytesize,
                value_int,
                value_int2,
                value_float,
                value_float2,
                value_str,
            });

            calculated_offset += bytesize;
        }

        if elements.is_empty() {
            return Err("No elements parsed in group scan command".to_string());
        }

        if blocksize == 0 {
            blocksize = calculated_offset;
        }

        Ok(GroupScanConfig {
            elements,
            blocksize,
            blockalignment,
            out_of_order,
            type_aligned,
        })
    }

    pub fn matches_block(&self, buf: &[u8], matched_offsets: &mut Vec<u32>) -> bool {
        if buf.len() < self.blocksize {
            return false;
        }

        matched_offsets.clear();

        if !self.out_of_order {

            for elem in &self.elements {
                if elem.offset + elem.bytesize > buf.len() {
                    return false;
                }
                if !elem.matches(&buf[elem.offset..elem.offset + elem.bytesize]) {
                    return false;
                }
                matched_offsets.push(elem.offset as u32);
            }
            true
        } else {

            let mut used_ranges: Vec<(usize, usize)> = Vec::new();

            for elem in &self.elements {
                if elem.wildcard {
                    matched_offsets.push(0);
                    continue;
                }

                let align = if self.type_aligned {
                    elem.scan_type.alignment(std::mem::size_of::<usize>())
                } else {
                    1
                };

                let mut found_offset = None;
                let max_off = self.blocksize.saturating_sub(elem.bytesize);
                let mut cur = 0;

                while cur <= max_off {
                    let overlaps = used_ranges.iter().any(|&(s, e)| cur < e && (cur + elem.bytesize) > s);
                    if !overlaps && elem.matches(&buf[cur..cur + elem.bytesize]) {
                        found_offset = Some(cur);
                        used_ranges.push((cur, cur + elem.bytesize));
                        break;
                    }
                    cur += align;
                }

                match found_offset {
                    Some(off) => matched_offsets.push(off as u32),
                    None => return false,
                }
            }
            true
        }
    }
}

fn parse_int(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix('$') {
        u64::from_str_radix(rest, 16).ok()
    } else if let Some(rest) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

#[derive(Debug, Clone)]
pub struct GroupScanMatch {
    pub base_address: usize,
    pub offsets: Vec<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_scan_parser_ordered() {
        let cmd = "4:100 4:200 4:50";
        let config = GroupScanConfig::parse(cmd).expect("Should parse group scan");
        assert_eq!(config.elements.len(), 3);
        assert_eq!(config.elements[0].offset, 0);
        assert_eq!(config.elements[1].offset, 4);
        assert_eq!(config.elements[2].offset, 8);
        assert_eq!(config.blocksize, 12);
        assert!(!config.out_of_order);

        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&100u32.to_ne_bytes());
        buf[4..8].copy_from_slice(&200u32.to_ne_bytes());
        buf[8..12].copy_from_slice(&50u32.to_ne_bytes());

        let mut offsets = Vec::new();
        assert!(config.matches_block(&buf, &mut offsets));
        assert_eq!(offsets, vec![0, 4, 8]);
    }

    #[test]
    fn test_group_scan_parser_out_of_order() {
        let cmd = "OOO:A BS:32 4:500 4:1000";
        let config = GroupScanConfig::parse(cmd).expect("Should parse OOO group scan");
        assert!(config.out_of_order);
        assert_eq!(config.blocksize, 32);

        let mut buf = vec![0u8; 32];
        buf[8..12].copy_from_slice(&1000u32.to_ne_bytes());
        buf[16..20].copy_from_slice(&500u32.to_ne_bytes());

        let mut offsets = Vec::new();
        assert!(config.matches_block(&buf, &mut offsets));
        assert_eq!(offsets, vec![16, 8]);
    }
}
