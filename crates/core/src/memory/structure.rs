// language: Rust, file: structure.rs, target: Windows 11, MSVC
// Data structure dissector and heuristic type analysis engine

use std::mem::size_of;
use crate::process::Process;

#[derive(Debug, Clone)]
pub enum GuessedType {
    Null,
    FunctionPointer(usize),
    VTable(usize),
    StringPointer(usize, String),
    DataPointer(usize),
    InlineString(String),
    Float(f32),
    Double(f64),
    Int32(i32),
    Int64(i64),
    Binary(u8),
    Bytes([u8; 8]),
    // CE 7.7: Unreal Engine structure dissect support
    UnrealTArray { data_ptr: usize, count: i32, max: i32 },
    UnrealFString { data_ptr: usize, len: i32, text: Option<String> },
    UnrealFName { index: u32, number: u32 },
}

impl GuessedType {
    pub fn type_name(&self) -> &'static str {
        match self {
            GuessedType::Null => "null",
            GuessedType::FunctionPointer(_) => "void (*)()",
            GuessedType::VTable(_) => "void** (vtable)",
            GuessedType::StringPointer(_, _) => "char*",
            GuessedType::DataPointer(_) => "void*",
            GuessedType::InlineString(_) => "char[]",
            GuessedType::Float(_) => "float",
            GuessedType::Double(_) => "double",
            GuessedType::Int32(_) => "int32_t",
            GuessedType::Int64(_) => "int64_t",
            GuessedType::Binary(_) => "uint8_t (bits)",
            GuessedType::Bytes(_) => "uint8_t[8]",
            GuessedType::UnrealTArray { .. } => "TArray<void*>",
            GuessedType::UnrealFString { .. } => "FString",
            GuessedType::UnrealFName { .. } => "FName",
        }
    }

    pub fn description(&self) -> String {
        match self {
            GuessedType::Null => "0".to_string(),
            GuessedType::FunctionPointer(addr) => format!("Func -> 0x{:016X}", addr),
            GuessedType::VTable(addr) => format!("VTable -> 0x{:016X}", addr),
            GuessedType::StringPointer(addr, s) => format!("0x{:016X} -> \"{}\"", addr, s),
            GuessedType::DataPointer(addr) => format!("Pointer -> 0x{:016X}", addr),
            GuessedType::InlineString(s) => format!("\"{}\"", s),
            GuessedType::Float(f) => format!("{:.4}f", f),
            GuessedType::Double(d) => format!("{:.6}", d),
            GuessedType::Int32(i) => format!("{} (0x{:08X})", i, i),
            GuessedType::Int64(i) => format!("{} (0x{:016X})", i, i),
            GuessedType::Binary(b) => format!("0b{:08b} (0x{:02X})", b, b),
            GuessedType::Bytes(b) => {
                b.iter().map(|x| format!("{:02X}", x)).collect::<Vec<_>>().join(" ")
            }
            GuessedType::UnrealTArray { data_ptr, count, max } => {
                format!("TArray [Count: {}, Max: {}] -> 0x{:016X}", count, max, data_ptr)
            }
            GuessedType::UnrealFString { data_ptr, len, text } => {
                if let Some(t) = text {
                    format!("FString [len: {}] -> \"{}\"", len, t)
                } else {
                    format!("FString [len: {}] -> 0x{:016X}", len, data_ptr)
                }
            }
            GuessedType::UnrealFName { index, number } => {
                format!("FName [Index: {}, Number: {}]", index, number)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct StructField {
    pub offset: usize,
    pub raw_bytes: [u8; 8],
    pub guessed: GuessedType,
    // CE 7.7: Preview field for pointers and nested types
    pub preview: Option<String>,
    // CE 7.7: Field display priority (1 = highest, e.g. VTable/Unreal/Names, 10 = default)
    pub priority: u8,
}

pub struct StructureDissector;

impl StructureDissector {
    pub fn dissect(proc: &Process, address: usize, total_size: usize) -> Result<Vec<StructField>, String> {
        let total = total_size.max(size_of::<usize>());
        let buf = proc.read_bytes(address, total)?;
        let regions = proc.regions(false).unwrap_or_default();

        let stride = size_of::<usize>(); // 8 bytes in x64
        let mut fields = Vec::new();
        let mut offset = 0;

        while offset + stride <= buf.len() {
            let chunk = &buf[offset..offset + stride];
            let mut raw_bytes = [0u8; 8];
            raw_bytes.copy_from_slice(&chunk[..8]);

            let u64_val = u64::from_le_bytes(raw_bytes);
            let ptr_val = u64_val as usize;

            // CE 7.7: Basic Unreal Engine structure dissect support (TArray, FString, FName)
            let is_unreal_container = if offset + 16 <= buf.len() {
                let count_bytes = [buf[offset + 8], buf[offset + 9], buf[offset + 10], buf[offset + 11]];
                let max_bytes = [buf[offset + 12], buf[offset + 13], buf[offset + 14], buf[offset + 15]];
                let count = i32::from_le_bytes(count_bytes);
                let max = i32::from_le_bytes(max_bytes);

                if count >= 0 && max >= count && max < 1_000_000 && (count > 0 || max > 0) {
                    if let Some(_target_reg) = regions.iter().find(|r| ptr_val >= r.base && ptr_val < r.base + r.size) {
                        // Check if wide characters (FString)
                        let mut wide_buf = [0u16; 32];
                        let read_chars = (count as usize).min(32);
                        if proc.read_raw(ptr_val, unsafe { std::slice::from_raw_parts_mut(wide_buf.as_mut_ptr() as *mut u8, read_chars * 2) }).is_ok() {
                            let text: String = String::from_utf16_lossy(&wide_buf[..read_chars]).trim_matches('\0').to_string();
                            if is_printable_ascii(&text) && text.len() >= 2 {
                                Some((GuessedType::UnrealFString { data_ptr: ptr_val, len: count, text: Some(text.clone()) }, Some(text), 1))
                            } else {
                                Some((GuessedType::UnrealTArray { data_ptr: ptr_val, count, max }, Some(format!("Count: {} / Max: {}", count, max)), 1))
                            }
                        } else {
                            Some((GuessedType::UnrealTArray { data_ptr: ptr_val, count, max }, Some(format!("Count: {} / Max: {}", count, max)), 1))
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let (guessed, prev, prio) = if let Some((g, p, pr)) = is_unreal_container {
                (g, p, pr)
            } else if u64_val == 0 {
                (GuessedType::Null, None, 9)
            } else if let Some(target_reg) = regions.iter().find(|r| ptr_val >= r.base && ptr_val < r.base + r.size) {
                // Address points into a valid committed memory region!
                if target_reg.is_executable() {
                    (GuessedType::FunctionPointer(ptr_val), Some(format!("Exec at 0x{:X}", ptr_val)), 2)
                } else if let Ok(str_val) = proc.read_string(ptr_val, 64, false) {
                    if is_printable_ascii(&str_val) && str_val.len() >= 2 {
                        let prev = Some(format!("\"{}\"", str_val));
                        (GuessedType::StringPointer(ptr_val, str_val), prev, 1)
                    } else if let Ok(first_qword) = proc.read::<usize>(ptr_val) {
                        if let Some(first_target) = regions.iter().find(|r| first_qword >= r.base && first_qword < r.base + r.size) {
                            if first_target.is_executable() {
                                (GuessedType::VTable(ptr_val), Some(format!("VTable [1st method: 0x{:X}]", first_qword)), 1)
                            } else {
                                (GuessedType::DataPointer(ptr_val), Some(format!("-> 0x{:X}", first_qword)), 3)
                            }
                        } else {
                            (GuessedType::DataPointer(ptr_val), Some(format!("-> 0x{:X}", first_qword)), 3)
                        }
                    } else {
                        (GuessedType::DataPointer(ptr_val), None, 3)
                    }
                } else {
                    (GuessedType::DataPointer(ptr_val), None, 3)
                }
            } else {
                let inline_str = String::from_utf8_lossy(&raw_bytes).to_string();
                let f32_val = f32::from_le_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]);
                let f64_val = f64::from_le_bytes(raw_bytes);

                if is_printable_ascii(&inline_str) && inline_str.trim().len() >= 3 {
                    let s = inline_str.trim().to_string();
                    (GuessedType::InlineString(s.clone()), Some(format!("\"{}\"", s)), 2)
                } else if f32_val.is_finite() && f32_val.abs() > 0.001 && f32_val.abs() < 100000.0 {
                    (GuessedType::Float(f32_val), Some(format!("{:.4}f", f32_val)), 4)
                } else if f64_val.is_finite() && f64_val.abs() > 0.001 && f64_val.abs() < 100000.0 {
                    (GuessedType::Double(f64_val), Some(format!("{:.6}", f64_val)), 4)
                } else if (u64_val as i64) >= -2147483648 && (u64_val as i64) <= 2147483647 && raw_bytes[4..] == [0, 0, 0, 0] {
                    let i = i32::from_le_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]);
                    (GuessedType::Int32(i), Some(format!("{} (0x{:X})", i, i)), 5)
                } else {
                    let i = u64_val as i64;
                    (GuessedType::Int64(i), Some(format!("{} (0x{:X})", i, i)), 5)
                }
            };

            fields.push(StructField {
                offset,
                raw_bytes,
                guessed,
                preview: prev,
                priority: prio,
            });

            offset += stride;
        }

        Ok(fields)
    }

    /// Sorts fields prioritizing high-signal structures (VTable, Unreal containers, strings, pointers) first
    pub fn sort_by_priority(fields: &mut [StructField]) {
        fields.sort_by_key(|f| f.priority);
    }

    /// Emits a C++ struct definition representing the dissected memory layout
    pub fn generate_cpp_struct(struct_name: &str, fields: &[StructField]) -> String {
        let mut s = format!("struct {} {{\n", struct_name);
        for f in fields {
            let field_name = format!("field_0x{:X}", f.offset);
            s.push_str(&format!(
                "    {:<18} {:<16}; // +0x{:04X} | {}\n",
                f.guessed.type_name(),
                field_name,
                f.offset,
                f.guessed.description()
            ));
        }
        s.push_str("};\n");
        s
    }

    /// Emits a Rust struct definition
    pub fn generate_rust_struct(struct_name: &str, fields: &[StructField]) -> String {
        let mut s = format!("#[repr(C)]\npub struct {} {{\n", struct_name);
        for f in fields {
            let rust_type = match &f.guessed {
                GuessedType::Null => "usize",
                GuessedType::FunctionPointer(_) | GuessedType::VTable(_) | GuessedType::DataPointer(_) | GuessedType::StringPointer(_, _) => "usize",
                GuessedType::InlineString(_) => "[u8; 8]",
                GuessedType::Float(_) => "f32",
                GuessedType::Double(_) => "f64",
                GuessedType::Int32(_) => "i32",
                GuessedType::Int64(_) => "i64",
                GuessedType::Binary(_) => "u8",
                GuessedType::Bytes(_) => "[u8; 8]",
                GuessedType::UnrealTArray { .. } => "(*mut u8, i32, i32)",
                GuessedType::UnrealFString { .. } => "(*mut u16, i32, i32)",
                GuessedType::UnrealFName { .. } => "(u32, u32)",
            };
            s.push_str(&format!(
                "    pub field_0x{:X}: {}, // +0x{:04X} | {}\n",
                f.offset,
                rust_type,
                f.offset,
                f.guessed.description()
            ));
        }
        s.push_str("}\n");
        s
    }
}

fn is_printable_ascii(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}
