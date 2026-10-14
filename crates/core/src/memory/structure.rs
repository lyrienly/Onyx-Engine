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
    Bytes([u8; 8]),
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
            GuessedType::Bytes(_) => "uint8_t[8]",
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
            GuessedType::Bytes(b) => {
                b.iter().map(|x| format!("{:02X}", x)).collect::<Vec<_>>().join(" ")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct StructField {
    pub offset: usize,
    pub raw_bytes: [u8; 8],
    pub guessed: GuessedType,
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

            let guessed = if u64_val == 0 {
                GuessedType::Null
            } else if let Some(target_reg) = regions.iter().find(|r| ptr_val >= r.base && ptr_val < r.base + r.size) {
                // Address points into a valid committed memory region!
                if target_reg.is_executable() {
                    GuessedType::FunctionPointer(ptr_val)
                } else if let Ok(str_val) = proc.read_string(ptr_val, 64, false) {
                    if is_printable_ascii(&str_val) && str_val.len() >= 2 {
                        GuessedType::StringPointer(ptr_val, str_val)
                    } else if let Ok(first_qword) = proc.read::<usize>(ptr_val) {
                        // Check if pointed memory itself contains function pointers (VTable!)
                        if let Some(first_target) = regions.iter().find(|r| first_qword >= r.base && first_qword < r.base + r.size) {
                            if first_target.is_executable() {
                                GuessedType::VTable(ptr_val)
                            } else {
                                GuessedType::DataPointer(ptr_val)
                            }
                        } else {
                            GuessedType::DataPointer(ptr_val)
                        }
                    } else {
                        GuessedType::DataPointer(ptr_val)
                    }
                } else {
                    GuessedType::DataPointer(ptr_val)
                }
            } else {
                // Non-pointer data: check for inline string, float, or integer
                let inline_str = String::from_utf8_lossy(&raw_bytes).to_string();
                let f32_val = f32::from_le_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]);
                let f64_val = f64::from_le_bytes(raw_bytes);

                if is_printable_ascii(&inline_str) && inline_str.trim().len() >= 3 {
                    GuessedType::InlineString(inline_str.trim().to_string())
                } else if f32_val.is_finite() && f32_val.abs() > 0.001 && f32_val.abs() < 100000.0 {
                    GuessedType::Float(f32_val)
                } else if f64_val.is_finite() && f64_val.abs() > 0.001 && f64_val.abs() < 100000.0 {
                    GuessedType::Double(f64_val)
                } else if (u64_val as i64) >= -2147483648 && (u64_val as i64) <= 2147483647 && raw_bytes[4..] == [0, 0, 0, 0] {
                    GuessedType::Int32(i32::from_le_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]))
                } else {
                    GuessedType::Int64(u64_val as i64)
                }
            };

            fields.push(StructField {
                offset,
                raw_bytes,
                guessed,
            });

            offset += stride;
        }

        Ok(fields)
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
                GuessedType::Bytes(_) => "[u8; 8]",
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
