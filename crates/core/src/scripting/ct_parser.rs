
use std::fs::File;
use std::io::{Read, Write};
use crate::scanner::ValType;
use crate::table::{CheatTable, TableEntry};

pub struct CtParser;

impl CtParser {

    pub fn load_ct_file(path: &str) -> Result<CheatTable, String> {
        let mut file = File::open(path).map_err(|e| format!("Failed to open {}: {}", path, e))?;
        let mut content = String::new();
        file.read_to_string(&mut content).map_err(|e| format!("Failed to read {}: {}", path, e))?;

        Self::parse_ct_xml(&content)
    }

    pub fn parse_ct_xml(xml: &str) -> Result<CheatTable, String> {
        let mut table = CheatTable::new();

        let mut cursor = 0;
        while let Some(start_pos) = xml[cursor..].find("<CheatEntry>") {
            let entry_start = cursor + start_pos + "<CheatEntry>".len();
            let entry_end = match xml[entry_start..].find("</CheatEntry>") {
                Some(pos) => entry_start + pos,
                None => break,
            };

            let entry_block = &xml[entry_start..entry_end];
            cursor = entry_end + "</CheatEntry>".len();

            let id = extract_tag_content(entry_block, "ID")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(table.entries.len() + 1);

            let description = extract_tag_content(entry_block, "Description")
                .map(|s| s.trim_matches('"').to_string())
                .unwrap_or_else(|| format!("Entry_{}", id));

            let type_str = extract_tag_content(entry_block, "VariableType")
                .unwrap_or_else(|| "4 Bytes".to_string());
            let val_type = parse_ct_variable_type(&type_str);

            let address_str = extract_tag_content(entry_block, "Address")
                .unwrap_or_default();

            let mut offsets = Vec::new();
            if let Some(offsets_block) = extract_block(entry_block, "Offsets") {
                let mut off_cursor = 0;
                while let Some(off_start) = offsets_block[off_cursor..].find("<Offset>") {
                    let s_idx = off_cursor + off_start + "<Offset>".len();
                    if let Some(e_idx) = offsets_block[s_idx..].find("</Offset>") {
                        let off_text = &offsets_block[s_idx..s_idx + e_idx];
                        if let Some(off_num) = parse_offset_str(off_text) {
                            offsets.push(off_num);
                        }
                        off_cursor = s_idx + e_idx + "</Offset>".len();
                    } else {
                        break;
                    }
                }
            }

            let (module_name, base_offset) = parse_ct_address(&address_str);

            table.entries.push(TableEntry {
                id,
                description,
                module_name,
                base_offset,
                offsets,
                val_type,
                is_frozen: false,
                freeze_value: None,
            });
        }

        Ok(table)
    }

    pub fn save_ct_file(table: &CheatTable, path: &str) -> Result<(), String> {
        let mut file = File::create(path).map_err(|e| format!("Failed to create {}: {}", path, e))?;

        writeln!(file, "<?xml version=\"1.0\" encoding=\"utf-8\"?>").map_err(|e| e.to_string())?;
        writeln!(file, "<CheatTable CheatEngineTableVersion=\"45\">").map_err(|e| e.to_string())?;
        writeln!(file, "  <CheatEntries>").map_err(|e| e.to_string())?;

        for entry in &table.entries {
            writeln!(file, "    <CheatEntry>").map_err(|e| e.to_string())?;
            writeln!(file, "      <ID>{}</ID>", entry.id).map_err(|e| e.to_string())?;
            writeln!(file, "      <Description>\"{}\"</Description>", entry.description).map_err(|e| e.to_string())?;
            writeln!(file, "      <VariableType>{}</VariableType>", format_ct_variable_type(entry.val_type)).map_err(|e| e.to_string())?;

            let addr_str = match &entry.module_name {
                Some(mod_name) => format!("\"{}\"+{:X}", mod_name, entry.base_offset),
                None => format!("{:X}", entry.base_offset),
            };
            writeln!(file, "      <Address>{}</Address>", addr_str).map_err(|e| e.to_string())?;

            if !entry.offsets.is_empty() {
                writeln!(file, "      <Offsets>").map_err(|e| e.to_string())?;
                for &off in &entry.offsets {
                    writeln!(file, "        <Offset>{:X}</Offset>", off).map_err(|e| e.to_string())?;
                }
                writeln!(file, "      </Offsets>").map_err(|e| e.to_string())?;
            }

            writeln!(file, "    </CheatEntry>").map_err(|e| e.to_string())?;
        }

        writeln!(file, "  </CheatEntries>").map_err(|e| e.to_string())?;
        writeln!(file, "</CheatTable>").map_err(|e| e.to_string())?;

        Ok(())
    }
}

fn extract_tag_content(source: &str, tag: &str) -> Option<String> {
    let open_tag = format!("<{}>", tag);
    let close_tag = format!("</{}>", tag);

    let start = source.find(&open_tag)? + open_tag.len();
    let end = source[start..].find(&close_tag)? + start;
    Some(source[start..end].trim().to_string())
}

fn extract_block<'a>(source: &'a str, tag: &str) -> Option<&'a str> {
    let open_tag = format!("<{}>", tag);
    let close_tag = format!("</{}>", tag);

    let start = source.find(&open_tag)? + open_tag.len();
    let end = source[start..].find(&close_tag)? + start;
    Some(&source[start..end])
}

fn parse_ct_variable_type(s: &str) -> ValType {
    match s.trim().to_lowercase().as_str() {
        "byte" => ValType::I8,
        "2 bytes" | "2bytes" => ValType::I16,
        "4 bytes" | "4bytes" => ValType::I32,
        "8 bytes" | "8bytes" => ValType::I64,
        "float" => ValType::Float,
        "double" => ValType::Double,
        "string" => ValType::Str,
        "array of byte" | "aob" => ValType::Aob,
        _ => ValType::I32,
    }
}

fn format_ct_variable_type(t: ValType) -> &'static str {
    match t {
        ValType::I8 | ValType::U8 => "Byte",
        ValType::I16 | ValType::U16 => "2 Bytes",
        ValType::I32 | ValType::U32 => "4 Bytes",
        ValType::I64 | ValType::U64 => "8 Bytes",
        ValType::Float => "Float",
        ValType::Double => "Double",
        ValType::Str => "String",
        ValType::Aob => "Array of byte",
        ValType::All => "All",
        ValType::Group => "Grouped",
    }
}

fn parse_offset_str(s: &str) -> Option<usize> {
    let t = s.trim();
    if t.starts_with("0x") || t.starts_with("0X") {
        usize::from_str_radix(&t[2..], 16).ok()
    } else {
        usize::from_str_radix(t, 16).or_else(|_| t.parse::<usize>()).ok()
    }
}

fn parse_ct_address(s: &str) -> (Option<String>, usize) {
    let trimmed = s.trim();
    if let Some(pos) = trimmed.find('+') {
        let mod_part = trimmed[..pos].trim().trim_matches('"');
        let off_part = trimmed[pos + 1..].trim();
        let off = parse_offset_str(off_part).unwrap_or(0);
        (Some(mod_part.to_string()), off)
    } else {
        (None, parse_offset_str(trimmed).unwrap_or(0))
    }
}

