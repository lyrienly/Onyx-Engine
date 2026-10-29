use std::fs::File;
use std::io::Write;
use crate::process::Process;
use crate::scanner::{ScanValue, ValType};

#[derive(Debug, Clone)]
pub struct TableEntry {
    pub id: usize,
    pub description: String,
    pub module_name: Option<String>,
    pub base_offset: usize,
    pub offsets: Vec<usize>,
    pub val_type: ValType,
    pub is_frozen: bool,
    pub freeze_value: Option<ScanValue>,
}

impl TableEntry {
    pub fn resolve_address(&self, proc: &Process) -> Result<usize, String> {
        let mut current_addr = match &self.module_name {
            Some(name) => {
                let m = proc.find_module(name)
                    .ok_or_else(|| format!("Module '{}' not found", name))?;
                m.base + self.base_offset
            }
            None => self.base_offset,
        };

        for &off in &self.offsets {
            let next_ptr: usize = proc.read(current_addr)?;
            if next_ptr == 0 {
                return Err(format!("Null pointer encountered at 0x{:X}", current_addr));
            }
            current_addr = next_ptr + off;
        }

        Ok(current_addr)
    }
}

pub struct CheatTable {
    next_id: usize,
    pub entries: Vec<TableEntry>,
}

impl CheatTable {
    pub fn new() -> Self {
        CheatTable {
            next_id: 1,
            entries: Vec::new(),
        }
    }

    pub fn add_simple(
        &mut self,
        description: &str,
        address: usize,
        val_type: ValType,
    ) -> usize {
        let id = self.next_id;
        self.next_id += 1;

        self.entries.push(TableEntry {
            id,
            description: description.to_string(),
            module_name: None,
            base_offset: address,
            offsets: Vec::new(),
            val_type,
            is_frozen: false,
            freeze_value: None,
        });

        id
    }

    pub fn add_pointer(
        &mut self,
        description: &str,
        module_name: &str,
        base_offset: usize,
        offsets: Vec<usize>,
        val_type: ValType,
    ) -> usize {
        let id = self.next_id;
        self.next_id += 1;

        self.entries.push(TableEntry {
            id,
            description: description.to_string(),
            module_name: Some(module_name.to_string()),
            base_offset,
            offsets,
            val_type,
            is_frozen: false,
            freeze_value: None,
        });

        id
    }

    pub fn remove(&mut self, id: usize) -> bool {
        if let Some(pos) = self.entries.iter().position(|e| e.id == id) {
            self.entries.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn export_tsv(&self, path: &str) -> Result<(), String> {
        let mut file = File::create(path).map_err(|e| e.to_string())?;
        writeln!(file, "ID\tDescription\tType\tModule\tBase\tOffsets").map_err(|e| e.to_string())?;

        for e in &self.entries {
            let mod_str = e.module_name.as_deref().unwrap_or("-");
            let off_str = e.offsets.iter().map(|o| format!("0x{:X}", o)).collect::<Vec<_>>().join(",");
            writeln!(
                file,
                "{}\t{}\t{:?}\t{}\t0x{:X}\t{}",
                e.id, e.description, e.val_type, mod_str, e.base_offset, off_str
            ).map_err(|e| e.to_string())?;
        }

        Ok(())
    }
}

impl Default for CheatTable {
    fn default() -> Self {
        Self::new()
    }
}
