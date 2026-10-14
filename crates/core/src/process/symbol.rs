// language: Rust, file: symbol.rs, target: Windows 11, MSVC
// PE Header parsing and Export Directory symbol resolver

use std::collections::HashMap;
use std::mem::size_of;
use crate::process::Process;

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct ImageDosHeader {
    e_magic: u16,      // Magic number 'MZ' (0x5A4D)
    _reserved: [u16; 29],
    e_lfanew: i32,     // File address of new exe header
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

#[derive(Debug, Clone)]
pub struct ExportSymbol {
    pub name: String,
    pub address: usize,
    pub ordinal: u16,
}

pub struct SymbolResolver {
    // module_name (lowercase) -> (export_name -> absolute_address)
    cache: HashMap<String, HashMap<String, usize>>,
}

impl SymbolResolver {
    pub fn new() -> Self {
        SymbolResolver {
            cache: HashMap::new(),
        }
    }

    /// Resolves expressions like "kernel32.dll!CreateProcessW" or "ntdll.dll!NtQuerySystemInformation"
    pub fn resolve(&mut self, proc: &Process, expr: &str) -> Option<usize> {
        let trimmed = expr.trim();
        if let Some(pos) = trimmed.find('!') {
            let mod_part = &trimmed[..pos];
            let sym_part = &trimmed[pos + 1..];
            self.resolve_module_export(proc, mod_part, sym_part)
        } else {
            // Search all loaded modules
            if let Ok(mods) = proc.modules() {
                for m in mods {
                    if let Some(addr) = self.resolve_module_export(proc, &m.name, trimmed) {
                        return Some(addr);
                    }
                }
            }
            None
        }
    }

    pub fn resolve_module_export(
        &mut self,
        proc: &Process,
        mod_name: &str,
        sym_name: &str,
    ) -> Option<usize> {
        let key = mod_name.to_lowercase();
        if !self.cache.contains_key(&key) {
            let _ = self.load_module_exports(proc, mod_name);
        }

        self.cache.get(&key)?.get(sym_name).copied()
    }

    pub fn load_module_exports(&mut self, proc: &Process, mod_name: &str) -> Result<usize, String> {
        let m = proc.find_module(mod_name)
            .ok_or_else(|| format!("Module '{}' not found", mod_name))?;

        let base = m.base;

        // 1. Read DOS Header
        let dos: ImageDosHeader = proc.read(base)?;
        if dos.e_magic != 0x5A4D {
            return Err("Invalid MZ magic".to_string());
        }

        // 2. Read NT Headers signature
        let nt_sig_addr = base + dos.e_lfanew as usize;
        let sig: u32 = proc.read(nt_sig_addr)?;
        if sig != 0x00004550 { // 'PE\0\0'
            return Err("Invalid PE signature".to_string());
        }

        // 3. Read Optional Header (magic determines 32 or 64-bit)
        let opt_hdr_addr = nt_sig_addr + 4 + size_of::<ImageFileHeader>();
        let opt_magic: u16 = proc.read(opt_hdr_addr)?;

        let export_dir_rva: u32 = if opt_magic == 0x020B {
            // PE32+ (64-bit): Export Directory is at offset 112 in Optional Header
            let export_data_dir: ImageDataDirectory = proc.read(opt_hdr_addr + 112)?;
            export_data_dir.virtual_address
        } else if opt_magic == 0x010B {
            // PE32 (32-bit): Export Directory is at offset 96 in Optional Header
            let export_data_dir: ImageDataDirectory = proc.read(opt_hdr_addr + 96)?;
            export_data_dir.virtual_address
        } else {
            return Err("Unknown PE optional header magic".to_string());
        };

        if export_dir_rva == 0 {
            return Err("Module has no export directory".to_string());
        }

        // 4. Read Export Directory Table
        let export_dir_addr = base + export_dir_rva as usize;
        let exp_dir: ImageExportDirectory = proc.read(export_dir_addr)?;

        let num_functions = exp_dir.number_of_functions as usize;
        let num_names = exp_dir.number_of_names as usize;

        if num_names == 0 || num_functions == 0 {
            return Ok(0);
        }

        // Read Name RVAs
        let names_addr = base + exp_dir.address_of_names as usize;
        let ords_addr = base + exp_dir.address_of_name_ordinals as usize;
        let funcs_addr = base + exp_dir.address_of_functions as usize;

        let name_rvas: Vec<u32> = {
            let mut buf = vec![0u8; num_names * 4];
            proc.read_raw(names_addr, &mut buf)?;
            buf.chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect()
        };

        let ordinals: Vec<u16> = {
            let mut buf = vec![0u8; num_names * 2];
            proc.read_raw(ords_addr, &mut buf)?;
            buf.chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect()
        };

        let func_rvas: Vec<u32> = {
            let mut buf = vec![0u8; num_functions * 4];
            proc.read_raw(funcs_addr, &mut buf)?;
            buf.chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect()
        };

        let mut sym_map = HashMap::new();

        for i in 0..num_names {
            let name_addr = base + name_rvas[i] as usize;
            if let Ok(name) = proc.read_string(name_addr, 128, false) {
                let ord = ordinals[i] as usize;
                if ord < func_rvas.len() {
                    let func_rva = func_rvas[ord];
                    let func_addr = base + func_rva as usize;
                    sym_map.insert(name, func_addr);
                }
            }
        }

        let count = sym_map.len();
        self.cache.insert(mod_name.to_lowercase(), sym_map);
        Ok(count)
    }

    pub fn list_exports(&self, mod_name: &str) -> Vec<(&str, usize)> {
        if let Some(map) = self.cache.get(&mod_name.to_lowercase()) {
            let mut list: Vec<(&str, usize)> = map.iter().map(|(k, &v)| (k.as_str(), v)).collect();
            list.sort_by_key(|&(name, _)| name);
            list
        } else {
            Vec::new()
        }
    }
}
