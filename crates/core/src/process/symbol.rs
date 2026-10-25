
use std::collections::HashMap;
use std::mem::size_of;
use crate::process::Process;

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct ImageDosHeader {
    e_magic: u16,
    _reserved: [u16; 29],
    e_lfanew: i32,
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

    cache: HashMap<String, HashMap<String, usize>>,

    pub module_preference: Vec<String>,
}

impl SymbolResolver {
    pub fn new() -> Self {
        let default_pref = vec![
            "kernel32.dll".to_string(),
            "kernelbase.dll".to_string(),
            "ntdll.dll".to_string(),
            "user32.dll".to_string(),
            "advapi32.dll".to_string(),
            "ucrtbase.dll".to_string(),
            "msvcrt.dll".to_string(),
            "mono-2.0-bdwgc.dll".to_string(),
            "libc.so.6".to_string(),
            "libc.so".to_string(),
            "libdl.so.2".to_string(),
            "libdl.so".to_string(),
            "libpthread.so.0".to_string(),
        ];

        SymbolResolver {
            cache: HashMap::new(),
            module_preference: default_pref,
        }
    }

    pub fn set_module_preference(&mut self, pref: Vec<String>) {
        self.module_preference = pref.into_iter().map(|s| s.to_lowercase()).collect();
    }

    pub fn add_module_preference(&mut self, mod_name: &str) {
        let key = mod_name.to_lowercase();
        if !self.module_preference.contains(&key) {
            self.module_preference.push(key);
        }
    }

    pub fn resolve(&mut self, proc: &Process, expr: &str) -> Option<usize> {
        let trimmed = expr.trim();
        if let Some(pos) = trimmed.find('!') {
            let mod_part = &trimmed[..pos];
            let sym_part = &trimmed[pos + 1..];
            self.resolve_module_export(proc, mod_part, sym_part)
        } else {
            let mods = proc.modules().ok()?;

            let preferences = self.module_preference.clone();

            for pref in &preferences {
                if let Some(m) = mods.iter().find(|m| {
                    let mn = m.name.to_lowercase();
                    mn == *pref || mn.strip_suffix(".dll").unwrap_or(&mn) == pref.strip_suffix(".dll").unwrap_or(pref)
                }) {
                    if let Some(addr) = self.resolve_module_export(proc, &m.name, trimmed) {
                        return Some(addr);
                    }
                }
            }

            for m in &mods {
                let mn = m.name.to_lowercase();
                let already_checked = preferences.iter().any(|pref| {
                    mn == *pref || mn.strip_suffix(".dll").unwrap_or(&mn) == pref.strip_suffix(".dll").unwrap_or(pref)
                });
                if !already_checked {
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

        let dos: ImageDosHeader = proc.read(base)?;
        if dos.e_magic != 0x5A4D {
            return Err("Invalid MZ magic".to_string());
        }

        let nt_sig_addr = base + dos.e_lfanew as usize;
        let sig: u32 = proc.read(nt_sig_addr)?;
        if sig != 0x00004550 {
            return Err("Invalid PE signature".to_string());
        }

        let opt_hdr_addr = nt_sig_addr + 4 + size_of::<ImageFileHeader>();
        let opt_magic: u16 = proc.read(opt_hdr_addr)?;

        let export_dir_rva: u32 = if opt_magic == 0x020B {

            let export_data_dir: ImageDataDirectory = proc.read(opt_hdr_addr + 112)?;
            export_data_dir.virtual_address
        } else if opt_magic == 0x010B {

            let export_data_dir: ImageDataDirectory = proc.read(opt_hdr_addr + 96)?;
            export_data_dir.virtual_address
        } else {
            return Err("Unknown PE optional header magic".to_string());
        };

        if export_dir_rva == 0 {
            return Err("Module has no export directory".to_string());
        }

        let export_dir_addr = base + export_dir_rva as usize;
        let exp_dir: ImageExportDirectory = proc.read(export_dir_addr)?;

        let num_functions = exp_dir.number_of_functions as usize;
        let num_names = exp_dir.number_of_names as usize;

        if num_names == 0 || num_functions == 0 {
            return Ok(0);
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_preference_order() {
        let mut resolver = SymbolResolver::new();
        assert!(resolver.module_preference.contains(&"kernel32.dll".to_string()));
        assert!(resolver.module_preference.contains(&"ntdll.dll".to_string()));

        resolver.set_module_preference(vec!["custom_mod.dll".to_string(), "kernel32.dll".to_string()]);
        assert_eq!(resolver.module_preference[0], "custom_mod.dll");
        assert_eq!(resolver.module_preference[1], "kernel32.dll");

        resolver.add_module_preference("another.dll");
        assert_eq!(resolver.module_preference.len(), 3);
        assert_eq!(resolver.module_preference[2], "another.dll");
    }
}

