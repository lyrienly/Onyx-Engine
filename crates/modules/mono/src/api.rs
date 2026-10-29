//! Resolucao de exports do runtime Mono/IL2CPP.
//!
//! Duas modalidades:
//! - Local (`MonoApi::resolve_local`): quando o Onyx carrega a mesma DLL (ou e
//!   injetado como DLL no alvo). Usa `GetModuleHandleW` + `GetProcAddress`.
//! - Remota (`MonoApi::resolve_remote`): quando o Onyx apenas inspeciona o
//!   processo alvo. Caminha a Export Directory do PE em memoria por leitura.
//!   A leitura e injetada pelo chamador (callback `read_bytes`) para desacoplar
//!   do backend de leitura de memoria (NtReadVirtualMemory / driver kernel).

use std::collections::HashMap;

/// Exports essenciais do Mono classic enumerados pelo issue #10.
pub const MONO_ESSENTIAL_EXPORTS: &[&str] = &[
    "mono_get_root_domain",
    "mono_thread_attach",
    "mono_domain_get",
    "mono_domain_get_assemblies",
    "mono_domain_foreach",
    "mono_assembly_foreach",
    "mono_assembly_get_image",
    "mono_image_get_name",
    "mono_image_get_table_info",
    "mono_class_from_name",
    "mono_class_get_name",
    "mono_class_get_fields",
    "mono_class_get_methods",
    "mono_field_get_name",
    "mono_field_get_offset",
    "mono_method_get_name",
    "mono_compile_method",
    "mono_runtime_invoke",
];

/// Exports essenciais do IL2CPP enumerados pelo issue #10.
pub const IL2CPP_ESSENTIAL_EXPORTS: &[&str] = &[
    "il2cpp_domain_get",
    "il2cpp_thread_attach",
    "il2cpp_thread_detach",
    "il2cpp_domain_get_assemblies",
    "il2cpp_assembly_get_image",
    "il2cpp_image_get_name",
    "il2cpp_image_get_class_count",
    "il2cpp_image_get_class",
    "il2cpp_class_from_name",
    "il2cpp_class_get_name",
    "il2cpp_class_get_fields",
    "il2cpp_class_get_methods",
    "il2cpp_field_get_name",
    "il2cpp_field_get_offset",
    "il2cpp_method_get_name",
    "il2cpp_runtime_invoke",
];

/// Agrupa os enderecos resolvidos para um dado modulo.
#[derive(Debug, Default, Clone)]
pub struct MonoApi {
    pub module: String,
    pub module_base: usize,
    pub resolved: HashMap<String, usize>,
}

impl MonoApi {
    pub fn new(module: &str, module_base: usize) -> Self {
        MonoApi {
            module: module.to_string(),
            module_base,
            resolved: HashMap::new(),
        }
    }

    pub fn get(&self, export: &str) -> Option<usize> {
        self.resolved.get(export).copied()
    }

    pub fn missing<'a>(&self, wanted: &'a [&'a str]) -> Vec<&'a str> {
        wanted
            .iter()
            .copied()
            .filter(|e| !self.resolved.contains_key(*e))
            .collect()
    }

    /// Resolucao local: a DLL ja esta carregada no processo atual.
    ///
    /// Preenche `resolved` com os exports encontrados em `wanted`. Nao falha
    /// quando a DLL nao esta presente: devolve 0 enderecos.
    #[cfg(windows)]
    pub fn resolve_local(module: &str, wanted: &[&str]) -> Result<Self, String> {
        use std::ffi::CString;
        use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

        let wide: Vec<u16> = module.encode_utf16().chain(std::iter::once(0)).collect();
        let hmod = unsafe { GetModuleHandleW(wide.as_ptr()) };
        if hmod == 0 {
            return Err(format!("GetModuleHandleW({}) returned null", module));
        }

        let mut api = MonoApi::new(module, hmod as usize);
        for name in wanted {
            let cname = CString::new(*name).map_err(|e| e.to_string())?;
            let maybe_addr = unsafe { GetProcAddress(hmod, cname.as_ptr() as *const u8) };
            if let Some(fn_ptr) = maybe_addr {
                api.resolved.insert((*name).to_string(), fn_ptr as usize);
            }
        }
        Ok(api)
    }

    #[cfg(not(windows))]
    pub fn resolve_local(_module: &str, _wanted: &[&str]) -> Result<Self, String> {
        Err("resolve_local is Windows-only".to_string())
    }

    /// Resolucao remota: caminha a Export Directory do PE a partir do image base
    /// no espaco de endereco do alvo. `read_bytes` recupera um bloco arbitrario
    /// de memoria do processo (o chamador decide se via `ReadProcessMemory`,
    /// driver kernel ou qualquer outro backend).
    pub fn resolve_remote<F>(
        module: &str,
        module_base: usize,
        wanted: &[&str],
        mut read_bytes: F,
    ) -> Result<Self, String>
    where
        F: FnMut(usize, usize) -> Result<Vec<u8>, String>,
    {
        let mut api = MonoApi::new(module, module_base);

        let dos = read_bytes(module_base, 0x40)?;
        if dos.len() < 0x40 || &dos[0..2] != b"MZ" {
            return Err("invalid DOS header (MZ magic missing)".to_string());
        }
        let e_lfanew = u32::from_le_bytes(dos[0x3C..0x40].try_into().unwrap()) as usize;

        let nt = read_bytes(module_base + e_lfanew, 0x108)?;
        if nt.len() < 0x18 + 0x70 || &nt[0..4] != b"PE\0\0" {
            return Err("invalid NT headers (PE magic missing)".to_string());
        }
        let opt_magic = u16::from_le_bytes(nt[0x18..0x1A].try_into().unwrap());
        let (export_rva, export_size) = if opt_magic == 0x20B {
            // PE32+
            let dd_off = 0x18 + 0x70;
            if nt.len() < dd_off + 8 {
                return Err("optional header truncated".to_string());
            }
            (
                u32::from_le_bytes(nt[dd_off..dd_off + 4].try_into().unwrap()) as usize,
                u32::from_le_bytes(nt[dd_off + 4..dd_off + 8].try_into().unwrap()) as usize,
            )
        } else if opt_magic == 0x10B {
            // PE32
            let dd_off = 0x18 + 0x60;
            if nt.len() < dd_off + 8 {
                return Err("optional header truncated".to_string());
            }
            (
                u32::from_le_bytes(nt[dd_off..dd_off + 4].try_into().unwrap()) as usize,
                u32::from_le_bytes(nt[dd_off + 4..dd_off + 8].try_into().unwrap()) as usize,
            )
        } else {
            return Err(format!("unknown optional header magic 0x{:04X}", opt_magic));
        };

        if export_rva == 0 || export_size < 40 {
            return Err("module has no export directory".to_string());
        }

        let exp_dir = read_bytes(module_base + export_rva, 40)?;
        if exp_dir.len() < 40 {
            return Err("export directory truncated".to_string());
        }
        let num_names = u32::from_le_bytes(exp_dir[0x18..0x1C].try_into().unwrap()) as usize;
        let addr_funcs = u32::from_le_bytes(exp_dir[0x1C..0x20].try_into().unwrap()) as usize;
        let addr_names = u32::from_le_bytes(exp_dir[0x20..0x24].try_into().unwrap()) as usize;
        let addr_ords = u32::from_le_bytes(exp_dir[0x24..0x28].try_into().unwrap()) as usize;

        if num_names == 0 {
            return Ok(api);
        }

        let names_tbl = read_bytes(module_base + addr_names, num_names * 4)?;
        let ords_tbl = read_bytes(module_base + addr_ords, num_names * 2)?;

        for i in 0..num_names {
            let name_rva =
                u32::from_le_bytes(names_tbl[i * 4..i * 4 + 4].try_into().unwrap()) as usize;
            let name_bytes = read_bytes(module_base + name_rva, 128)?;
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(0);
            if end == 0 {
                continue;
            }
            let name = match std::str::from_utf8(&name_bytes[..end]) {
                Ok(s) => s,
                Err(_) => continue,
            };

            if !wanted.contains(&name) {
                continue;
            }

            let ord = u16::from_le_bytes(ords_tbl[i * 2..i * 2 + 2].try_into().unwrap()) as usize;
            let fn_tbl = read_bytes(module_base + addr_funcs + ord * 4, 4)?;
            let fn_rva = u32::from_le_bytes(fn_tbl[0..4].try_into().unwrap()) as usize;
            api.resolved.insert(name.to_string(), module_base + fn_rva);
        }
        Ok(api)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_lists_only_absent_exports() {
        let mut api = MonoApi::new("mono-2.0-bdwgc.dll", 0x1000);
        api.resolved
            .insert("mono_get_root_domain".to_string(), 0x2000);
        let missing = api.missing(&["mono_get_root_domain", "mono_thread_attach"]);
        assert_eq!(missing, vec!["mono_thread_attach"]);
    }

    #[test]
    fn resolve_remote_rejects_non_pe() {
        let result =
            MonoApi::resolve_remote("fake.dll", 0, &["mono_get_root_domain"], |_, size| {
                Ok(vec![0u8; size])
            });
        assert!(result.is_err());
    }

    #[cfg(windows)]
    #[test]
    fn resolve_local_kernel32() {
        // kernel32 sempre carregado; usamos exports conhecidos como proxy para
        // validar o mecanismo (nao ha Mono em testes).
        let api = MonoApi::resolve_local("kernel32.dll", &["GetProcessHeap", "LoadLibraryW"])
            .expect("kernel32 should be loaded");
        assert!(api.get("GetProcessHeap").is_some());
        assert!(api.get("LoadLibraryW").is_some());
    }
}
