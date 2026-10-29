use crate::process::Process;
use crate::process::pe_info::{
    IMAGE_DOS_SIGNATURE, IMAGE_FILE_MACHINE_AMD64, IMAGE_NT_SIGNATURE, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use crate::process::win32::*;
use std::ffi::CString;
use std::ptr::null_mut;

pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;

pub const DLL_PROCESS_ATTACH: u32 = 1;

#[derive(Debug, Clone)]
pub struct ManualMapOptions {
    pub wipe_headers: bool,

    pub erase_discardable_sections: bool,

    pub execute_tls: bool,

    pub call_dllmain: bool,

    pub protect_sections: bool,

    pub timeout_ms: u32,
}

impl Default for ManualMapOptions {
    fn default() -> Self {
        ManualMapOptions {
            wipe_headers: true,
            erase_discardable_sections: true,
            execute_tls: true,
            call_dllmain: true,
            protect_sections: true,
            timeout_ms: 5000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManualMapResult {
    pub base_address: usize,

    pub entry_point: usize,

    pub size_of_image: usize,

    pub sections_mapped: usize,

    pub tls_callbacks_executed: usize,
}

#[derive(Debug, Clone)]
pub struct PeSectionData {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_ptr: u32,
    pub raw_data_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone)]
pub struct ParsedPe {
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub export_dir: (u32, u32),
    pub import_dir: (u32, u32),
    pub reloc_dir: (u32, u32),
    pub tls_dir: (u32, u32),
    pub sections: Vec<PeSectionData>,
}

impl ParsedPe {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 0x200 {
            return Err("Buffer muito pequeno para conter um executável PE válido".to_string());
        }

        let e_magic = u16::from_le_bytes([bytes[0], bytes[1]]);
        if e_magic != IMAGE_DOS_SIGNATURE {
            return Err("Assinatura DOS inválida (esperado 'MZ')".to_string());
        }

        let e_lfanew =
            u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
        if e_lfanew + 0x108 > bytes.len() {
            return Err("Offset e_lfanew aponta para fora dos limites do buffer".to_string());
        }

        let nt_sig = u32::from_le_bytes([
            bytes[e_lfanew],
            bytes[e_lfanew + 1],
            bytes[e_lfanew + 2],
            bytes[e_lfanew + 3],
        ]);
        if nt_sig != IMAGE_NT_SIGNATURE {
            return Err("Assinatura NT inválida (esperado 'PE\\0\\0')".to_string());
        }

        let file_header_offset = e_lfanew + 4;
        let machine =
            u16::from_le_bytes([bytes[file_header_offset], bytes[file_header_offset + 1]]);
        if machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(format!(
                "Arquitetura incompatível: esperado AMD64 (0x{:04X}), encontrado 0x{:04X}",
                IMAGE_FILE_MACHINE_AMD64, machine
            ));
        }

        let num_sections =
            u16::from_le_bytes([bytes[file_header_offset + 2], bytes[file_header_offset + 3]])
                as usize;
        let size_of_opt_header = u16::from_le_bytes([
            bytes[file_header_offset + 16],
            bytes[file_header_offset + 17],
        ]) as usize;

        let opt_header_offset = file_header_offset + 20;
        let opt_magic =
            u16::from_le_bytes([bytes[opt_header_offset], bytes[opt_header_offset + 1]]);
        if opt_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(format!(
                "Magic do OptionalHeader inválido (esperado PE32+ 0x020B, encontrado 0x{:04X})",
                opt_magic
            ));
        }

        let entry_point_rva = u32::from_le_bytes([
            bytes[opt_header_offset + 16],
            bytes[opt_header_offset + 17],
            bytes[opt_header_offset + 18],
            bytes[opt_header_offset + 19],
        ]);
        let image_base = u64::from_le_bytes(
            bytes[opt_header_offset + 24..opt_header_offset + 32]
                .try_into()
                .unwrap(),
        );
        let size_of_image = u32::from_le_bytes([
            bytes[opt_header_offset + 56],
            bytes[opt_header_offset + 57],
            bytes[opt_header_offset + 58],
            bytes[opt_header_offset + 59],
        ]);
        let size_of_headers = u32::from_le_bytes([
            bytes[opt_header_offset + 60],
            bytes[opt_header_offset + 61],
            bytes[opt_header_offset + 62],
            bytes[opt_header_offset + 63],
        ]);

        let num_rva_and_sizes = u32::from_le_bytes([
            bytes[opt_header_offset + 108],
            bytes[opt_header_offset + 109],
            bytes[opt_header_offset + 110],
            bytes[opt_header_offset + 111],
        ]) as usize;

        let data_dir_offset = opt_header_offset + 112;
        let read_dir = |idx: usize| -> (u32, u32) {
            if idx >= num_rva_and_sizes || data_dir_offset + (idx * 8) + 8 > bytes.len() {
                return (0, 0);
            }
            let pos = data_dir_offset + (idx * 8);
            let rva =
                u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
            let sz = u32::from_le_bytes([
                bytes[pos + 4],
                bytes[pos + 5],
                bytes[pos + 6],
                bytes[pos + 7],
            ]);
            (rva, sz)
        };

        let export_dir = read_dir(IMAGE_DIRECTORY_ENTRY_EXPORT);
        let import_dir = read_dir(IMAGE_DIRECTORY_ENTRY_IMPORT);
        let reloc_dir = read_dir(IMAGE_DIRECTORY_ENTRY_BASERELOC);
        let tls_dir = read_dir(IMAGE_DIRECTORY_ENTRY_TLS);

        let section_table_offset = opt_header_offset + size_of_opt_header;
        let mut sections = Vec::with_capacity(num_sections);

        for i in 0..num_sections {
            let sec_pos = section_table_offset + (i * 40);
            if sec_pos + 40 > bytes.len() {
                break;
            }

            let raw_name = &bytes[sec_pos..sec_pos + 8];
            let name = String::from_utf8_lossy(raw_name)
                .trim_matches(char::from(0))
                .to_string();

            let virtual_size = u32::from_le_bytes([
                bytes[sec_pos + 8],
                bytes[sec_pos + 9],
                bytes[sec_pos + 10],
                bytes[sec_pos + 11],
            ]);
            let virtual_address = u32::from_le_bytes([
                bytes[sec_pos + 12],
                bytes[sec_pos + 13],
                bytes[sec_pos + 14],
                bytes[sec_pos + 15],
            ]);
            let raw_data_size = u32::from_le_bytes([
                bytes[sec_pos + 16],
                bytes[sec_pos + 17],
                bytes[sec_pos + 18],
                bytes[sec_pos + 19],
            ]);
            let raw_data_ptr = u32::from_le_bytes([
                bytes[sec_pos + 20],
                bytes[sec_pos + 21],
                bytes[sec_pos + 22],
                bytes[sec_pos + 23],
            ]);
            let characteristics = u32::from_le_bytes([
                bytes[sec_pos + 36],
                bytes[sec_pos + 37],
                bytes[sec_pos + 38],
                bytes[sec_pos + 39],
            ]);

            sections.push(PeSectionData {
                name,
                virtual_address,
                virtual_size,
                raw_data_ptr,
                raw_data_size,
                characteristics,
            });
        }

        Ok(ParsedPe {
            image_base,
            entry_point_rva,
            size_of_image,
            size_of_headers,
            export_dir,
            import_dir,
            reloc_dir,
            tls_dir,
            sections,
        })
    }
}

pub struct ManualMapper;

impl ManualMapper {
    pub fn inject(
        proc: &Process,
        pe_bytes: &[u8],
        options: &ManualMapOptions,
    ) -> Result<ManualMapResult, String> {
        let pe = ParsedPe::parse(pe_bytes)?;

        let remote_base = proc.alloc(pe.size_of_image as usize, PAGE_EXECUTE_READWRITE)?;
        let delta = remote_base.wrapping_sub(pe.image_base as usize) as isize;

        let mapping_guard = MappingGuard {
            proc,
            base: remote_base,
            committed: false,
        };

        let header_bytes = pe.size_of_headers.min(pe_bytes.len() as u32) as usize;
        proc.write_raw(remote_base, &pe_bytes[..header_bytes])?;

        let mut sections_mapped = 0;
        for sec in &pe.sections {
            if sec.virtual_address as usize >= pe.size_of_image as usize {
                continue;
            }

            let sec_dest = remote_base + sec.virtual_address as usize;
            let copy_len = (sec.raw_data_size as usize).min(sec.virtual_size as usize);

            if copy_len > 0 && (sec.raw_data_ptr as usize + copy_len) <= pe_bytes.len() {
                let slice =
                    &pe_bytes[sec.raw_data_ptr as usize..sec.raw_data_ptr as usize + copy_len];
                proc.write_raw(sec_dest, slice)?;
            }
            sections_mapped += 1;
        }

        if delta != 0 && pe.reloc_dir.0 != 0 && pe.reloc_dir.1 != 0 {
            Self::apply_relocations(proc, remote_base, delta, pe.reloc_dir.0, pe.reloc_dir.1)?;
        }

        if pe.import_dir.0 != 0 && pe.import_dir.1 != 0 {
            Self::resolve_imports(proc, remote_base, pe.import_dir.0)?;
        }

        let mut tls_callbacks_executed = 0;
        if options.execute_tls && pe.tls_dir.0 != 0 && pe.tls_dir.1 != 0 {
            tls_callbacks_executed = Self::execute_tls_callbacks(proc, remote_base, pe.tls_dir.0)?;
        }

        let entry_point = if pe.entry_point_rva != 0 {
            remote_base + pe.entry_point_rva as usize
        } else {
            0
        };

        if options.call_dllmain && entry_point != 0 {
            Self::invoke_entry_point(proc, remote_base, entry_point, options.timeout_ms)?;
        }

        if options.wipe_headers {
            let zero_headers = vec![0u8; header_bytes];
            let _ = proc.write_raw(remote_base, &zero_headers);
        }

        if options.erase_discardable_sections {
            for sec in &pe.sections {
                if (sec.characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0 && sec.virtual_size > 0 {
                    let zero_sec = vec![0u8; sec.virtual_size as usize];
                    let _ = proc.write_raw(remote_base + sec.virtual_address as usize, &zero_sec);
                }
            }
        }

        if options.protect_sections {
            Self::protect_mapped_sections(proc, remote_base, &pe.sections);
        }

        std::mem::forget(mapping_guard);

        Ok(ManualMapResult {
            base_address: remote_base,
            entry_point,
            size_of_image: pe.size_of_image as usize,
            sections_mapped,
            tls_callbacks_executed,
        })
    }

    fn apply_relocations(
        proc: &Process,
        remote_base: usize,
        delta: isize,
        reloc_rva: u32,
        reloc_size: u32,
    ) -> Result<(), String> {
        let mut offset = 0usize;
        let max_len = reloc_size as usize;

        while offset + 8 <= max_len {
            let page_rva = proc.read::<u32>(remote_base + reloc_rva as usize + offset)? as usize;
            let block_size =
                proc.read::<u32>(remote_base + reloc_rva as usize + offset + 4)? as usize;

            if block_size == 0 || block_size < 8 || offset + block_size > max_len {
                break;
            }

            let entries_count = (block_size - 8) / 2;
            let entries_addr = remote_base + reloc_rva as usize + offset + 8;

            for i in 0..entries_count {
                let entry = proc.read::<u16>(entries_addr + (i * 2))?;
                let reloc_type = entry >> 12;
                let reloc_offset = (entry & 0x0FFF) as usize;

                let target_addr = remote_base + page_rva + reloc_offset;

                match reloc_type {
                    IMAGE_REL_BASED_DIR64 => {
                        let original_val = proc.read::<u64>(target_addr)?;
                        let patched_val = original_val.wrapping_add(delta as u64);
                        proc.write::<u64>(target_addr, &patched_val)?;
                    }
                    IMAGE_REL_BASED_HIGHLOW => {
                        let original_val = proc.read::<u32>(target_addr)?;
                        let patched_val = original_val.wrapping_add(delta as u32);
                        proc.write::<u32>(target_addr, &patched_val)?;
                    }
                    IMAGE_REL_BASED_ABSOLUTE => {}
                    _ => {}
                }
            }

            offset += block_size;
        }

        Ok(())
    }

    fn resolve_imports(proc: &Process, remote_base: usize, import_rva: u32) -> Result<(), String> {
        let mut desc_offset = remote_base + import_rva as usize;

        loop {
            let original_first_thunk = proc.read::<u32>(desc_offset)?;
            let _time_date_stamp = proc.read::<u32>(desc_offset + 4)?;
            let _forwarder_chain = proc.read::<u32>(desc_offset + 8)?;
            let name_rva = proc.read::<u32>(desc_offset + 12)?;
            let first_thunk = proc.read::<u32>(desc_offset + 16)?;

            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }

            if name_rva != 0 && first_thunk != 0 {
                let mod_name = proc.read_string(remote_base + name_rva as usize, 256, false)?;
                let thunk_rva = if original_first_thunk != 0 {
                    original_first_thunk
                } else {
                    first_thunk
                };

                let target_mod = proc.find_module(&mod_name);
                let mod_base = match target_mod {
                    Some(m) => m.base,
                    None => Self::load_remote_library(proc, &mod_name)?,
                };

                let mut thunk_idx = 0usize;
                loop {
                    let thunk_val =
                        proc.read::<u64>(remote_base + thunk_rva as usize + (thunk_idx * 8))?;
                    if thunk_val == 0 {
                        break;
                    }

                    let proc_address = if (thunk_val & 0x8000_0000_0000_0000) != 0 {
                        let ordinal = (thunk_val & 0xFFFF) as u16;
                        Self::resolve_export_by_ordinal(proc, mod_base, ordinal)?
                    } else {
                        let name_addr = remote_base + (thunk_val as usize) + 2;
                        let func_name = proc.read_string(name_addr, 256, false)?;
                        Self::resolve_export_by_name(proc, mod_base, &func_name)?
                    };

                    let iat_entry = remote_base + first_thunk as usize + (thunk_idx * 8);
                    proc.write::<u64>(iat_entry, &(proc_address as u64))?;

                    thunk_idx += 1;
                }
            }

            desc_offset += 20;
        }

        Ok(())
    }

    fn resolve_export_by_name(
        proc: &Process,
        mod_base: usize,
        func_name: &str,
    ) -> Result<usize, String> {
        let e_lfanew = proc.read::<i32>(mod_base + 0x3C)? as usize;
        let opt_header = mod_base + e_lfanew + 24;
        let export_rva = proc.read::<u32>(opt_header + 112)? as usize;
        let export_size = proc.read::<u32>(opt_header + 116)? as usize;

        if export_rva == 0 || export_size == 0 {
            return Err(format!(
                "Módulo em 0x{:X} não possui tabela de exportação",
                mod_base
            ));
        }

        let export_dir = mod_base + export_rva;
        let num_functions = proc.read::<u32>(export_dir + 0x14)? as usize;
        let num_names = proc.read::<u32>(export_dir + 0x18)? as usize;
        let addr_functions = mod_base + proc.read::<u32>(export_dir + 0x1C)? as usize;
        let addr_names = mod_base + proc.read::<u32>(export_dir + 0x20)? as usize;
        let addr_ordinals = mod_base + proc.read::<u32>(export_dir + 0x24)? as usize;

        for i in 0..num_names {
            let name_rva = proc.read::<u32>(addr_names + (i * 4))? as usize;
            let current_name = proc.read_string(mod_base + name_rva, 256, false)?;

            if current_name == func_name {
                let ordinal = proc.read::<u16>(addr_ordinals + (i * 2))? as usize;
                if ordinal >= num_functions {
                    return Err(format!(
                        "Ordinal fora dos limites para função '{}'",
                        func_name
                    ));
                }

                let func_rva = proc.read::<u32>(addr_functions + (ordinal * 4))? as usize;

                if func_rva >= export_rva && func_rva < export_rva + export_size {
                    let forward_str = proc.read_string(mod_base + func_rva, 256, false)?;
                    return Self::resolve_forwarder(proc, &forward_str);
                }

                return Ok(mod_base + func_rva);
            }
        }

        if let Ok(c_name) = CString::new(func_name) {
            unsafe {
                let local_mod = GetModuleHandleW(null_mut());
                let local_fn = GetProcAddress(local_mod, c_name.as_ptr() as *const u8);
                if !local_fn.is_null() {
                    return Ok(local_fn as usize);
                }
            }
        }

        Err(format!(
            "Símbolo '{}' não encontrado nas exportações do módulo 0x{:X}",
            func_name, mod_base
        ))
    }

    fn resolve_export_by_ordinal(
        proc: &Process,
        mod_base: usize,
        ordinal: u16,
    ) -> Result<usize, String> {
        let e_lfanew = proc.read::<i32>(mod_base + 0x3C)? as usize;
        let opt_header = mod_base + e_lfanew + 24;
        let export_rva = proc.read::<u32>(opt_header + 112)? as usize;

        if export_rva == 0 {
            return Err("Tabela de exportação inexistente".to_string());
        }

        let export_dir = mod_base + export_rva;
        let base_ordinal = proc.read::<u32>(export_dir + 0x10)? as u16;
        let addr_functions = mod_base + proc.read::<u32>(export_dir + 0x1C)? as usize;

        if ordinal < base_ordinal {
            return Err("Ordinal inferior à base do módulo".to_string());
        }

        let index = (ordinal - base_ordinal) as usize;
        let func_rva = proc.read::<u32>(addr_functions + (index * 4))? as usize;
        Ok(mod_base + func_rva)
    }

    fn resolve_forwarder(proc: &Process, forward_str: &str) -> Result<usize, String> {
        let parts: Vec<&str> = forward_str.split('.').collect();
        if parts.len() != 2 {
            return Err(format!("Formato de forwarder inválido: {}", forward_str));
        }

        let target_dll = format!("{}.dll", parts[0]);
        let func_name = parts[1];

        let target_mod = proc
            .find_module(&target_dll)
            .ok_or_else(|| format!("Módulo redirecionado '{}' não carregado", target_dll))?;

        Self::resolve_export_by_name(proc, target_mod.base, func_name)
    }

    fn load_remote_library(proc: &Process, dll_name: &str) -> Result<usize, String> {
        if let Some(m) = proc.find_module(dll_name) {
            return Ok(m.base);
        }

        let wide_name: Vec<u16> = dll_name.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes_len = wide_name.len() * 2;
        let remote_str = proc.alloc(bytes_len, PAGE_READWRITE)?;

        let raw_bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(wide_name.as_ptr() as *const u8, bytes_len) };
        proc.write_raw(remote_str, raw_bytes)?;

        let kernel32 = proc
            .find_module("kernel32.dll")
            .ok_or_else(|| "kernel32.dll não encontrado no processo alvo".to_string())?;

        let load_lib_addr = Self::resolve_export_by_name(proc, kernel32.base, "LoadLibraryW")?;

        let h_thread = unsafe {
            CreateRemoteThread(
                proc.handle,
                null_mut(),
                0,
                std::mem::transmute::<usize, unsafe extern "system" fn(LPVOID) -> DWORD>(
                    load_lib_addr,
                ),
                remote_str as LPVOID,
                0,
                null_mut(),
            )
        };

        if h_thread.is_null() {
            let _ = proc.free(remote_str);
            return Err("Falha ao invocar CreateRemoteThread para LoadLibraryW".to_string());
        }

        unsafe {
            WaitForSingleObject(h_thread, 5000);
            let mut exit_code: u32 = 0;
            GetExitCodeThread(h_thread, &mut exit_code);
            CloseHandle(h_thread);
            let _ = proc.free(remote_str);

            if exit_code == 0 {
                return Err(format!("LoadLibraryW falhou ao carregar '{}'", dll_name));
            }
        }

        proc.find_module(dll_name)
            .map(|m| m.base)
            .ok_or_else(|| format!("Módulo '{}' não encontrado após LoadLibraryW", dll_name))
    }

    fn execute_tls_callbacks(
        proc: &Process,
        remote_base: usize,
        tls_rva: u32,
    ) -> Result<usize, String> {
        let tls_dir_addr = remote_base + tls_rva as usize;

        let callbacks_array_va = proc.read::<u64>(tls_dir_addr + 0x18)? as usize;
        if callbacks_array_va == 0 {
            return Ok(0);
        }

        let mut count = 0usize;
        let mut idx = 0usize;

        loop {
            let callback_addr = proc.read::<u64>(callbacks_array_va + (idx * 8))? as usize;
            if callback_addr == 0 {
                break;
            }

            Self::invoke_entry_point(proc, remote_base, callback_addr, 3000)?;
            count += 1;
            idx += 1;
        }

        Ok(count)
    }

    fn invoke_entry_point(
        proc: &Process,
        remote_base: usize,
        target_fn: usize,
        timeout_ms: u32,
    ) -> Result<(), String> {
        let mut shellcode = Vec::with_capacity(48);

        shellcode.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

        shellcode.extend_from_slice(&[0x48, 0xB9]);
        shellcode.extend_from_slice(&(remote_base as u64).to_le_bytes());

        shellcode.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);

        shellcode.extend_from_slice(&[0x45, 0x31, 0xC0]);

        shellcode.extend_from_slice(&[0x48, 0xB8]);
        shellcode.extend_from_slice(&(target_fn as u64).to_le_bytes());

        shellcode.extend_from_slice(&[0xFF, 0xD0]);

        shellcode.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);

        shellcode.push(0xC3);

        let stub_addr = proc.alloc(shellcode.len(), PAGE_EXECUTE_READWRITE)?;
        proc.write_raw(stub_addr, &shellcode)?;

        let h_thread = unsafe {
            CreateRemoteThread(
                proc.handle,
                null_mut(),
                0,
                std::mem::transmute::<usize, unsafe extern "system" fn(LPVOID) -> DWORD>(stub_addr),
                null_mut(),
                0,
                null_mut(),
            )
        };

        if h_thread.is_null() {
            let _ = proc.free(stub_addr);
            return Err("Falha ao invocar CreateRemoteThread para entry point".to_string());
        }

        unsafe {
            WaitForSingleObject(h_thread, timeout_ms);
            CloseHandle(h_thread);
        }

        let _ = proc.free(stub_addr);
        Ok(())
    }

    fn protect_mapped_sections(proc: &Process, remote_base: usize, sections: &[PeSectionData]) {
        for sec in sections {
            if sec.virtual_size == 0 {
                continue;
            }

            let sec_addr = remote_base + sec.virtual_address as usize;
            let c = sec.characteristics;

            let protect = if (c & IMAGE_SCN_MEM_EXECUTE) != 0 {
                if (c & IMAGE_SCN_MEM_WRITE) != 0 {
                    PAGE_EXECUTE_READWRITE
                } else {
                    PAGE_EXECUTE_READ
                }
            } else if (c & IMAGE_SCN_MEM_WRITE) != 0 {
                PAGE_READWRITE
            } else if (c & IMAGE_SCN_MEM_READ) != 0 {
                PAGE_READONLY
            } else {
                PAGE_NOACCESS
            };

            let mut old_protect = 0u32;
            unsafe {
                VirtualProtectEx(
                    proc.handle,
                    sec_addr as LPVOID,
                    sec.virtual_size as usize,
                    protect,
                    &mut old_protect,
                );
            }
        }
    }
}

struct MappingGuard<'a> {
    proc: &'a Process,
    base: usize,
    committed: bool,
}

impl<'a> Drop for MappingGuard<'a> {
    fn drop(&mut self) {
        if !self.committed && self.base != 0 {
            let _ = self.proc.free(self.base);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_invalid_buffer() {
        let res = ParsedPe::parse(&[0u8; 10]);
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_invalid_dos_magic() {
        let mut buf = vec![0u8; 0x300];
        buf[0] = 0xAA;
        buf[1] = 0xBB;
        let res = ParsedPe::parse(&buf);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("MZ"));
    }

    #[test]
    fn test_parse_valid_system_dll() {
        let path = "C:\\Windows\\System32\\ntdll.dll";
        if let Ok(bytes) = std::fs::read(path) {
            let pe = ParsedPe::parse(&bytes).expect("Falha ao analisar ntdll.dll");
            assert!(pe.size_of_image > 0);
            assert!(pe.size_of_headers > 0);
            assert!(!pe.sections.is_empty());
            assert!(pe.sections.iter().any(|s| s.name.starts_with(".text")));
        }
    }

    #[test]
    fn test_apply_relocations_delta() {
        let proc = Process::attach_current().expect("Falha ao anexar ao processo atual");
        let test_mem = proc
            .alloc(0x1000, PAGE_READWRITE)
            .expect("Falha ao alocar memória de teste");

        let reloc_rva = 0x200u32;
        let block_addr = test_mem + reloc_rva as usize;

        proc.write::<u32>(block_addr, &0x100).unwrap();
        proc.write::<u32>(block_addr + 4, &12).unwrap();

        proc.write::<u16>(block_addr + 8, &0xA008).unwrap();
        proc.write::<u16>(block_addr + 10, &0).unwrap();

        let target_addr = test_mem + 0x108;
        let original_pointer = 0x0000_7FF6_0000_1000u64;
        proc.write::<u64>(target_addr, &original_pointer).unwrap();

        let delta = 0x2000isize;
        ManualMapper::apply_relocations(&proc, test_mem, delta, reloc_rva, 12).unwrap();

        let updated_pointer = proc.read::<u64>(target_addr).unwrap();
        assert_eq!(updated_pointer, original_pointer + 0x2000);

        proc.free(test_mem).unwrap();
    }
}
