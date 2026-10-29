use std::mem::size_of;
use std::ptr::null_mut;

use onyx_core::win32::{
    CloseHandle, CreateRemoteThread, GetModuleHandleA, GetProcAddress, OpenProcess,
    ReadProcessMemory, VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, WaitForSingleObject,
    WriteProcessMemory, DWORD, HANDLE, LPCVOID, LPVOID, PROCESS_ALL_ACCESS,
    PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY,
    PAGE_READWRITE, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
};

use crate::imports::{parse_imports, ImportSymbol};
use crate::pe::PeImage;
use crate::reloc::apply_relocations;
use crate::stub::{call_stub, CallRequest};

const INFINITE: DWORD = 0xFFFF_FFFF;
const SCRATCH_SIZE: usize = 0x1000;
const NAME_BUFFER_SIZE: usize = 0x200;

#[derive(Debug, Clone, Copy)]
pub struct MapOptions {
    pub erase_headers: bool,
    pub protect_sections: bool,
    pub call_tls: bool,
}

impl Default for MapOptions {
    fn default() -> Self {
        Self {
            erase_headers: false,
            protect_sections: true,
            call_tls: true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MapOutcome {
    pub image_base: usize,
    pub entry_point: usize,
    pub dll_main_result: i32,
    pub relocations: u32,
    pub imports: u32,
}

fn open_target(pid: u32) -> Result<HANDLE, String> {
    let full = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
    if !full.is_null() {
        return Ok(full);
    }

    let reduced = PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE;
    let handle = unsafe { OpenProcess(reduced, 0, pid) };
    if handle.is_null() {
        Err(format!("OpenProcess failed for pid {}", pid))
    } else {
        Ok(handle)
    }
}

fn alloc_remote(process: HANDLE, size: usize, protect: DWORD) -> Result<usize, String> {
    let ptr = unsafe {
        VirtualAllocEx(process, null_mut(), size, MEM_COMMIT | MEM_RESERVE, protect)
    };
    if ptr.is_null() {
        Err("VirtualAllocEx failed".to_string())
    } else {
        Ok(ptr as usize)
    }
}

fn free_remote(process: HANDLE, address: usize) {
    if address != 0 {
        unsafe {
            VirtualFreeEx(process, address as LPVOID, 0, MEM_RELEASE);
        }
    }
}

fn write_remote(process: HANDLE, address: usize, bytes: &[u8]) -> Result<(), String> {
    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            process,
            address as LPVOID,
            bytes.as_ptr() as LPCVOID,
            bytes.len(),
            &mut written,
        )
    };
    if ok == 0 || written != bytes.len() {
        Err(format!("WriteProcessMemory failed at 0x{:X}", address))
    } else {
        Ok(())
    }
}

fn read_remote(process: HANDLE, address: usize, buffer: &mut [u8]) -> Result<(), String> {
    let mut read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            address as LPCVOID,
            buffer.as_mut_ptr() as LPVOID,
            buffer.len(),
            &mut read,
        )
    };
    if ok == 0 || read != buffer.len() {
        Err(format!("ReadProcessMemory failed at 0x{:X}", address))
    } else {
        Ok(())
    }
}

fn local_proc(module: &str, name: &str) -> Result<u64, String> {
    let mut module_c = module.as_bytes().to_vec();
    module_c.push(0);
    let mut name_c = name.as_bytes().to_vec();
    name_c.push(0);

    let handle = unsafe { GetModuleHandleA(module_c.as_ptr()) };
    if handle.is_null() {
        return Err(format!("GetModuleHandleA failed for {}", module));
    }
    let proc = unsafe { GetProcAddress(handle, name_c.as_ptr()) };
    if proc.is_null() {
        Err(format!("GetProcAddress failed for {}", name))
    } else {
        Ok(proc as usize as u64)
    }
}

fn remote_call(
    process: HANDLE,
    stub: usize,
    request: usize,
    function: u64,
    args: [u64; 4],
) -> Result<u64, String> {
    let payload = CallRequest::new(function, args);
    let bytes = unsafe {
        std::slice::from_raw_parts(
            &payload as *const CallRequest as *const u8,
            size_of::<CallRequest>(),
        )
    };
    write_remote(process, request, bytes)?;

    let start: unsafe extern "system" fn(LPVOID) -> DWORD =
        unsafe { std::mem::transmute(stub) };
    let thread = unsafe { CreateRemoteThread(process, null_mut(), 0, start, request as LPVOID, 0, null_mut()) };
    if thread.is_null() {
        return Err("CreateRemoteThread failed".to_string());
    }

    unsafe {
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
    }

    let mut result = [0u8; size_of::<CallRequest>()];
    read_remote(process, request, &mut result)?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&result[0x28..0x30]);
    Ok(u64::from_le_bytes(raw))
}

fn section_protection(characteristics: u32) -> DWORD {
    let executable = characteristics & 0x2000_0000 != 0;
    let readable = characteristics & 0x4000_0000 != 0;
    let writable = characteristics & 0x8000_0000 != 0;

    if executable && writable {
        PAGE_EXECUTE_READWRITE
    } else if executable && readable {
        PAGE_EXECUTE_READ
    } else if executable {
        PAGE_EXECUTE
    } else if writable {
        PAGE_READWRITE
    } else {
        PAGE_READONLY
    }
}

fn apply_section_protections(process: HANDLE, base: usize, pe: &PeImage) -> Result<(), String> {
    for section in &pe.sections {
        if section.virtual_size == 0 {
            continue;
        }
        let mut old = 0u32;
        let ok = unsafe {
            VirtualProtectEx(
                process,
                (base + section.virtual_address as usize) as LPVOID,
                section.virtual_size as usize,
                section_protection(section.characteristics),
                &mut old,
            )
        };
        if ok == 0 {
            return Err(format!(
                "VirtualProtectEx failed for section {}",
                section.name_string()
            ));
        }
    }
    Ok(())
}

fn erase_headers(process: HANDLE, base: usize, size_of_headers: u32) -> Result<(), String> {
    if size_of_headers == 0 {
        return Ok(());
    }
    let mut old = 0u32;
    unsafe {
        VirtualProtectEx(
            process,
            base as LPVOID,
            size_of_headers as usize,
            PAGE_READWRITE,
            &mut old,
        );
    }
    let zeros = vec![0u8; size_of_headers as usize];
    write_remote(process, base, &zeros)?;
    unsafe {
        VirtualProtectEx(
            process,
            base as LPVOID,
            size_of_headers as usize,
            PAGE_READONLY,
            &mut old,
        );
    }
    Ok(())
}

fn call_tls_callbacks(
    process: HANDLE,
    base: usize,
    image: &[u8],
    pe: &PeImage,
    stub: usize,
    request: usize,
) -> Result<(), String> {
    if pe.tls_rva == 0 {
        return Ok(());
    }
    if pe.tls_size != 0 && pe.tls_size < 28 {
        return Ok(());
    }
    let tls = pe.tls_rva as usize;
    if tls + 28 > image.len() {
        return Ok(());
    }

    let mut raw = [0u8; 8];
    raw.copy_from_slice(&image[tls + 24..tls + 32]);
    let callbacks_va = u64::from_le_bytes(raw);
    if callbacks_va == 0 {
        return Ok(());
    }

    let callbacks_rva = match (callbacks_va as usize).checked_sub(base) {
        Some(rva) => rva,
        None => return Ok(()),
    };
    let image_end = base.saturating_add(pe.size_of_image as usize);
    let mut slot = base.saturating_add(callbacks_rva);

    loop {
        if slot + 8 > image_end {
            break;
        }
        let mut entry = [0u8; 8];
        read_remote(process, slot, &mut entry)?;
        let callback = u64::from_le_bytes(entry);
        if callback == 0 {
            break;
        }
        remote_call(process, stub, request, callback, [base as u64, 1, 0, 0])?;
        slot += 8;
    }

    Ok(())
}

fn resolve_imports(
    process: HANDLE,
    base: usize,
    image: &[u8],
    pe: &PeImage,
    stub: usize,
    request: usize,
    name_buffer: usize,
    load_library: u64,
    get_proc: u64,
) -> Result<u32, String> {
    let imports = parse_imports(image, pe.import_rva, pe.import_size)?;
    let mut modules: Vec<(String, u64)> = Vec::new();
    let mut resolved = 0u32;

    for entry in &imports {
        let module_base = match modules.iter().find(|(name, _)| name.eq_ignore_ascii_case(&entry.module)) {
            Some((_, cached)) => *cached,
            None => {
                let bytes = entry.module.as_bytes();
                if bytes.len() + 1 > NAME_BUFFER_SIZE {
                    return Err("module name too long".to_string());
                }
                let mut buffer = bytes.to_vec();
                buffer.push(0);
                write_remote(process, name_buffer, &buffer)?;
                let loaded = remote_call(
                    process,
                    stub,
                    request,
                    load_library,
                    [name_buffer as u64, 0, 0, 0],
                )?;
                if loaded == 0 {
                    return Err(format!("LoadLibraryA failed for {}", entry.module));
                }
                modules.push((entry.module.clone(), loaded));
                loaded
            }
        };

        let symbol_address = match &entry.symbol {
            ImportSymbol::Name(name) => {
                let bytes = name.as_bytes();
                if bytes.len() + 1 > NAME_BUFFER_SIZE {
                    return Err("import name too long".to_string());
                }
                let mut buffer = bytes.to_vec();
                buffer.push(0);
                write_remote(process, name_buffer, &buffer)?;
                remote_call(
                    process,
                    stub,
                    request,
                    get_proc,
                    [module_base, name_buffer as u64, 0, 0],
                )?
            }
            ImportSymbol::Ordinal(ordinal) => remote_call(
                process,
                stub,
                request,
                get_proc,
                [module_base, *ordinal as u64, 0, 0],
            )?,
        };

        if symbol_address == 0 {
            return Err(format!("GetProcAddress failed for {:?}", entry.symbol));
        }

        write_remote(
            process,
            base + entry.iat_rva as usize,
            &symbol_address.to_le_bytes(),
        )?;
        resolved += 1;
    }

    Ok(resolved)
}

fn run_mapping(
    process: HANDLE,
    pid: u32,
    dll_path: &str,
    options: &MapOptions,
    stub: usize,
    request: usize,
    name_buffer: usize,
) -> Result<MapOutcome, String> {
    let _ = pid;
    let pe = PeImage::parse_file(dll_path)?;
    if !pe.is_pe32_plus {
        return Err("only PE32+ (x64) DLLs are supported".to_string());
    }
    if !pe.is_dll() {
        return Err(format!("{} is not a DLL (IMAGE_FILE_DLL not set)", dll_path));
    }

    let mut image = pe.build_image()?;
    let image_size = image.len();

    let mut base = unsafe {
        VirtualAllocEx(
            process,
            pe.image_base as LPVOID,
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    } as usize;

    if base == 0 {
        base = alloc_remote(process, image_size, PAGE_EXECUTE_READWRITE)?;
    }

    let delta = base as i64 - pe.image_base as i64;
    let relocations = apply_relocations(&mut image, pe.reloc_rva, pe.reloc_size, delta)?;
    write_remote(process, base, &image)?;

    let load_library = local_proc("kernel32.dll", "LoadLibraryA")?;
    let get_proc = local_proc("kernel32.dll", "GetProcAddress")?;
    let imports = resolve_imports(
        process,
        base,
        &image,
        &pe,
        stub,
        request,
        name_buffer,
        load_library,
        get_proc,
    )?;

    if options.protect_sections {
        apply_section_protections(process, base, &pe)?;
    }

    if options.call_tls {
        call_tls_callbacks(process, base, &image, &pe, stub, request)?;
    }

    let entry_point = if pe.entry_point_rva != 0 {
        base + pe.entry_point_rva as usize
    } else {
        0
    };

    let dll_main_result = if entry_point != 0 {
        remote_call(
            process,
            stub,
            request,
            entry_point as u64,
            [base as u64, 1, 0, 0],
        )? as i32
    } else {
        1
    };

    if options.erase_headers {
        erase_headers(process, base, pe.size_of_headers)?;
    }

    Ok(MapOutcome {
        image_base: base,
        entry_point,
        dll_main_result,
        relocations,
        imports,
    })
}

pub fn map_dll(pid: u32, dll_path: &str, options: &MapOptions) -> Result<MapOutcome, String> {
    let process = open_target(pid)?;

    let stub_code = call_stub();
    let stub = alloc_remote(process, stub_code.len(), PAGE_EXECUTE_READWRITE)?;
    let request = alloc_remote(process, SCRATCH_SIZE, PAGE_READWRITE)?;
    let name_buffer = alloc_remote(process, NAME_BUFFER_SIZE, PAGE_READWRITE)?;

    let setup = write_remote(process, stub, &stub_code);
    let outcome = match setup {
        Ok(()) => run_mapping(process, pid, dll_path, options, stub, request, name_buffer),
        Err(error) => Err(error),
    };

    free_remote(process, name_buffer);
    free_remote(process, request);
    free_remote(process, stub);
    unsafe {
        CloseHandle(process);
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_protection_mapping() {
        assert_eq!(section_protection(0x6000_0020), PAGE_EXECUTE_READ);
        assert_eq!(section_protection(0xE000_0040), PAGE_EXECUTE_READWRITE);
        assert_eq!(section_protection(0xC000_0040), PAGE_READWRITE);
        assert_eq!(section_protection(0x4000_0040), PAGE_READONLY);
        assert_eq!(section_protection(0x2000_0020), PAGE_EXECUTE);
    }

    #[test]
    fn test_default_options() {
        let options = MapOptions::default();
        assert!(!options.erase_headers);
        assert!(options.protect_sections);
        assert!(options.call_tls);
    }
}
