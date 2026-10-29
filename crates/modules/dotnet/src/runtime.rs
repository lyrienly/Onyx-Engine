//! Deteccao de runtime CLR por enumeracao de modulos do processo-alvo e
//! parse de versao via recurso VS_VERSIONINFO do binario (coreclr.dll / clr.dll).

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, HMODULE, MAX_PATH},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
            TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
        },
        ProcessStatus::{EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL},
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

/// Familia do CLR identificado no processo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClrKind {
    /// `coreclr.dll` -> .NET Core 2.0+ / .NET 5, 6, 7, 8, 9
    CoreClr,
    /// `clr.dll` -> .NET Framework 4.x
    FrameworkV4,
    /// `mscorwks.dll` -> .NET Framework 2.0 / 3.5 (legado)
    FrameworkV2,
}

impl ClrKind {
    pub fn module_name(&self) -> &'static str {
        match self {
            ClrKind::CoreClr => "coreclr.dll",
            ClrKind::FrameworkV4 => "clr.dll",
            ClrKind::FrameworkV2 => "mscorwks.dll",
        }
    }
}

/// Metadados de um modulo (DLL/EXE) carregado no processo-alvo.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub path: PathBuf,
    pub base: usize,
    pub size: u32,
}

/// Runtime CLR detectado no processo.
#[derive(Debug, Clone)]
pub struct ClrRuntime {
    pub kind: ClrKind,
    pub version: String,
    pub module_base: usize,
    pub module_path: PathBuf,
}

/// Enumera todos os modulos de um processo via ToolHelp (preferencial) com
/// fallback para EnumProcessModulesEx. Retorna vazio em erro.
#[cfg(windows)]
pub fn enumerate_modules(pid: u32) -> Vec<ModuleInfo> {
    if let Some(mods) = enum_via_toolhelp(pid) {
        return mods;
    }
    enum_via_psapi(pid).unwrap_or_default()
}

#[cfg(not(windows))]
pub fn enumerate_modules(_pid: u32) -> Vec<ModuleInfo> {
    Vec::new()
}

#[cfg(windows)]
fn enum_via_toolhelp(pid: u32) -> Option<Vec<ModuleInfo>> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap == 0 || snap == usize::MAX as HANDLE {
            return None;
        }
        let mut entry: MODULEENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        let mut out = Vec::new();
        if Module32FirstW(snap, &mut entry) == 0 {
            CloseHandle(snap);
            return Some(out);
        }
        loop {
            let name = wide_to_string(&entry.szModule);
            let path = PathBuf::from(wide_to_string(&entry.szExePath));
            out.push(ModuleInfo {
                name,
                path,
                base: entry.modBaseAddr as usize,
                size: entry.modBaseSize,
            });
            if Module32NextW(snap, &mut entry) == 0 {
                break;
            }
        }
        CloseHandle(snap);
        Some(out)
    }
}

#[cfg(windows)]
fn enum_via_psapi(pid: u32) -> Option<Vec<ModuleInfo>> {
    unsafe {
        let hproc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if hproc == 0 {
            return None;
        }
        let mut modules: [HMODULE; 1024] = [0; 1024];
        let mut needed: u32 = 0;
        let ok = EnumProcessModulesEx(
            hproc,
            modules.as_mut_ptr(),
            std::mem::size_of_val(&modules) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        );
        if ok == 0 {
            CloseHandle(hproc);
            return None;
        }
        let count = (needed as usize / std::mem::size_of::<HMODULE>()).min(modules.len());
        let mut out = Vec::with_capacity(count);
        let mut name_buf = [0u16; MAX_PATH as usize];
        for h in &modules[..count] {
            let len = GetModuleFileNameExW(hproc, *h, name_buf.as_mut_ptr(), name_buf.len() as u32);
            if len == 0 {
                continue;
            }
            let path = PathBuf::from(wide_to_string(&name_buf[..len as usize]));
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            out.push(ModuleInfo {
                name,
                path,
                base: *h as usize,
                size: 0,
            });
        }
        CloseHandle(hproc);
        Some(out)
    }
}

fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..end])
        .to_string_lossy()
        .into_owned()
}

/// Procura um CLR conhecido entre os modulos do processo. Retorna o primeiro
/// match na ordem de prioridade (CoreCLR > FrameworkV4 > FrameworkV2).
pub fn detect_runtime(pid: u32) -> Option<ClrRuntime> {
    let modules = enumerate_modules(pid);
    for kind in [ClrKind::CoreClr, ClrKind::FrameworkV4, ClrKind::FrameworkV2] {
        let target = kind.module_name();
        if let Some(m) = modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(target))
        {
            let version = read_file_version(&m.path).unwrap_or_else(|| "unknown".to_string());
            return Some(ClrRuntime {
                kind,
                version,
                module_base: m.base,
                module_path: m.path.clone(),
            });
        }
    }
    None
}

/// Le a versao "fixed" (FIXEDFILEINFO.dwFileVersionMS/LS) de um PE Windows,
/// retornando no formato "major.minor.build.revision". Implementacao minimal
/// que parseia o diretorio de recursos e localiza VS_VERSION_INFO.
pub fn read_file_version(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    parse_pe_file_version(&bytes)
}

/// Parser standalone (testavel sem FS) do VS_FIXEDFILEINFO embarcado num PE.
pub fn parse_pe_file_version(bytes: &[u8]) -> Option<String> {
    // DOS header
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().ok()?) as usize;
    if bytes.len() < e_lfanew + 24 {
        return None;
    }
    if &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    let num_sections = u16::from_le_bytes(bytes[coff + 2..coff + 4].try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(bytes[coff + 16..coff + 18].try_into().ok()?) as usize;
    let opt = coff + 20;
    if bytes.len() < opt + opt_size {
        return None;
    }
    let magic = u16::from_le_bytes(bytes[opt..opt + 2].try_into().ok()?);
    // RVA da data directory[2] (RESOURCE)
    let (data_dir_offset, _is_pe32plus) = match magic {
        0x10b => (opt + 96, false), // PE32
        0x20b => (opt + 112, true), // PE32+
        _ => return None,
    };
    let res_entry = data_dir_offset + 2 * 8;
    if bytes.len() < res_entry + 8 {
        return None;
    }
    let res_rva = u32::from_le_bytes(bytes[res_entry..res_entry + 4].try_into().ok()?) as usize;
    let res_size = u32::from_le_bytes(bytes[res_entry + 4..res_entry + 8].try_into().ok()?) as usize;
    if res_rva == 0 || res_size == 0 {
        return None;
    }

    // Section table
    let sec_start = opt + opt_size;
    let mut res_offset = 0usize;
    let mut res_va = 0usize;
    for i in 0..num_sections {
        let s = sec_start + i * 40;
        if bytes.len() < s + 40 {
            return None;
        }
        let va = u32::from_le_bytes(bytes[s + 12..s + 16].try_into().ok()?) as usize;
        let vsize = u32::from_le_bytes(bytes[s + 8..s + 12].try_into().ok()?) as usize;
        let raw = u32::from_le_bytes(bytes[s + 20..s + 24].try_into().ok()?) as usize;
        if res_rva >= va && res_rva < va + vsize.max(1) {
            res_offset = raw + (res_rva - va);
            res_va = va;
            break;
        }
    }
    if res_offset == 0 {
        return None;
    }

    // Resource directory: procuramos RT_VERSION (16) na raiz.
    // Estrutura: IMAGE_RESOURCE_DIRECTORY (16 bytes) + entries (8 bytes cada).
    let rt_version_id: u32 = 16;
    let ver_dir_offset = find_resource_entry(bytes, res_offset, res_offset, rt_version_id)?;
    // Dentro dele ha subdirs por Name. Pegamos a primeira.
    let name_entry = read_first_entry(bytes, ver_dir_offset + res_offset)?;
    // Dentro dele subdirs por Language. Pegamos a primeira.
    let lang_entry = read_first_entry(bytes, name_entry + res_offset)?;
    // Agora e um DataEntry (nao-subdir): 16 bytes, primeiro campo RVA do payload.
    let data_entry = lang_entry + res_offset;
    if bytes.len() < data_entry + 16 {
        return None;
    }
    let payload_rva = u32::from_le_bytes(bytes[data_entry..data_entry + 4].try_into().ok()?) as usize;
    let payload_size = u32::from_le_bytes(bytes[data_entry + 4..data_entry + 8].try_into().ok()?) as usize;
    let payload_off = res_offset + (payload_rva - res_va);
    if bytes.len() < payload_off + payload_size.min(0x1000) {
        return None;
    }
    parse_vs_versioninfo(&bytes[payload_off..payload_off + payload_size.min(bytes.len() - payload_off)])
}

fn find_resource_entry(
    bytes: &[u8],
    dir_abs: usize,
    _res_base: usize,
    target_id: u32,
) -> Option<usize> {
    if bytes.len() < dir_abs + 16 {
        return None;
    }
    let n_named = u16::from_le_bytes(bytes[dir_abs + 12..dir_abs + 14].try_into().ok()?) as usize;
    let n_id = u16::from_le_bytes(bytes[dir_abs + 14..dir_abs + 16].try_into().ok()?) as usize;
    let entries_start = dir_abs + 16;
    for i in 0..(n_named + n_id) {
        let e = entries_start + i * 8;
        if bytes.len() < e + 8 {
            return None;
        }
        let name_or_id = u32::from_le_bytes(bytes[e..e + 4].try_into().ok()?);
        let offset = u32::from_le_bytes(bytes[e + 4..e + 8].try_into().ok()?);
        // High bit nao setado em name_or_id -> ID numerico.
        if (name_or_id & 0x8000_0000) == 0 && name_or_id == target_id {
            // High bit em offset -> subdirectory
            let child = (offset & 0x7FFF_FFFF) as usize;
            return Some(child);
        }
    }
    None
}

fn read_first_entry(bytes: &[u8], dir_abs: usize) -> Option<usize> {
    if bytes.len() < dir_abs + 16 {
        return None;
    }
    let n_named = u16::from_le_bytes(bytes[dir_abs + 12..dir_abs + 14].try_into().ok()?) as usize;
    let n_id = u16::from_le_bytes(bytes[dir_abs + 14..dir_abs + 16].try_into().ok()?) as usize;
    if n_named + n_id == 0 {
        return None;
    }
    let e = dir_abs + 16;
    let offset = u32::from_le_bytes(bytes[e + 4..e + 8].try_into().ok()?);
    Some((offset & 0x7FFF_FFFF) as usize)
}

/// Parse de VS_VERSIONINFO -> extrai VS_FIXEDFILEINFO.dwFileVersion.
pub fn parse_vs_versioninfo(buf: &[u8]) -> Option<String> {
    // Layout: WORD wLength, WORD wValueLength, WORD wType, WCHAR szKey[], padding, VS_FIXEDFILEINFO...
    if buf.len() < 6 {
        return None;
    }
    let value_len = u16::from_le_bytes(buf[2..4].try_into().ok()?) as usize;
    if value_len < 52 {
        return None;
    }
    // Procurar a assinatura 0xFEEF04BD do VS_FIXEDFILEINFO.
    let max_start = buf.len().saturating_sub(52);
    for i in 0..=max_start {
        if &buf[i..i + 4] == &[0xBD, 0x04, 0xEF, 0xFE] {
            let ff = &buf[i..i + 52];
            let file_ver_ms = u32::from_le_bytes(ff[8..12].try_into().ok()?);
            let file_ver_ls = u32::from_le_bytes(ff[12..16].try_into().ok()?);
            let major = (file_ver_ms >> 16) & 0xFFFF;
            let minor = file_ver_ms & 0xFFFF;
            let build = (file_ver_ls >> 16) & 0xFFFF;
            let rev = file_ver_ls & 0xFFFF;
            return Some(format!("{}.{}.{}.{}", major, minor, build, rev));
        }
    }
    None
}
