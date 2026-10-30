#![cfg(all(windows, target_arch = "x86_64"))]

//! Zera cabeçalhos PE (DOS header + NT headers + section table) de modulos
//! mapeados em memoria. Scanners que iteram paginas e procuram `MZ`/`PE\0\0`
//! no inicio das regioes nao vao mais encontrar o modulo depois de passar
//! aqui.
//!
//! Entradas publicas:
//! * [`strip_module_headers`] – API Rust (segura de usar em modulos nao
//!   essenciais do processo).
//! * [`onyx_pe_strip_headers`] – entrypoint FFI (`extern "C"`).

use core::ffi::c_void;
use core::ptr;

use windows_sys::Win32::System::Diagnostics::Debug::{
    FlushInstructionCache, IMAGE_NT_HEADERS64,
};
use windows_sys::Win32::System::Memory::{
    VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION, PAGE_READWRITE,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// Diagnostico retornado por [`strip_module_headers`].
#[derive(Debug, Clone, Copy)]
pub struct StripReport {
    /// Quantos bytes foram efetivamente zerados.
    pub cleared_bytes: usize,
    /// Protecao original da pagina (passada de volta pro VirtualProtect final).
    pub previous_protect: u32,
    /// Primeiros dois bytes antes do strip (deveria ser `0x4D 0x5A` = "MZ").
    pub dos_signature_before: u16,
    /// Primeiros dois bytes depois do strip (deveria ser `0x0000`).
    pub dos_signature_after: u16,
    /// `IMAGE_NT_SIGNATURE` (`"PE\0\0"`) antes do strip (ou 0 se o
    /// `e_lfanew` apontava fora da regiao zerada).
    pub nt_signature_before: u32,
    /// `IMAGE_NT_SIGNATURE` depois do strip.
    pub nt_signature_after: u32,
}

/// Codigo de erro retornado em modo FFI/`Result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripError {
    InvalidPointer,
    NotAPeImage,
    VirtualProtectFailed,
}

/// Zera os cabeçalhos PE do modulo em `base`.
///
/// `size` eh usado apenas como teto; a quantidade real de bytes zerados
/// vem do campo `SizeOfHeaders` do opcional header (clampado a `size`).
///
/// # Safety
/// O caller deve garantir que `[base, base+size)` eh mapeado e que o
/// processo pode sobrescrever esses bytes (o resto do codigo do modulo
/// nao deve depender dos headers em runtime).
pub unsafe fn strip_module_headers(
    base: *mut u8,
    size: usize,
) -> Result<StripReport, StripError> {
    if base.is_null() || size < core::mem::size_of::<IMAGE_DOS_HEADER>() {
        return Err(StripError::InvalidPointer);
    }

    // Leia o header original para construir o relatorio.
    let dos = &*(base as *const IMAGE_DOS_HEADER);
    let dos_before = dos.e_magic;
    let is_pe = dos.e_magic == IMAGE_DOS_SIGNATURE;

    let (clear_len, nt_signature_before) = if is_pe {
        let e_lfanew = dos.e_lfanew as usize;
        let mut len = size.min(0x1000);
        let mut nt_sig = 0u32;
        if e_lfanew != 0 && e_lfanew + core::mem::size_of::<IMAGE_NT_HEADERS64>() <= size {
            let nt = &*(base.add(e_lfanew) as *const IMAGE_NT_HEADERS64);
            if nt.Signature == IMAGE_NT_SIGNATURE {
                nt_sig = nt.Signature;
                // SizeOfHeaders e o jeito oficial - mas clampa pela regiao.
                let header_size = nt.OptionalHeader.SizeOfHeaders as usize;
                if header_size > 0 && header_size <= size {
                    len = header_size.min(size).min(0x4000);
                }
            }
        }
        (len, nt_sig)
    } else {
        (size.min(0x1000), 0u32)
    };

    // VirtualProtect -> RW, zera, restaura.
    let mut old_prot: u32 = 0;
    if VirtualProtect(base as *const c_void, clear_len, PAGE_READWRITE, &mut old_prot) == 0 {
        return Err(StripError::VirtualProtectFailed);
    }

    ptr::write_bytes(base, 0, clear_len);

    // Flush pra garantir que leitura subsequente nao venha de I-cache antiga.
    let _ = FlushInstructionCache(GetCurrentProcess(), base as *const c_void, clear_len);

    // Restaura protecao original.
    let mut tmp: u32 = 0;
    VirtualProtect(base as *const c_void, clear_len, old_prot, &mut tmp);

    // Re-le p/ relatorio.
    let dos_after = *(base as *const u16);
    let nt_after = if is_pe && (dos.e_lfanew as usize) + 4 <= clear_len {
        // dentro da area zerada
        0u32
    } else if is_pe {
        // nao foi zerado (fora do SizeOfHeaders): le valor atual
        *((base as usize + dos.e_lfanew as usize) as *const u32)
    } else {
        0
    };

    Ok(StripReport {
        cleared_bytes: clear_len,
        previous_protect: old_prot,
        dos_signature_before: dos_before,
        dos_signature_after: dos_after,
        nt_signature_before,
        nt_signature_after: nt_after,
    })
}

/// Variante segura que descobre o tamanho via `VirtualQuery`.
///
/// Util quando o chamador tem o endereco base mas nao o tamanho exato.
///
/// # Safety
/// Vide [`strip_module_headers`].
pub unsafe fn strip_module_headers_auto(base: *mut u8) -> Result<StripReport, StripError> {
    if base.is_null() {
        return Err(StripError::InvalidPointer);
    }
    let mut mbi: MEMORY_BASIC_INFORMATION = core::mem::zeroed();
    if VirtualQuery(
        base as *const c_void,
        &mut mbi,
        core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
    ) == 0
    {
        return Err(StripError::InvalidPointer);
    }
    strip_module_headers(base, mbi.RegionSize)
}

/// FFI consumido por loaders/DLLs externos.
///
/// Retorna 0 em sucesso ou um codigo negativo em caso de falha.
/// Se `out_report` for valido, preenche com o diagnostico.
#[no_mangle]
pub unsafe extern "C" fn onyx_pe_strip_headers(
    base: *mut u8,
    size: usize,
    out_report: *mut StripReport,
) -> i32 {
    match strip_module_headers(base, size) {
        Ok(rep) => {
            if !out_report.is_null() {
                *out_report = rep;
            }
            0
        }
        Err(StripError::InvalidPointer) => -1,
        Err(StripError::NotAPeImage) => -2,
        Err(StripError::VirtualProtectFailed) => -3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::LibraryLoader::{
        GetModuleHandleA, LoadLibraryExA, DONT_RESOLVE_DLL_REFERENCES,
    };
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READONLY,
    };

    /// Monta um "mini-PE" falso em memoria com PAGE_READONLY e verifica que
    /// o strip zera DOS + NT, mantendo bytes alem do SizeOfHeaders e
    /// restaurando a protecao original.
    #[test]
    fn strip_zeroes_fake_pe_and_restores_protection() {
        unsafe {
            let region_size = 0x2000usize;
            let base = VirtualAlloc(
                core::ptr::null(),
                region_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ) as *mut u8;
            assert!(!base.is_null(), "VirtualAlloc falhou");

            // Escreve DOS header
            let dos = &mut *(base as *mut IMAGE_DOS_HEADER);
            dos.e_magic = IMAGE_DOS_SIGNATURE; // "MZ"
            dos.e_lfanew = 0x40;

            // Escreve NT header (soh os campos criticos)
            let nt_ptr = base.add(0x40) as *mut IMAGE_NT_HEADERS64;
            (*nt_ptr).Signature = IMAGE_NT_SIGNATURE; // "PE\0\0"
            (*nt_ptr).OptionalHeader.SizeOfHeaders = 0x400;

            // Marca um padrao DEPOIS da area de header, pra provar que nao foi tocado.
            let sentinel_off = 0x1000;
            let sentinel: &[u8] = b"ONYX_SENTINEL_MARK";
            core::ptr::copy_nonoverlapping(sentinel.as_ptr(), base.add(sentinel_off), sentinel.len());

            // Troca a protecao pra READONLY, pra forcar o VirtualProtect do strip.
            let mut old: u32 = 0;
            let ok = VirtualProtect(
                base as *const c_void,
                region_size,
                PAGE_READONLY,
                &mut old,
            );
            assert_ne!(ok, 0, "VirtualProtect pre-strip falhou");

            // Executa o strip
            let rep = strip_module_headers(base, region_size).expect("strip falhou");

            assert_eq!(rep.dos_signature_before, IMAGE_DOS_SIGNATURE);
            assert_eq!(rep.dos_signature_after, 0, "DOS signature nao foi zerada");
            assert_eq!(rep.nt_signature_before, IMAGE_NT_SIGNATURE);
            assert_eq!(rep.nt_signature_after, 0, "NT signature nao foi zerada");
            assert_eq!(rep.cleared_bytes, 0x400, "deve ter zerado SizeOfHeaders=0x400");
            assert_eq!(rep.previous_protect & 0xFF, PAGE_READONLY & 0xFF);

            // Verifica que os primeiros 0x400 bytes estao TODOS zerados.
            // Precisa re-habilitar leitura pra inspecionar.
            let mut tmp: u32 = 0;
            VirtualProtect(base as *const c_void, region_size, PAGE_READWRITE, &mut tmp);

            let hdr = core::slice::from_raw_parts(base, 0x400);
            assert!(hdr.iter().all(|&b| b == 0), "header nao esta zerado");

            // Sentinel preservado.
            let sentinel_slice =
                core::slice::from_raw_parts(base.add(sentinel_off), sentinel.len());
            assert_eq!(sentinel_slice, sentinel, "sentinel foi corrompido");

            VirtualFree(base as *mut c_void, 0, MEM_RELEASE);
        }
    }

    /// Load uma DLL real via `DONT_RESOLVE_DLL_REFERENCES`, zera os headers
    /// da imagem mapeada e verifica que o `MZ` sumiu.
    ///
    /// Usamos `psapi.dll`: funcoes dessa DLL ja foram tipicamente
    /// resolvidas no loader principal via outra DLL; a copia aqui eh
    /// solta.
    #[test]
    fn strip_real_loaded_module_headers() {
        unsafe {
            // Nao chame LoadLibraryExA em ntdll/kernel32 (compartilhadas e vitais).
            let h = LoadLibraryExA(
                c"shcore.dll".as_ptr() as *const u8,
                0,
                DONT_RESOLVE_DLL_REFERENCES,
            );
            if h == 0 {
                eprintln!("shcore.dll nao disponivel; pulando teste");
                return;
            }
            let base = h as *mut u8;

            // Confirma que eh um PE antes.
            let magic_before = *(base as *const u16);
            assert_eq!(magic_before, IMAGE_DOS_SIGNATURE);

            // Descobre tamanho via NT headers.
            let dos = &*(base as *const IMAGE_DOS_HEADER);
            let nt = &*(base.add(dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
            let image_size = nt.OptionalHeader.SizeOfImage as usize;

            let rep = strip_module_headers(base, image_size).expect("strip falhou");
            assert_eq!(rep.dos_signature_before, IMAGE_DOS_SIGNATURE);
            assert_eq!(rep.dos_signature_after, 0);
            assert_eq!(rep.nt_signature_before, IMAGE_NT_SIGNATURE);
            assert_eq!(rep.nt_signature_after, 0);

            // Confere diretamente: ler os primeiros 2 bytes nao deve dar MZ.
            let magic_after = *(base as *const u16);
            assert_eq!(magic_after, 0, "primeiros 2 bytes nao estao zerados");

            // Nao chamar FreeLibrary - a estrutura PE foi destruida e o
            // unloader da ntdll pode tentar le-la. Deixa o processo
            // terminar normalmente.
            let _ = h;
            let _ = FreeLibrary; // silencia unused import warning
        }
    }

    /// Garante que a API `_auto` funciona em um buffer alocado por nos.
    #[test]
    fn strip_auto_via_virtual_query() {
        unsafe {
            let region_size = 0x2000usize;
            let base = VirtualAlloc(
                core::ptr::null(),
                region_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ) as *mut u8;
            assert!(!base.is_null());

            // Grava DOS "MZ"
            *(base as *mut u16) = IMAGE_DOS_SIGNATURE;
            let rep = strip_module_headers_auto(base).expect("auto strip falhou");
            assert_eq!(rep.dos_signature_before, IMAGE_DOS_SIGNATURE);
            assert_eq!(rep.dos_signature_after, 0);
            assert!(rep.cleared_bytes >= 2);

            VirtualFree(base as *mut c_void, 0, MEM_RELEASE);
        }
    }

    #[test]
    fn ffi_rejects_null() {
        unsafe {
            let rc = onyx_pe_strip_headers(core::ptr::null_mut(), 0x1000, core::ptr::null_mut());
            assert_eq!(rc, -1);
        }
    }

    #[test]
    fn ffi_reports_populated() {
        unsafe {
            let region_size = 0x2000usize;
            let base = VirtualAlloc(
                core::ptr::null(),
                region_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ) as *mut u8;
            *(base as *mut u16) = IMAGE_DOS_SIGNATURE;
            let mut rep: StripReport = core::mem::zeroed();
            let rc = onyx_pe_strip_headers(base, region_size, &mut rep);
            assert_eq!(rc, 0);
            assert_eq!(rep.dos_signature_before, IMAGE_DOS_SIGNATURE);
            assert_eq!(rep.dos_signature_after, 0);
            VirtualFree(base as *mut c_void, 0, MEM_RELEASE);
            let _ = GetModuleHandleA;
        }
    }
}
