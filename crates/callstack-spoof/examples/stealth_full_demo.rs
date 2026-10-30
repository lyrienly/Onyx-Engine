#![cfg(all(windows, target_arch = "x86_64"))]

//! Demo integrado: callstack spoof + PE header strip em um unico fluxo.
//! Imprime o resultado em stdout e grava `screenshots/stealth_full_demo_output.txt`.

use core::ffi::c_void;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::ptr;

use callstack_spoof::{call_spoofed, gadget_info, module_base_of};
use pe_strip::{strip_module_headers, StripReport};

use windows_sys::Win32::System::Diagnostics::Debug::{
    RtlCaptureStackBackTrace, IMAGE_NT_HEADERS64,
};
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryExA, DONT_RESOLVE_DLL_REFERENCES};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

#[inline(never)]
unsafe extern "C" fn capture_target(
    frames_out: *mut *mut c_void,
    frames_cap: usize,
    count_out: *mut u32,
    _unused: usize,
) -> usize {
    // Chama direto a syscall da ntdll pra o frame imediatamente acima do
    // capture_target ser nosso "fake return" (gadget) quando houver spoof.
    let n = RtlCaptureStackBackTrace(0, frames_cap as u32, frames_out, ptr::null_mut());
    if !count_out.is_null() {
        *count_out = n as u32;
    }
    0
}

fn log_frames<W: Write>(w: &mut W, label: &str, frames: &[*mut c_void], count: u32) {
    writeln!(w, "--- {label} ---").unwrap();
    let n = count as usize;
    for i in 0..n {
        let addr = frames[i];
        let base = unsafe { module_base_of(addr) };
        writeln!(w, "  frame[{:>2}] = {:p}  (module base = {:p})", i, addr, base).unwrap();
    }
}

fn format_bytes(bytes: &[u8]) -> String {
    let hex: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    let printable: String = bytes
        .iter()
        .map(|&b| if (0x20..=0x7E).contains(&b) { b as char } else { '.' })
        .collect();
    format!("{} | {}", hex.join(" "), printable)
}

struct TeeWriter<A: Write, B: Write> {
    a: A,
    b: B,
}
impl<A: Write, B: Write> Write for TeeWriter<A, B> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.a.write_all(buf)?;
        self.b.write_all(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.a.flush()?;
        self.b.flush()
    }
}

fn main() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // de crates/callstack-spoof sobe para o worktree root
    let repo_root = crate_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root nao encontrado");
    let shots_dir = repo_root.join("screenshots");
    fs::create_dir_all(&shots_dir).expect("mkdir screenshots falhou");
    let out_path = shots_dir.join("stealth_full_demo_output.txt");
    let file = File::create(&out_path).expect("abertura do output falhou");
    let stdout = std::io::stdout();
    let stdout_lock = stdout.lock();
    let mut out = TeeWriter {
        a: stdout_lock,
        b: file,
    };

    writeln!(
        out,
        "============================================================"
    )
    .unwrap();
    writeln!(out, " OnyxEngine - StealthCore full demo").unwrap();
    writeln!(out, " issue #25 (callstack spoof + PE header strip)").unwrap();
    writeln!(
        out,
        "============================================================\n"
    )
    .unwrap();

    // -------- Parte 1: callstack spoof --------
    let info = gadget_info();
    writeln!(out, "[gadget] ntdll base   : {:p}", info.ntdll_base).unwrap();
    writeln!(out, "[gadget] ntdll size   : 0x{:X}", info.ntdll_size).unwrap();
    writeln!(out, "[gadget] gadget addr  : {:p}", info.gadget).unwrap();
    writeln!(
        out,
        "[gadget] gadget bytes : 48 83 C4 28 C3  (add rsp, 0x28 ; ret)\n"
    )
    .unwrap();

    let mut frames = [ptr::null_mut::<c_void>(); 16];
    let mut count: u32 = 0;
    unsafe {
        let _ = capture_target(frames.as_mut_ptr(), frames.len(), &mut count, 0);
    }
    log_frames(&mut out, "ANTES do spoof (call direta)", &frames, count);

    frames = [ptr::null_mut(); 16];
    count = 0;
    unsafe {
        call_spoofed(
            capture_target as *const u8,
            frames.as_mut_ptr() as usize,
            frames.len(),
            &mut count as *mut u32 as usize,
            0,
        );
    }
    log_frames(
        &mut out,
        "DEPOIS do spoof (onyx_callstack_gate)",
        &frames,
        count,
    );

    let frame1 = frames[1] as usize;
    let base = info.ntdll_base as usize;
    let end = base + info.ntdll_size;
    let in_ntdll = frame1 >= base && frame1 < end;
    writeln!(
        out,
        "\n[spoof] frame[1] em ntdll? {}  (frame1={:#x}, ntdll=[{:#x}..{:#x}))\n",
        in_ntdll, frame1, base, end
    )
    .unwrap();
    if !in_ntdll {
        writeln!(out, "FALHA: spoof nao posicionou frame[1] dentro de ntdll").unwrap();
        std::process::exit(1);
    }

    // -------- Parte 2: PE header strip --------
    writeln!(
        out,
        "------------------------------------------------------------"
    )
    .unwrap();
    writeln!(out, " PE header stripping").unwrap();
    writeln!(
        out,
        "------------------------------------------------------------\n"
    )
    .unwrap();

    // Carrega uma DLL com DONT_RESOLVE_DLL_REFERENCES para nao executar
    // DllMain. `shcore.dll` existe em qualquer Windows moderno e nao eh
    // vital pra demo ficar viva depois do strip.
    let dll_name = c"shcore.dll";
    let h = unsafe {
        LoadLibraryExA(
            dll_name.as_ptr() as *const u8,
            0,
            DONT_RESOLVE_DLL_REFERENCES,
        )
    };
    if h == 0 {
        writeln!(out, "FALHA: LoadLibraryExA(shcore.dll) retornou NULL").unwrap();
        std::process::exit(1);
    }
    let base = h as *mut u8;
    writeln!(out, "[pe] shcore.dll carregada @ {:p}", base).unwrap();

    unsafe {
        let dos = &*(base as *const IMAGE_DOS_HEADER);
        let nt = &*(base.add(dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        let image_size = nt.OptionalHeader.SizeOfImage as usize;
        let header_size = nt.OptionalHeader.SizeOfHeaders as usize;
        writeln!(out, "[pe] SizeOfImage      = 0x{:X}", image_size).unwrap();
        writeln!(out, "[pe] SizeOfHeaders    = 0x{:X}", header_size).unwrap();

        let before: Vec<u8> = core::slice::from_raw_parts(base, 64).to_vec();
        writeln!(out, "[pe] primeiros 64 bytes ANTES do strip:").unwrap();
        writeln!(out, "     {}", format_bytes(&before[..32])).unwrap();
        writeln!(out, "     {}", format_bytes(&before[32..64])).unwrap();

        let rep: StripReport = strip_module_headers(base, image_size).expect("strip falhou");
        writeln!(
            out,
            "\n[pe] StripReport: cleared={} bytes previous_protect=0x{:X}",
            rep.cleared_bytes, rep.previous_protect
        )
        .unwrap();
        writeln!(
            out,
            "[pe] DOS sig: antes=0x{:04X} ({}MZ)  depois=0x{:04X}",
            rep.dos_signature_before,
            if rep.dos_signature_before == 0x5A4D {
                ""
            } else {
                "nao-"
            },
            rep.dos_signature_after
        )
        .unwrap();
        writeln!(
            out,
            "[pe] NT  sig: antes=0x{:08X}  depois=0x{:08X}",
            rep.nt_signature_before, rep.nt_signature_after
        )
        .unwrap();

        let after: Vec<u8> = core::slice::from_raw_parts(base, 64).to_vec();
        writeln!(out, "\n[pe] primeiros 64 bytes DEPOIS do strip:").unwrap();
        writeln!(out, "     {}", format_bytes(&after[..32])).unwrap();
        writeln!(out, "     {}", format_bytes(&after[32..64])).unwrap();

        if rep.dos_signature_after != 0 || rep.nt_signature_after != 0 {
            writeln!(out, "\nFALHA: assinaturas PE nao foram zeradas").unwrap();
            std::process::exit(1);
        }
    }

    writeln!(
        out,
        "\n============================================================"
    )
    .unwrap();
    writeln!(out, " demo concluida com sucesso").unwrap();
    writeln!(
        out,
        "============================================================"
    )
    .unwrap();
    writeln!(out, "\noutput salvo em: {}", out_path.display()).unwrap();
}
