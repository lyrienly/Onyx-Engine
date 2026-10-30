#![cfg(all(windows, target_arch = "x86_64"))]

//! Demo isolado do PE header strip. Carrega `shcore.dll` com
//! `DONT_RESOLVE_DLL_REFERENCES`, dumpa os primeiros 64 bytes, zera os
//! cabeçalhos e dumpa de novo.

use pe_strip::{strip_module_headers, StripReport};
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryExA, DONT_RESOLVE_DLL_REFERENCES};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

fn hex_dump(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn main() {
    let name = c"shcore.dll";
    let h = unsafe { LoadLibraryExA(name.as_ptr() as *const u8, 0, DONT_RESOLVE_DLL_REFERENCES) };
    if h == 0 {
        eprintln!("LoadLibraryExA falhou");
        std::process::exit(1);
    }
    let base = h as *mut u8;

    unsafe {
        let dos = &*(base as *const IMAGE_DOS_HEADER);
        let nt = &*(base.add(dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        let image_size = nt.OptionalHeader.SizeOfImage as usize;

        let before = core::slice::from_raw_parts(base, 64).to_vec();
        println!("ANTES  : {}", hex_dump(&before[..32]));
        println!("         {}", hex_dump(&before[32..]));

        let rep: StripReport = strip_module_headers(base, image_size).expect("strip falhou");
        println!(
            "report : cleared={} previous_protect=0x{:X} dos_before=0x{:04X} dos_after=0x{:04X} nt_before=0x{:08X} nt_after=0x{:08X}",
            rep.cleared_bytes,
            rep.previous_protect,
            rep.dos_signature_before,
            rep.dos_signature_after,
            rep.nt_signature_before,
            rep.nt_signature_after
        );

        let after = core::slice::from_raw_parts(base, 64).to_vec();
        println!("DEPOIS : {}", hex_dump(&after[..32]));
        println!("         {}", hex_dump(&after[32..]));

        if rep.dos_signature_after != 0 || rep.nt_signature_after != 0 {
            eprintln!("FALHA: assinaturas nao zeradas");
            std::process::exit(1);
        }
    }
}
