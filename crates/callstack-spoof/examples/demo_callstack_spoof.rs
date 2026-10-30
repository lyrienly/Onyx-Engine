#![cfg(all(windows, target_arch = "x86_64"))]

//! Demo isolado: imprime o callstack de uma funcao chamada com e sem
//! `call_spoofed`.

use core::ffi::c_void;
use std::ptr;

use callstack_spoof::{call_spoofed, gadget_info, module_base_of};
use windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace;

#[inline(never)]
unsafe extern "C" fn capture_target(
    frames_out: *mut *mut c_void,
    frames_cap: usize,
    count_out: *mut u32,
    _unused: usize,
) -> usize {
    let n = RtlCaptureStackBackTrace(0, frames_cap as u32, frames_out, ptr::null_mut());
    if !count_out.is_null() {
        *count_out = n as u32;
    }
    0
}

fn print_frames(label: &str, frames: &[*mut c_void], count: u32) {
    println!("--- {label} ---");
    let n = count as usize;
    for i in 0..n {
        let addr = frames[i];
        let base = unsafe { module_base_of(addr) };
        println!("  frame[{i:>2}] = {addr:p}  (module base = {base:p})");
    }
}

fn main() {
    let info = gadget_info();
    println!("ntdll base         : {:p}", info.ntdll_base);
    println!("ntdll size         : 0x{:X}", info.ntdll_size);
    println!("spoof gadget @     : {:p}", info.gadget);

    let mut frames = [ptr::null_mut::<c_void>(); 16];
    let mut count: u32 = 0;
    unsafe {
        let _ = capture_target(frames.as_mut_ptr(), frames.len(), &mut count, 0);
    }
    print_frames("call direta (sem spoof)", &frames, count);

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
    print_frames("call via onyx_callstack_gate (spoof)", &frames, count);

    let frame1 = frames[1] as usize;
    let base = info.ntdll_base as usize;
    let end = base + info.ntdll_size;
    if frame1 >= base && frame1 < end {
        println!(
            "\nOK: frame[1] = {:#x} esta dentro de ntdll [{:#x}..{:#x})",
            frame1, base, end
        );
    } else {
        println!(
            "\nFALHA: frame[1] = {:#x} nao esta em ntdll [{:#x}..{:#x})",
            frame1, base, end
        );
        std::process::exit(1);
    }
}
