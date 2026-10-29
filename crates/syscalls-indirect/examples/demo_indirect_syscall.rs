#![cfg(all(windows, target_arch = "x86_64"))]

use std::ffi::c_void;

use syscalls_indirect::{
    get_ssn, nt_query_system_information, ntdll, ProcessIter, SYSTEM_PROCESS_INFORMATION,
};

fn main() {
    let info = ntdll();
    println!("ntdll base      : {:p}", info.base);
    println!("syscall gadget  : {:p}", info.gadget);
    println!("resolved SSNs   : {}", info.ssn.len());
    for name in [
        "NtQuerySystemInformation",
        "NtOpenProcess",
        "NtReadVirtualMemory",
        "NtClose",
        "NtAllocateVirtualMemory",
    ] {
        println!("  {name:30} = 0x{:04X}", get_ssn(name).unwrap_or(0));
    }

    let mut size: usize = 1024 * 1024;
    let mut buf: Vec<u8>;
    let mut returned = 0u32;
    loop {
        buf = vec![0u8; size];
        let status = unsafe {
            nt_query_system_information(
                SYSTEM_PROCESS_INFORMATION,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut returned,
            )
        };
        if status == 0 {
            break;
        }
        if status as u32 == 0xC0000004 {
            size = (size * 2).max(returned as usize + 0x10000);
            if size > 64 * 1024 * 1024 {
                eprintln!("buffer explodiu");
                std::process::exit(1);
            }
            continue;
        }
        eprintln!("NtQuerySystemInformation falhou: 0x{:08X}", status);
        std::process::exit(1);
    }
    println!("buffer preenchido: {returned} bytes");
    println!("primeiros 20 processos enumerados via syscall indireta:\n");

    let it = unsafe { ProcessIter::new(buf.as_ptr()) };
    for (i, (pid, name)) in it.enumerate().take(20) {
        println!("  {:>2}  pid={:<6}  {}", i + 1, pid, name);
    }
}
