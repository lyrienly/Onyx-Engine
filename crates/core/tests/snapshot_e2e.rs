#![cfg(windows)]
#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::time::{Duration, Instant};

use onyx_core::memory::snapshot::{
    DEFAULT_CHUNK_SIZE, HashAlgo, MemorySnapshot, xxh3,
};
use onyx_core::process::Process;
use onyx_core::win32::{
    CloseHandle, HANDLE, LPCVOID, LPVOID, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_READWRITE, SIZE_T, VirtualAllocEx, VirtualFreeEx, WriteProcessMemory,
};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateProcessW(
        lpApplicationName: *const u16,
        lpCommandLine: *mut u16,
        lpProcessAttributes: *mut std::ffi::c_void,
        lpThreadAttributes: *mut std::ffi::c_void,
        bInheritHandles: i32,
        dwCreationFlags: u32,
        lpEnvironment: *mut std::ffi::c_void,
        lpCurrentDirectory: *const u16,
        lpStartupInfo: *mut StartupInfoW,
        lpProcessInformation: *mut ProcessInformation,
    ) -> i32;
    fn TerminateProcess(hProcess: HANDLE, uExitCode: u32) -> i32;
}

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    lpReserved: *mut u16,
    lpDesktop: *mut u16,
    lpTitle: *mut u16,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    dwFlags: u32,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *mut u8,
    hStdInput: HANDLE,
    hStdOutput: HANDLE,
    hStdError: HANDLE,
}

#[repr(C)]
struct ProcessInformation {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: u32,
    dwThreadId: u32,
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

struct CobaiaGuard {
    pid: u32,
    h_process: HANDLE,
    h_thread: HANDLE,
    region: usize,
    size: usize,
}

impl Drop for CobaiaGuard {
    fn drop(&mut self) {
        unsafe {
            if self.region != 0 {
                VirtualFreeEx(self.h_process, self.region as LPVOID, 0, MEM_RELEASE);
            }
            TerminateProcess(self.h_process, 0);
            CloseHandle(self.h_thread);
            CloseHandle(self.h_process);
        }
    }
}

fn spawn_cobaia(size: usize) -> CobaiaGuard {
    let mut cmd = to_wide("C:\\Windows\\System32\\cmd.exe /K rem onyx-snap-e2e-cobaia");
    let mut si: StartupInfoW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<StartupInfoW>() as u32;
    let mut pi: ProcessInformation = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            null_mut(),
            cmd.as_mut_ptr(),
            null_mut(),
            null_mut(),
            0,
            0x08000000,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        )
    };
    assert!(ok != 0, "CreateProcessW falhou");

    std::thread::sleep(Duration::from_millis(400));

    let region = unsafe {
        VirtualAllocEx(
            pi.hProcess,
            null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    assert!(!region.is_null(), "VirtualAllocEx falhou");

    let seed = vec![0xAAu8; size];
    let mut written: SIZE_T = 0;
    let ok = unsafe {
        WriteProcessMemory(
            pi.hProcess,
            region as LPVOID,
            seed.as_ptr() as LPCVOID,
            size,
            &mut written as *mut _,
        )
    };
    assert!(ok != 0 && written == size, "seed WPM falhou");

    CobaiaGuard {
        pid: pi.dwProcessId,
        h_process: pi.hProcess,
        h_thread: pi.hThread,
        region: region as usize,
        size,
    }
}

fn write_bytes(guard: &CobaiaGuard, offset: usize, bytes: &[u8]) {
    let mut written: SIZE_T = 0;
    let ok = unsafe {
        WriteProcessMemory(
            guard.h_process,
            (guard.region + offset) as LPVOID,
            bytes.as_ptr() as LPCVOID,
            bytes.len(),
            &mut written as *mut _,
        )
    };
    assert!(ok != 0 && written == bytes.len(), "WPM falhou offset=0x{:X}", offset);
}

#[test]
fn e2e_snapshot_detecta_chunks_alterados() {
    let region_size = 16 * DEFAULT_CHUNK_SIZE;
    let guard = spawn_cobaia(region_size);
    let addr = guard.region;
    let proc = Process::attach(guard.pid).expect("attach");

    println!(
        "[snap-e2e] pid={} region=0x{:X} size=0x{:X}",
        guard.pid, addr, region_size
    );

    let snap1 = MemorySnapshot::capture_range(&proc, addr, region_size).expect("snap1");
    let in_range: Vec<_> = snap1
        .chunks
        .iter()
        .filter(|c| c.address >= addr && c.address < addr + region_size)
        .collect();
    assert_eq!(in_range.len(), 16, "esperado 16 chunks de 4KB");
    println!(
        "[snap-e2e] snap1 total_chunks={} chunks_na_regiao={}",
        snap1.chunks.len(),
        in_range.len()
    );

    write_bytes(&guard, DEFAULT_CHUNK_SIZE * 3 + 10, &[0xDE, 0xAD, 0xBE, 0xEF]);
    write_bytes(&guard, DEFAULT_CHUNK_SIZE * 7, &[0xCA, 0xFE]);

    let snap2 = MemorySnapshot::capture_range(&proc, addr, region_size).expect("snap2");
    let diff = snap1.diff(&snap2);
    let in_diff: Vec<_> = diff
        .iter()
        .filter(|r| r.start >= addr && r.start < addr + region_size)
        .copied()
        .collect();
    println!("[snap-e2e] diff_regioes={:?}", in_diff);
    assert_eq!(in_diff.len(), 2, "esperado 2 regioes alteradas");
    assert_eq!(in_diff[0].start, addr + DEFAULT_CHUNK_SIZE * 3);
    assert_eq!(in_diff[1].start, addr + DEFAULT_CHUNK_SIZE * 7);

    let detailed = snap1.diff_detailed(&snap2);
    let detailed_in: Vec<_> = detailed
        .into_iter()
        .filter(|c| c.address >= addr && c.address < addr + region_size)
        .collect();
    assert_eq!(detailed_in.len(), 2);
    for d in &detailed_in {
        assert_ne!(d.old_hash, d.new_hash);
        println!(
            "[snap-e2e] chunk 0x{:X} old=0x{:016X} new=0x{:016X}",
            d.address, d.old_hash, d.new_hash
        );
    }

    write_bytes(&guard, DEFAULT_CHUNK_SIZE * 11 + 100, &[0x12, 0x34, 0x56]);
    let changed = snap1.diff_with_bytes(&proc).expect("diff_with_bytes");
    let changed_in: Vec<_> = changed
        .into_iter()
        .filter(|c| c.address >= addr && c.address < addr + region_size)
        .collect();
    assert_eq!(changed_in.len(), 3);
    for c in &changed_in {
        assert_eq!(c.bytes.len(), DEFAULT_CHUNK_SIZE);
        let recomputed = xxh3(&c.bytes);
        assert_eq!(recomputed, c.new_hash);
    }
    println!("[snap-e2e] PASS: diff_with_bytes retornou {} chunks", changed_in.len());
}

#[test]
fn benchmark_xxh3_vs_memcmp_100mb() {
    const MB: usize = 1024 * 1024;
    let size = 100 * MB;
    let mut a = vec![0u8; size];
    for (i, b) in a.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(31);
    }
    let mut b = a.clone();
    b[size - 1024] ^= 0xFF;

    let t = Instant::now();
    let mut hashed = 0u64;
    for chunk in a.chunks(DEFAULT_CHUNK_SIZE) {
        hashed = hashed.wrapping_add(xxh3(chunk));
    }
    let dt_hash = t.elapsed();

    let t = Instant::now();
    let eq = a == b;
    let dt_memcmp = t.elapsed();

    println!(
        "[bench] xxh3 100MB em {} chunks de {}B: {:?} (acc=0x{:X})",
        a.len() / DEFAULT_CHUNK_SIZE,
        DEFAULT_CHUNK_SIZE,
        dt_hash,
        hashed
    );
    println!(
        "[bench] memcmp direto 100MB: {:?} (eq={})",
        dt_memcmp, eq
    );

    let max_duration = if cfg!(debug_assertions) {
        Duration::from_millis(2500)
    } else {
        Duration::from_millis(500)
    };

    assert!(
        dt_hash < max_duration,
        "xxh3 muito lento: {:?}",
        dt_hash
    );
}

#[test]
fn test_algo_switch_fnv_vs_xxh3() {
    let data = vec![0x5Au8; 4096];
    let h_fnv = HashAlgo::Fnv1a64.hash(&data);
    let h_xxh = HashAlgo::Xxh3.hash(&data);
    assert_ne!(h_fnv, h_xxh);
    assert_eq!(HashAlgo::Xxh3.hash(&data), xxh3(&data));
}
