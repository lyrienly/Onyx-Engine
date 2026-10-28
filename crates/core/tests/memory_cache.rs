#![cfg(windows)]
#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use onyx_core::memory::cache::{MemoryCache, MIN_CHUNK_SIZE};
use onyx_core::process::Process;
use onyx_core::win32::{
    CloseHandle, HANDLE, LPVOID, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    VirtualAllocEx, VirtualFreeEx,
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
    fn WriteProcessMemory(
        hProcess: HANDLE,
        lpBaseAddress: LPVOID,
        lpBuffer: *const u8,
        nSize: usize,
        lpNumberOfBytesWritten: *mut usize,
    ) -> i32;
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
    region_size: usize,
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

fn spawn_cobaia(region_size: usize) -> CobaiaGuard {
    let mut cmd = to_wide("C:\\Windows\\System32\\cmd.exe /K rem onyx-cache-e2e-cobaia");
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
    assert!(ok != 0, "CreateProcessW failed");
    thread::sleep(Duration::from_millis(400));

    let region = unsafe {
        VirtualAllocEx(
            pi.hProcess,
            null_mut(),
            region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    assert!(!region.is_null(), "VirtualAllocEx failed");

    let pattern: Vec<u8> = (0..region_size).map(|i| (i & 0xff) as u8).collect();
    let mut written = 0usize;
    let wr = unsafe {
        WriteProcessMemory(
            pi.hProcess,
            region as LPVOID,
            pattern.as_ptr(),
            region_size,
            &mut written,
        )
    };
    assert!(wr != 0 && written == region_size, "WriteProcessMemory failed");

    CobaiaGuard {
        pid: pi.dwProcessId,
        h_process: pi.hProcess,
        h_thread: pi.hThread,
        region: region as usize,
        region_size,
    }
}

#[test]
fn concurrent_readers_same_region() {
    let cache = Arc::new(MemoryCache::new(16, MIN_CHUNK_SIZE));
    let backing: Arc<Vec<u8>> = Arc::new(
        (0..(64 * 1024usize)).map(|i| (i & 0xff) as u8).collect(),
    );
    let load_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let cache = cache.clone();
        let backing = backing.clone();
        let load_count = load_count.clone();
        handles.push(thread::spawn(move || {
            for i in 0..200 {
                let addr = (i % 16) as u64 * 64;
                let want = &backing[addr as usize..addr as usize + 128];
                let got = cache
                    .get_or_load(addr, 128, |a, n| -> Result<Vec<u8>, String> {
                        load_count.fetch_add(1, Ordering::Relaxed);
                        Ok(backing[a as usize..a as usize + n].to_vec())
                    })
                    .unwrap();
                assert_eq!(&got[..], want, "deterministic read mismatch");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let stats = cache.stats();
    println!(
        "[concurrent] loads={} hits={} misses={} evictions={}",
        load_count.load(Ordering::Relaxed),
        stats.hits,
        stats.misses,
        stats.evictions
    );
    assert!(stats.hits > 0);
}

#[test]
fn e2e_cmd_cobaia_sequential_scan_hit_rate() {
    const REGION: usize = 256 * 1024;
    let guard = spawn_cobaia(REGION);
    let proc = Process::attach(guard.pid).expect("attach");

    let cache = MemoryCache::new(32, MIN_CHUNK_SIZE);
    let base = guard.region as u64;

    let step = 32usize;
    let read_size = 64usize;
    let iters = (REGION - read_size) / step;

    let t0 = Instant::now();
    for i in 0..iters {
        let a = base + (i * step) as u64;
        let got = cache.read_process(&proc, a, read_size).expect("read");
        assert_eq!(got.len(), read_size);
        let expect0 = (((a as usize) - guard.region) & 0xff) as u8;
        assert_eq!(got[0], expect0, "first byte mismatch at off {}", i * step);
    }
    let dt_cached = t0.elapsed();
    let s = cache.stats();
    let total = s.hits + s.misses;
    let hit_rate = (s.hits as f64) / (total as f64) * 100.0;

    let t1 = Instant::now();
    for i in 0..iters {
        let a = (base + (i * step) as u64) as usize;
        let got = proc.read_bytes(a, read_size).expect("direct read");
        assert_eq!(got.len(), read_size);
    }
    let dt_direct = t1.elapsed();

    println!(
        "[e2e] iters={} chunk={} hits={} misses={} hit_rate={:.1}% cached={:?} direct={:?}",
        iters, MIN_CHUNK_SIZE, s.hits, s.misses, hit_rate, dt_cached, dt_direct
    );

    assert!(
        hit_rate > 50.0,
        "hit rate too low on sequential scan: {:.1}%",
        hit_rate
    );
}

#[test]
fn e2e_cmd_cobaia_benchmark_10k() {
    const REGION: usize = 512 * 1024;
    let guard = spawn_cobaia(REGION);
    let proc = Process::attach(guard.pid).expect("attach");

    let cache = MemoryCache::new(64, MIN_CHUNK_SIZE);
    let base = guard.region as u64;
    let read_size = 32usize;
    let iters = 10_000usize;
    let step = (REGION - read_size) / iters;
    let step = step.max(1);

    let t0 = Instant::now();
    for i in 0..iters {
        let a = base + ((i * step) % (REGION - read_size)) as u64;
        let _ = cache.read_process(&proc, a, read_size).expect("read cached");
    }
    let dt_cached = t0.elapsed();

    let t1 = Instant::now();
    for i in 0..iters {
        let a = (base + ((i * step) % (REGION - read_size)) as u64) as usize;
        let _ = proc.read_bytes(a, read_size).expect("direct");
    }
    let dt_direct = t1.elapsed();

    let s = cache.stats();
    let total = s.hits + s.misses;
    let hit_rate = (s.hits as f64) / (total as f64) * 100.0;

    println!(
        "[bench] iters={} step={} cached={:?} direct={:?} hits={} misses={} hit_rate={:.1}%",
        iters, step, dt_cached, dt_direct, s.hits, s.misses, hit_rate
    );
    assert!(hit_rate > 50.0, "hit rate too low: {:.1}%", hit_rate);
}
