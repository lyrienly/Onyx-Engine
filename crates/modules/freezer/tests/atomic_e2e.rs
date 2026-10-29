#![cfg(windows)]

use onyx_freezer::{AtomicFreezer, FreezeMode};
use std::os::raw::c_void;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

type HANDLE = *mut c_void;
type DWORD = u32;
type BOOL = i32;
#[allow(non_camel_case_types)]
type SIZE_T = usize;

const FALSE: BOOL = 0;
const PROCESS_ALL_ACCESS: DWORD = 0x001F_FFFF;
const MEM_COMMIT: DWORD = 0x1000;
const MEM_RESERVE: DWORD = 0x2000;
const MEM_RELEASE: DWORD = 0x8000;
const PAGE_READWRITE: DWORD = 0x04;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(access: DWORD, inherit: BOOL, pid: DWORD) -> HANDLE;
    fn CloseHandle(h: HANDLE) -> BOOL;
    fn VirtualAllocEx(
        h: HANDLE,
        addr: *mut c_void,
        size: SIZE_T,
        alloc: DWORD,
        protect: DWORD,
    ) -> *mut c_void;
    fn VirtualFreeEx(h: HANDLE, addr: *mut c_void, size: SIZE_T, free: DWORD) -> BOOL;
    fn WriteProcessMemory(
        h: HANDLE,
        addr: *mut c_void,
        buf: *const c_void,
        size: SIZE_T,
        written: *mut SIZE_T,
    ) -> BOOL;
    fn ReadProcessMemory(
        h: HANDLE,
        addr: *const c_void,
        buf: *mut c_void,
        size: SIZE_T,
        read: *mut SIZE_T,
    ) -> BOOL;
}

fn write_i32(h: HANDLE, addr: usize, v: i32) -> bool {
    let bytes = v.to_le_bytes();
    let mut written: SIZE_T = 0;
    let ok = unsafe {
        WriteProcessMemory(
            h,
            addr as *mut c_void,
            bytes.as_ptr() as *const c_void,
            4,
            &mut written,
        )
    };
    ok != 0 && written == 4
}

fn read_i32(h: HANDLE, addr: usize) -> Option<i32> {
    let mut buf = [0u8; 4];
    let mut read: SIZE_T = 0;
    let ok = unsafe {
        ReadProcessMemory(
            h,
            addr as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            4,
            &mut read,
        )
    };
    if ok != 0 && read == 4 {
        Some(i32::from_le_bytes(buf))
    } else {
        None
    }
}

#[test]
fn e2e_freeze_mantem_valor_contra_sobrescrita_externa() {

    let mut child = Command::new("cmd.exe")
        .args(["/C", "ping -n 15 127.0.0.1 > nul"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn cmd.exe");

    let pid = child.id();

    let test_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
    assert!(!test_handle.is_null(), "OpenProcess cobaia falhou");

    let addr = unsafe {
        VirtualAllocEx(
            test_handle,
            std::ptr::null_mut(),
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    assert!(!addr.is_null(), "VirtualAllocEx falhou");
    let addr_us = addr as usize;

    assert!(write_i32(test_handle, addr_us, 100));
    assert_eq!(read_i32(test_handle, addr_us), Some(100));

    let freezer = AtomicFreezer::new();
    freezer.attach(pid);
    freezer.set_interval(Duration::from_millis(5));
    let frozen = 42i32.to_le_bytes().to_vec();
    let id = freezer.freeze(addr_us, frozen.clone(), FreezeMode::Normal);

    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        read_i32(test_handle, addr_us),
        Some(42),
        "freezer deveria ter aplicado 42"
    );

    for _ in 0..5 {
        write_i32(test_handle, addr_us, 999);
        thread::sleep(Duration::from_millis(80));
    }

    thread::sleep(Duration::from_millis(150));
    let final_val = read_i32(test_handle, addr_us);
    assert_eq!(
        final_val,
        Some(42),
        "memoria deveria ter sido restaurada para 42, veio {:?}",
        final_val
    );

    freezer.reset_stats();

    let stop_sig = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_c = stop_sig.clone();
    let addr_copy = addr_us;
    let handle_bits = test_handle as usize;
    let noise = thread::spawn(move || {
        let h = handle_bits as HANDLE;
        while !stop_c.load(std::sync::atomic::Ordering::Relaxed) {
            write_i32(h, addr_copy, 999);
            thread::sleep(Duration::from_millis(2));
        }
    });

    let t0 = Instant::now();
    thread::sleep(Duration::from_secs(1));
    let elapsed = t0.elapsed().as_secs_f64();
    stop_sig.store(true, std::sync::atomic::Ordering::Relaxed);
    noise.join().unwrap();
    let stats = freezer.stats();
    let rate = stats.writes as f64 / elapsed;
    eprintln!(
        "[freezer][e2e] rate={:.1} writes/s reads={} writes={} errors={} cache_hits={} elapsed={:.3}s",
        rate, stats.reads, stats.writes, stats.errors, stats.cache_hits, elapsed
    );
    assert!(
        stats.reads > 0,
        "worker nao executou nenhuma leitura (reads=0)"
    );

    assert!(
        stats.writes >= 10,
        "freeze rate muito baixo ({} writes/s)",
        rate
    );

    assert!(freezer.unfreeze(id));
    thread::sleep(Duration::from_millis(50));
    write_i32(test_handle, addr_us, 999);
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        read_i32(test_handle, addr_us),
        Some(999),
        "apos unfreeze a sobrescrita deveria persistir"
    );

    freezer.stop();
    unsafe {
        VirtualFreeEx(test_handle, addr, 0, MEM_RELEASE);
        CloseHandle(test_handle);
    }
    let _ = child.kill();
    let _ = child.wait();
}
