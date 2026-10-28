#![cfg(windows)]
#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::time::Duration;

use onyx_core::memory::transaction::MemoryTransaction;
use onyx_core::process::Process;
use onyx_core::win32::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    VirtualAllocEx, VirtualFreeEx, CloseHandle, HANDLE, LPVOID,
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

struct NotepadGuard {
    pid: u32,
    h_process: HANDLE,
    h_thread: HANDLE,
    region: usize,
}

impl Drop for NotepadGuard {
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

fn spawn_notepad() -> NotepadGuard {
    let mut cmd = to_wide("C:\\Windows\\System32\\cmd.exe /K rem onyx-tx-e2e-cobaia");
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

    std::thread::sleep(Duration::from_millis(400));

    let region = unsafe {
        VirtualAllocEx(
            pi.hProcess,
            null_mut(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    assert!(!region.is_null(), "VirtualAllocEx failed");

    NotepadGuard {
        pid: pi.dwProcessId,
        h_process: pi.hProcess,
        h_thread: pi.hThread,
        region: region as usize,
    }
}

#[test]
fn e2e_notepad_write_then_rollback() {
    let guard = spawn_notepad();
    let addr = guard.region;
    let proc = Process::attach(guard.pid).expect("attach");

    let mut initial = [0u8; 16];
    proc.read_raw(addr, &mut initial).expect("read initial");
    println!(
        "[e2e] pid={} region=0x{:X} initial={:?}",
        guard.pid, addr, initial
    );

    let payload = [0xDEu8, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let mut tx = MemoryTransaction::begin(guard.pid).expect("begin");
    tx.write(addr, &payload).expect("tx write");

    let mut after_write = [0u8; 8];
    proc.read_raw(addr, &mut after_write).expect("read after write");
    println!("[e2e] after write bytes={:X?}", after_write);
    assert_eq!(&after_write, &payload);

    tx.rollback().expect("rollback");

    let mut after_rollback = [0u8; 8];
    proc.read_raw(addr, &mut after_rollback).expect("read after rb");
    println!("[e2e] after rollback bytes={:X?}", after_rollback);
    assert_eq!(&after_rollback, &initial[..8]);
    println!("[e2e] PASS: rollback restored original bytes on remote process");
}
