#![cfg(windows)]
#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use onyx_core::debugger::page_guard::{AccessType, PageGuardManager};
use onyx_core::win32::{
    CloseHandle, CreateRemoteThread, GetExitCodeThread, HANDLE, LPCVOID, LPVOID, MEM_COMMIT,
    MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, SIZE_T, VirtualAllocEx,
    VirtualFreeEx, WaitForSingleObject, WriteProcessMemory,
};

const DEBUG_ONLY_THIS_PROCESS: u32 = 0x0000_0002;
const CREATE_SUSPENDED: u32 = 0x0000_0004;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

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
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

struct CobaiaGuard {
    pid: u32,
    h_process: HANDLE,
    h_thread: HANDLE,
    data_page: usize,
    code_page: usize,
}

impl Drop for CobaiaGuard {
    fn drop(&mut self) {
        unsafe {
            if self.data_page != 0 {
                VirtualFreeEx(self.h_process, self.data_page as LPVOID, 0, MEM_RELEASE);
            }
            if self.code_page != 0 {
                VirtualFreeEx(self.h_process, self.code_page as LPVOID, 0, MEM_RELEASE);
            }
            TerminateProcess(self.h_process, 0);
            CloseHandle(self.h_thread);
            CloseHandle(self.h_process);
        }
    }
}

const SHELLCODE_WRITE_DWORD: [u8; 10] =
    [0xC7, 0x01, 0xEF, 0xBE, 0xAD, 0xDE, 0x31, 0xC0, 0xC3, 0x90];

const SHELLCODE_READ_DWORD: [u8; 4] = [0x8B, 0x01, 0xC3, 0x90];

fn spawn_cobaia() -> CobaiaGuard {
    let mut cmd = to_wide("C:\\Windows\\System32\\cmd.exe /K rem onyx-page-guard-cobaia");
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
            CREATE_NO_WINDOW,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        )
    };
    assert!(ok != 0, "CreateProcessW falhou (cobaia)");

    std::thread::sleep(Duration::from_millis(600));

    let data = unsafe {
        VirtualAllocEx(
            pi.hProcess,
            null_mut(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    assert!(!data.is_null(), "VirtualAllocEx data falhou");

    let code = unsafe {
        VirtualAllocEx(
            pi.hProcess,
            null_mut(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    assert!(!code.is_null(), "VirtualAllocEx code falhou");

    CobaiaGuard {
        pid: pi.dwProcessId,
        h_process: pi.hProcess,
        h_thread: pi.hThread,
        data_page: data as usize,
        code_page: code as usize,
    }
}

fn write_remote(h_process: HANDLE, addr: usize, bytes: &[u8]) {
    let mut written: SIZE_T = 0;
    let ok = unsafe {
        WriteProcessMemory(
            h_process,
            addr as LPVOID,
            bytes.as_ptr() as LPCVOID,
            bytes.len(),
            &mut written,
        )
    };
    assert!(
        ok != 0 && written == bytes.len(),
        "WriteProcessMemory falhou @ 0x{:X}",
        addr
    );
}

fn run_remote_shellcode(h_process: HANDLE, code_addr: usize, arg: usize) -> u32 {
    let mut tid: u32 = 0;
    let h = unsafe {
        CreateRemoteThread(
            h_process,
            null_mut(),
            0,
            std::mem::transmute::<usize, unsafe extern "system" fn(LPVOID) -> u32>(code_addr),
            arg as LPVOID,
            0,
            &mut tid,
        )
    };
    assert!(!h.is_null(), "CreateRemoteThread falhou");

    unsafe { WaitForSingleObject(h, 3000) };
    let mut code: u32 = 0;
    unsafe { GetExitCodeThread(h, &mut code) };
    unsafe { CloseHandle(h) };
    code
}

#[test]
fn e2e_page_guard_captura_write_remoto_e_filtra_falso_positivo() {
    let cobaia = spawn_cobaia();
    let data_base = cobaia.data_page;
    let code_base = cobaia.code_page;

    let alvo_bp = data_base + 0x40;
    let alvo_fora = data_base + 0x800;

    write_remote(cobaia.h_process, code_base, &SHELLCODE_WRITE_DWORD);

    let mgr = PageGuardManager::attach(cobaia.pid).expect("attach");

    let hits = Arc::new(Mutex::new(Vec::new()));
    let hits_clone = Arc::clone(&hits);
    mgr.on_hit(move |hit| {
        hits_clone.lock().unwrap().push(hit);
    });

    let bp_id = mgr
        .set(alvo_bp as u64, 4, AccessType::Write)
        .expect("set bp");

    run_remote_shellcode(cobaia.h_process, code_base, alvo_fora);

    std::thread::sleep(Duration::from_millis(300));

    let hits_after_falso = hits.lock().unwrap().clone();
    eprintln!(
        "[e2e] hits apos acesso FORA do range: {:?}",
        hits_after_falso
    );
    assert!(
        hits_after_falso.is_empty(),
        "falso positivo nao foi filtrado: {:?}",
        hits_after_falso
    );

    run_remote_shellcode(cobaia.h_process, code_base, alvo_bp);

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let n = hits.lock().unwrap().len();
        if n > 0 || Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let hits_final = hits.lock().unwrap().clone();
    eprintln!("[e2e] hits apos acesso DENTRO: {:?}", hits_final);
    assert_eq!(hits_final.len(), 1, "esperava exatamente 1 hit real");
    let h = hits_final[0];
    assert_eq!(h.id, bp_id);
    assert_eq!(h.address, alvo_bp as u64);
    assert_eq!(h.fault_address, alvo_bp as u64);
    assert_eq!(h.access_type, AccessType::Write);

    mgr.remove(bp_id).expect("remove");
    run_remote_shellcode(cobaia.h_process, code_base, alvo_bp);
    std::thread::sleep(Duration::from_millis(300));
    let hits_pos_remove = hits.lock().unwrap().clone();
    assert_eq!(
        hits_pos_remove.len(),
        1,
        "nao devia disparar apos remove: {:?}",
        hits_pos_remove
    );

    drop(mgr);
    drop(cobaia);
}

#[test]
fn e2e_page_guard_captura_read_remoto() {
    let cobaia = spawn_cobaia();
    let data_base = cobaia.data_page;
    let code_base = cobaia.code_page;
    let alvo = data_base + 0x100;

    write_remote(cobaia.h_process, code_base, &SHELLCODE_READ_DWORD);

    let mgr = PageGuardManager::attach(cobaia.pid).expect("attach");
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = Arc::clone(&count);
    mgr.on_hit(move |_hit| {
        count_clone.fetch_add(1, Ordering::SeqCst);
    });

    mgr.set(alvo as u64, 4, AccessType::Read).expect("set bp");

    run_remote_shellcode(cobaia.h_process, code_base, alvo);

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if count.load(Ordering::SeqCst) > 0 || Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let n = count.load(Ordering::SeqCst);
    eprintln!("[e2e] read hits: {}", n);
    assert!(n >= 1, "esperava pelo menos 1 hit de read, obteve {}", n);

    drop(mgr);
    drop(cobaia);
}
