// language: Rust, file: lib.rs (vehdebug_dll), target: Windows 11, MSVC
// Standalone injectable Vectored Exception Handling (VEH) debugger DLL

#![allow(non_snake_case, non_camel_case_types, dead_code, unsafe_op_in_unsafe_fn, static_mut_refs)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

type BOOL = i32;
type DWORD = u32;
type LONG = i32;
type HANDLE = *mut c_void;
type HMODULE = *mut c_void;
type LPVOID = *mut c_void;
type LPCVOID = *const c_void;
type PVOID = *mut c_void;

const DLL_PROCESS_ATTACH: DWORD = 1;
const EXCEPTION_CONTINUE_EXECUTION: LONG = -1;
const EXCEPTION_CONTINUE_SEARCH: LONG = 0;

const EXCEPTION_SINGLE_STEP: DWORD = 0x80000004;
const EXCEPTION_BREAKPOINT: DWORD = 0x80000003;

#[repr(C)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode: DWORD,
    pub ExceptionFlags: DWORD,
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ExceptionAddress: PVOID,
    pub NumberParameters: DWORD,
    pub ExceptionInformation: [usize; 15],
}

#[repr(C, align(16))]
#[derive(Copy, Clone)]
pub struct CONTEXT {
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: DWORD,
    pub MxCsr: DWORD,
    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: DWORD,
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,
    pub Rip: u64,
}

#[repr(C)]
pub struct EXCEPTION_POINTERS {
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ContextRecord: *mut CONTEXT,
}

type PVECTORED_EXCEPTION_HANDLER = unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> LONG;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn DisableThreadLibraryCalls(hLibModule: HMODULE) -> BOOL;
    fn AddVectoredExceptionHandler(First: u32, Handler: PVECTORED_EXCEPTION_HANDLER) -> PVOID;
    fn RemoveVectoredExceptionHandler(Handle: PVOID) -> DWORD;
    fn GetCurrentProcessId() -> DWORD;
    fn GetCurrentThreadId() -> DWORD;
    fn CreateNamedPipeA(
        lpName: *const u8,
        dwOpenMode: DWORD,
        dwPipeMode: DWORD,
        nMaxInstances: DWORD,
        nOutBufferSize: DWORD,
        nInBufferSize: DWORD,
        nDefaultTimeOut: DWORD,
        lpSecurityAttributes: LPVOID,
    ) -> HANDLE;
    fn ConnectNamedPipe(hNamedPipe: HANDLE, lpOverlapped: LPVOID) -> BOOL;
    fn DisconnectNamedPipe(hNamedPipe: HANDLE) -> BOOL;
    fn WriteFile(hFile: HANDLE, lpBuffer: LPCVOID, nNumberOfBytesToWrite: DWORD, lpNumberOfBytesWritten: *mut DWORD, lpOverlapped: LPVOID) -> BOOL;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VehHitReport {
    pub process_id: u32,
    pub thread_id: u32,
    pub rip: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub dr6: u64,
}

static VEH_INITIALIZED: AtomicBool = AtomicBool::new(false);
static VEH_HANDLER_HANDLE: Mutex<Option<usize>> = Mutex::new(None);
static LAST_HIT: Mutex<Option<VehHitReport>> = Mutex::new(None);

unsafe extern "system" fn VectoredExceptionHandler(ex: *mut EXCEPTION_POINTERS) -> LONG {
    if ex.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let p_rec = (*ex).ExceptionRecord;
    let p_ctx = (*ex).ContextRecord;

    if p_rec.is_null() || p_ctx.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let code = (*p_rec).ExceptionCode;

    if code == EXCEPTION_SINGLE_STEP {
        let report = VehHitReport {
            process_id: GetCurrentProcessId(),
            thread_id: GetCurrentThreadId(),
            rip: (*p_ctx).Rip,
            rax: (*p_ctx).Rax,
            rbx: (*p_ctx).Rbx,
            rcx: (*p_ctx).Rcx,
            rdx: (*p_ctx).Rdx,
            rsi: (*p_ctx).Rsi,
            rdi: (*p_ctx).Rdi,
            rsp: (*p_ctx).Rsp,
            rbp: (*p_ctx).Rbp,
            dr6: (*p_ctx).Dr6,
        };

        // Store last hit
        if let Ok(mut lock) = LAST_HIT.lock() {
            *lock = Some(report);
        }

        // Clear status and set Resume Flag (RF = bit 16) in EFlags
        (*p_ctx).Dr6 = 0;
        (*p_ctx).EFlags |= 0x00010000;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}

#[unsafe(no_mangle)]
pub extern "system" fn InitializeVEH() -> BOOL {
    if VEH_INITIALIZED.swap(true, Ordering::SeqCst) {
        return 1;
    }

    unsafe {
        let h = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
        if !h.is_null() {
            let mut lock = VEH_HANDLER_HANDLE.lock().unwrap();
            *lock = Some(h as usize);
            1
        } else {
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn UninitializeVEH() -> BOOL {
    let mut lock = VEH_HANDLER_HANDLE.lock().unwrap();
    if let Some(h) = lock.take() {
        unsafe {
            RemoveVectoredExceptionHandler(h as PVOID);
        }
        VEH_INITIALIZED.store(false, Ordering::SeqCst);
        1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    hinstDLL: HMODULE,
    fdwReason: DWORD,
    _lpReserved: LPVOID,
) -> BOOL {
    if fdwReason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(hinstDLL);
        InitializeVEH();
    }
    1
}
