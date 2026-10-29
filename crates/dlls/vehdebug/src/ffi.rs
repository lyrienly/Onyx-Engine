#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ffi::c_void;

pub type BOOL = i32;
pub type DWORD = u32;
pub type LONG = i32;
pub type HANDLE = *mut c_void;
pub type HMODULE = *mut c_void;
pub type LPVOID = *mut c_void;
pub type LPCVOID = *const c_void;
pub type PVOID = *mut c_void;

pub const DLL_PROCESS_ATTACH: DWORD = 1;
pub const EXCEPTION_CONTINUE_EXECUTION: LONG = -1;
pub const EXCEPTION_CONTINUE_SEARCH: LONG = 0;

pub const EXCEPTION_SINGLE_STEP: DWORD = 0x8000_0004;
pub const EXCEPTION_BREAKPOINT: DWORD = 0x8000_0003;
pub const EXCEPTION_ACCESS_VIOLATION: DWORD = 0xC000_0005;
pub const STATUS_GUARD_PAGE_VIOLATION: DWORD = 0x8000_0001;

pub const EFLAGS_TF: u32 = 0x0000_0100;
pub const EFLAGS_RF: u32 = 0x0001_0000;

pub const CONTEXT_AMD64: u32 = 0x0010_0000;
pub const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x1;
pub const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x2;
pub const CONTEXT_SEGMENTS: u32 = CONTEXT_AMD64 | 0x4;
pub const CONTEXT_FLOATING_POINT: u32 = CONTEXT_AMD64 | 0x8;
pub const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x10;
pub const CONTEXT_XSTATE: u32 = CONTEXT_AMD64 | 0x40;
pub const CONTEXT_ALL: u32 = CONTEXT_CONTROL
    | CONTEXT_INTEGER
    | CONTEXT_SEGMENTS
    | CONTEXT_FLOATING_POINT
    | CONTEXT_DEBUG_REGISTERS;

pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;

pub const THREAD_ALL_ACCESS: DWORD = 0x001F_FFFF;

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
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}

#[repr(C, align(16))]
#[derive(Copy, Clone)]
pub struct XMM_SAVE_AREA32 {
    pub ControlWord: u16,
    pub StatusWord: u16,
    pub TagWord: u8,
    pub Reserved1: u8,
    pub ErrorOpcode: u16,
    pub ErrorOffset: u32,
    pub ErrorSelector: u16,
    pub Reserved2: u16,
    pub DataOffset: u32,
    pub DataSelector: u16,
    pub Reserved3: u16,
    pub MxCsr: u32,
    pub MxCsr_Mask: u32,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 16],
    pub Reserved4: [u8; 96],
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

    pub FltSave: XMM_SAVE_AREA32,

    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,

    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

#[repr(C)]
pub struct EXCEPTION_POINTERS {
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ContextRecord: *mut CONTEXT,
}

pub type PVECTORED_EXCEPTION_HANDLER =
    unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> LONG;

#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn DisableThreadLibraryCalls(hLibModule: HMODULE) -> BOOL;
    pub fn AddVectoredExceptionHandler(
        First: u32,
        Handler: PVECTORED_EXCEPTION_HANDLER,
    ) -> PVOID;
    pub fn RemoveVectoredExceptionHandler(Handle: PVOID) -> DWORD;
    pub fn GetCurrentProcessId() -> DWORD;
    pub fn GetCurrentThreadId() -> DWORD;
    pub fn GetCurrentThread() -> HANDLE;
    pub fn GetThreadContext(hThread: HANDLE, lpContext: *mut CONTEXT) -> BOOL;
    pub fn SetThreadContext(hThread: HANDLE, lpContext: *const CONTEXT) -> BOOL;
    pub fn VirtualProtect(
        lpAddress: LPVOID,
        dwSize: usize,
        flNewProtect: DWORD,
        lpflOldProtect: *mut DWORD,
    ) -> BOOL;
    pub fn FlushInstructionCache(
        hProcess: HANDLE,
        lpBaseAddress: LPCVOID,
        dwSize: usize,
    ) -> BOOL;
    pub fn GetCurrentProcess() -> HANDLE;
}
