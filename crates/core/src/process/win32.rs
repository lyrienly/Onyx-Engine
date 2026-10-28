
#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, dead_code)]

use std::ffi::c_void;

pub type HANDLE = *mut c_void;
pub type HMODULE = *mut c_void;
pub type BOOL = i32;
pub type DWORD = u32;
pub type WORD = u16;
pub type BYTE = u8;
pub type ULONG = u32;
pub type ULONG_PTR = usize;
pub type SIZE_T = usize;
pub type LPCWSTR = *const u16;
pub type LPWSTR = *mut u16;
pub type LPVOID = *mut c_void;
pub type LPCVOID = *const c_void;
pub type LPDWORD = *mut u32;
pub type PDWORD = *mut u32;

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;
pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

pub const PROCESS_TERMINATE: DWORD = 0x0001;
pub const PROCESS_CREATE_THREAD: DWORD = 0x0002;
pub const PROCESS_SET_SESSIONID: DWORD = 0x0004;
pub const PROCESS_VM_OPERATION: DWORD = 0x0008;
pub const PROCESS_VM_READ: DWORD = 0x0010;
pub const PROCESS_VM_WRITE: DWORD = 0x0020;
pub const PROCESS_DUP_HANDLE: DWORD = 0x0040;
pub const PROCESS_CREATE_PROCESS: DWORD = 0x0080;
pub const PROCESS_SET_QUOTA: DWORD = 0x0100;
pub const PROCESS_SET_INFORMATION: DWORD = 0x0200;
pub const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;
pub const PROCESS_SUSPEND_RESUME: DWORD = 0x0800;
pub const PROCESS_QUERY_LIMITED_INFORMATION: DWORD = 0x1000;
pub const SYNCHRONIZE: DWORD = 0x00100000;
pub const STANDARD_RIGHTS_REQUIRED: DWORD = 0x000F0000;
pub const PROCESS_ALL_ACCESS: DWORD = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF;

pub const THREAD_TERMINATE: DWORD = 0x0001;
pub const THREAD_SUSPEND_RESUME: DWORD = 0x0002;
pub const THREAD_GET_CONTEXT: DWORD = 0x0008;
pub const THREAD_SET_CONTEXT: DWORD = 0x0010;
pub const THREAD_SET_INFORMATION: DWORD = 0x0020;
pub const THREAD_QUERY_INFORMATION: DWORD = 0x0040;
pub const THREAD_SET_THREAD_TOKEN: DWORD = 0x0080;
pub const THREAD_IMPERSONATE: DWORD = 0x0100;
pub const THREAD_DIRECT_IMPERSONATION: DWORD = 0x0200;
pub const THREAD_ALL_ACCESS: DWORD = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF;

pub const PAGE_NOACCESS: DWORD = 0x01;
pub const PAGE_READONLY: DWORD = 0x02;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_WRITECOPY: DWORD = 0x08;
pub const PAGE_EXECUTE: DWORD = 0x10;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: DWORD = 0x80;
pub const PAGE_GUARD: DWORD = 0x100;
pub const PAGE_NOCACHE: DWORD = 0x200;
pub const PAGE_WRITECOMBINE: DWORD = 0x400;

pub const MEM_COMMIT: DWORD = 0x1000;
pub const MEM_RESERVE: DWORD = 0x2000;
pub const MEM_DECOMMIT: DWORD = 0x4000;
pub const MEM_RELEASE: DWORD = 0x8000;
pub const MEM_FREE: DWORD = 0x10000;
pub const MEM_PRIVATE: DWORD = 0x20000;
pub const MEM_MAPPED: DWORD = 0x40000;
pub const MEM_RESET: DWORD = 0x80000;
pub const MEM_IMAGE: DWORD = 0x1000000;

pub const TH32CS_SNAPHEAPLIST: DWORD = 0x00000001;
pub const TH32CS_SNAPPROCESS: DWORD = 0x00000002;
pub const TH32CS_SNAPTHREAD: DWORD = 0x00000004;
pub const TH32CS_SNAPMODULE: DWORD = 0x00000008;
pub const TH32CS_SNAPMODULE32: DWORD = 0x00000010;
pub const TH32CS_SNAPALL: DWORD = TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE;

pub const TOKEN_ADJUST_PRIVILEGES: DWORD = 0x0020;
pub const TOKEN_QUERY: DWORD = 0x0008;
pub const SE_PRIVILEGE_ENABLED: DWORD = 0x00000002;

pub const GENERIC_READ: DWORD = 0x80000000;
pub const GENERIC_WRITE: DWORD = 0x40000000;
pub const FILE_SHARE_READ: DWORD = 0x00000001;
pub const FILE_SHARE_WRITE: DWORD = 0x00000002;
pub const OPEN_EXISTING: DWORD = 3;
pub const FILE_ATTRIBUTE_NORMAL: DWORD = 0x00000080;

pub const EXCEPTION_DEBUG_EVENT: DWORD = 1;
pub const CREATE_THREAD_DEBUG_EVENT: DWORD = 2;
pub const CREATE_PROCESS_DEBUG_EVENT: DWORD = 3;
pub const EXIT_THREAD_DEBUG_EVENT: DWORD = 4;
pub const EXIT_PROCESS_DEBUG_EVENT: DWORD = 5;
pub const LOAD_DLL_DEBUG_EVENT: DWORD = 6;
pub const UNLOAD_DLL_DEBUG_EVENT: DWORD = 7;
pub const OUTPUT_DEBUG_STRING_EVENT: DWORD = 8;
pub const RIP_EVENT: DWORD = 9;

pub const DBG_CONTINUE: DWORD = 0x00010002;
pub const DBG_EXCEPTION_NOT_HANDLED: DWORD = 0x80010001;

pub const EXCEPTION_BREAKPOINT: DWORD = 0x80000003;
pub const EXCEPTION_SINGLE_STEP: DWORD = 0x80000004;
pub const EXCEPTION_ACCESS_VIOLATION: DWORD = 0xC0000005;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress: PVOID,
    pub AllocationBase: PVOID,
    pub AllocationProtect: DWORD,
    pub PartitionId: WORD,
    pub RegionSize: SIZE_T,
    pub State: DWORD,
    pub Protect: DWORD,
    pub Type: DWORD,
}

pub type PVOID = *mut c_void;

#[repr(C)]
pub struct PROCESSENTRY32W {
    pub dwSize: DWORD,
    pub cntUsage: DWORD,
    pub th32ProcessID: DWORD,
    pub th32DefaultHeapID: ULONG_PTR,
    pub th32ModuleID: DWORD,
    pub cntThreads: DWORD,
    pub th32ParentProcessID: DWORD,
    pub pcPriClassBase: i32,
    pub dwFlags: DWORD,
    pub szExeFile: [u16; 260],
}

#[repr(C)]
pub struct THREADENTRY32 {
    pub dwSize: DWORD,
    pub cntUsage: DWORD,
    pub th32ThreadID: DWORD,
    pub th32OwnerProcessID: DWORD,
    pub tpBasePri: i32,
    pub tpDeltaPri: i32,
    pub dwFlags: DWORD,
}

#[repr(C)]
pub struct MODULEENTRY32W {
    pub dwSize: DWORD,
    pub th32ModuleID: DWORD,
    pub th32ProcessID: DWORD,
    pub GlblcntUsage: DWORD,
    pub ProccntUsage: DWORD,
    pub modBaseAddr: *mut u8,
    pub modBaseSize: DWORD,
    pub hModule: HMODULE,
    pub szModule: [u16; 256],
    pub szExePath: [u16; 260],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LUID {
    pub LowPart: DWORD,
    pub HighPart: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LUID_AND_ATTRIBUTES {
    pub Luid: LUID,
    pub Attributes: DWORD,
}

#[repr(C)]
pub struct TOKEN_PRIVILEGES {
    pub PrivilegeCount: DWORD,
    pub Privileges: [LUID_AND_ATTRIBUTES; 1],
}

#[repr(C, align(16))]
#[derive(Copy, Clone)]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}

#[repr(C, align(16))]
#[derive(Copy, Clone)]
pub struct XSAVE_FORMAT {
    pub ControlWord: WORD,
    pub StatusWord: WORD,
    pub TagWord: BYTE,
    pub Reserved1: BYTE,
    pub ErrorOpcode: WORD,
    pub ErrorOffset: DWORD,
    pub ErrorSelector: WORD,
    pub Reserved2: WORD,
    pub DataOffset: DWORD,
    pub DataSelector: WORD,
    pub Reserved3: WORD,
    pub MxCsr: DWORD,
    pub MxCsr_Mask: DWORD,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 16],
    pub Reserved4: [BYTE; 96],
}

pub const CONTEXT_AMD64: DWORD = 0x00100000;
pub const CONTEXT_CONTROL: DWORD = CONTEXT_AMD64 | 0x00000001;
pub const CONTEXT_INTEGER: DWORD = CONTEXT_AMD64 | 0x00000002;
pub const CONTEXT_SEGMENTS: DWORD = CONTEXT_AMD64 | 0x00000004;
pub const CONTEXT_FLOATING_POINT: DWORD = CONTEXT_AMD64 | 0x00000008;
pub const CONTEXT_DEBUG_REGISTERS: DWORD = CONTEXT_AMD64 | 0x00000010;
pub const CONTEXT_ALL: DWORD = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS;

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
    pub SegCs: WORD,
    pub SegDs: WORD,
    pub SegEs: WORD,
    pub SegFs: WORD,
    pub SegGs: WORD,
    pub SegSs: WORD,
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
    pub FltSave: XSAVE_FORMAT,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode: DWORD,
    pub ExceptionFlags: DWORD,
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ExceptionAddress: PVOID,
    pub NumberParameters: DWORD,
    pub ExceptionInformation: [ULONG_PTR; 15],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct EXCEPTION_DEBUG_INFO {
    pub ExceptionRecord: EXCEPTION_RECORD,
    pub dwFirstChance: DWORD,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CREATE_THREAD_DEBUG_INFO {
    pub hThread: HANDLE,
    pub lpThreadLocalBase: LPVOID,
    pub lpStartAddress: LPVOID,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CREATE_PROCESS_DEBUG_INFO {
    pub hFile: HANDLE,
    pub hProcess: HANDLE,
    pub hThread: HANDLE,
    pub lpBaseOfImage: LPVOID,
    pub dwDebugInfoFileOffset: DWORD,
    pub nDebugInfoSize: DWORD,
    pub lpThreadLocalBase: LPVOID,
    pub lpStartAddress: LPVOID,
    pub lpImageName: LPVOID,
    pub fUnicode: WORD,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct EXIT_THREAD_DEBUG_INFO {
    pub dwExitCode: DWORD,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct EXIT_PROCESS_DEBUG_INFO {
    pub dwExitCode: DWORD,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct LOAD_DLL_DEBUG_INFO {
    pub hFile: HANDLE,
    pub lpBaseOfDll: LPVOID,
    pub dwDebugInfoFileOffset: DWORD,
    pub nDebugInfoSize: DWORD,
    pub lpImageName: LPVOID,
    pub fUnicode: WORD,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct UNLOAD_DLL_DEBUG_INFO {
    pub lpBaseOfDll: LPVOID,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct OUTPUT_DEBUG_STRING_INFO {
    pub lpDebugStringData: *mut u8,
    pub fUnicode: WORD,
    pub nDebugStringLength: WORD,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RIP_INFO {
    pub dwError: DWORD,
    pub dwType: DWORD,
}

#[repr(C)]
pub union DEBUG_EVENT_UNION {
    pub Exception: EXCEPTION_DEBUG_INFO,
    pub CreateThread: CREATE_THREAD_DEBUG_INFO,
    pub CreateProcessInfo: CREATE_PROCESS_DEBUG_INFO,
    pub ExitThread: EXIT_THREAD_DEBUG_INFO,
    pub ExitProcess: EXIT_PROCESS_DEBUG_INFO,
    pub LoadDll: LOAD_DLL_DEBUG_INFO,
    pub UnloadDll: UNLOAD_DLL_DEBUG_INFO,
    pub DebugString: OUTPUT_DEBUG_STRING_INFO,
    pub RipInfo: RIP_INFO,
}

#[repr(C)]
pub struct DEBUG_EVENT {
    pub dwDebugEventCode: DWORD,
    pub dwProcessId: DWORD,
    pub dwThreadId: DWORD,
    pub u: DEBUG_EVENT_UNION,
}

#[link(name = "kernel32")]
unsafe extern "system" {

    pub fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) -> HANDLE;
    pub fn CloseHandle(hObject: HANDLE) -> BOOL;
    pub fn GetCurrentProcess() -> HANDLE;
    pub fn ReadProcessMemory(hProcess: HANDLE, lpBaseAddress: LPCVOID, lpBuffer: LPVOID, nSize: SIZE_T, lpNumberOfBytesRead: *mut SIZE_T) -> BOOL;
    pub fn WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: LPVOID, lpBuffer: LPCVOID, nSize: SIZE_T, lpNumberOfBytesWritten: *mut SIZE_T) -> BOOL;
    pub fn VirtualQueryEx(hProcess: HANDLE, lpAddress: LPCVOID, lpBuffer: *mut MEMORY_BASIC_INFORMATION, dwLength: SIZE_T) -> SIZE_T;
    pub fn VirtualAllocEx(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID;
    pub fn VirtualFreeEx(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T, dwFreeType: DWORD) -> BOOL;
    pub fn VirtualProtectEx(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: PDWORD) -> BOOL;
    pub fn VirtualProtect(lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: PDWORD) -> BOOL;
    pub fn GetCurrentThread() -> HANDLE;
    pub fn CheckRemoteDebuggerPresent(hProcess: HANDLE, pbDebuggerPresent: *mut BOOL) -> BOOL;
    pub fn IsDebuggerPresent() -> BOOL;

    pub fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) -> HANDLE;
    pub fn Process32FirstW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
    pub fn Process32NextW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> BOOL;
    pub fn Thread32First(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL;
    pub fn Thread32Next(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> BOOL;
    pub fn Module32FirstW(hSnapshot: HANDLE, lpme: *mut MODULEENTRY32W) -> BOOL;
    pub fn Module32NextW(hSnapshot: HANDLE, lpme: *mut MODULEENTRY32W) -> BOOL;

    pub fn OpenThread(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwThreadId: DWORD) -> HANDLE;
    pub fn SuspendThread(hThread: HANDLE) -> DWORD;
    pub fn ResumeThread(hThread: HANDLE) -> DWORD;
    pub fn GetThreadContext(hThread: HANDLE, lpContext: *mut CONTEXT) -> BOOL;
    pub fn SetThreadContext(hThread: HANDLE, lpContext: *const CONTEXT) -> BOOL;
}

#[link(name = "advapi32")]
unsafe extern "system" {

    pub fn OpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: DWORD, TokenHandle: *mut HANDLE) -> BOOL;
    pub fn LookupPrivilegeValueW(lpSystemName: LPCWSTR, lpName: LPCWSTR, lpLuid: *mut LUID) -> BOOL;
    pub fn AdjustTokenPrivileges(TokenHandle: HANDLE, DisableAllPrivileges: BOOL, NewState: *const TOKEN_PRIVILEGES, BufferLength: DWORD, PreviousState: *mut TOKEN_PRIVILEGES, ReturnLength: PDWORD) -> BOOL;
}

#[link(name = "kernel32")]
unsafe extern "system" {

    pub fn CreateFileW(
        lpFileName: LPCWSTR,
        dwDesiredAccess: DWORD,
        dwShareMode: DWORD,
        lpSecurityAttributes: LPVOID,
        dwCreationDisposition: DWORD,
        dwFlagsAndAttributes: DWORD,
        hTemplateFile: HANDLE,
    ) -> HANDLE;
    pub fn DeviceIoControl(
        hDevice: HANDLE,
        dwIoControlCode: DWORD,
        lpInBuffer: LPVOID,
        nInBufferSize: DWORD,
        lpOutBuffer: LPVOID,
        nOutBufferSize: DWORD,
        lpBytesReturned: LPDWORD,
        lpOverlapped: LPVOID,
    ) -> BOOL;

    pub fn DebugActiveProcess(dwProcessId: DWORD) -> BOOL;
    pub fn DebugActiveProcessStop(dwProcessId: DWORD) -> BOOL;
    pub fn WaitForDebugEvent(lpDebugEvent: *mut DEBUG_EVENT, dwMilliseconds: DWORD) -> BOOL;
    pub fn ContinueDebugEvent(dwProcessId: DWORD, dwThreadId: DWORD, dwContinueStatus: DWORD) -> BOOL;
    pub fn GetLastError() -> DWORD;
    pub fn GetCurrentProcessId() -> DWORD;

    pub fn CreateRemoteThread(
        hProcess: HANDLE,
        lpThreadAttributes: LPVOID,
        dwStackSize: SIZE_T,
        lpStartAddress: unsafe extern "system" fn(LPVOID) -> DWORD,
        lpParameter: LPVOID,
        dwCreationFlags: DWORD,
        lpThreadId: LPDWORD,
    ) -> HANDLE;
    pub fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD;
    pub fn GetExitCodeThread(hThread: HANDLE, lpExitCode: LPDWORD) -> BOOL;
    pub fn GetModuleHandleW(lpModuleName: LPCWSTR) -> HMODULE;
    pub fn GetModuleHandleA(lpModuleName: *const u8) -> HMODULE;
    pub fn LoadLibraryW(lpLibFileName: LPCWSTR) -> HMODULE;
    pub fn FreeLibrary(hLibModule: HMODULE) -> BOOL;
    pub fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> *mut c_void;
}

pub type NTSTATUS = i32;
pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_UNSUCCESSFUL: NTSTATUS = 0xC0000001_u32 as i32;
pub const STATUS_ACCESS_DENIED: NTSTATUS = 0xC0000022_u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC0000023_u32 as i32;
pub const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004_u32 as i32;

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: ULONG,
    pub RootDirectory: HANDLE,
    pub ObjectName: *mut UNICODE_STRING,
    pub Attributes: ULONG,
    pub SecurityDescriptor: PVOID,
    pub SecurityQualityOfService: PVOID,
}

#[repr(C)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread: HANDLE,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn NtOpenProcess(
        ProcessHandle: *mut HANDLE,
        DesiredAccess: DWORD,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ClientId: *mut CLIENT_ID,
    ) -> NTSTATUS;

    pub fn NtReadVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        Buffer: PVOID,
        NumberOfBytesToRead: SIZE_T,
        NumberOfBytesRead: *mut SIZE_T,
    ) -> NTSTATUS;

    pub fn NtWriteVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        Buffer: LPCVOID,
        NumberOfBytesToWrite: SIZE_T,
        NumberOfBytesWritten: *mut SIZE_T,
    ) -> NTSTATUS;

    pub fn NtAllocateVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        ZeroBits: ULONG_PTR,
        RegionSize: *mut SIZE_T,
        AllocationType: ULONG,
        Protect: ULONG,
    ) -> NTSTATUS;

    pub fn NtFreeVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: *mut SIZE_T,
        FreeType: ULONG,
    ) -> NTSTATUS;

    pub fn NtProtectVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut PVOID,
        RegionSize: *mut SIZE_T,
        NewProtect: ULONG,
        OldProtect: *mut ULONG,
    ) -> NTSTATUS;

    pub fn NtQueryVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: PVOID,
        MemoryInformationClass: ULONG,
        MemoryInformation: PVOID,
        MemoryInformationLength: SIZE_T,
        ReturnLength: *mut SIZE_T,
    ) -> NTSTATUS;
}

pub type HICON = HANDLE;
pub type HBITMAP = HANDLE;
pub type HDC = HANDLE;

pub const SHGFI_ICON: DWORD = 0x000000100;
pub const SHGFI_SMALLICON: DWORD = 0x000000001;
pub const SHGFI_LARGEICON: DWORD = 0x000000000;
pub const SHGFI_USEFILEATTRIBUTES: DWORD = 0x000000010;

pub const BI_RGB: DWORD = 0;
pub const DIB_RGB_COLORS: DWORD = 0;

#[repr(C)]
pub struct ICONINFO {
    pub fIcon: BOOL,
    pub xHotspot: DWORD,
    pub yHotspot: DWORD,
    pub hbmMask: HBITMAP,
    pub hbmColor: HBITMAP,
}

#[repr(C)]
pub struct BITMAP {
    pub bmType: i32,
    pub bmWidth: i32,
    pub bmHeight: i32,
    pub bmWidthBytes: i32,
    pub bmPlanes: u16,
    pub bmBitsPixel: u16,
    pub bmBits: LPVOID,
}

#[repr(C)]
pub struct BITMAPINFOHEADER {
    pub biSize: DWORD,
    pub biWidth: i32,
    pub biHeight: i32,
    pub biPlanes: WORD,
    pub biBitCount: WORD,
    pub biCompression: DWORD,
    pub biSizeImage: DWORD,
    pub biXPelsPerMeter: i32,
    pub biYPelsPerMeter: i32,
    pub biClrUsed: DWORD,
    pub biClrImportant: DWORD,
}

#[repr(C)]
pub struct RGBQUAD {
    pub rgbBlue: BYTE,
    pub rgbGreen: BYTE,
    pub rgbRed: BYTE,
    pub rgbReserved: BYTE,
}

#[repr(C)]
pub struct BITMAPINFO {
    pub bmiHeader: BITMAPINFOHEADER,
    pub bmiColors: [RGBQUAD; 1],
}

#[repr(C)]
pub struct SHFILEINFOW {
    pub hIcon: HICON,
    pub iIcon: i32,
    pub dwAttributes: DWORD,
    pub szDisplayName: [u16; 260],
    pub szTypeName: [u16; 80],
}

pub const IDI_APPLICATION: LPCWSTR = 32512 as LPCWSTR;
pub const COINIT_APARTMENTTHREADED: DWORD = 0x2;
pub const COINIT_MULTITHREADED: DWORD = 0x0;
pub const COINIT_DISABLE_OLE1DDE: DWORD = 0x4;

#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn QueryFullProcessImageNameW(
        hProcess: HANDLE,
        dwFlags: DWORD,
        lpExeName: LPWSTR,
        lpdwSize: PDWORD,
    ) -> BOOL;
}

#[link(name = "user32")]
unsafe extern "system" {
    pub fn GetIconInfo(hIcon: HICON, piconinfo: *mut ICONINFO) -> BOOL;
    pub fn DestroyIcon(hIcon: HICON) -> BOOL;
    pub fn LoadIconW(hInstance: HANDLE, lpIconName: LPCWSTR) -> HICON;
    pub fn GetDC(hWnd: HANDLE) -> HDC;
    pub fn ReleaseDC(hWnd: HANDLE, hDC: HDC) -> i32;
}

#[link(name = "gdi32")]
unsafe extern "system" {
    pub fn GetObjectW(hgdiobj: HANDLE, cbBuffer: i32, lpvObject: LPVOID) -> i32;
    pub fn DeleteObject(ho: HANDLE) -> BOOL;
    pub fn GetDIBits(
        hdc: HDC,
        hbm: HBITMAP,
        start: u32,
        cLines: u32,
        lpvBits: LPVOID,
        lpbmi: *mut BITMAPINFO,
        usage: u32,
    ) -> i32;
}

#[link(name = "shell32")]
unsafe extern "system" {
    pub fn SHGetFileInfoW(
        pszPath: LPCWSTR,
        dwFileAttributes: DWORD,
        psfi: *mut SHFILEINFOW,
        cbFileInfo: u32,
        uFlags: DWORD,
    ) -> usize;
    pub fn ExtractIconExW(
        lpszFile: LPCWSTR,
        nIconIndex: i32,
        phiconLarge: *mut HICON,
        phiconSmall: *mut HICON,
        nIcons: u32,
    ) -> u32;
}

#[link(name = "ole32")]
unsafe extern "system" {
    pub fn CoInitializeEx(pvReserved: LPVOID, dwCoInit: DWORD) -> i32;
    pub fn CoUninitialize();
}

pub const SystemProcessInformation: u32 = 5;

#[repr(C)]
pub struct SYSTEM_PROCESS_INFORMATION {
    pub NextEntryOffset: u32,
    pub NumberOfThreads: u32,
    pub WorkingSetPrivateSize: i64,
    pub HardFaultCount: u32,
    pub NumberOfThreadsHighWatermark: u32,
    pub CycleTime: u64,
    pub CreateTime: i64,
    pub UserTime: i64,
    pub KernelTime: i64,
    pub ImageName: UNICODE_STRING,
    pub BasePriority: i32,
    pub UniqueProcessId: HANDLE,
    pub InheritedFromUniqueProcessId: HANDLE,
    pub HandleCount: u32,
    pub SessionId: u32,
    pub UniqueProcessKey: usize,
    pub PeakVirtualSize: usize,
    pub VirtualSize: usize,
    pub PageFaultCount: u32,
    pub PeakWorkingSetSize: usize,
    pub WorkingSetSize: usize,
    pub QuotaPeakPagedPoolUsage: usize,
    pub QuotaPagedPoolUsage: usize,
    pub QuotaPeakNonPagedPoolUsage: usize,
    pub QuotaNonPagedPoolUsage: usize,
    pub PagefileUsage: usize,
    pub PeakPagefileUsage: usize,
    pub PrivatePageCount: usize,
    pub ReadOperationCount: i64,
    pub WriteOperationCount: i64,
    pub OtherOperationCount: i64,
    pub ReadTransferCount: i64,
    pub WriteTransferCount: i64,
    pub OtherTransferCount: i64,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn NtQuerySystemInformation(
        SystemInformationClass: u32,
        SystemInformation: *mut c_void,
        SystemInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
    pub fn NtSuspendProcess(ProcessHandle: HANDLE) -> i32;
    pub fn NtResumeProcess(ProcessHandle: HANDLE) -> i32;
}

