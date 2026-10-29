#![allow(non_snake_case, non_camel_case_types, dead_code, unsafe_op_in_unsafe_fn, static_mut_refs)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, Ordering};
use std::ptr::{null_mut, copy_nonoverlapping};

type HANDLE = *mut c_void;
type HMODULE = *mut c_void;
type BOOL = i32;
type DWORD = u32;
type NTSTATUS = i32;

const STATUS_SUCCESS: NTSTATUS = 0;
const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
const MEM_COMMIT: DWORD = 0x1000;
const MEM_RESERVE: DWORD = 0x2000;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AllocRecord {
    pub event_type: u32,
    pub address: u64,
    pub size: u64,
    pub flags: u32,
    pub protection: u32,
    pub caller_ip: u64,
    pub timestamp_ms: u64,
}

const MAX_RING_BUFFER: usize = 1024;
static mut ALLOC_RING: [AllocRecord; MAX_RING_BUFFER] = [AllocRecord {
    event_type: 0,
    address: 0,
    size: 0,
    flags: 0,
    protection: 0,
    caller_ip: 0,
    timestamp_ms: 0,
}; MAX_RING_BUFFER];

static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static HOOKS_INSTALLED: AtomicBool = AtomicBool::new(false);
static IN_HOOK: AtomicBool = AtomicBool::new(false);

unsafe extern "system" {
    fn GetModuleHandleA(lpModuleName: *const u8) -> HMODULE;
    fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> *mut c_void;
    fn VirtualProtect(lpAddress: *mut c_void, dwSize: usize, flNewProtect: DWORD, lpflOldProtect: *mut DWORD) -> BOOL;
    fn VirtualAlloc(lpAddress: *mut c_void, dwSize: usize, flAllocationType: DWORD, flProtect: DWORD) -> *mut c_void;
    fn GetCurrentProcessId() -> DWORD;
    fn GetTickCount64() -> u64;
    fn CreateFileA(
        lpFileName: *const u8,
        dwDesiredAccess: DWORD,
        dwShareMode: DWORD,
        lpSecurityAttributes: *mut c_void,
        dwCreationDisposition: DWORD,
        dwFlagsAndAttributes: DWORD,
        hTemplateFile: HANDLE,
    ) -> HANDLE;
    fn WriteFile(
        hFile: HANDLE,
        lpBuffer: *const c_void,
        nNumberOfBytesToWrite: DWORD,
        lpNumberOfBytesWritten: *mut DWORD,
        lpOverlapped: *mut c_void,
    ) -> BOOL;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
}

type FnNtAllocateVirtualMemory = unsafe extern "system" fn(
    HANDLE, *mut *mut c_void, usize, *mut usize, DWORD, DWORD
) -> NTSTATUS;

type FnNtFreeVirtualMemory = unsafe extern "system" fn(
    HANDLE, *mut *mut c_void, *mut usize, DWORD
) -> NTSTATUS;

type FnRtlAllocateHeap = unsafe extern "system" fn(
    *mut c_void, DWORD, usize
) -> *mut c_void;

type FnRtlFreeHeap = unsafe extern "system" fn(
    *mut c_void, DWORD, *mut c_void
) -> BOOL;

static mut ORIG_NT_ALLOC: Option<FnNtAllocateVirtualMemory> = None;
static mut ORIG_NT_FREE: Option<FnNtFreeVirtualMemory> = None;
static mut ORIG_RTL_ALLOC: Option<FnRtlAllocateHeap> = None;
static mut ORIG_RTL_FREE: Option<FnRtlFreeHeap> = None;

static PIPE_HANDLE: AtomicIsize = AtomicIsize::new(-1);

fn push_record(event_type: u32, address: u64, size: u64, flags: u32, protection: u32) {
    let count = ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
    let idx = (count as usize) % MAX_RING_BUFFER;

    let rec = AllocRecord {
        event_type,
        address,
        size,
        flags,
        protection,
        caller_ip: 0,
        timestamp_ms: unsafe { GetTickCount64() },
    };

    unsafe {
        ALLOC_RING[idx] = rec;
    }

    let h_val = PIPE_HANDLE.load(Ordering::Relaxed);
    if h_val != -1 {
        let h = h_val as HANDLE;
        let mut written: DWORD = 0;
        unsafe {
            WriteFile(h, &rec as *const _ as *const c_void, std::mem::size_of::<AllocRecord>() as DWORD, &mut written, null_mut());
        }
    }
}

unsafe extern "system" fn hook_nt_allocate_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: DWORD,
    protect: DWORD,
) -> NTSTATUS {
    let orig = ORIG_NT_ALLOC.expect("orig NtAlloc missing");
    let status = orig(process_handle, base_address, zero_bits, region_size, allocation_type, protect);

    if status == STATUS_SUCCESS && !base_address.is_null() && !region_size.is_null() {
        if !IN_HOOK.swap(true, Ordering::SeqCst) {
            let addr = *base_address as u64;
            let sz = *region_size as u64;
            push_record(0, addr, sz, allocation_type, protect);
            IN_HOOK.store(false, Ordering::SeqCst);
        }
    }

    status
}

unsafe extern "system" fn hook_nt_free_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    free_type: DWORD,
) -> NTSTATUS {
    let orig = ORIG_NT_FREE.expect("orig NtFree missing");

    let addr = if !base_address.is_null() { *base_address as u64 } else { 0 };
    let sz = if !region_size.is_null() { *region_size as u64 } else { 0 };

    let status = orig(process_handle, base_address, region_size, free_type);

    if status == STATUS_SUCCESS {
        if !IN_HOOK.swap(true, Ordering::SeqCst) {
            push_record(1, addr, sz, free_type, 0);
            IN_HOOK.store(false, Ordering::SeqCst);
        }
    }

    status
}

unsafe extern "system" fn hook_rtl_allocate_heap(
    heap_handle: *mut c_void,
    flags: DWORD,
    size: usize,
) -> *mut c_void {
    let orig = ORIG_RTL_ALLOC.expect("orig RtlAlloc missing");
    let ptr = orig(heap_handle, flags, size);

    if !ptr.is_null() {
        if !IN_HOOK.swap(true, Ordering::SeqCst) {
            push_record(2, ptr as u64, size as u64, flags, 0);
            IN_HOOK.store(false, Ordering::SeqCst);
        }
    }

    ptr
}

unsafe extern "system" fn hook_rtl_free_heap(
    heap_handle: *mut c_void,
    flags: DWORD,
    base_address: *mut c_void,
) -> BOOL {
    let orig = ORIG_RTL_FREE.expect("orig RtlFree missing");

    if !base_address.is_null() {
        if !IN_HOOK.swap(true, Ordering::SeqCst) {
            push_record(3, base_address as u64, 0, flags, 0);
            IN_HOOK.store(false, Ordering::SeqCst);
        }
    }

    orig(heap_handle, flags, base_address)
}

unsafe fn install_detour64(target: *mut c_void, detour: *mut c_void) -> *mut c_void {

    let trampoline = VirtualAlloc(null_mut(), 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if trampoline.is_null() {
        return null_mut();
    }

    copy_nonoverlapping(target as *const u8, trampoline as *mut u8, 14);

    let return_addr = (target as usize) + 14;
    let mut jump_back = [0u8; 14];
    jump_back[0] = 0xFF;
    jump_back[1] = 0x25;
    jump_back[2..6].copy_from_slice(&0u32.to_ne_bytes());
    jump_back[6..14].copy_from_slice(&(return_addr as u64).to_ne_bytes());
    copy_nonoverlapping(jump_back.as_ptr(), (trampoline as usize + 14) as *mut u8, 14);

    let mut old_protect: DWORD = 0;
    VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &mut old_protect);

    let mut jump_to_detour = [0u8; 14];
    jump_to_detour[0] = 0xFF;
    jump_to_detour[1] = 0x25;
    jump_to_detour[2..6].copy_from_slice(&0u32.to_ne_bytes());
    jump_to_detour[6..14].copy_from_slice(&(detour as usize as u64).to_ne_bytes());
    copy_nonoverlapping(jump_to_detour.as_ptr(), target as *mut u8, 14);

    VirtualProtect(target, 14, old_protect, &mut old_protect);

    trampoline
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CeInitializeAllocHook() -> BOOL {
    if HOOKS_INSTALLED.load(Ordering::SeqCst) {
        return 1;
    }

    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if ntdll.is_null() {
        return 0;
    }

    let pid = GetCurrentProcessId();
    let pipe_name = format!("\\\\.\\pipe\\ce_allochook_{}\0", pid);
    let h_pipe = CreateFileA(
        pipe_name.as_ptr(),
        0xC0000000,
        0,
        null_mut(),
        3,
        0,
        null_mut(),
    );

    if h_pipe != -1isize as HANDLE {
        PIPE_HANDLE.store(h_pipe as isize, Ordering::SeqCst);
    }

    let p_nt_alloc = GetProcAddress(ntdll, b"NtAllocateVirtualMemory\0".as_ptr());
    if !p_nt_alloc.is_null() {
        let tramp = install_detour64(p_nt_alloc, hook_nt_allocate_virtual_memory as *mut c_void);
        if !tramp.is_null() {
            ORIG_NT_ALLOC = Some(std::mem::transmute::<*mut c_void, FnNtAllocateVirtualMemory>(tramp));
        }
    }

    let p_nt_free = GetProcAddress(ntdll, b"NtFreeVirtualMemory\0".as_ptr());
    if !p_nt_free.is_null() {
        let tramp = install_detour64(p_nt_free, hook_nt_free_virtual_memory as *mut c_void);
        if !tramp.is_null() {
            ORIG_NT_FREE = Some(std::mem::transmute::<*mut c_void, FnNtFreeVirtualMemory>(tramp));
        }
    }

    let p_rtl_alloc = GetProcAddress(ntdll, b"RtlAllocateHeap\0".as_ptr());
    if !p_rtl_alloc.is_null() {
        let tramp = install_detour64(p_rtl_alloc, hook_rtl_allocate_heap as *mut c_void);
        if !tramp.is_null() {
            ORIG_RTL_ALLOC = Some(std::mem::transmute::<*mut c_void, FnRtlAllocateHeap>(tramp));
        }
    }

    let p_rtl_free = GetProcAddress(ntdll, b"RtlFreeHeap\0".as_ptr());
    if !p_rtl_free.is_null() {
        let tramp = install_detour64(p_rtl_free, hook_rtl_free_heap as *mut c_void);
        if !tramp.is_null() {
            ORIG_RTL_FREE = Some(std::mem::transmute::<*mut c_void, FnRtlFreeHeap>(tramp));
        }
    }

    HOOKS_INSTALLED.store(true, Ordering::SeqCst);
    1
}

#[unsafe(no_mangle)]
pub extern "system" fn CeGetAllocCount() -> u64 {
    ALLOC_COUNT.load(Ordering::Relaxed)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CeGetLastAlloc(out: *mut AllocRecord) -> BOOL {
    if out.is_null() {
        return 0;
    }
    let count = ALLOC_COUNT.load(Ordering::Relaxed);
    if count == 0 {
        return 0;
    }
    let idx = ((count - 1) as usize) % MAX_RING_BUFFER;
    *out = ALLOC_RING[idx];
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: *mut c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> BOOL {
    match fdw_reason {
        1 => {
            CeInitializeAllocHook();
        }
        0 => {
            let h_val = PIPE_HANDLE.swap(-1, Ordering::SeqCst);
            if h_val != -1 {
                CloseHandle(h_val as HANDLE);
            }
        }
        _ => {}
    }
    1
}
