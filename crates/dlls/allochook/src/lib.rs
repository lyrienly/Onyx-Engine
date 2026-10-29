#![allow(
    non_snake_case,
    non_camel_case_types,
    dead_code,
    unsafe_op_in_unsafe_fn,
    static_mut_refs,
    clippy::upper_case_acronyms,
    clippy::missing_safety_doc,
    clippy::collapsible_if,
    clippy::manual_c_str_literals
)]

use std::ffi::c_void;
use std::ptr::{copy_nonoverlapping, null_mut};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, Ordering};

type HANDLE = *mut c_void;
type HMODULE = *mut c_void;
type BOOL = i32;
type DWORD = u32;
type NTSTATUS = i32;

const STATUS_SUCCESS: NTSTATUS = 0;
const TRUE: BOOL = 1;
const FALSE: BOOL = 0;

pub const PAGE_NOACCESS: DWORD = 0x01;
pub const PAGE_READONLY: DWORD = 0x02;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_EXECUTE: DWORD = 0x10;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;

pub const MEM_COMMIT: DWORD = 0x1000;
pub const MEM_RESERVE: DWORD = 0x2000;
pub const MEM_RELEASE: DWORD = 0x8000;

pub const STEALTH_FLAG_MASKED_RWX: u32 = 0x8000_0000;

pub const HOOKEVENT_ALLOC: i32 = 0;
pub const HOOKEVENT_FREE: i32 = 1;
pub const HOOKEVENT_HEAPALLOC: i32 = 2;
pub const HOOKEVENT_HEAPFREE: i32 = 3;
pub const HOOKEVENT_HEAPDESTROY: i32 = 4;

const PROCESS_HEAP_ENTRY_BUSY: u16 = 0x0001;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocRecord {
    pub event_type: u32,
    pub address: u64,
    pub size: u64,
    pub flags: u32,
    pub protection: u32,
    pub caller_ip: u64,
    pub timestamp_ms: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PascalAllocData {
    pub handle: u64,
    pub baseaddress: u64,
    pub allocationType: u32,
    pub protect: u32,
    pub size: u32,
    pub _padding: u32,
    pub esp: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PascalHeapAllocData {
    pub HeapHandle: u64,
    pub Flags: u32,
    pub Size: u32,
    pub esp: u64,
    pub address: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union PascalHookPayload {
    pub alloc: PascalAllocData,
    pub heap_alloc: PascalHeapAllocData,
    pub raw: [u8; 64],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PascalHookEvent {
    pub eventtype: i32,
    pub _align_pad: u32,
    pub payload: PascalHookPayload,
}

#[repr(C)]
pub struct PROCESS_HEAP_ENTRY {
    pub lpData: *mut c_void,
    pub cbData: DWORD,
    pub cbOverhead: u8,
    pub iRegionIndex: u8,
    pub wFlags: u16,
    pub union_data: [u8; 32],
}

#[unsafe(no_mangle)]
pub static mut HasSetupDataEvent: u64 = 0;

#[unsafe(no_mangle)]
pub static mut CEHasHandledItEvent: u64 = 0;

#[unsafe(no_mangle)]
pub static mut CEInitializationFinished: u64 = 0;

#[unsafe(no_mangle)]
pub static mut HookEventData: PascalHookEvent = PascalHookEvent {
    eventtype: 0,
    _align_pad: 0,
    payload: PascalHookPayload { raw: [0u8; 64] },
};

const MAX_RING_BUFFER: usize = 4096;

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

static STEALTH_MASKING_ENABLED: AtomicBool = AtomicBool::new(true);
static HEAP_MIN_SIZE_FILTER: AtomicU64 = AtomicU64::new(0);
static PIPE_HANDLE: AtomicIsize = AtomicIsize::new(-1);

unsafe extern "system" {
    fn GetModuleHandleA(lpModuleName: *const u8) -> HMODULE;
    fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> *mut c_void;
    fn VirtualProtect(
        lpAddress: *mut c_void,
        dwSize: usize,
        flNewProtect: DWORD,
        lpflOldProtect: *mut DWORD,
    ) -> BOOL;
    fn VirtualAlloc(
        lpAddress: *mut c_void,
        dwSize: usize,
        flAllocationType: DWORD,
        flProtect: DWORD,
    ) -> *mut c_void;
    fn GetCurrentProcess() -> HANDLE;
    fn GetCurrentProcessId() -> DWORD;
    fn GetTickCount64() -> u64;
    fn FlushInstructionCache(hProcess: HANDLE, lpBaseAddress: *const c_void, dwSize: usize)
    -> BOOL;
    fn SetEvent(hEvent: HANDLE) -> BOOL;
    fn ResetEvent(hEvent: HANDLE) -> BOOL;
    fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD;
    fn GetProcessHeaps(NumberOfHeaps: DWORD, ProcessHeaps: *mut HANDLE) -> DWORD;
    fn HeapLock(hHeap: HANDLE) -> BOOL;
    fn HeapUnlock(hHeap: HANDLE) -> BOOL;
    fn HeapWalk(hHeap: HANDLE, lpEntry: *mut PROCESS_HEAP_ENTRY) -> BOOL;
    fn RtlCaptureStackBackTrace(
        frames_to_skip: DWORD,
        frames_to_capture: DWORD,
        back_trace: *mut *mut c_void,
        back_trace_hash: *mut DWORD,
    ) -> u16;
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
    HANDLE,
    *mut *mut c_void,
    usize,
    *mut usize,
    DWORD,
    DWORD,
) -> NTSTATUS;

type FnNtFreeVirtualMemory =
    unsafe extern "system" fn(HANDLE, *mut *mut c_void, *mut usize, DWORD) -> NTSTATUS;

type FnRtlAllocateHeap = unsafe extern "system" fn(*mut c_void, DWORD, usize) -> *mut c_void;

type FnRtlFreeHeap = unsafe extern "system" fn(*mut c_void, DWORD, *mut c_void) -> BOOL;

static mut ORIG_NT_ALLOC: Option<FnNtAllocateVirtualMemory> = None;
static mut ORIG_NT_FREE: Option<FnNtFreeVirtualMemory> = None;
static mut ORIG_RTL_ALLOC: Option<FnRtlAllocateHeap> = None;
static mut ORIG_RTL_FREE: Option<FnRtlFreeHeap> = None;

#[inline(always)]
fn capture_caller_ip() -> u64 {
    let mut caller: *mut c_void = null_mut();
    let captured = unsafe { RtlCaptureStackBackTrace(2, 1, &mut caller, null_mut()) };
    if captured > 0 && !caller.is_null() {
        caller as u64
    } else {
        0
    }
}

fn dispatch_event_to_pascal_gui(
    event_type: i32,
    address: u64,
    size: u32,
    flags: u32,
    protect: u32,
    esp: u64,
) {
    unsafe {
        let setup_event = HasSetupDataEvent as HANDLE;
        let handled_event = CEHasHandledItEvent as HANDLE;

        if !setup_event.is_null() && !handled_event.is_null() {
            if event_type == HOOKEVENT_HEAPALLOC {
                HookEventData.eventtype = HOOKEVENT_HEAPALLOC;
                HookEventData.payload.heap_alloc = PascalHeapAllocData {
                    HeapHandle: 0,
                    Flags: flags,
                    Size: size,
                    esp,
                    address,
                };
            } else if event_type == HOOKEVENT_ALLOC {
                HookEventData.eventtype = HOOKEVENT_ALLOC;
                HookEventData.payload.alloc = PascalAllocData {
                    handle: 0,
                    baseaddress: address,
                    allocationType: flags,
                    protect,
                    size,
                    _padding: 0,
                    esp,
                };
            }

            SetEvent(setup_event);
            WaitForSingleObject(handled_event, 5);
        }
    }
}

fn push_record(
    event_type: u32,
    address: u64,
    size: u64,
    flags: u32,
    protection: u32,
    caller_ip: u64,
) {
    let count = ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
    let idx = (count as usize) % MAX_RING_BUFFER;

    let rec = AllocRecord {
        event_type,
        address,
        size,
        flags,
        protection,
        caller_ip,
        timestamp_ms: unsafe { GetTickCount64() },
    };

    unsafe {
        ALLOC_RING[idx] = rec;
    }

    let pas_event_type = match event_type {
        0 => HOOKEVENT_ALLOC,
        2 => HOOKEVENT_HEAPALLOC,
        _ => -1,
    };
    if pas_event_type != -1 {
        dispatch_event_to_pascal_gui(
            pas_event_type,
            address,
            size as u32,
            flags,
            protection,
            caller_ip,
        );
    }

    let h_val = PIPE_HANDLE.load(Ordering::Relaxed);
    if h_val != -1 {
        let h = h_val as HANDLE;
        let mut written: DWORD = 0;
        unsafe {
            WriteFile(
                h,
                &rec as *const _ as *const c_void,
                std::mem::size_of::<AllocRecord>() as DWORD,
                &mut written,
                null_mut(),
            );
        }
    }
}

unsafe fn perform_initial_heap_walk() {
    let mut dummy: HANDLE = null_mut();
    let num_heaps = GetProcessHeaps(0, &mut dummy);
    if num_heaps == 0 {
        return;
    }

    let mut heaps = vec![null_mut(); num_heaps as usize];
    let actual_count = GetProcessHeaps(num_heaps, heaps.as_mut_ptr());

    let mut entry: PROCESS_HEAP_ENTRY = std::mem::zeroed();

    for &h_heap in heaps.iter().take(actual_count as usize) {
        if h_heap.is_null() {
            continue;
        }

        HeapLock(h_heap);
        entry.lpData = null_mut();

        while HeapWalk(h_heap, &mut entry) != 0 {
            if (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0 && entry.cbData > 0 {
                let addr = entry.lpData as u64;
                let sz = entry.cbData;

                let count = ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
                let idx = (count as usize) % MAX_RING_BUFFER;
                ALLOC_RING[idx] = AllocRecord {
                    event_type: 2,
                    address: addr,
                    size: sz as u64,
                    flags: 0,
                    protection: PAGE_READWRITE,
                    caller_ip: 0,
                    timestamp_ms: GetTickCount64(),
                };

                dispatch_event_to_pascal_gui(HOOKEVENT_HEAPALLOC, addr, sz, 0, PAGE_READWRITE, 0);
            }
        }

        HeapUnlock(h_heap);
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
    let orig = match ORIG_NT_ALLOC {
        Some(f) => f,
        None => return -1,
    };

    let caller_ip = capture_caller_ip();
    let actual_protect = protect;
    let mut flags_record = allocation_type;

    if STEALTH_MASKING_ENABLED.load(Ordering::Relaxed) && (protect == PAGE_EXECUTE_READWRITE) {
        flags_record |= STEALTH_FLAG_MASKED_RWX;
    }

    let status = orig(
        process_handle,
        base_address,
        zero_bits,
        region_size,
        allocation_type,
        actual_protect,
    );

    if status == STATUS_SUCCESS
        && !base_address.is_null()
        && !region_size.is_null()
        && !IN_HOOK.swap(true, Ordering::SeqCst)
    {
        let addr = *base_address as u64;
        let sz = *region_size as u64;
        push_record(0, addr, sz, flags_record, actual_protect, caller_ip);
        IN_HOOK.store(false, Ordering::SeqCst);
    }

    status
}

unsafe extern "system" fn hook_nt_free_virtual_memory(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    region_size: *mut usize,
    free_type: DWORD,
) -> NTSTATUS {
    let orig = match ORIG_NT_FREE {
        Some(f) => f,
        None => return -1,
    };

    let caller_ip = capture_caller_ip();
    let addr = if !base_address.is_null() {
        *base_address as u64
    } else {
        0
    };
    let sz = if !region_size.is_null() {
        *region_size as u64
    } else {
        0
    };

    let status = orig(process_handle, base_address, region_size, free_type);

    if status == STATUS_SUCCESS && !IN_HOOK.swap(true, Ordering::SeqCst) {
        push_record(1, addr, sz, free_type, 0, caller_ip);
        IN_HOOK.store(false, Ordering::SeqCst);
    }

    status
}

unsafe extern "system" fn hook_rtl_allocate_heap(
    heap_handle: *mut c_void,
    flags: DWORD,
    size: usize,
) -> *mut c_void {
    let orig = match ORIG_RTL_ALLOC {
        Some(f) => f,
        None => return null_mut(),
    };

    let ptr = orig(heap_handle, flags, size);

    if !ptr.is_null() && !IN_HOOK.swap(true, Ordering::SeqCst) {
        let caller_ip = capture_caller_ip();
        push_record(2, ptr as u64, size as u64, flags, 0, caller_ip);
        IN_HOOK.store(false, Ordering::SeqCst);
    }

    ptr
}

unsafe extern "system" fn hook_rtl_free_heap(
    heap_handle: *mut c_void,
    flags: DWORD,
    base_address: *mut c_void,
) -> BOOL {
    let orig = match ORIG_RTL_FREE {
        Some(f) => f,
        None => return FALSE,
    };

    if !base_address.is_null() && !IN_HOOK.swap(true, Ordering::SeqCst) {
        let caller_ip = capture_caller_ip();
        push_record(3, base_address as u64, 0, flags, 0, caller_ip);
        IN_HOOK.store(false, Ordering::SeqCst);
    }

    orig(heap_handle, flags, base_address)
}

unsafe fn install_detour64(
    target: *mut c_void,
    detour: *mut c_void,
    stolen_bytes_count: usize,
) -> *mut c_void {
    if target.is_null() || detour.is_null() || stolen_bytes_count < 14 {
        return null_mut();
    }

    let trampoline = VirtualAlloc(
        null_mut(),
        64,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if trampoline.is_null() {
        return null_mut();
    }

    copy_nonoverlapping(
        target as *const u8,
        trampoline as *mut u8,
        stolen_bytes_count,
    );

    let return_addr = (target as usize) + stolen_bytes_count;
    let mut jump_back = [0u8; 14];
    jump_back[0] = 0xFF;
    jump_back[1] = 0x25;
    jump_back[2..6].copy_from_slice(&0u32.to_ne_bytes());
    jump_back[6..14].copy_from_slice(&(return_addr as u64).to_ne_bytes());
    copy_nonoverlapping(
        jump_back.as_ptr(),
        (trampoline as usize + stolen_bytes_count) as *mut u8,
        14,
    );

    let mut old_protect: DWORD = 0;
    if VirtualProtect(
        target,
        stolen_bytes_count,
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    ) == 0
    {
        return null_mut();
    }

    let mut jump_to_detour = vec![0x90u8; stolen_bytes_count];
    jump_to_detour[0] = 0xFF;
    jump_to_detour[1] = 0x25;
    jump_to_detour[2..6].copy_from_slice(&0u32.to_ne_bytes());
    jump_to_detour[6..14].copy_from_slice(&(detour as usize as u64).to_ne_bytes());

    copy_nonoverlapping(
        jump_to_detour.as_ptr(),
        target as *mut u8,
        stolen_bytes_count,
    );

    VirtualProtect(target, stolen_bytes_count, old_protect, &mut old_protect);

    let h_proc = GetCurrentProcess();
    FlushInstructionCache(h_proc, target, stolen_bytes_count);
    FlushInstructionCache(h_proc, trampoline, stolen_bytes_count + 14);

    trampoline
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CeInitializeAllocHook() -> BOOL {
    if HOOKS_INSTALLED.load(Ordering::SeqCst) {
        let finished = CEInitializationFinished as HANDLE;
        if !finished.is_null() {
            SetEvent(finished);
        }
        return TRUE;
    }

    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if ntdll.is_null() {
        return FALSE;
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
        let tramp = install_detour64(
            p_nt_alloc,
            hook_nt_allocate_virtual_memory as *mut c_void,
            16,
        );
        if !tramp.is_null() {
            ORIG_NT_ALLOC =
                Some(std::mem::transmute::<*mut c_void, FnNtAllocateVirtualMemory>(tramp));
        }
    }

    let p_nt_free = GetProcAddress(ntdll, b"NtFreeVirtualMemory\0".as_ptr());
    if !p_nt_free.is_null() {
        let tramp = install_detour64(p_nt_free, hook_nt_free_virtual_memory as *mut c_void, 16);
        if !tramp.is_null() {
            ORIG_NT_FREE = Some(std::mem::transmute::<*mut c_void, FnNtFreeVirtualMemory>(
                tramp,
            ));
        }
    }

    let p_rtl_alloc = GetProcAddress(ntdll, b"RtlAllocateHeap\0".as_ptr());
    if !p_rtl_alloc.is_null() {
        let tramp = install_detour64(p_rtl_alloc, hook_rtl_allocate_heap as *mut c_void, 19);
        if !tramp.is_null() {
            ORIG_RTL_ALLOC = Some(std::mem::transmute::<*mut c_void, FnRtlAllocateHeap>(tramp));
        }
    }

    let p_rtl_free = GetProcAddress(ntdll, b"RtlFreeHeap\0".as_ptr());
    if !p_rtl_free.is_null() {
        let tramp = install_detour64(p_rtl_free, hook_rtl_free_heap as *mut c_void, 14);
        if !tramp.is_null() {
            ORIG_RTL_FREE = Some(std::mem::transmute::<*mut c_void, FnRtlFreeHeap>(tramp));
        }
    }

    HOOKS_INSTALLED.store(true, Ordering::SeqCst);

    perform_initial_heap_walk();

    let finished = CEInitializationFinished as HANDLE;
    if !finished.is_null() {
        SetEvent(finished);
    }

    TRUE
}

#[unsafe(no_mangle)]
pub extern "system" fn CeGetAllocCount() -> u64 {
    ALLOC_COUNT.load(Ordering::Relaxed)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CeGetLastAlloc(out: *mut AllocRecord) -> BOOL {
    if out.is_null() {
        return FALSE;
    }
    let count = ALLOC_COUNT.load(Ordering::Relaxed);
    if count == 0 {
        return FALSE;
    }
    let idx = ((count - 1) as usize) % MAX_RING_BUFFER;
    *out = ALLOC_RING[idx];
    TRUE
}

#[unsafe(no_mangle)]
pub extern "system" fn CeSetStealthMasking(enabled: BOOL) -> BOOL {
    let prev = STEALTH_MASKING_ENABLED.swap(enabled != 0, Ordering::SeqCst);
    if prev { TRUE } else { FALSE }
}

#[unsafe(no_mangle)]
pub extern "system" fn CeIsStealthMaskingEnabled() -> BOOL {
    if STEALTH_MASKING_ENABLED.load(Ordering::Relaxed) {
        TRUE
    } else {
        FALSE
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn CeSetHeapMinFilter(min_size: u64) {
    HEAP_MIN_SIZE_FILTER.store(min_size, Ordering::Relaxed);
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
    TRUE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_structure_alignment() {
        assert_eq!(std::mem::size_of::<AllocRecord>(), 48);
    }

    #[test]
    fn test_pascal_alignment() {
        assert_eq!(std::mem::size_of::<PascalAllocData>(), 40);
        assert_eq!(std::mem::size_of::<PascalHeapAllocData>(), 32);
    }

    #[test]
    fn test_ring_buffer_atomic_push() {
        let initial_count = ALLOC_COUNT.load(Ordering::Relaxed);
        push_record(0, 0x7FFF0000, 4096, 0x1000, PAGE_READWRITE, 0x7FF71234);

        let new_count = ALLOC_COUNT.load(Ordering::Relaxed);
        assert_eq!(new_count, initial_count + 1);

        let mut rec = AllocRecord {
            event_type: 0,
            address: 0,
            size: 0,
            flags: 0,
            protection: 0,
            caller_ip: 0,
            timestamp_ms: 0,
        };

        unsafe {
            let res = CeGetLastAlloc(&mut rec);
            assert_eq!(res, TRUE);
            assert_eq!(rec.address, 0x7FFF0000);
            assert_eq!(rec.size, 4096);
            assert_eq!(rec.protection, PAGE_READWRITE);
            assert_eq!(rec.caller_ip, 0x7FF71234);
        }
    }

    #[test]
    fn test_stealth_toggle() {
        CeSetStealthMasking(TRUE);
        assert_eq!(CeIsStealthMaskingEnabled(), TRUE);

        CeSetStealthMasking(FALSE);
        assert_eq!(CeIsStealthMaskingEnabled(), FALSE);

        CeSetStealthMasking(TRUE);
    }
}
