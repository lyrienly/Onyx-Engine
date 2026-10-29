#![allow(non_snake_case, non_camel_case_types, dead_code, unsafe_op_in_unsafe_fn, static_mut_refs)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, Ordering};
use std::ptr::null_mut;

type HANDLE = *mut c_void;
type HMODULE = *mut c_void;
type HWND = *mut c_void;
type BOOL = i32;
type DWORD = u32;
type HRESULT = i32;

const S_OK: HRESULT = 0;
const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
const MEM_COMMIT: DWORD = 0x1000;
const MEM_RESERVE: DWORD = 0x2000;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RenderCommand {
    pub cmd_type: u32,
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
    pub color_rgba: u32,
    pub text_len: u32,
    pub text_buf: [u8; 64],
}

const MAX_COMMANDS: usize = 256;
static mut COMMAND_BUFFER: [RenderCommand; MAX_COMMANDS] = [RenderCommand {
    cmd_type: 0,
    x: 0.0,
    y: 0.0,
    w: 0.0,
    h: 0.0,
    color_rgba: 0,
    text_len: 0,
    text_buf: [0u8; 64],
}; MAX_COMMANDS];

static COMMAND_COUNT: AtomicU32 = AtomicU32::new(0);
static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
static PIPE_THREAD_RUNNING: AtomicBool = AtomicBool::new(false);
static PIPE_HANDLE: AtomicIsize = AtomicIsize::new(-1);

unsafe extern "system" {
    fn GetModuleHandleA(lpModuleName: *const u8) -> HMODULE;
    fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> *mut c_void;
    fn VirtualProtect(lpAddress: *mut c_void, dwSize: usize, flNewProtect: DWORD, lpflOldProtect: *mut DWORD) -> BOOL;
    fn VirtualAlloc(lpAddress: *mut c_void, dwSize: usize, flAllocationType: DWORD, flProtect: DWORD) -> *mut c_void;
    fn GetCurrentProcessId() -> DWORD;
    fn CreateThread(
        lpThreadAttributes: *mut c_void,
        dwStackSize: usize,
        lpStartAddress: unsafe extern "system" fn(*mut c_void) -> DWORD,
        lpParameter: *mut c_void,
        dwCreationFlags: DWORD,
        lpThreadId: *mut DWORD,
    ) -> HANDLE;
    fn CreateNamedPipeA(
        lpName: *const u8,
        dwOpenMode: DWORD,
        dwPipeMode: DWORD,
        nMaxInstances: DWORD,
        nOutBufferSize: DWORD,
        nInBufferSize: DWORD,
        nDefaultTimeOut: DWORD,
        lpSecurityAttributes: *mut c_void,
    ) -> HANDLE;
    fn ConnectNamedPipe(hNamedPipe: HANDLE, lpOverlapped: *mut c_void) -> BOOL;
    fn DisconnectNamedPipe(hNamedPipe: HANDLE) -> BOOL;
    fn ReadFile(
        hFile: HANDLE,
        lpBuffer: *mut c_void,
        nNumberOfBytesToRead: DWORD,
        lpNumberOfBytesRead: *mut DWORD,
        lpOverlapped: *mut c_void,
    ) -> BOOL;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
}

type FnPresent = unsafe extern "system" fn(*mut c_void, u32, u32) -> HRESULT;
static mut ORIG_PRESENT: Option<FnPresent> = None;

unsafe extern "system" fn hook_present(
    p_swap_chain: *mut c_void,
    sync_interval: u32,
    flags: u32,
) -> HRESULT {
    let count = COMMAND_COUNT.load(Ordering::Relaxed);
    if count > 0 {

    }

    if let Some(orig) = ORIG_PRESENT {
        orig(p_swap_chain, sync_interval, flags)
    } else {
        S_OK
    }
}

unsafe fn hook_vtable_function(vtable_slot: *mut *mut c_void, detour: *mut c_void) -> *mut c_void {
    let orig = *vtable_slot;
    let mut old_protect: DWORD = 0;
    VirtualProtect(vtable_slot as *mut c_void, std::mem::size_of::<*mut c_void>(), PAGE_EXECUTE_READWRITE, &mut old_protect);
    *vtable_slot = detour;
    VirtualProtect(vtable_slot as *mut c_void, std::mem::size_of::<*mut c_void>(), old_protect, &mut old_protect);
    orig
}

unsafe extern "system" fn pipe_server_worker(_param: *mut c_void) -> DWORD {
    let pid = GetCurrentProcessId();
    let pipe_name = format!("\\\\.\\pipe\\ce_d3dhook_{}\0", pid);

    while PIPE_THREAD_RUNNING.load(Ordering::SeqCst) {
        let pipe = CreateNamedPipeA(
            pipe_name.as_ptr(),
            0x00000003,
            0x00000000,
            1,
            4096,
            4096,
            0,
            null_mut(),
        );

        if pipe == -1isize as HANDLE {
            break;
        }

        PIPE_HANDLE.store(pipe as isize, Ordering::SeqCst);

        let connected = ConnectNamedPipe(pipe, null_mut()) != 0 || {

            true
        };

        if connected {
            let mut buf = [0u8; std::mem::size_of::<RenderCommand>()];
            let mut read_bytes: DWORD = 0;

            while ReadFile(pipe, buf.as_mut_ptr() as *mut c_void, buf.len() as DWORD, &mut read_bytes, null_mut()) != 0 {
                if read_bytes as usize == std::mem::size_of::<RenderCommand>() {
                    let cmd = std::ptr::read_unaligned(buf.as_ptr() as *const RenderCommand);
                    let current = COMMAND_COUNT.load(Ordering::Relaxed) as usize;
                    if current < MAX_COMMANDS {
                        COMMAND_BUFFER[current] = cmd;
                        COMMAND_COUNT.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        PIPE_HANDLE.store(-1, Ordering::SeqCst);
    }

    0
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn D3DHook_Initialize() -> BOOL {
    if HOOK_INSTALLED.load(Ordering::SeqCst) {
        return 1;
    }

    PIPE_THREAD_RUNNING.store(true, Ordering::SeqCst);
    CreateThread(null_mut(), 0, pipe_server_worker, null_mut(), 0, null_mut());

    HOOK_INSTALLED.store(true, Ordering::SeqCst);
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn D3DHook_GetCommandCount() -> u32 {
    COMMAND_COUNT.load(Ordering::Relaxed)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn D3DHook_ClearCommands() {
    COMMAND_COUNT.store(0, Ordering::SeqCst);
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: *mut c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> BOOL {
    match fdw_reason {
        1 => {
            D3DHook_Initialize();
        }
        0 => {
            PIPE_THREAD_RUNNING.store(false, Ordering::SeqCst);
            let h_val = PIPE_HANDLE.swap(-1, Ordering::SeqCst);
            if h_val != -1 {
                CloseHandle(h_val as HANDLE);
            }
        }
        _ => {}
    }
    1
}
