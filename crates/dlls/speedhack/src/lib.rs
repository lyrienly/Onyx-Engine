// language: Rust, file: lib.rs (speedhack_dll), target: Windows 11, MSVC
// Standalone injectable speedhack DLL for x86_64 target processes

#![allow(non_snake_case, non_camel_case_types, dead_code, unsafe_op_in_unsafe_fn, static_mut_refs)]

use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;

type BOOL = i32;
type DWORD = u32;
type QWORD = u64;
type HANDLE = *mut c_void;
type HMODULE = *mut c_void;
type LPVOID = *mut c_void;
type LPCVOID = *const c_void;
type LPCWSTR = *const u16;

const DLL_PROCESS_ATTACH: DWORD = 1;
const DLL_PROCESS_DETACH: DWORD = 0;
const PAGE_EXECUTE_READWRITE: DWORD = 0x40;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn DisableThreadLibraryCalls(hLibModule: HMODULE) -> BOOL;
    fn VirtualProtect(lpAddress: LPVOID, dwSize: usize, flNewProtect: DWORD, lpflOldProtect: *mut DWORD) -> BOOL;
    fn GetCurrentProcessId() -> DWORD;
    fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> *mut c_void;
    fn GetModuleHandleA(lpModuleName: *const u8) -> HMODULE;
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
    fn ReadFile(hFile: HANDLE, lpBuffer: LPVOID, nNumberOfBytesToRead: DWORD, lpNumberOfBytesRead: *mut DWORD, lpOverlapped: LPVOID) -> BOOL;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
    fn QueryPerformanceCounter(lpPerformanceCount: *mut i64) -> BOOL;
    fn GetTickCount() -> DWORD;
    fn GetTickCount64() -> u64;
}

struct SpeedState {
    multiplier: f32,
    initial_real_qpc: i64,
    initial_virtual_qpc: i64,
    initial_real_tick: u32,
    initial_virtual_tick: u32,
    initial_real_tick64: u64,
    initial_virtual_tick64: u64,
}

static SPEED_STATE: Mutex<Option<SpeedState>> = Mutex::new(None);
static HOOKS_INSTALLED: AtomicBool = AtomicBool::new(false);

// Function pointer signatures
type FnQpc = unsafe extern "system" fn(*mut i64) -> BOOL;
type FnGtc = unsafe extern "system" fn() -> DWORD;
type FnGtc64 = unsafe extern "system" fn() -> u64;

static mut TRAMPOLINE_QPC: Option<FnQpc> = None;
static mut TRAMPOLINE_GTC: Option<FnGtc> = None;
static mut TRAMPOLINE_GTC64: Option<FnGtc64> = None;

// Hook implementations
unsafe extern "system" fn Hooked_QueryPerformanceCounter(lpCount: *mut i64) -> BOOL {
    let mut real_qpc: i64 = 0;
    let orig = TRAMPOLINE_QPC.unwrap_or(QueryPerformanceCounter);
    let res = orig(&mut real_qpc);

    if res != 0 && !lpCount.is_null() {
        let mut lock = SPEED_STATE.lock().unwrap();
        if let Some(state) = lock.as_mut() {
            let delta = real_qpc - state.initial_real_qpc;
            let scaled_delta = ((delta as f64) * (state.multiplier as f64)) as i64;
            *lpCount = state.initial_virtual_qpc + scaled_delta;
        } else {
            *lpCount = real_qpc;
        }
    }

    res
}

unsafe extern "system" fn Hooked_GetTickCount() -> DWORD {
    let orig = TRAMPOLINE_GTC.unwrap_or(GetTickCount);
    let real_tick = orig();

    let mut lock = SPEED_STATE.lock().unwrap();
    if let Some(state) = lock.as_mut() {
        let delta = real_tick.wrapping_sub(state.initial_real_tick);
        let scaled_delta = ((delta as f64) * (state.multiplier as f64)) as u32;
        state.initial_virtual_tick.wrapping_add(scaled_delta)
    } else {
        real_tick
    }
}

unsafe extern "system" fn Hooked_GetTickCount64() -> u64 {
    let orig = TRAMPOLINE_GTC64.unwrap_or(GetTickCount64);
    let real_tick64 = orig();

    let mut lock = SPEED_STATE.lock().unwrap();
    if let Some(state) = lock.as_mut() {
        let delta = real_tick64.wrapping_sub(state.initial_real_tick64);
        let scaled_delta = ((delta as f64) * (state.multiplier as f64)) as u64;
        state.initial_virtual_tick64.wrapping_add(scaled_delta)
    } else {
        real_tick64
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn SetSpeed(speed: f32) {
    let mut lock = SPEED_STATE.lock().unwrap();
    if let Some(state) = lock.as_mut() {
        unsafe {
            let mut cur_qpc: i64 = 0;
            QueryPerformanceCounter(&mut cur_qpc);
            let cur_tick = GetTickCount();
            let cur_tick64 = GetTickCount64();

            // Rescale baselines
            let qpc_delta = ((cur_qpc - state.initial_real_qpc) as f64 * state.multiplier as f64) as i64;
            state.initial_virtual_qpc += qpc_delta;
            state.initial_real_qpc = cur_qpc;

            let tick_delta = (cur_tick.wrapping_sub(state.initial_real_tick) as f64 * state.multiplier as f64) as u32;
            state.initial_virtual_tick = state.initial_virtual_tick.wrapping_add(tick_delta);
            state.initial_real_tick = cur_tick;

            let tick64_delta = (cur_tick64.wrapping_sub(state.initial_real_tick64) as f64 * state.multiplier as f64) as u64;
            state.initial_virtual_tick64 = state.initial_virtual_tick64.wrapping_add(tick64_delta);
            state.initial_real_tick64 = cur_tick64;

            state.multiplier = speed;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn InitializeSpeedhack(speed: f32) {
    let mut cur_qpc: i64 = 0;
    unsafe {
        QueryPerformanceCounter(&mut cur_qpc);
        let cur_tick = GetTickCount();
        let cur_tick64 = GetTickCount64();

        let mut lock = SPEED_STATE.lock().unwrap();
        *lock = Some(SpeedState {
            multiplier: speed,
            initial_real_qpc: cur_qpc,
            initial_virtual_qpc: cur_qpc,
            initial_real_tick: cur_tick,
            initial_virtual_tick: cur_tick,
            initial_real_tick64: cur_tick64,
            initial_virtual_tick64: cur_tick64,
        });

        if !HOOKS_INSTALLED.swap(true, Ordering::SeqCst) {
            install_inline_hooks();
        }
    }
}

unsafe fn install_inline_hooks() {
    let k32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    if k32.is_null() {
        return;
    }

    let p_qpc = GetProcAddress(k32, b"QueryPerformanceCounter\0".as_ptr());
    let p_gtc = GetProcAddress(k32, b"GetTickCount\0".as_ptr());
    let p_gtc64 = GetProcAddress(k32, b"GetTickCount64\0".as_ptr());

    if !p_qpc.is_null() {
        TRAMPOLINE_QPC = Some(std::mem::transmute(p_qpc));
    }
    if !p_gtc.is_null() {
        TRAMPOLINE_GTC = Some(std::mem::transmute(p_gtc));
    }
    if !p_gtc64.is_null() {
        TRAMPOLINE_GTC64 = Some(std::mem::transmute(p_gtc64));
    }
}

fn start_pipe_listener() {
    thread::spawn(|| {
        let pid = unsafe { GetCurrentProcessId() };
        let pipe_name = format!("\\\\.\\pipe\\ce_speedhack_{}\0", pid);

        loop {
            let h_pipe = unsafe {
                CreateNamedPipeA(
                    pipe_name.as_ptr(),
                    0x00000003, // PIPE_ACCESS_DUPLEX
                    0x00000000, // PIPE_TYPE_BYTE
                    1,
                    512,
                    512,
                    0,
                    null_mut(),
                )
            };

            if h_pipe == -1isize as HANDLE {
                break;
            }

            if unsafe { ConnectNamedPipe(h_pipe, null_mut()) } != 0 {
                let mut buf = [0u8; 4];
                let mut read: DWORD = 0;
                if unsafe { ReadFile(h_pipe, buf.as_mut_ptr() as LPVOID, 4, &mut read, null_mut()) } != 0 && read == 4 {
                    let new_speed = f32::from_le_bytes(buf);
                    SetSpeed(new_speed);
                }
            }

            unsafe {
                DisconnectNamedPipe(h_pipe);
                CloseHandle(h_pipe);
            }
        }
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    hinstDLL: HMODULE,
    fdwReason: DWORD,
    _lpReserved: LPVOID,
) -> BOOL {
    if fdwReason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(hinstDLL);
        InitializeSpeedhack(1.0);
        start_pipe_listener();
    }
    1
}
