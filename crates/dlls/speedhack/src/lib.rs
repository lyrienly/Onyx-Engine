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

type FnQpc = unsafe extern "system" fn(*mut i64) -> BOOL;
type FnGtc = unsafe extern "system" fn() -> DWORD;
type FnGtc64 = unsafe extern "system" fn() -> u64;
type FnTimeGetTime = unsafe extern "system" fn() -> DWORD;
type FnSleep = unsafe extern "system" fn(DWORD);

static mut TRAMPOLINE_QPC: Option<FnQpc> = None;
static mut TRAMPOLINE_GTC: Option<FnGtc> = None;
static mut TRAMPOLINE_GTC64: Option<FnGtc64> = None;
static mut TRAMPOLINE_TGT: Option<FnTimeGetTime> = None;
static mut TRAMPOLINE_SLEEP: Option<FnSleep> = None;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn Sleep(dwMilliseconds: DWORD);
    fn VirtualAlloc(lpAddress: LPVOID, dwSize: usize, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID;
    fn FlushInstructionCache(hProcess: HANDLE, lpBaseAddress: LPCVOID, dwSize: usize) -> BOOL;
    fn GetCurrentProcess() -> HANDLE;
}

unsafe extern "system" fn Hooked_QueryPerformanceCounter(lpCount: *mut i64) -> BOOL {
    let mut real_qpc: i64 = 0;
    let orig = TRAMPOLINE_QPC.unwrap_or(QueryPerformanceCounter);
    let res = orig(&mut real_qpc);

    if res != 0 && !lpCount.is_null() {
        let mut lock = SPEED_STATE.lock().unwrap();
        if let Some(state) = lock.as_mut() {
            if state.multiplier <= 0.0 {

                *lpCount = state.initial_virtual_qpc;
            } else {
                let delta = real_qpc - state.initial_real_qpc;
                let scaled_delta = ((delta as f64) * (state.multiplier as f64)) as i64;
                *lpCount = state.initial_virtual_qpc + scaled_delta;
            }
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
        if state.multiplier <= 0.0 {
            state.initial_virtual_tick
        } else {
            let delta = real_tick.wrapping_sub(state.initial_real_tick);
            let scaled_delta = ((delta as f64) * (state.multiplier as f64)) as u32;
            state.initial_virtual_tick.wrapping_add(scaled_delta)
        }
    } else {
        real_tick
    }
}

unsafe extern "system" fn Hooked_GetTickCount64() -> u64 {
    let orig = TRAMPOLINE_GTC64.unwrap_or(GetTickCount64);
    let real_tick64 = orig();

    let mut lock = SPEED_STATE.lock().unwrap();
    if let Some(state) = lock.as_mut() {
        if state.multiplier <= 0.0 {
            state.initial_virtual_tick64
        } else {
            let delta = real_tick64.wrapping_sub(state.initial_real_tick64);
            let scaled_delta = ((delta as f64) * (state.multiplier as f64)) as u64;
            state.initial_virtual_tick64.wrapping_add(scaled_delta)
        }
    } else {
        real_tick64
    }
}

unsafe extern "system" fn Hooked_timeGetTime() -> DWORD {
    let real_tgt = if let Some(orig) = TRAMPOLINE_TGT {
        orig()
    } else {
        GetTickCount()
    };

    let mut lock = SPEED_STATE.lock().unwrap();
    if let Some(state) = lock.as_mut() {
        if state.multiplier <= 0.0 {
            state.initial_virtual_tick
        } else {
            let delta = real_tgt.wrapping_sub(state.initial_real_tick);
            let scaled_delta = ((delta as f64) * (state.multiplier as f64)) as u32;
            state.initial_virtual_tick.wrapping_add(scaled_delta)
        }
    } else {
        real_tgt
    }
}

unsafe extern "system" fn Hooked_Sleep(dwMilliseconds: DWORD) {
    let mult = {
        let lock = SPEED_STATE.lock().unwrap();
        lock.as_ref().map(|s| s.multiplier).unwrap_or(1.0)
    };

    let orig = TRAMPOLINE_SLEEP.unwrap_or(Sleep);

    if mult <= 0.0 {

        orig(50);
    } else if dwMilliseconds > 0 {
        let scaled = ((dwMilliseconds as f32) / mult) as DWORD;
        orig(scaled.max(1));
    } else {
        orig(0);
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

            let qpc_delta = ((cur_qpc - state.initial_real_qpc) as f64 * state.multiplier as f64) as i64;
            state.initial_virtual_qpc += qpc_delta;
            state.initial_real_qpc = cur_qpc;

            let tick_delta = (cur_tick.wrapping_sub(state.initial_real_tick) as f64 * state.multiplier as f64) as u32;
            state.initial_virtual_tick = state.initial_virtual_tick.wrapping_add(tick_delta);
            state.initial_real_tick = cur_tick;

            let tick64_delta = (cur_tick64.wrapping_sub(state.initial_real_tick64) as f64 * state.multiplier as f64) as u64;
            state.initial_virtual_tick64 = state.initial_virtual_tick64.wrapping_add(tick64_delta);
            state.initial_real_tick64 = cur_tick64;

            state.multiplier = speed.max(0.0);
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

static mut TRAMPOLINE_BUF: *mut u8 = null_mut();
static mut TRAMPOLINE_POS: usize = 0;

unsafe fn create_detour_64(target: *mut c_void, detour: *mut c_void) -> *mut c_void {
    if target.is_null() || detour.is_null() {
        return target;
    }

    if TRAMPOLINE_BUF.is_null() {
        TRAMPOLINE_BUF = VirtualAlloc(null_mut(), 4096, 0x1000 | 0x2000, PAGE_EXECUTE_READWRITE) as *mut u8;
        TRAMPOLINE_POS = 0;
    }

    if TRAMPOLINE_BUF.is_null() || TRAMPOLINE_POS + 64 > 4096 {
        return target;
    }

    let stolen_len = 14;
    let tramp = TRAMPOLINE_BUF.add(TRAMPOLINE_POS);

    std::ptr::copy_nonoverlapping(target as *const u8, tramp, stolen_len);

    let jmp_back = tramp.add(stolen_len);
    *jmp_back = 0xFF;
    *jmp_back.add(1) = 0x25;
    *jmp_back.add(2) = 0x00;
    *jmp_back.add(3) = 0x00;
    *jmp_back.add(4) = 0x00;
    *jmp_back.add(5) = 0x00;
    let target_resume = (target as usize) + stolen_len;
    std::ptr::copy_nonoverlapping(&target_resume as *const usize as *const u8, jmp_back.add(6), 8);

    TRAMPOLINE_POS += stolen_len + 14;

    let mut old_protect: DWORD = 0;
    if VirtualProtect(target, stolen_len, PAGE_EXECUTE_READWRITE, &mut old_protect) != 0 {
        let t_ptr = target as *mut u8;
        *t_ptr = 0xFF;
        *t_ptr.add(1) = 0x25;
        *t_ptr.add(2) = 0x00;
        *t_ptr.add(3) = 0x00;
        *t_ptr.add(4) = 0x00;
        *t_ptr.add(5) = 0x00;
        let detour_addr = detour as usize;
        std::ptr::copy_nonoverlapping(&detour_addr as *const usize as *const u8, t_ptr.add(6), 8);

        VirtualProtect(target, stolen_len, old_protect, &mut old_protect);
        FlushInstructionCache(GetCurrentProcess(), target, stolen_len);
    }

    tramp as *mut c_void
}

unsafe fn install_inline_hooks() {
    let k32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    let kbase = GetModuleHandleA(b"kernelbase.dll\0".as_ptr());
    let winmm = GetModuleHandleA(b"winmm.dll\0".as_ptr());

    let p_qpc = if !kbase.is_null() {
        GetProcAddress(kbase, b"QueryPerformanceCounter\0".as_ptr())
    } else if !k32.is_null() {
        GetProcAddress(k32, b"QueryPerformanceCounter\0".as_ptr())
    } else {
        null_mut()
    };

    if !p_qpc.is_null() {
        let tramp = create_detour_64(p_qpc, Hooked_QueryPerformanceCounter as *mut c_void);
        TRAMPOLINE_QPC = Some(std::mem::transmute(tramp));
    }

    let p_gtc = if !kbase.is_null() {
        GetProcAddress(kbase, b"GetTickCount\0".as_ptr())
    } else if !k32.is_null() {
        GetProcAddress(k32, b"GetTickCount\0".as_ptr())
    } else {
        null_mut()
    };

    if !p_gtc.is_null() {
        let tramp = create_detour_64(p_gtc, Hooked_GetTickCount as *mut c_void);
        TRAMPOLINE_GTC = Some(std::mem::transmute(tramp));
    }

    let p_gtc64 = if !kbase.is_null() {
        GetProcAddress(kbase, b"GetTickCount64\0".as_ptr())
    } else if !k32.is_null() {
        GetProcAddress(k32, b"GetTickCount64\0".as_ptr())
    } else {
        null_mut()
    };

    if !p_gtc64.is_null() {
        let tramp = create_detour_64(p_gtc64, Hooked_GetTickCount64 as *mut c_void);
        TRAMPOLINE_GTC64 = Some(std::mem::transmute(tramp));
    }

    if !winmm.is_null() {
        let p_tgt = GetProcAddress(winmm, b"timeGetTime\0".as_ptr());
        if !p_tgt.is_null() {
            let tramp = create_detour_64(p_tgt, Hooked_timeGetTime as *mut c_void);
            TRAMPOLINE_TGT = Some(std::mem::transmute(tramp));
        }
    }

    if !k32.is_null() {
        let p_sleep = GetProcAddress(k32, b"Sleep\0".as_ptr());
        if !p_sleep.is_null() {
            let tramp = create_detour_64(p_sleep, Hooked_Sleep as *mut c_void);
            TRAMPOLINE_SLEEP = Some(std::mem::transmute(tramp));
        }
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
                    0x00000003,
                    0x00000000,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_speed_scaling_math() {
        let state = SpeedState {
            multiplier: 2.0,
            initial_real_qpc: 1000,
            initial_virtual_qpc: 1000,
            initial_real_tick: 500,
            initial_virtual_tick: 500,
            initial_real_tick64: 500,
            initial_virtual_tick64: 500,
        };

        let real_now = 600u32;
        let delta = real_now - state.initial_real_tick;
        let scaled_delta = ((delta as f64) * (state.multiplier as f64)) as u32;
        let virtual_now = state.initial_virtual_tick + scaled_delta;

        assert_eq!(scaled_delta, 200);
        assert_eq!(virtual_now, 700);
    }

    #[test]
    fn test_freeze_math() {
        let state = SpeedState {
            multiplier: 0.0,
            initial_real_qpc: 1000,
            initial_virtual_qpc: 1000,
            initial_real_tick: 500,
            initial_virtual_tick: 500,
            initial_real_tick64: 500,
            initial_virtual_tick64: 500,
        };

        assert_eq!(state.multiplier, 0.0);

        assert_eq!(state.initial_virtual_tick, 500);
    }
}
