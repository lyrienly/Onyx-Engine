use crate::win32::*;
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

pub type HWND = *mut c_void;
pub type WNDPROC = Option<unsafe extern "system" fn(HWND, u32, usize, isize) -> isize>;
pub type WNDENUMPROC = Option<unsafe extern "system" fn(HWND, isize) -> BOOL>;

pub const GWLP_WNDPROC: i32 = -4;
pub const WM_SYSCOMMAND: u32 = 0x0112;
pub const SC_MINIMIZE: usize = 0xF020;
pub const WM_WINDOWPOSCHANGING: u32 = 0x0046;
pub const WM_SHOWWINDOW: u32 = 0x0018;
pub const WM_SIZE: u32 = 0x0005;
pub const SIZE_MINIMIZED: usize = 1;

pub const SWP_NOSIZE: u32 = 0x0001;
pub const SWP_NOMOVE: u32 = 0x0002;
pub const SWP_SHOWWINDOW: u32 = 0x0040;
pub const SWP_HIDEWINDOW: u32 = 0x0080;
pub const SWP_NOACTIVATE: u32 = 0x0010;

pub const HWND_TOPMOST: isize = -1;
pub const HWND_BOTTOM: isize = 1;
pub const SW_RESTORE: i32 = 9;

pub const WDA_NONE: u32 = 0x00000000;
pub const WDA_MONITOR: u32 = 0x00000001;
pub const WDA_EXCLUDEFROMCAPTURE: u32 = 0x00000011;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WindowPos {
    pub hwnd: usize,
    pub hwnd_insert_after: isize,
    pub x: i32,
    pub y: i32,
    pub cx: i32,
    pub cy: i32,
    pub flags: u32,
}

static ORIGINAL_WNDPROCS: Mutex<Option<HashMap<usize, usize>>> = Mutex::new(None);
static WATCHDOG_RUNNING: AtomicBool = AtomicBool::new(false);
static PROTECTED_WINDOWS: Mutex<Option<Vec<usize>>> = Mutex::new(None);

unsafe extern "system" {
    #[cfg(target_arch = "x86_64")]
    fn SetWindowLongPtrW(hwnd: HWND, index: i32, new_long: isize) -> isize;
    #[cfg(target_arch = "x86")]
    #[link_name = "SetWindowLongW"]
    fn SetWindowLongPtrW(hwnd: HWND, index: i32, new_long: isize) -> isize;
    fn CallWindowProcW(
        prev_wnd_proc: WNDPROC,
        hwnd: HWND,
        msg: u32,
        wparam: usize,
        lparam: isize,
    ) -> isize;
    fn SetWindowPos(
        hwnd: HWND,
        insert_after: HWND,
        x: i32,
        y: i32,
        cx: i32,
        cy: i32,
        flags: u32,
    ) -> BOOL;
    fn ShowWindow(hwnd: HWND, cmd_show: i32) -> BOOL;
    fn IsIconic(hwnd: HWND) -> BOOL;
    fn SetWindowTextW(hwnd: HWND, text: *const u16) -> BOOL;
    fn SetWindowDisplayAffinity(hwnd: HWND, affinity: u32) -> BOOL;
    fn EnumWindows(lpEnumFunc: WNDENUMPROC, lParam: isize) -> BOOL;
    fn GetWindowThreadProcessId(hwnd: HWND, process_id: *mut u32) -> u32;
    fn GetCurrentProcessId() -> u32;
    fn IsWindowVisible(hwnd: HWND) -> BOOL;
}

unsafe extern "system" fn window_shield_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    match msg {
        WM_SYSCOMMAND => {
            let cmd = wparam & 0xFFF0;
            if cmd == SC_MINIMIZE {
                return 0;
            }
        }
        WM_WINDOWPOSCHANGING => {
            if lparam != 0 {
                let pos = unsafe { &mut *(lparam as *mut WindowPos) };
                if (pos.flags & SWP_HIDEWINDOW) != 0 {
                    pos.flags &= !SWP_HIDEWINDOW;
                    pos.flags |= SWP_SHOWWINDOW;
                }
                if pos.hwnd_insert_after == HWND_BOTTOM {
                    pos.hwnd_insert_after = HWND_TOPMOST;
                }
                // Block ShowWindow(SW_MINIMIZE) — Windows moves the window
                // to (-32000, -32000) when minimizing
                if pos.x == -32000 || pos.y == -32000 {
                    pos.flags |= SWP_NOMOVE | SWP_NOSIZE;
                    pos.x = 0;
                    pos.y = 0;
                }
            }
        }
        WM_SIZE if wparam == SIZE_MINIMIZED => {
            // ShowWindow(SW_MINIMIZE) lands here; immediately restore
            unsafe { ShowWindow(hwnd, SW_RESTORE); }
            return 0;
        }
        WM_SHOWWINDOW if wparam == 0 => {
            return 0;
        }
        _ => {}
    }

    let hwnd_key = hwnd as usize;
    let original = {
        let guard = ORIGINAL_WNDPROCS.lock().unwrap();
        guard.as_ref().and_then(|map| map.get(&hwnd_key).copied())
    };

    if let Some(orig) = original {
        let proc_fn: WNDPROC = unsafe { std::mem::transmute(orig) };
        unsafe { CallWindowProcW(proc_fn, hwnd, msg, wparam, lparam) }
    } else {
        0
    }
}

pub struct WindowShield;

impl WindowShield {
    pub fn protect_window(hwnd: usize, title_camouflage: Option<&str>) -> Result<(), String> {
        if hwnd == 0 {
            return Err("Invalid window handle".to_string());
        }

        let hwnd_val = hwnd as HWND;
        let proc_addr = window_shield_wndproc as *const () as isize;

        unsafe {
            // 1. Subclass Window Procedure to trap and drop minimize / hide messages
            let old_proc = SetWindowLongPtrW(hwnd_val, GWLP_WNDPROC, proc_addr);
            if old_proc != 0 && old_proc != proc_addr {
                let mut guard = ORIGINAL_WNDPROCS.lock().unwrap();
                let map = guard.get_or_insert_with(HashMap::new);
                map.insert(hwnd, old_proc as usize);
            }

            // 2. Cloak from screen capture (Xigncode/anticheat window screenshot sweeps)
            let _ = SetWindowDisplayAffinity(hwnd_val, WDA_EXCLUDEFROMCAPTURE);

            // 3. Lock window to topmost
            SetWindowPos(
                hwnd_val,
                HWND_TOPMOST as HWND,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW,
            );

            // 4. Camouflage window title if requested
            if let Some(title) = title_camouflage {
                let wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
                SetWindowTextW(hwnd_val, wide.as_ptr());
            }

            // Register in protected list for watchdog
            let mut list_guard = PROTECTED_WINDOWS.lock().unwrap();
            let list = list_guard.get_or_insert_with(Vec::new);
            if !list.contains(&hwnd) {
                list.push(hwnd);
            }

            // Start watchdog if not active
            Self::ensure_watchdog();
        }

        Ok(())
    }

    pub fn protect_process_windows(pid: u32, title_camouflage: Option<&str>) -> usize {
        struct EnumContext<'a> {
            target_pid: u32,
            camouflage: Option<&'a str>,
            count: usize,
        }

        unsafe extern "system" fn enum_callback(hwnd: HWND, lparam: isize) -> BOOL {
            unsafe {
                let ctx = &mut *(lparam as *mut EnumContext);
                let mut proc_id = 0u32;
                GetWindowThreadProcessId(hwnd, &mut proc_id);

                if proc_id == ctx.target_pid
                    && IsWindowVisible(hwnd) != 0
                    && WindowShield::protect_window(hwnd as usize, ctx.camouflage).is_ok()
                {
                    ctx.count += 1;
                }
            }
            1 // Continue enumeration
        }

        let mut ctx = EnumContext {
            target_pid: pid,
            camouflage: title_camouflage,
            count: 0,
        };

        unsafe {
            EnumWindows(Some(enum_callback), &mut ctx as *mut _ as isize);
        }

        ctx.count
    }

    pub fn is_active() -> bool {
        WATCHDOG_RUNNING.load(Ordering::SeqCst)
    }

    pub fn protect_current_process(title_camouflage: Option<&str>) -> usize {
        let pid = unsafe { GetCurrentProcessId() };
        Self::protect_process_windows(pid, title_camouflage)
    }

    fn ensure_watchdog() {
        if WATCHDOG_RUNNING
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            thread::spawn(|| {
                while WATCHDOG_RUNNING.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(50));

                    let windows = {
                        let guard = PROTECTED_WINDOWS.lock().unwrap();
                        guard.as_ref().cloned().unwrap_or_default()
                    };

                    for hwnd in windows {
                        let hwnd_val = hwnd as HWND;
                        unsafe {
                            // If anti-cheat managed to minimize via low-level hook, immediately restore!
                            if IsIconic(hwnd_val) != 0 {
                                ShowWindow(hwnd_val, SW_RESTORE);
                            }

                            // Keep topmost assertion
                            SetWindowPos(
                                hwnd_val,
                                HWND_TOPMOST as HWND,
                                0,
                                0,
                                0,
                                0,
                                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW,
                            );
                        }
                    }
                }
            });
        }
    }

    pub fn stop_watchdog() {
        WATCHDOG_RUNNING.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_shield_constants() {
        assert_eq!(WM_SYSCOMMAND, 0x0112);
        assert_eq!(SC_MINIMIZE, 0xF020);
        assert_eq!(WDA_EXCLUDEFROMCAPTURE, 0x00000011);
        assert_eq!(HWND_TOPMOST, -1);
    }

    #[test]
    fn test_protect_invalid_hwnd() {
        assert!(WindowShield::protect_window(0, None).is_err());
    }
}
