use crate::win32::*;
use std::sync::atomic::{AtomicBool, Ordering};

type HWND = *mut std::ffi::c_void;

static HUNTER_STARTED: AtomicBool = AtomicBool::new(false);

pub struct AnalysisHunter;

impl AnalysisHunter {
    pub fn is_blacklisted_title(title: &str) -> bool {
        let lower = title.to_lowercase();
        let targets = [
            "x64dbg",
            "x32dbg",
            "ida: quick start",
            "ida pro",
            "ksdumper",
            "http debugger",
            "wireshark",
            "process hacker",
            "cheat engine",
        ];

        for t in &targets {
            if lower.contains(t) {
                return true;
            }
        }
        false
    }

    pub fn scan_window_titles() -> bool {
        unsafe {
            let mut found = false;
            let callback: WNDENUMPROC = Some(enum_windows_proc);
            EnumWindows(callback, &mut found as *mut bool as isize);
            found
        }
    }

    pub fn start_monitor() {
        if HUNTER_STARTED.swap(true, Ordering::SeqCst) {
            return;
        }

        std::thread::spawn(|| {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(1500));
            }
        });
    }
}

type WNDENUMPROC = Option<unsafe extern "system" fn(HWND, isize) -> BOOL>;

#[link(name = "user32")]
unsafe extern "system" {
    fn EnumWindows(lpEnumFunc: WNDENUMPROC, lParam: isize) -> BOOL;
    fn GetWindowTextW(hWnd: HWND, lpString: *mut u16, nMaxCount: i32) -> i32;
    fn IsWindowVisible(hWnd: HWND) -> BOOL;
}

unsafe extern "system" fn enum_windows_proc(hwnd: HWND, lparam: isize) -> BOOL {
    unsafe {
        if IsWindowVisible(hwnd) == TRUE {
            let mut buf = [0u16; 512];
            let len = GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
            if len > 0 {
                let title = String::from_utf16_lossy(&buf[..len as usize]);
                if AnalysisHunter::is_blacklisted_title(&title) {
                    let out_found = &mut *(lparam as *mut bool);
                    *out_found = true;
                    return FALSE;
                }
            }
        }
    }
    TRUE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blacklisted_titles() {
        assert!(AnalysisHunter::is_blacklisted_title("x64dbg - module.dll"));
        assert!(AnalysisHunter::is_blacklisted_title("IDA Pro - main"));
        assert!(!AnalysisHunter::is_blacklisted_title("File Explorer"));
        assert!(!AnalysisHunter::is_blacklisted_title(
            "Gerenciador de Arquivos"
        ));
    }
}
