use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::Mutex;

type HMODULE = *mut c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(lpLibFileName: *const u16) -> HMODULE;
    fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> *mut c_void;
    fn GetModuleFileNameW(hModule: HMODULE, lpFilename: *mut u16, nSize: u32) -> u32;
    fn FreeLibrary(hLibModule: HMODULE) -> i32;
}

pub struct ModuleRegistry {
    pub base_dir: PathBuf,
    pub pointer_dll: Option<HMODULE>,
    pub scanner_dll: Option<HMODULE>,
    pub disasm_dll: Option<HMODULE>,
    pub freezer_dll: Option<HMODULE>,
}

unsafe impl Send for ModuleRegistry {}
unsafe impl Sync for ModuleRegistry {}

static REGISTRY: Mutex<Option<ModuleRegistry>> = Mutex::new(None);

fn get_exe_dir() -> PathBuf {
    let mut buf = vec![0u16; 1024];
    let len = unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) };
    if len > 0 {
        let path_str = String::from_utf16_lossy(&buf[..len as usize]);
        if let Some(parent) = std::path::Path::new(&path_str).parent() {
            return parent.to_path_buf();
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn load_dll_from_path(path: &std::path::Path) -> Option<HMODULE> {
    if !path.exists() {
        return None;
    }
    let path_w: Vec<u16> = path.to_str()?.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe { LoadLibraryW(path_w.as_ptr()) };
    if handle.is_null() {
        None
    } else {
        Some(handle)
    }
}

pub fn init_modules() {
    let pid = std::process::id();
    let _ = onyx_core::security::activate_process_shield();
    if let Ok(driver) = onyx_core::process::kernel::DbkDriver::connect() {
        let _ = driver.hide_process(pid);
    }

    let mut guard = REGISTRY.lock().unwrap();
    if guard.is_some() {
        return;
    }

    let base = get_exe_dir();
    let modules_dir = base.join("modules");

    let ptr_path = modules_dir.join("pointer").join("onyx_pointer.dll");
    let scan_path = modules_dir.join("scanner").join("onyx_scanner.dll");
    let disasm_path = modules_dir.join("debugger").join("onyx_disasm.dll");
    let freeze_path = modules_dir.join("freezer").join("onyx_freezer.dll");

    let pointer_dll = load_dll_from_path(&ptr_path);
    let scanner_dll = load_dll_from_path(&scan_path);
    let disasm_dll = load_dll_from_path(&disasm_path);
    let freezer_dll = load_dll_from_path(&freeze_path);

    *guard = Some(ModuleRegistry {
        base_dir: base,
        pointer_dll,
        scanner_dll,
        disasm_dll,
        freezer_dll,
    });
}

pub fn cleanup_modules() {
    let mut guard = REGISTRY.lock().unwrap();
    if let Some(mut reg) = guard.take() {
        unsafe {
            if let Some(h) = reg.pointer_dll.take() { FreeLibrary(h); }
            if let Some(h) = reg.scanner_dll.take() { FreeLibrary(h); }
            if let Some(h) = reg.disasm_dll.take() { FreeLibrary(h); }
            if let Some(h) = reg.freezer_dll.take() { FreeLibrary(h); }
        }
    }
}

#[no_mangle]
pub extern "C" fn onyx_module_is_loaded(module_idx: u32) -> i32 {
    let guard = REGISTRY.lock().unwrap();
    if let Some(reg) = guard.as_ref() {
        match module_idx {
            0 => if reg.pointer_dll.is_some() { 1 } else { 0 },
            1 => if reg.scanner_dll.is_some() { 1 } else { 0 },
            2 => if reg.disasm_dll.is_some() { 1 } else { 0 },
            3 if reg.freezer_dll.is_some() => { 1 },
            _ => 0,
        }
    } else {
        0
    }
}
