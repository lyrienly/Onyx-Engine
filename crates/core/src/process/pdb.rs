use crate::win32::*;
use std::ffi::{OsStr, c_void};
use std::mem::zeroed;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};

pub const SYMOPT_CASE_INSENSITIVE: u32 = 0x00000001;
pub const SYMOPT_UNDNAME: u32 = 0x00000002;
pub const SYMOPT_DEFERRED_LOADS: u32 = 0x00000004;
pub const SYMOPT_LOAD_LINES: u32 = 0x00000010;
pub const SYMOPT_AUTO_PUBLICS: u32 = 0x00010000;

#[repr(C)]
pub struct SYMBOL_INFOW {
    pub size_of_struct: u32,
    pub type_index: u32,
    pub reserved: [u64; 2],
    pub index: u32,
    pub size: u32,
    pub mod_base: u64,
    pub flags: u32,
    pub value: u64,
    pub address: u64,
    pub register: u32,
    pub scope: u32,
    pub tag: u32,
    pub name_len: u32,
    pub max_name_len: u32,
    pub name: [u16; 256],
}

type SymInitializeWFn = unsafe extern "system" fn(HANDLE, LPCWSTR, BOOL) -> BOOL;
type SymCleanupFn = unsafe extern "system" fn(HANDLE) -> BOOL;
type SymLoadModuleExWFn =
    unsafe extern "system" fn(HANDLE, HANDLE, LPCWSTR, LPCWSTR, u64, u32, *mut c_void, u32) -> u64;
type SymFromNameWFn = unsafe extern "system" fn(HANDLE, LPCWSTR, *mut SYMBOL_INFOW) -> BOOL;
type SymFromAddrWFn = unsafe extern "system" fn(HANDLE, u64, *mut u64, *mut SYMBOL_INFOW) -> BOOL;
type SymSetOptionsFn = unsafe extern "system" fn(u32) -> u32;
type SymSetSearchPathWFn = unsafe extern "system" fn(HANDLE, LPCWSTR) -> BOOL;

#[allow(dead_code)]
pub struct DbgHelpSymbolEngine {
    _module: HMODULE,
    fn_sym_initialize: SymInitializeWFn,
    fn_sym_cleanup: SymCleanupFn,
    fn_sym_load_module: SymLoadModuleExWFn,
    fn_sym_from_name: SymFromNameWFn,
    fn_sym_from_addr: SymFromAddrWFn,
    fn_sym_set_options: SymSetOptionsFn,
    fn_sym_set_search_path: SymSetSearchPathWFn,
    pub handle: HANDLE,
    pub initialized: bool,
}

unsafe impl Send for DbgHelpSymbolEngine {}
unsafe impl Sync for DbgHelpSymbolEngine {}

impl DbgHelpSymbolEngine {
    pub fn new(process_handle: HANDLE) -> Result<Self, String> {
        unsafe {
            let dbghelp_name: Vec<u16> = OsStr::new("dbghelp.dll")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let h_mod = LoadLibraryW(dbghelp_name.as_ptr());
            if h_mod.is_null() {
                return Err("Failed to load dbghelp.dll".to_string());
            }

            macro_rules! get_proc {
                ($fn_type:ty, $name:expr) => {{
                    let c_str = std::ffi::CString::new($name).unwrap();
                    let ptr = GetProcAddress(h_mod, c_str.as_ptr() as *const u8);
                    if ptr.is_null() {
                        FreeLibrary(h_mod);
                        return Err(format!("Failed to find {} in dbghelp.dll", $name));
                    }
                    std::mem::transmute::<_, $fn_type>(ptr)
                }};
            }

            let fn_sym_initialize: SymInitializeWFn = get_proc!(SymInitializeWFn, "SymInitializeW");
            let fn_sym_cleanup: SymCleanupFn = get_proc!(SymCleanupFn, "SymCleanup");
            let fn_sym_load_module: SymLoadModuleExWFn =
                get_proc!(SymLoadModuleExWFn, "SymLoadModuleExW");
            let fn_sym_from_name: SymFromNameWFn = get_proc!(SymFromNameWFn, "SymFromNameW");
            let fn_sym_from_addr: SymFromAddrWFn = get_proc!(SymFromAddrWFn, "SymFromAddrW");
            let fn_sym_set_options: SymSetOptionsFn = get_proc!(SymSetOptionsFn, "SymSetOptions");
            let fn_sym_set_search_path: SymSetSearchPathWFn =
                get_proc!(SymSetSearchPathWFn, "SymSetSearchPathW");

            let options = SYMOPT_CASE_INSENSITIVE
                | SYMOPT_UNDNAME
                | SYMOPT_DEFERRED_LOADS
                | SYMOPT_LOAD_LINES
                | SYMOPT_AUTO_PUBLICS;
            (fn_sym_set_options)(options);

            let default_path = "SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols";
            let path_wide: Vec<u16> = OsStr::new(default_path)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let target_handle = if process_handle.is_null() {
                GetCurrentProcess()
            } else {
                process_handle
            };

            let init_res = (fn_sym_initialize)(target_handle, path_wide.as_ptr(), FALSE);
            if init_res != TRUE {
                FreeLibrary(h_mod);
                return Err("SymInitializeW failed to initialize the symbol handler".to_string());
            }

            Ok(Self {
                _module: h_mod,
                fn_sym_initialize,
                fn_sym_cleanup,
                fn_sym_load_module,
                fn_sym_from_name,
                fn_sym_from_addr,
                fn_sym_set_options,
                fn_sym_set_search_path,
                handle: target_handle,
                initialized: true,
            })
        }
    }

    pub fn set_search_path(&self, path: &str) -> bool {
        let wide: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        unsafe { (self.fn_sym_set_search_path)(self.handle, wide.as_ptr()) == TRUE }
    }

    pub fn load_module(&self, image_path: &str, base: usize, size: usize) -> Result<u64, String> {
        let path_wide: Vec<u16> = OsStr::new(image_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let base_res = unsafe {
            (self.fn_sym_load_module)(
                self.handle,
                null_mut(),
                path_wide.as_ptr(),
                null(),
                base as u64,
                size as u32,
                null_mut(),
                0,
            )
        };

        if base_res == 0 {
            let err = unsafe { GetLastError() };
            if err != 0 {
                return Err(format!("SymLoadModuleExW failed with error code {}", err));
            }
        }

        Ok(base_res)
    }

    pub fn resolve_name(&self, symbol_name: &str) -> Option<usize> {
        let name_wide: Vec<u16> = OsStr::new(symbol_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let mut info: SYMBOL_INFOW = zeroed();
            info.size_of_struct = std::mem::size_of::<SYMBOL_INFOW>() as u32;
            info.max_name_len = 255;

            if (self.fn_sym_from_name)(self.handle, name_wide.as_ptr(), &mut info) == TRUE {
                Some(info.address as usize)
            } else {
                None
            }
        }
    }

    pub fn resolve_address(&self, address: usize) -> Option<(String, usize)> {
        unsafe {
            let mut info: SYMBOL_INFOW = zeroed();
            info.size_of_struct = std::mem::size_of::<SYMBOL_INFOW>() as u32;
            info.max_name_len = 255;
            let mut displacement: u64 = 0;

            if (self.fn_sym_from_addr)(self.handle, address as u64, &mut displacement, &mut info)
                == TRUE
            {
                let len = (info.name_len as usize).min(255);
                let name = String::from_utf16_lossy(&info.name[..len]);
                Some((name, displacement as usize))
            } else {
                None
            }
        }
    }
}

impl Drop for DbgHelpSymbolEngine {
    fn drop(&mut self) {
        if self.initialized && !self.handle.is_null() {
            unsafe {
                (self.fn_sym_cleanup)(self.handle);
                FreeLibrary(self._module);
            }
            self.initialized = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dbghelp_initialization() {
        let engine = DbgHelpSymbolEngine::new(null_mut());
        assert!(
            engine.is_ok(),
            "DbgHelpSymbolEngine should load dbghelp.dll on Windows"
        );
        let eng = engine.unwrap();
        assert!(eng.initialized);
    }
}
