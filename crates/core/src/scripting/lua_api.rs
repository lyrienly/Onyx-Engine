// language: Rust, file: lua_api.rs, target: Windows 11, MSVC
// Cheat Engine Lua Scripting Engine and API binding

#![allow(non_snake_case, non_camel_case_types, dead_code, unsafe_op_in_unsafe_fn, static_mut_refs)]

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr::null_mut;
use std::sync::Mutex;
use crate::process::Process;
use crate::win32::*;

type LuaState = *mut c_void;
type LuaCFunction = unsafe extern "C" fn(LuaState) -> c_int;

// Function pointers from lua53-64.dll
type FnLuaLNewstate = unsafe extern "C" fn() -> LuaState;
type FnLuaOpenlibs = unsafe extern "C" fn(LuaState);
type FnLuaClose = unsafe extern "C" fn(LuaState);
type FnLuaLLoadstring = unsafe extern "C" fn(LuaState, *const c_char) -> c_int;
type FnLuaPcallk = unsafe extern "C" fn(LuaState, c_int, c_int, c_int, isize, *mut c_void) -> c_int;
type FnLuaPushcclosure = unsafe extern "C" fn(LuaState, LuaCFunction, c_int);
type FnLuaSetglobal = unsafe extern "C" fn(LuaState, *const c_char);
type FnLuaGetglobal = unsafe extern "C" fn(LuaState, *const c_char) -> c_int;
type FnLuaPushinteger = unsafe extern "C" fn(LuaState, i64);
type FnLuaPushnumber = unsafe extern "C" fn(LuaState, f64);
type FnLuaPushstring = unsafe extern "C" fn(LuaState, *const c_char) -> *const c_char;
type FnLuaPushboolean = unsafe extern "C" fn(LuaState, c_int);
type FnLuaPushnil = unsafe extern "C" fn(LuaState);
type FnLuaTointegerx = unsafe extern "C" fn(LuaState, c_int, *mut c_int) -> i64;
type FnLuaTonumberx = unsafe extern "C" fn(LuaState, c_int, *mut c_int) -> f64;
type FnLuaTostring = unsafe extern "C" fn(LuaState, c_int, *mut usize) -> *const c_char;
type FnLuaToboolean = unsafe extern "C" fn(LuaState, c_int) -> c_int;
type FnLuaGetbottom = unsafe extern "C" fn(LuaState) -> c_int;
type FnLuaCreatetable = unsafe extern "C" fn(LuaState, c_int, c_int);
type FnLuaRawseti = unsafe extern "C" fn(LuaState, c_int, i64);

struct LuaLib {
    newstate: FnLuaLNewstate,
    openlibs: FnLuaOpenlibs,
    close: FnLuaClose,
    loadstring: FnLuaLLoadstring,
    pcallk: FnLuaPcallk,
    pushcclosure: FnLuaPushcclosure,
    setglobal: FnLuaSetglobal,
    getglobal: FnLuaGetglobal,
    pushinteger: FnLuaPushinteger,
    pushnumber: FnLuaPushnumber,
    pushstring: FnLuaPushstring,
    pushboolean: FnLuaPushboolean,
    pushnil: FnLuaPushnil,
    tointegerx: FnLuaTointegerx,
    tonumberx: FnLuaTonumberx,
    tostring: FnLuaTostring,
    toboolean: FnLuaToboolean,
    gettop: FnLuaGetbottom,
    createtable: FnLuaCreatetable,
    rawseti: FnLuaRawseti,
}

static mut LUA_LIB: Option<LuaLib> = None;
static ACTIVE_PROCESS_HANDLE: Mutex<Option<usize>> = Mutex::new(None);
static ACTIVE_PROCESS_PID: Mutex<Option<u32>> = Mutex::new(None);

pub struct CeLuaEngine {
    state: LuaState,
}

impl CeLuaEngine {
    pub fn init() -> Result<Self, String> {
        unsafe {
            if LUA_LIB.is_none() {
                load_lua_library()?;
            }

            let lib = LUA_LIB.as_ref().unwrap();
            let L = (lib.newstate)();
            if L.is_null() {
                return Err("Failed to create Lua state".to_string());
            }

            (lib.openlibs)(L);

            // Register standard Cheat Engine functions
            register_ce_functions(L, lib);

            Ok(CeLuaEngine { state: L })
        }
    }

    pub fn set_active_process(&self, proc: &Process) {
        let mut lock_h = ACTIVE_PROCESS_HANDLE.lock().unwrap();
        *lock_h = Some(proc.handle as usize);
        let mut lock_pid = ACTIVE_PROCESS_PID.lock().unwrap();
        *lock_pid = Some(proc.pid);
    }

    pub fn execute(&self, script: &str) -> Result<String, String> {
        unsafe {
            let lib = LUA_LIB.as_ref().ok_or("Lua library not loaded")?;
            let c_script = CString::new(script).map_err(|e| e.to_string())?;

            let load_res = (lib.loadstring)(self.state, c_script.as_ptr());
            if load_res != 0 {
                let err_ptr = (lib.tostring)(self.state, -1, null_mut());
                let err_msg = if !err_ptr.is_null() {
                    CStr::from_ptr(err_ptr).to_string_lossy().to_string()
                } else {
                    "Syntax error in Lua script".to_string()
                };
                return Err(err_msg);
            }

            let pcall_res = (lib.pcallk)(self.state, 0, 1, 0, 0, null_mut());
            if pcall_res != 0 {
                let err_ptr = (lib.tostring)(self.state, -1, null_mut());
                let err_msg = if !err_ptr.is_null() {
                    CStr::from_ptr(err_ptr).to_string_lossy().to_string()
                } else {
                    "Lua runtime error".to_string()
                };
                return Err(err_msg);
            }

            let res_ptr = (lib.tostring)(self.state, -1, null_mut());
            if !res_ptr.is_null() {
                Ok(CStr::from_ptr(res_ptr).to_string_lossy().to_string())
            } else {
                Ok("nil".to_string())
            }
        }
    }
}

impl Drop for CeLuaEngine {
    fn drop(&mut self) {
        if !self.state.is_null() {
            unsafe {
                if let Some(lib) = LUA_LIB.as_ref() {
                    (lib.close)(self.state);
                }
            }
        }
    }
}

unsafe fn load_lua_library() -> Result<(), String> {
    let search_paths = [
        "lua53-64.dll",
        "bin\\lua53-64.dll",
        "..\\bin\\lua53-64.dll",
        "..\\Cheat Engine\\bin\\lua53-64.dll",
        "Cheat Engine\\bin\\lua53-64.dll",
    ];

    let mut h_mod: HMODULE = null_mut();
    for p in &search_paths {
        let wide: Vec<u16> = p.encode_utf16().chain(std::iter::once(0)).collect();
        h_mod = LoadLibraryW(wide.as_ptr());
        if !h_mod.is_null() {
            break;
        }
    }

    if h_mod.is_null() {
        return Err("Could not load lua53-64.dll. Ensure it is in PATH or Cheat Engine bin/".to_string());
    }

    macro_rules! get_fn {
        ($name:expr, $t:ty) => {
            std::mem::transmute::<*mut c_void, $t>(
                GetProcAddress(h_mod, concat!($name, "\0").as_ptr())
            )
        };
    }

    let lib = LuaLib {
        newstate: get_fn!("luaL_newstate", FnLuaLNewstate),
        openlibs: get_fn!("luaL_openlibs", FnLuaOpenlibs),
        close: get_fn!("lua_close", FnLuaClose),
        loadstring: get_fn!("luaL_loadstring", FnLuaLLoadstring),
        pcallk: get_fn!("lua_pcallk", FnLuaPcallk),
        pushcclosure: get_fn!("lua_pushcclosure", FnLuaPushcclosure),
        setglobal: get_fn!("lua_setglobal", FnLuaSetglobal),
        getglobal: get_fn!("lua_getglobal", FnLuaGetglobal),
        pushinteger: get_fn!("lua_pushinteger", FnLuaPushinteger),
        pushnumber: get_fn!("lua_pushnumber", FnLuaPushnumber),
        pushstring: get_fn!("lua_pushstring", FnLuaPushstring),
        pushboolean: get_fn!("lua_pushboolean", FnLuaPushboolean),
        pushnil: get_fn!("lua_pushnil", FnLuaPushnil),
        tointegerx: get_fn!("lua_tointegerx", FnLuaTointegerx),
        tonumberx: get_fn!("lua_tonumberx", FnLuaTonumberx),
        tostring: get_fn!("lua_tolstring", FnLuaTostring),
        toboolean: get_fn!("lua_toboolean", FnLuaToboolean),
        gettop: get_fn!("lua_gettop", FnLuaGetbottom),
        createtable: get_fn!("lua_createtable", FnLuaCreatetable),
        rawseti: get_fn!("lua_rawseti", FnLuaRawseti),
    };

    LUA_LIB = Some(lib);
    Ok(())
}

unsafe fn register_ce_functions(L: LuaState, lib: &LuaLib) {
    macro_rules! reg_fn {
        ($name:expr, $f:expr) => {
            (lib.pushcclosure)(L, $f, 0);
            (lib.setglobal)(L, concat!($name, "\0").as_ptr() as *const c_char);
        };
    }

    reg_fn!("getCEVersion", ce_lua_getCEVersion);
    reg_fn!("readInteger", ce_lua_readInteger);
    reg_fn!("readQword", ce_lua_readQword);
    reg_fn!("readFloat", ce_lua_readFloat);
    reg_fn!("readDouble", ce_lua_readDouble);
    reg_fn!("readString", ce_lua_readString);
    reg_fn!("writeInteger", ce_lua_writeInteger);
    reg_fn!("writeQword", ce_lua_writeQword);
    reg_fn!("writeFloat", ce_lua_writeFloat);
    reg_fn!("writeDouble", ce_lua_writeDouble);
    reg_fn!("fullAccess", ce_lua_fullAccess);
    reg_fn!("allocateMemory", ce_lua_allocateMemory);
    reg_fn!("freeMemory", ce_lua_freeMemory);
    reg_fn!("autoAssemble", ce_lua_autoAssemble);
    reg_fn!("getProcessIDFromProcessName", ce_lua_getProcessIDFromProcessName);
    reg_fn!("openProcess", ce_lua_openProcess);
}

// Lua C Functions
unsafe extern "C" fn ce_lua_getCEVersion(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        (lib.pushnumber)(L, 7.5);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_readInteger(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let addr = (lib.tointegerx)(L, 1, null_mut()) as usize;
        let mut val: i32 = 0;
        let mut read: SIZE_T = 0;

        let h_proc = ACTIVE_PROCESS_HANDLE.lock().unwrap().unwrap_or(0);
        if h_proc != 0 {
            if ReadProcessMemory(h_proc as HANDLE, addr as LPCVOID, &mut val as *mut _ as LPVOID, 4, &mut read) != 0 && read == 4 {
                (lib.pushinteger)(L, val as i64);
                return 1;
            }
        }
        (lib.pushnil)(L);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_readQword(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let addr = (lib.tointegerx)(L, 1, null_mut()) as usize;
        let mut val: u64 = 0;
        let mut read: SIZE_T = 0;

        let h_proc = ACTIVE_PROCESS_HANDLE.lock().unwrap().unwrap_or(0);
        if h_proc != 0 {
            if ReadProcessMemory(h_proc as HANDLE, addr as LPCVOID, &mut val as *mut _ as LPVOID, 8, &mut read) != 0 && read == 8 {
                (lib.pushinteger)(L, val as i64);
                return 1;
            }
        }
        (lib.pushnil)(L);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_readFloat(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let addr = (lib.tointegerx)(L, 1, null_mut()) as usize;
        let mut val: f32 = 0.0;
        let mut read: SIZE_T = 0;

        let h_proc = ACTIVE_PROCESS_HANDLE.lock().unwrap().unwrap_or(0);
        if h_proc != 0 {
            if ReadProcessMemory(h_proc as HANDLE, addr as LPCVOID, &mut val as *mut _ as LPVOID, 4, &mut read) != 0 && read == 4 {
                (lib.pushnumber)(L, val as f64);
                return 1;
            }
        }
        (lib.pushnil)(L);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_readDouble(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let addr = (lib.tointegerx)(L, 1, null_mut()) as usize;
        let mut val: f64 = 0.0;
        let mut read: SIZE_T = 0;

        let h_proc = ACTIVE_PROCESS_HANDLE.lock().unwrap().unwrap_or(0);
        if h_proc != 0 {
            if ReadProcessMemory(h_proc as HANDLE, addr as LPCVOID, &mut val as *mut _ as LPVOID, 8, &mut read) != 0 && read == 8 {
                (lib.pushnumber)(L, val);
                return 1;
            }
        }
        (lib.pushnil)(L);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_readString(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let addr = (lib.tointegerx)(L, 1, null_mut()) as usize;
        let max_len = (lib.tointegerx)(L, 2, null_mut()) as usize;
        let len = if max_len == 0 { 256 } else { max_len.min(4096) };

        let mut buf = vec![0u8; len];
        let mut read: SIZE_T = 0;

        let h_proc = ACTIVE_PROCESS_HANDLE.lock().unwrap().unwrap_or(0);
        if h_proc != 0 {
            if ReadProcessMemory(h_proc as HANDLE, addr as LPCVOID, buf.as_mut_ptr() as LPVOID, len, &mut read) != 0 && read > 0 {
                let term = buf[..read].iter().position(|&b| b == 0).unwrap_or(read);
                let c_str = CString::new(&buf[..term]).unwrap_or_default();
                (lib.pushstring)(L, c_str.as_ptr());
                return 1;
            }
        }
        (lib.pushnil)(L);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_writeInteger(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let addr = (lib.tointegerx)(L, 1, null_mut()) as usize;
        let val = (lib.tointegerx)(L, 2, null_mut()) as i32;
        let mut written: SIZE_T = 0;

        let h_proc = ACTIVE_PROCESS_HANDLE.lock().unwrap().unwrap_or(0);
        if h_proc != 0 {
            let ok = WriteProcessMemory(h_proc as HANDLE, addr as LPVOID, &val as *const _ as LPCVOID, 4, &mut written);
            (lib.pushboolean)(L, if ok != 0 && written == 4 { 1 } else { 0 });
            return 1;
        }
        (lib.pushboolean)(L, 0);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_writeQword(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let addr = (lib.tointegerx)(L, 1, null_mut()) as usize;
        let val = (lib.tointegerx)(L, 2, null_mut()) as u64;
        let mut written: SIZE_T = 0;

        let h_proc = ACTIVE_PROCESS_HANDLE.lock().unwrap().unwrap_or(0);
        if h_proc != 0 {
            let ok = WriteProcessMemory(h_proc as HANDLE, addr as LPVOID, &val as *const _ as LPCVOID, 8, &mut written);
            (lib.pushboolean)(L, if ok != 0 && written == 8 { 1 } else { 0 });
            return 1;
        }
        (lib.pushboolean)(L, 0);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_writeFloat(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let addr = (lib.tointegerx)(L, 1, null_mut()) as usize;
        let val = (lib.tonumberx)(L, 2, null_mut()) as f32;
        let mut written: SIZE_T = 0;

        let h_proc = ACTIVE_PROCESS_HANDLE.lock().unwrap().unwrap_or(0);
        if h_proc != 0 {
            let ok = WriteProcessMemory(h_proc as HANDLE, addr as LPVOID, &val as *const _ as LPCVOID, 4, &mut written);
            (lib.pushboolean)(L, if ok != 0 && written == 4 { 1 } else { 0 });
            return 1;
        }
        (lib.pushboolean)(L, 0);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_writeDouble(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let addr = (lib.tointegerx)(L, 1, null_mut()) as usize;
        let val = (lib.tonumberx)(L, 2, null_mut());
        let mut written: SIZE_T = 0;

        let h_proc = ACTIVE_PROCESS_HANDLE.lock().unwrap().unwrap_or(0);
        if h_proc != 0 {
            let ok = WriteProcessMemory(h_proc as HANDLE, addr as LPVOID, &val as *const _ as LPCVOID, 8, &mut written);
            (lib.pushboolean)(L, if ok != 0 && written == 8 { 1 } else { 0 });
            return 1;
        }
        (lib.pushboolean)(L, 0);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_fullAccess(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let addr = (lib.tointegerx)(L, 1, null_mut()) as usize;
        let size = (lib.tointegerx)(L, 2, null_mut()) as usize;
        let mut old_protect: DWORD = 0;

        let h_proc = ACTIVE_PROCESS_HANDLE.lock().unwrap().unwrap_or(0);
        if h_proc != 0 {
            let ok = VirtualProtectEx(h_proc as HANDLE, addr as LPVOID, size, PAGE_EXECUTE_READWRITE, &mut old_protect);
            (lib.pushboolean)(L, if ok != 0 { 1 } else { 0 });
            return 1;
        }
        (lib.pushboolean)(L, 0);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_allocateMemory(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let size = (lib.tointegerx)(L, 1, null_mut()) as usize;
        let h_proc = ACTIVE_PROCESS_HANDLE.lock().unwrap().unwrap_or(0);
        if h_proc != 0 {
            let addr = VirtualAllocEx(h_proc as HANDLE, null_mut(), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if !addr.is_null() {
                (lib.pushinteger)(L, addr as i64);
                return 1;
            }
        }
        (lib.pushnil)(L);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_freeMemory(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let addr = (lib.tointegerx)(L, 1, null_mut()) as usize;
        let h_proc = ACTIVE_PROCESS_HANDLE.lock().unwrap().unwrap_or(0);
        if h_proc != 0 {
            let ok = VirtualFreeEx(h_proc as HANDLE, addr as LPVOID, 0, MEM_RELEASE);
            (lib.pushboolean)(L, if ok != 0 { 1 } else { 0 });
            return 1;
        }
        (lib.pushboolean)(L, 0);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_autoAssemble(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let script_ptr = (lib.tostring)(L, 1, null_mut());
        if !script_ptr.is_null() {
            let script_str = CStr::from_ptr(script_ptr).to_string_lossy().to_string();
            let pid = ACTIVE_PROCESS_PID.lock().unwrap().unwrap_or(0);
            if pid != 0 {
                if let Ok(proc) = Process::attach(pid) {
                    let mut aa = crate::autoassembler::AutoAssembler::new();
                    match aa.execute(&proc, &script_str, true) {
                        Ok(_) => {
                            (lib.pushboolean)(L, 1);
                            return 1;
                        }
                        Err(e) => {
                            let err_c = CString::new(e).unwrap_or_default();
                            (lib.pushboolean)(L, 0);
                            (lib.pushstring)(L, err_c.as_ptr());
                            return 2;
                        }
                    }
                }
            }
        }
        (lib.pushboolean)(L, 0);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_getProcessIDFromProcessName(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let name_ptr = (lib.tostring)(L, 1, null_mut());
        if !name_ptr.is_null() {
            let name = CStr::from_ptr(name_ptr).to_string_lossy().to_string();
            if let Ok(procs) = Process::list_all() {
                for pe in procs {
                    if pe.name.eq_ignore_ascii_case(&name) {
                        (lib.pushinteger)(L, pe.pid as i64);
                        return 1;
                    }
                }
            }
        }
        (lib.pushnil)(L);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_openProcess(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let pid = (lib.tointegerx)(L, 1, null_mut()) as u32;
        if pid != 0 {
            if let Ok(proc) = Process::attach(pid) {
                *ACTIVE_PROCESS_HANDLE.lock().unwrap() = Some(proc.handle as usize);
                *ACTIVE_PROCESS_PID.lock().unwrap() = Some(pid);
                (lib.pushboolean)(L, 1);
                return 1;
            }
        }
        (lib.pushboolean)(L, 0);
        1
    } else {
        0
    }
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(lpLibFileName: LPCWSTR) -> HMODULE;
    fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> *mut c_void;
}
