#![allow(non_snake_case, non_camel_case_types, dead_code, unsafe_op_in_unsafe_fn, static_mut_refs)]

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use crate::process::Process;
use crate::win32::*;

type LuaState = *mut c_void;
type LuaCFunction = unsafe extern "C" fn(LuaState) -> c_int;

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
type FnLuaSetfield = unsafe extern "C" fn(LuaState, c_int, *const c_char);
type FnLuaGetfield = unsafe extern "C" fn(LuaState, c_int, *const c_char) -> c_int;
type FnLuaSetmetatable = unsafe extern "C" fn(LuaState, c_int) -> c_int;
type FnLuaPushvalue = unsafe extern "C" fn(LuaState, c_int);

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
    setfield: FnLuaSetfield,
    getfield: FnLuaGetfield,
    setmetatable: FnLuaSetmetatable,
    pushvalue: FnLuaPushvalue,
}

static mut LUA_LIB: Option<LuaLib> = None;
static ACTIVE_PROCESS_HANDLE: Mutex<Option<usize>> = Mutex::new(None);
static ACTIVE_PROCESS_PID: Mutex<Option<u32>> = Mutex::new(None);
static SCANNER_REGISTRY: Mutex<Option<HashMap<i64, crate::scanner::Scanner>>> = Mutex::new(None);
static NEXT_SCANNER_ID: AtomicI64 = AtomicI64::new(1);

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

            {
                let mut reg = SCANNER_REGISTRY.lock().unwrap();
                if reg.is_none() {
                    *reg = Some(HashMap::new());
                }
            }

            register_ce_functions(L, lib);

            let json_bootstrap = CString::new(r#"
json = {}
local function encode_val(val)
    local t = type(val)
    if t == "nil" then return "null"
    elseif t == "boolean" or t == "number" then return tostring(val)
    elseif t == "string" then
        return string.format("%q", val):gsub("\n", "\\n"):gsub("\r", "\\r")
    elseif t == "table" then
        local is_array = true
        local n = #val
        for k, _ in pairs(val) do
            if type(k) ~= "number" or k < 1 or k > n or math.floor(k) ~= k then
                is_array = false
                break
            end
        end
        if is_array then
            local p = {}
            for i = 1, n do p[i] = encode_val(val[i]) end
            return "[" .. table.concat(p, ",") .. "]"
        else
            local p = {}
            for k, v in pairs(val) do
                table.insert(p, string.format("%q", tostring(k)) .. ":" .. encode_val(v))
            end
            return "{" .. table.concat(p, ",") .. "}"
        end
    else
        return '"' .. tostring(val) .. '"'
    end
end
json.encode = encode_val

local function decode_json(s)
    local pos = 1
    local len = #s
    local function skip()
        while pos <= len do
            local c = s:sub(pos, pos)
            if c == ' ' or c == '\t' or c == '\n' or c == '\r' then pos = pos + 1 else break end
        end
    end
    local function parse_val()
        skip()
        if pos > len then return nil end
        local c = s:sub(pos, pos)
        if c == '{' then
            pos = pos + 1
            local obj = {}
            skip()
            if s:sub(pos, pos) == '}' then pos = pos + 1; return obj end
            while pos <= len do
                skip()
                local k = parse_val()
                skip()
                if s:sub(pos, pos) == ':' then pos = pos + 1 end
                local v = parse_val()
                obj[k] = v
                skip()
                local nc = s:sub(pos, pos)
                if nc == ',' then pos = pos + 1
                elseif nc == '}' then pos = pos + 1; break
                else break end
            end
            return obj
        elseif c == '[' then
            pos = pos + 1
            local arr = {}
            skip()
            if s:sub(pos, pos) == ']' then pos = pos + 1; return arr end
            while pos <= len do
                local v = parse_val()
                table.insert(arr, v)
                skip()
                local nc = s:sub(pos, pos)
                if nc == ',' then pos = pos + 1
                elseif nc == ']' then pos = pos + 1; break
                else break end
            end
            return arr
        elseif c == '"' then
            local ep = pos + 1
            while ep <= len do
                if s:sub(ep, ep) == '"' and s:sub(ep - 1, ep - 1) ~= '\\' then break end
                ep = ep + 1
            end
            local str = s:sub(pos + 1, ep - 1):gsub('\\"', '"'):gsub('\\\\', '\\')
            pos = ep + 1
            return str
        elseif s:sub(pos, pos + 3) == "true" then pos = pos + 4; return true
        elseif s:sub(pos, pos + 4) == "false" then pos = pos + 5; return false
        elseif s:sub(pos, pos + 3) == "null" then pos = pos + 4; return nil
        else
            local num = s:match('^[%-%d%.eE%+]+', pos)
            if num then pos = pos + #num; return tonumber(num) end
            pos = pos + 1
            return nil
        end
    end
    return parse_val()
end
json.decode = decode_json
package.loaded["json"] = json
"#).unwrap();
            let load_res = (lib.loadstring)(L, json_bootstrap.as_ptr());
            if load_res == 0 {
                (lib.pcallk)(L, 0, 0, 0, 0, null_mut());
            }

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
        "../lua53-64.dll",
        "../../lua53-64.dll",
        "crates/gui/lua53-64.dll",
        "../crates/gui/lua53-64.dll",
        "../../crates/gui/lua53-64.dll",
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
        setfield: get_fn!("lua_setfield", FnLuaSetfield),
        getfield: get_fn!("lua_getfield", FnLuaGetfield),
        setmetatable: get_fn!("lua_setmetatable", FnLuaSetmetatable),
        pushvalue: get_fn!("lua_pushvalue", FnLuaPushvalue),
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

    reg_fn!("createMemScan", ce_lua_createMemScan);
    reg_fn!("stacktrace", ce_lua_stacktrace);
    reg_fn!("getThreadList", ce_lua_getThreadList);
    reg_fn!("executeCodeExThread", ce_lua_executeCodeExThread);
    reg_fn!("executeMethodThread", ce_lua_executeMethodThread);
}

unsafe extern "C" fn ce_lua_getCEVersion(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        (lib.pushnumber)(L, 7.7);
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
        if h_proc != 0
            && ReadProcessMemory(h_proc as HANDLE, addr as LPCVOID, &mut val as *mut _ as LPVOID, 4, &mut read) != 0 && read == 4 {
                (lib.pushinteger)(L, val as i64);
                return 1;
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
        if h_proc != 0
            && ReadProcessMemory(h_proc as HANDLE, addr as LPCVOID, &mut val as *mut _ as LPVOID, 8, &mut read) != 0 && read == 8 {
                (lib.pushinteger)(L, val as i64);
                return 1;
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
        if h_proc != 0
            && ReadProcessMemory(h_proc as HANDLE, addr as LPCVOID, &mut val as *mut _ as LPVOID, 4, &mut read) != 0 && read == 4 {
                (lib.pushnumber)(L, val as f64);
                return 1;
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
        if h_proc != 0
            && ReadProcessMemory(h_proc as HANDLE, addr as LPCVOID, &mut val as *mut _ as LPVOID, 8, &mut read) != 0 && read == 8 {
                (lib.pushnumber)(L, val);
                return 1;
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
        if h_proc != 0
            && ReadProcessMemory(h_proc as HANDLE, addr as LPCVOID, buf.as_mut_ptr() as LPVOID, len, &mut read) != 0 && read > 0 {
                let term = buf[..read].iter().position(|&b| b == 0).unwrap_or(read);
                let c_str = CString::new(&buf[..term]).unwrap_or_default();
                (lib.pushstring)(L, c_str.as_ptr());
                return 1;
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
            if pid != 0
                && let Ok(proc) = Process::attach(pid) {
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
        if pid != 0
            && let Ok(proc) = Process::attach(pid) {
                *ACTIVE_PROCESS_HANDLE.lock().unwrap() = Some(proc.handle as usize);
                *ACTIVE_PROCESS_PID.lock().unwrap() = Some(pid);
                (lib.pushboolean)(L, 1);
                return 1;
            }
        (lib.pushboolean)(L, 0);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_createMemScan(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let scan_id = NEXT_SCANNER_ID.fetch_add(1, Ordering::SeqCst);
        {
            let mut reg = SCANNER_REGISTRY.lock().unwrap();
            if let Some(map) = reg.as_mut() {
                map.insert(scan_id, crate::scanner::Scanner::new(crate::scanner::ValType::I32));
            }
        }

        (lib.createtable)(L, 0, 8);

        (lib.pushinteger)(L, scan_id);
        (lib.setfield)(L, -2, b"_id\0".as_ptr() as *const c_char);

        macro_rules! add_method {
            ($name:expr, $f:expr) => {
                (lib.pushcclosure)(L, $f, 0);
                (lib.setfield)(L, -2, concat!($name, "\0").as_ptr() as *const c_char);
            };
        }
        add_method!("firstScan", ce_lua_memscan_firstScan);
        add_method!("nextScan", ce_lua_memscan_nextScan);
        add_method!("getCount", ce_lua_memscan_getCount);
        add_method!("getOnlyOneResult", ce_lua_memscan_getOnlyOneResult);
        add_method!("getResults", ce_lua_memscan_getResults);

        (lib.createtable)(L, 0, 1);
        (lib.pushcclosure)(L, ce_lua_memscan_index, 0);
        (lib.setfield)(L, -2, b"__index\0".as_ptr() as *const c_char);
        (lib.setmetatable)(L, -2);

        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_memscan_getResults(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        (lib.getfield)(L, 1, b"_id\0".as_ptr() as *const c_char);
        let id = (lib.tointegerx)(L, -1, null_mut());

        let addrs: Vec<usize> = {
            let reg = SCANNER_REGISTRY.lock().unwrap();
            if let Some(map) = reg.as_ref() {
                if let Some(scanner) = map.get(&id) {
                    scanner.candidates.iter().map(|c| c.address).collect()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        };

        (lib.createtable)(L, addrs.len() as c_int, 0);
        for (i, addr) in addrs.iter().enumerate() {
            (lib.pushinteger)(L, *addr as i64);
            (lib.rawseti)(L, -2, (i + 1) as i64);
        }
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_memscan_getCount(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        (lib.getfield)(L, 1, b"_id\0".as_ptr() as *const c_char);
        let id = (lib.tointegerx)(L, -1, null_mut());

        let count = {
            let reg = SCANNER_REGISTRY.lock().unwrap();
            if let Some(map) = reg.as_ref() {
                map.get(&id).map(|s| s.candidates.len()).unwrap_or(0)
            } else {
                0
            }
        };

        (lib.pushinteger)(L, count as i64);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_memscan_getOnlyOneResult(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        (lib.getfield)(L, 1, b"_id\0".as_ptr() as *const c_char);
        let id = (lib.tointegerx)(L, -1, null_mut());

        let res = {
            let reg = SCANNER_REGISTRY.lock().unwrap();
            if let Some(map) = reg.as_ref() {
                if let Some(s) = map.get(&id) {
                    if s.candidates.len() == 1 {
                        Some(s.candidates[0].address)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(addr) = res {
            (lib.pushinteger)(L, addr as i64);
        } else {
            (lib.pushnil)(L);
        }
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_memscan_firstScan(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        (lib.getfield)(L, 1, b"_id\0".as_ptr() as *const c_char);
        let id = (lib.tointegerx)(L, -1, null_mut());

        let val_ptr = (lib.tostring)(L, 5, null_mut());
        let val_str = if !val_ptr.is_null() {
            CStr::from_ptr(val_ptr).to_string_lossy().to_string()
        } else {
            let v2 = (lib.tostring)(L, 2, null_mut());
            if !v2.is_null() {
                CStr::from_ptr(v2).to_string_lossy().to_string()
            } else {
                "".to_string()
            }
        };

        let pid = ACTIVE_PROCESS_PID.lock().unwrap().unwrap_or(0);
        if pid != 0
            && let Ok(proc) = Process::attach(pid) {
                let mut reg = SCANNER_REGISTRY.lock().unwrap();
                if let Some(map) = reg.as_mut()
                    && let Some(scanner) = map.get_mut(&id)
                        && let Ok(scan_val) = crate::scanner::ScanValue::parse(scanner.val_type, &val_str) {
                            let res = scanner.first_scan(&proc, crate::scanner::ScanCondition::Exact(scan_val));
                            (lib.pushboolean)(L, if res.is_ok() { 1 } else { 0 });
                            return 1;
                        }
            }
        (lib.pushboolean)(L, 0);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_memscan_nextScan(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        (lib.getfield)(L, 1, b"_id\0".as_ptr() as *const c_char);
        let id = (lib.tointegerx)(L, -1, null_mut());

        let val_ptr = (lib.tostring)(L, 4, null_mut());
        let val_str = if !val_ptr.is_null() {
            CStr::from_ptr(val_ptr).to_string_lossy().to_string()
        } else {
            let v2 = (lib.tostring)(L, 2, null_mut());
            if !v2.is_null() {
                CStr::from_ptr(v2).to_string_lossy().to_string()
            } else {
                "".to_string()
            }
        };

        let pid = ACTIVE_PROCESS_PID.lock().unwrap().unwrap_or(0);
        if pid != 0
            && let Ok(proc) = Process::attach(pid) {
                let mut reg = SCANNER_REGISTRY.lock().unwrap();
                if let Some(map) = reg.as_mut()
                    && let Some(scanner) = map.get_mut(&id)
                        && let Ok(scan_val) = crate::scanner::ScanValue::parse(scanner.val_type, &val_str) {
                            let res = scanner.next_scan(&proc, crate::scanner::ScanCondition::Exact(scan_val));
                            (lib.pushboolean)(L, if res.is_ok() { 1 } else { 0 });
                            return 1;
                        }
            }
        (lib.pushboolean)(L, 0);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_memscan_index(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let key_ptr = (lib.tostring)(L, 2, null_mut());
        if !key_ptr.is_null() {
            let key = CStr::from_ptr(key_ptr).to_string_lossy();
            if key == "Results" {

                return ce_lua_memscan_getResults(L);
            } else if key == "Count" {
                return ce_lua_memscan_getCount(L);
            }
        }
        (lib.getfield)(L, 1, key_ptr);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_stacktrace(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let mut tid = (lib.tointegerx)(L, 1, null_mut()) as u32;
        let h_proc = ACTIVE_PROCESS_HANDLE.lock().unwrap().unwrap_or(0);
        let pid = ACTIVE_PROCESS_PID.lock().unwrap().unwrap_or(0);

        if tid == 0 && pid != 0 {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap != INVALID_HANDLE_VALUE {
                let mut te: THREADENTRY32 = std::mem::zeroed();
                te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32First(snap, &mut te) == TRUE {
                    loop {
                        if te.th32OwnerProcessID == pid {
                            tid = te.th32ThreadID;
                            break;
                        }
                        if Thread32Next(snap, &mut te) != TRUE {
                            break;
                        }
                    }
                }
                CloseHandle(snap);
            }
        }

        (lib.createtable)(L, 0, 0);
        if tid == 0 || h_proc == 0 {
            return 1;
        }

        let h_thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
        if !h_thread.is_null() && h_thread != INVALID_HANDLE_VALUE {
            SuspendThread(h_thread);

            let mut ctx: CONTEXT = std::mem::zeroed();
            ctx.ContextFlags = CONTEXT_ALL;
            if GetThreadContext(h_thread, &mut ctx) == TRUE {
                let mut idx = 1i64;

                (lib.pushinteger)(L, ctx.Rip as i64);
                (lib.rawseti)(L, -2, idx);
                idx += 1;

                let rsp = ctx.Rsp as usize;
                let mut stack_buf = [0usize; 128];
                let mut read: SIZE_T = 0;
                if ReadProcessMemory(h_proc as HANDLE, rsp as LPCVOID, stack_buf.as_mut_ptr() as LPVOID, 128 * 8, &mut read) != 0 {
                    let count = read / 8;
                    for i in 0..count {
                        let potential_ret = stack_buf[i];
                        if potential_ret > 0x10000 && potential_ret < 0x7FFFFFFF_FFFFFFFF {
                            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                            if VirtualQueryEx(h_proc as HANDLE, potential_ret as LPCVOID, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0
                                && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0 {
                                    (lib.pushinteger)(L, potential_ret as i64);
                                    (lib.rawseti)(L, -2, idx);
                                    idx += 1;
                                    if idx > 32 {
                                        break;
                                    }
                                }
                        }
                    }
                }
            }

            ResumeThread(h_thread);
            CloseHandle(h_thread);
        }

        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_getThreadList(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let mut target_pid = (lib.tointegerx)(L, 1, null_mut()) as u32;
        if target_pid == 0 {
            target_pid = ACTIVE_PROCESS_PID.lock().unwrap().unwrap_or(0);
        }

        (lib.createtable)(L, 0, 0);
        if target_pid == 0 {
            return 1;
        }

        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap != INVALID_HANDLE_VALUE {
            let mut te: THREADENTRY32 = std::mem::zeroed();
            te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            let mut idx = 1i64;
            if Thread32First(snap, &mut te) == TRUE {
                loop {
                    if te.th32OwnerProcessID == target_pid {
                        (lib.pushinteger)(L, te.th32ThreadID as i64);
                        (lib.rawseti)(L, -2, idx);
                        idx += 1;
                    }
                    if Thread32Next(snap, &mut te) != TRUE {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_executeCodeExThread(L: LuaState) -> c_int {
    if let Some(lib) = LUA_LIB.as_ref() {
        let tid = (lib.tointegerx)(L, 1, null_mut()) as u32;
        let code_addr = (lib.tointegerx)(L, 2, null_mut()) as usize;
        let param = (lib.tointegerx)(L, 3, null_mut()) as usize;

        let pid = ACTIVE_PROCESS_PID.lock().unwrap().unwrap_or(0);
        if pid != 0 && code_addr != 0
            && let Ok(proc) = Process::attach(pid) {
                let h_thread = if tid != 0 {
                    OpenThread(THREAD_ALL_ACCESS, FALSE, tid)
                } else {
                    null_mut()
                };

                let thread_start = std::mem::transmute::<LPVOID, unsafe extern "system" fn(LPVOID) -> DWORD>(code_addr as LPVOID);
                let h_remote = CreateRemoteThread(
                    proc.handle,
                    null_mut(),
                    0,
                    thread_start,
                    param as LPVOID,
                    0,
                    null_mut(),
                );

                if !h_thread.is_null() && h_thread != INVALID_HANDLE_VALUE {
                    CloseHandle(h_thread);
                }

                if !h_remote.is_null() && h_remote != INVALID_HANDLE_VALUE {
                    WaitForSingleObject(h_remote, 5000);
                    let mut exit_code: DWORD = 0;
                    GetExitCodeThread(h_remote, &mut exit_code);
                    CloseHandle(h_remote);
                    (lib.pushinteger)(L, exit_code as i64);
                    return 1;
                }
            }
        (lib.pushnil)(L);
        1
    } else {
        0
    }
}

unsafe extern "C" fn ce_lua_executeMethodThread(L: LuaState) -> c_int {
    ce_lua_executeCodeExThread(L)
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(lpLibFileName: LPCWSTR) -> HMODULE;
    fn GetProcAddress(hModule: HMODULE, lpProcName: *const u8) -> *mut c_void;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ce_lua_engine_77() {
        if let Ok(lua) = CeLuaEngine::init() {

            let ver = lua.execute("return getCEVersion()").unwrap();
            assert_eq!(ver, "7.7");

            let json_enc = lua.execute(r#"return json.encode({name="CheatEngine", version=7.7})"#).unwrap();
            assert!(json_enc.contains("\"name\":\"CheatEngine\""));
            assert!(json_enc.contains("\"version\":7.7"));

            let json_dec = lua.execute(r#"
                local obj = json.decode('{"val":1337,"flag":true}')
                return obj.val
            "#).unwrap();
            assert_eq!(json_dec, "1337");

            let ms_test = lua.execute(r#"
                local ms = createMemScan()
                if ms and type(ms.Results) == "table" and ms.Count == 0 then
                    return "OK"
                else
                    return "FAIL"
                end
            "#).unwrap();
            assert_eq!(ms_test, "OK");
        }
    }
}
