
#![allow(non_snake_case, non_camel_case_types, dead_code, unsafe_op_in_unsafe_fn, static_mut_refs)]

use std::ffi::{c_char, c_void, CStr};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Mutex;
use std::ptr::null_mut;

type HANDLE = *mut c_void;
type BOOL = i32;
type DWORD = u32;

unsafe extern "system" {
    fn CreateFileA(
        lpFileName: *const u8,
        dwDesiredAccess: DWORD,
        dwShareMode: DWORD,
        lpSecurityAttributes: *mut c_void,
        dwCreationDisposition: DWORD,
        dwFlagsAndAttributes: DWORD,
        hTemplateFile: HANDLE,
    ) -> HANDLE;
    fn ReadFile(
        hFile: HANDLE,
        lpBuffer: *mut c_void,
        nNumberOfBytesToRead: DWORD,
        lpNumberOfBytesRead: *mut DWORD,
        lpOverlapped: *mut c_void,
    ) -> BOOL;
    fn WriteFile(
        hFile: HANDLE,
        lpBuffer: *const c_void,
        nNumberOfBytesToWrite: DWORD,
        lpNumberOfBytesWritten: *mut DWORD,
        lpOverlapped: *mut c_void,
    ) -> BOOL;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
    fn GetCurrentProcessId() -> DWORD;
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LuaParamType {
    Nil = 0,
    Boolean = 1,
    Int64 = 2,
    Int32 = 3,
    Number = 4,
    String = 5,
    Table = 6,
    Unknown = 255,
}

static PIPE_HANDLE: AtomicIsize = AtomicIsize::new(-1);
static PIPE_LOCK: Mutex<()> = Mutex::new(());
static mut SERVER_NAME: [u8; 260] = [0u8; 260];

unsafe fn write_exact(h: HANDLE, data: &[u8]) -> bool {
    let mut written: DWORD = 0;
    let res = WriteFile(h, data.as_ptr() as *const c_void, data.len() as DWORD, &mut written, null_mut());
    res != 0 && (written as usize == data.len())
}

unsafe fn read_exact(h: HANDLE, buf: &mut [u8]) -> bool {
    let mut read_bytes: DWORD = 0;
    let res = ReadFile(h, buf.as_mut_ptr() as *mut c_void, buf.len() as DWORD, &mut read_bytes, null_mut());
    res != 0 && (read_bytes as usize == buf.len())
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CELUA_Initialize(pipename: *const c_char) -> BOOL {
    let _guard = PIPE_LOCK.lock().unwrap();

    let pipe_str = if !pipename.is_null() {
        CStr::from_ptr(pipename).to_str().unwrap_or("ce_luaserver")
    } else {
        "ce_luaserver"
    };

    let full_path = if pipe_str.starts_with("\\\\.\\pipe\\") {
        format!("{}\0", pipe_str)
    } else {
        format!("\\\\.\\pipe\\{}\0", pipe_str)
    };

    let bytes = full_path.as_bytes();
    let len = bytes.len().min(SERVER_NAME.len() - 1);
    SERVER_NAME[..len].copy_from_slice(&bytes[..len]);
    SERVER_NAME[len] = 0;

    let old_h = PIPE_HANDLE.swap(-1, Ordering::SeqCst);
    if old_h != -1 {
        CloseHandle(old_h as HANDLE);
    }

    let h = CreateFileA(
        full_path.as_ptr(),
        0xC0000000,
        0,
        null_mut(),
        3,
        0,
        null_mut(),
    );

    if h == -1isize as HANDLE {
        return 0;
    }

    PIPE_HANDLE.store(h as isize, Ordering::SeqCst);
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CELUA_ExecuteFunction(script: *const c_char, _params: usize) -> usize {
    if script.is_null() {
        return 0;
    }
    let _guard = PIPE_LOCK.lock().unwrap();
    let h_val = PIPE_HANDLE.load(Ordering::SeqCst);
    if h_val == -1 {
        return 0;
    }
    let h = h_val as HANDLE;

    let c_str = CStr::from_ptr(script);
    let bytes = c_str.to_bytes();
    let len = bytes.len() as u32;

    let cmd: [u8; 1] = [1];
    if !write_exact(h, &cmd) { return 0; }
    if !write_exact(h, &len.to_le_bytes()) { return 0; }
    if !write_exact(h, bytes) { return 0; }

    let mut resp = [0u8; 9];
    if !read_exact(h, &mut resp) {
        return 0;
    }

    u64::from_le_bytes(resp[1..9].try_into().unwrap()) as usize
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CELUA_ExecuteFunctionAsync(script: *const c_char, _params: usize) -> usize {
    if script.is_null() {
        return 0;
    }
    let _guard = PIPE_LOCK.lock().unwrap();
    let h_val = PIPE_HANDLE.load(Ordering::SeqCst);
    if h_val == -1 {
        return 0;
    }
    let h = h_val as HANDLE;

    let c_str = CStr::from_ptr(script);
    let bytes = c_str.to_bytes();
    let len = bytes.len() as u32;

    let cmd: [u8; 1] = [2];
    if !write_exact(h, &cmd) { return 0; }
    if !write_exact(h, &len.to_le_bytes()) { return 0; }
    if !write_exact(h, bytes) { return 0; }

    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CELUA_GetFunctionReferenceFromName(functionname: *const c_char) -> i32 {
    if functionname.is_null() {
        return -1;
    }
    let _guard = PIPE_LOCK.lock().unwrap();
    let h_val = PIPE_HANDLE.load(Ordering::SeqCst);
    if h_val == -1 {
        return -1;
    }
    let h = h_val as HANDLE;

    let c_str = CStr::from_ptr(functionname);
    let bytes = c_str.to_bytes();
    let len = bytes.len() as u32;

    let cmd: [u8; 1] = [4];
    if !write_exact(h, &cmd) { return -1; }
    if !write_exact(h, &len.to_le_bytes()) { return -1; }
    if !write_exact(h, bytes) { return -1; }

    let mut ref_bytes = [0u8; 4];
    if !read_exact(h, &mut ref_bytes) {
        return -1;
    }

    i32::from_le_bytes(ref_bytes)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn CELUA_ExecuteFunctionByReference(
    func_ref: i32,
    paramcount: i32,
    params: *const *const c_void,
    async_call: BOOL,
) -> usize {
    let _guard = PIPE_LOCK.lock().unwrap();
    let h_val = PIPE_HANDLE.load(Ordering::SeqCst);
    if h_val == -1 {
        return 0;
    }
    let h = h_val as HANDLE;

    let cmd: [u8; 1] = [3];
    let is_async: [u8; 1] = [if async_call != 0 { 1 } else { 0 }];

    if !write_exact(h, &cmd) { return 0; }
    if !write_exact(h, &is_async) { return 0; }
    if !write_exact(h, &func_ref.to_le_bytes()) { return 0; }
    if !write_exact(h, &(paramcount as u8).to_le_bytes()) { return 0; }

    for i in 0..paramcount {
        let p_val = *params.add(i as usize);
        let val_type: [u8; 1] = [LuaParamType::Int64 as u8];
        let val_bytes = (p_val as u64).to_le_bytes();
        if !write_exact(h, &val_type) { return 0; }
        if !write_exact(h, &val_bytes) { return 0; }
    }

    if async_call != 0 {
        return 1;
    }

    let mut ret_count = [0u8; 1];
    if !read_exact(h, &mut ret_count) {
        return 0;
    }

    if ret_count[0] > 0 {
        let mut ret_type = [0u8; 1];
        let mut ret_val = [0u8; 8];
        if !read_exact(h, &mut ret_type) { return 0; }
        if !read_exact(h, &mut ret_val) { return 0; }
        u64::from_le_bytes(ret_val) as usize
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: *mut c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> BOOL {
    if fdw_reason == 0 {
        let h_val = PIPE_HANDLE.swap(-1, Ordering::SeqCst);
        if h_val != -1 {
            CloseHandle(h_val as HANDLE);
        }
    }
    1
}

