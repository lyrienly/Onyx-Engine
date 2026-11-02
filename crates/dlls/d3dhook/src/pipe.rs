use crate::exports::{COMMAND_BUFFER, COMMAND_COUNT, MAX_COMMANDS, RenderCommand};
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

pub static PIPE_THREAD_RUNNING: AtomicBool = AtomicBool::new(false);
pub static PIPE_HANDLE: AtomicIsize = AtomicIsize::new(-1);

type HANDLE = *mut c_void;
type BOOL = i32;
type DWORD = u32;

const PIPE_ACCESS_INBOUND: DWORD = 0x00000001;
const PIPE_TYPE_BYTE: DWORD = 0x00000000;
const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

unsafe extern "system" {
    fn CreateThread(
        attrs: *mut c_void,
        stack: usize,
        start: unsafe extern "system" fn(*mut c_void) -> DWORD,
        param: *mut c_void,
        flags: DWORD,
        tid: *mut DWORD,
    ) -> HANDLE;
    fn GetCurrentProcessId() -> DWORD;
    fn CreateNamedPipeA(
        name: *const u8,
        open_mode: DWORD,
        pipe_mode: DWORD,
        max_instances: DWORD,
        out_buf: DWORD,
        in_buf: DWORD,
        timeout: DWORD,
        sec: *mut c_void,
    ) -> HANDLE;
    fn ConnectNamedPipe(h: HANDLE, overlapped: *mut c_void) -> BOOL;
    fn DisconnectNamedPipe(h: HANDLE) -> BOOL;
    fn ReadFile(
        h: HANDLE,
        buf: *mut c_void,
        n: DWORD,
        read: *mut DWORD,
        overlapped: *mut c_void,
    ) -> BOOL;
    fn CloseHandle(h: HANDLE) -> BOOL;
}

pub unsafe fn spawn_pipe_server() {
    PIPE_THREAD_RUNNING.store(true, Ordering::SeqCst);
    CreateThread(null_mut(), 0, pipe_worker, null_mut(), 0, null_mut());
}

pub unsafe fn stop_pipe_server() {
    PIPE_THREAD_RUNNING.store(false, Ordering::SeqCst);
    let h = PIPE_HANDLE.swap(-1, Ordering::SeqCst);
    if h != -1 {
        CloseHandle(h as HANDLE);
    }
}

unsafe extern "system" fn pipe_worker(_: *mut c_void) -> DWORD {
    let pid = GetCurrentProcessId();
    let name = format!("\\\\.\\pipe\\onyx_d3dhook_{}\0", pid);

    while PIPE_THREAD_RUNNING.load(Ordering::SeqCst) {
        let pipe = CreateNamedPipeA(
            name.as_ptr(),
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE,
            1,
            4096,
            4096,
            0,
            null_mut(),
        );
        if pipe == INVALID_HANDLE_VALUE {
            break;
        }
        PIPE_HANDLE.store(pipe as isize, Ordering::SeqCst);

        if ConnectNamedPipe(pipe, null_mut()) != 0 {
            let mut buf = [0u8; size_of::<RenderCommand>()];
            let mut read: DWORD = 0;
            while ReadFile(
                pipe,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as DWORD,
                &mut read,
                null_mut(),
            ) != 0
            {
                if read as usize == size_of::<RenderCommand>() {
                    let cmd = std::ptr::read_unaligned(buf.as_ptr() as *const RenderCommand);
                    let idx = COMMAND_COUNT.load(Ordering::Relaxed) as usize;
                    if idx < MAX_COMMANDS {
                        COMMAND_BUFFER[idx] = cmd;
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
