//! Listener de pipe nomeado: a UI Pascal envia um `f32` little-endian para
//! ajustar a velocidade sem recarregar a DLL.

#![cfg(windows)]
#![allow(non_snake_case, unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::ptr::null_mut;
use std::thread;

use crate::hooks;

type BOOL = i32;
type DWORD = u32;
type HANDLE = *mut c_void;
type LPVOID = *mut c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcessId() -> DWORD;
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
    fn ReadFile(
        hFile: HANDLE,
        lpBuffer: LPVOID,
        nNumberOfBytesToRead: DWORD,
        lpNumberOfBytesRead: *mut DWORD,
        lpOverlapped: LPVOID,
    ) -> BOOL;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
}

pub fn start_listener() {
    thread::spawn(|| {
        let pid = unsafe { GetCurrentProcessId() };
        let pipe_name = format!("\\\\.\\pipe\\ce_speedhack_{}\0", pid);

        loop {
            let h = unsafe {
                CreateNamedPipeA(
                    pipe_name.as_ptr(),
                    0x00000003, // PIPE_ACCESS_DUPLEX
                    0x00000000, // PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
                    1,
                    512,
                    512,
                    0,
                    null_mut(),
                )
            };
            if h == -1isize as HANDLE {
                break;
            }

            if unsafe { ConnectNamedPipe(h, null_mut()) } != 0 {
                let mut buf = [0u8; 4];
                let mut read: DWORD = 0;
                if unsafe {
                    ReadFile(h, buf.as_mut_ptr() as LPVOID, 4, &mut read, null_mut())
                } != 0
                    && read == 4
                {
                    let speed = f32::from_le_bytes(buf) as f64;
                    if hooks::is_installed() {
                        hooks::set_speed(speed);
                    } else {
                        let _ = hooks::install(speed);
                    }
                }
            }

            unsafe {
                DisconnectNamedPipe(h);
                CloseHandle(h);
            }
        }
    });
}
