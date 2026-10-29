use std::ffi::c_void;
use std::io;
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};

use onyx_gdb_server::{GdbServer, GdbTarget, Registers, StopReason};

use crate::api::abi_util::{cstr_to_str, guard, ERR_INTERNAL, ERR_INVALID_UTF8, ERR_NULL, OK};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OnyxGdbRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
}

impl From<&Registers> for OnyxGdbRegisters {
    fn from(r: &Registers) -> Self {
        Self {
            rax: r.rax,
            rbx: r.rbx,
            rcx: r.rcx,
            rdx: r.rdx,
            rsi: r.rsi,
            rdi: r.rdi,
            rbp: r.rbp,
            rsp: r.rsp,
            r8: r.r8,
            r9: r.r9,
            r10: r.r10,
            r11: r.r11,
            r12: r.r12,
            r13: r.r13,
            r14: r.r14,
            r15: r.r15,
            rip: r.rip,
        }
    }
}

impl From<&OnyxGdbRegisters> for Registers {
    fn from(r: &OnyxGdbRegisters) -> Self {
        Self {
            rax: r.rax,
            rbx: r.rbx,
            rcx: r.rcx,
            rdx: r.rdx,
            rsi: r.rsi,
            rdi: r.rdi,
            rbp: r.rbp,
            rsp: r.rsp,
            r8: r.r8,
            r9: r.r9,
            r10: r.r10,
            r11: r.r11,
            r12: r.r12,
            r13: r.r13,
            r14: r.r14,
            r15: r.r15,
            rip: r.rip,
        }
    }
}

#[repr(C)]
pub struct OnyxGdbTargetVTable {
    pub read_registers:
        Option<unsafe extern "C" fn(user: *mut c_void, out: *mut OnyxGdbRegisters) -> i32>,
    pub write_registers:
        Option<unsafe extern "C" fn(user: *mut c_void, regs: *const OnyxGdbRegisters) -> i32>,
    pub read_memory: Option<
        unsafe extern "C" fn(user: *mut c_void, addr: u64, out_buf: *mut u8, len: usize) -> i32,
    >,
    pub write_memory: Option<
        unsafe extern "C" fn(user: *mut c_void, addr: u64, buf: *const u8, len: usize) -> i32,
    >,
    pub cont: Option<unsafe extern "C" fn(user: *mut c_void, out_reason: *mut u32) -> i32>,
    pub step: Option<unsafe extern "C" fn(user: *mut c_void, out_reason: *mut u32) -> i32>,
    pub add_sw_breakpoint:
        Option<unsafe extern "C" fn(user: *mut c_void, addr: u64, kind: u32) -> i32>,
    pub remove_sw_breakpoint:
        Option<unsafe extern "C" fn(user: *mut c_void, addr: u64, kind: u32) -> i32>,
    pub add_hw_breakpoint:
        Option<unsafe extern "C" fn(user: *mut c_void, addr: u64, kind: u32) -> i32>,
    pub remove_hw_breakpoint:
        Option<unsafe extern "C" fn(user: *mut c_void, addr: u64, kind: u32) -> i32>,
}

struct CTarget {
    vt: OnyxGdbTargetVTable,
    user: *mut c_void,
}

unsafe impl Send for CTarget {}

fn reason_from_u32(v: u32) -> StopReason {
    match v {
        2 => StopReason::Interrupt,
        3 => StopReason::Exited,
        _ => StopReason::Trap,
    }
}

impl GdbTarget for CTarget {
    fn read_registers(&self) -> io::Result<Registers> {
        let f = self
            .vt
            .read_registers
            .ok_or_else(|| io::Error::other("unimpl"))?;
        let mut out = OnyxGdbRegisters {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
        };
        let rc = unsafe { f(self.user, &mut out) };
        if rc != 0 {
            return Err(io::Error::other("read_regs"));
        }
        Ok(Registers::from(&out))
    }

    fn write_registers(&mut self, regs: &Registers) -> io::Result<()> {
        let f = self
            .vt
            .write_registers
            .ok_or_else(|| io::Error::other("unimpl"))?;
        let c = OnyxGdbRegisters::from(regs);
        let rc = unsafe { f(self.user, &c) };
        if rc != 0 {
            Err(io::Error::other("write_regs"))
        } else {
            Ok(())
        }
    }

    fn read_memory(&self, addr: u64, len: usize) -> io::Result<Vec<u8>> {
        let f = self
            .vt
            .read_memory
            .ok_or_else(|| io::Error::other("unimpl"))?;
        let mut buf = vec![0u8; len];
        let rc = unsafe { f(self.user, addr, buf.as_mut_ptr(), len) };
        if rc != 0 {
            Err(io::Error::other("read_mem"))
        } else {
            Ok(buf)
        }
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> io::Result<()> {
        let f = self
            .vt
            .write_memory
            .ok_or_else(|| io::Error::other("unimpl"))?;
        let rc = unsafe { f(self.user, addr, data.as_ptr(), data.len()) };
        if rc != 0 {
            Err(io::Error::other("write_mem"))
        } else {
            Ok(())
        }
    }

    fn cont(&mut self) -> io::Result<StopReason> {
        if let Some(f) = self.vt.cont {
            let mut r: u32 = 1;
            let rc = unsafe { f(self.user, &mut r) };
            if rc != 0 {
                return Err(io::Error::other("cont"));
            }
            return Ok(reason_from_u32(r));
        }
        Ok(StopReason::Trap)
    }

    fn step(&mut self) -> io::Result<StopReason> {
        if let Some(f) = self.vt.step {
            let mut r: u32 = 1;
            let rc = unsafe { f(self.user, &mut r) };
            if rc != 0 {
                return Err(io::Error::other("step"));
            }
            return Ok(reason_from_u32(r));
        }
        Ok(StopReason::Trap)
    }

    fn add_sw_breakpoint(&mut self, addr: u64, kind: u32) -> io::Result<()> {
        if let Some(f) = self.vt.add_sw_breakpoint {
            let rc = unsafe { f(self.user, addr, kind) };
            if rc != 0 {
                return Err(io::Error::other("add_sw"));
            }
        }
        Ok(())
    }
    fn remove_sw_breakpoint(&mut self, addr: u64, kind: u32) -> io::Result<()> {
        if let Some(f) = self.vt.remove_sw_breakpoint {
            let rc = unsafe { f(self.user, addr, kind) };
            if rc != 0 {
                return Err(io::Error::other("rm_sw"));
            }
        }
        Ok(())
    }
    fn add_hw_breakpoint(&mut self, addr: u64, kind: u32) -> io::Result<()> {
        if let Some(f) = self.vt.add_hw_breakpoint {
            let rc = unsafe { f(self.user, addr, kind) };
            if rc != 0 {
                return Err(io::Error::other("add_hw"));
            }
        }
        Ok(())
    }
    fn remove_hw_breakpoint(&mut self, addr: u64, kind: u32) -> io::Result<()> {
        if let Some(f) = self.vt.remove_hw_breakpoint {
            let rc = unsafe { f(self.user, addr, kind) };
            if rc != 0 {
                return Err(io::Error::other("rm_hw"));
            }
        }
        Ok(())
    }
}

pub struct OnyxGdbHandle {
    _server: GdbServer,
}

#[no_mangle]
pub unsafe extern "C" fn onyx_gdb_start(
    addr: *const c_char,
    vtable: *const OnyxGdbTargetVTable,
    user: *mut c_void,
    out_handle: *mut *mut c_void,
) -> i32 {
    guard(|| {
        if addr.is_null() || vtable.is_null() || out_handle.is_null() {
            return ERR_NULL;
        }
        let addr_str = match cstr_to_str(addr) {
            Some(s) => s,
            None => return ERR_INVALID_UTF8,
        };
        let vt_copy = std::ptr::read(vtable);
        let target = CTarget { vt: vt_copy, user };
        let shared = Arc::new(Mutex::new(target));
        match GdbServer::listen(addr_str, shared) {
            Ok(server) => {
                let handle = Box::new(OnyxGdbHandle { _server: server });
                *out_handle = Box::into_raw(handle) as *mut c_void;
                OK
            }
            Err(_) => ERR_INTERNAL,
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn onyx_gdb_stop(handle: *mut c_void) -> i32 {
    guard(|| {
        if handle.is_null() {
            return ERR_NULL;
        }
        drop(Box::from_raw(handle as *mut OnyxGdbHandle));
        OK
    })
}
