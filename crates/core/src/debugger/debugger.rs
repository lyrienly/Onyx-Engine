// language: Rust, file: debugger.rs, target: Windows 11, MSVC
// Hardware breakpoint engine and "Find out what accesses/writes to this address"

use std::collections::HashMap;
use std::mem::zeroed;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use crate::disasm::Disassembler;
use crate::process::Process;
use crate::win32::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointType {
    Execute = 0b00,
    Write = 0b01,
    ReadWrite = 0b11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointSize {
    Byte1 = 0b00,
    Byte2 = 0b01,
    Byte8 = 0b10,
    Byte4 = 0b11,
}

#[derive(Debug, Clone)]
pub struct AccessHit {
    pub instruction_address: usize,
    pub instruction_text: String,
    pub count: usize,
    pub last_rax: u64,
    pub last_rbx: u64,
    pub last_rcx: u64,
    pub last_rdx: u64,
    pub last_rsi: u64,
    pub last_rdi: u64,
    pub last_rsp: u64,
    pub last_rbp: u64,
}

pub struct HardwareBreakpointMonitor;

impl HardwareBreakpointMonitor {
    /// Monitors accesses or writes to a target address for a given duration or until stopped.
    /// Returns all instructions that touched the address and their hit counts.
    pub fn monitor_address(
        proc: &Process,
        watch_addr: usize,
        bp_type: BreakpointType,
        size: BreakpointSize,
        duration_secs: u64,
        stop_signal: Arc<AtomicBool>,
    ) -> Result<Vec<AccessHit>, String> {
        let pid = proc.pid;
        let thread_ids = proc.threads()?;
        if thread_ids.is_empty() {
            return Err("No active threads found in target process".to_string());
        }

        // Attach Windows debug loop
        let attached = unsafe { DebugActiveProcess(pid) };
        if attached != TRUE {
            return Err(format!("DebugActiveProcess failed for PID {}", pid));
        }

        // Set DR0 and DR7 on all target threads
        for &tid in &thread_ids {
            let _ = set_hw_breakpoint_on_thread(tid, 0, watch_addr, bp_type, size);
        }

        let mut hits: HashMap<usize, AccessHit> = HashMap::new();
        let start_time = std::time::Instant::now();

        let mut event: DEBUG_EVENT = unsafe { zeroed() };

        while !stop_signal.load(Ordering::Relaxed) {
            if start_time.elapsed() >= Duration::from_secs(duration_secs) {
                break;
            }

            let got_event = unsafe { WaitForDebugEvent(&mut event, 100) };
            if got_event == TRUE {
                let mut continue_status = DBG_CONTINUE;

                if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
                    let ex = unsafe { event.u.Exception };
                    let code = ex.ExceptionRecord.ExceptionCode;

                    if code == EXCEPTION_SINGLE_STEP {
                        let insn_addr = ex.ExceptionRecord.ExceptionAddress as usize;

                        // Query thread context to read registers and set RF (Resume Flag)
                        let h_thread = unsafe { OpenThread(THREAD_ALL_ACCESS, FALSE, event.dwThreadId) };
                        if !h_thread.is_null() && h_thread != INVALID_HANDLE_VALUE {
                            let mut ctx: CONTEXT = unsafe { zeroed() };
                            ctx.ContextFlags = CONTEXT_ALL;

                            if unsafe { GetThreadContext(h_thread, &mut ctx) } == TRUE {
                                // Record hit
                                let entry = hits.entry(insn_addr).or_insert_with(|| {
                                    // Disassemble instruction at faulting address
                                    let mut insn_bytes = [0u8; 15];
                                    let read = proc.read_raw(insn_addr, &mut insn_bytes).unwrap_or(0);
                                    let decoded = Disassembler::decode_one(insn_addr, &insn_bytes[..read]);

                                    AccessHit {
                                        instruction_address: insn_addr,
                                        instruction_text: format!("{} {}", decoded.mnemonic, decoded.operands),
                                        count: 0,
                                        last_rax: ctx.Rax,
                                        last_rbx: ctx.Rbx,
                                        last_rcx: ctx.Rcx,
                                        last_rdx: ctx.Rdx,
                                        last_rsi: ctx.Rsi,
                                        last_rdi: ctx.Rdi,
                                        last_rsp: ctx.Rsp,
                                        last_rbp: ctx.Rbp,
                                    }
                                });

                                entry.count += 1;
                                entry.last_rax = ctx.Rax;
                                entry.last_rbx = ctx.Rbx;
                                entry.last_rcx = ctx.Rcx;
                                entry.last_rdx = ctx.Rdx;
                                entry.last_rsi = ctx.Rsi;
                                entry.last_rdi = ctx.Rdi;

                                // Set EFLAGS RF (bit 16) so execution resumes without re-triggering immediately
                                ctx.EFlags |= 0x00010000;
                                unsafe { SetThreadContext(h_thread, &ctx) };
                            }
                            unsafe { CloseHandle(h_thread) };
                        }
                    } else if code == EXCEPTION_BREAKPOINT {
                        // Initial debugger attach breakpoint
                        continue_status = DBG_CONTINUE;
                    } else {
                        continue_status = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }

                unsafe {
                    ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continue_status);
                }
            }
        }

        // Clean up: Clear DR0 and DR7 on all threads
        for &tid in &thread_ids {
            let _ = clear_hw_breakpoint_on_thread(tid, 0);
        }

        // Detach debugger
        unsafe {
            DebugActiveProcessStop(pid);
        }

        let mut result: Vec<AccessHit> = hits.into_values().collect();
        result.sort_by(|a, b| b.count.cmp(&a.count));
        Ok(result)
    }
}

pub fn set_hw_breakpoint_on_thread(
    tid: u32,
    index: usize, // 0 to 3
    address: usize,
    bp_type: BreakpointType,
    size: BreakpointSize,
) -> Result<(), String> {
    if index > 3 {
        return Err("Hardware breakpoint index must be 0, 1, 2, or 3".to_string());
    }

    let h_thread = unsafe { OpenThread(THREAD_ALL_ACCESS, FALSE, tid) };
    if h_thread.is_null() || h_thread == INVALID_HANDLE_VALUE {
        return Err(format!("Failed to open thread ID {}", tid));
    }

    unsafe {
        SuspendThread(h_thread);

        let mut ctx: CONTEXT = zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if GetThreadContext(h_thread, &mut ctx) == TRUE {
            // Set DRn address
            match index {
                0 => ctx.Dr0 = address as u64,
                1 => ctx.Dr1 = address as u64,
                2 => ctx.Dr2 = address as u64,
                3 => ctx.Dr3 = address as u64,
                _ => {}
            }

            // Enable local breakpoint in DR7
            let enable_bit = 1 << (index * 2);
            let rw_shift = 16 + (index * 4);
            let len_shift = 18 + (index * 4);

            ctx.Dr7 |= enable_bit;
            // Clear old condition and length
            ctx.Dr7 &= !((0b11 << rw_shift) | (0b11 << len_shift));
            // Set condition and length
            ctx.Dr7 |= (bp_type as u64) << rw_shift;
            ctx.Dr7 |= (size as u64) << len_shift;

            SetThreadContext(h_thread, &ctx);
        }

        ResumeThread(h_thread);
        CloseHandle(h_thread);
    }

    Ok(())
}

pub fn clear_hw_breakpoint_on_thread(tid: u32, index: usize) -> Result<(), String> {
    let h_thread = unsafe { OpenThread(THREAD_ALL_ACCESS, FALSE, tid) };
    if h_thread.is_null() || h_thread == INVALID_HANDLE_VALUE {
        return Err(format!("Failed to open thread ID {}", tid));
    }

    unsafe {
        SuspendThread(h_thread);

        let mut ctx: CONTEXT = zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if GetThreadContext(h_thread, &mut ctx) == TRUE {
            match index {
                0 => ctx.Dr0 = 0,
                1 => ctx.Dr1 = 0,
                2 => ctx.Dr2 = 0,
                3 => ctx.Dr3 = 0,
                _ => {}
            }

            // Disable local breakpoint
            let enable_bit = 1 << (index * 2);
            ctx.Dr7 &= !enable_bit;

            SetThreadContext(h_thread, &ctx);
        }

        ResumeThread(h_thread);
        CloseHandle(h_thread);
    }

    Ok(())
}
