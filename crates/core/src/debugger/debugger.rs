
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

        let attached = unsafe { DebugActiveProcess(pid) };
        if attached != TRUE {
            return Err(format!("DebugActiveProcess failed for PID {}", pid));
        }

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

                        let h_thread = unsafe { OpenThread(THREAD_ALL_ACCESS, FALSE, event.dwThreadId) };
                        if !h_thread.is_null() && h_thread != INVALID_HANDLE_VALUE {
                            let mut ctx: CONTEXT = unsafe { zeroed() };
                            ctx.ContextFlags = CONTEXT_ALL;

                            if unsafe { GetThreadContext(h_thread, &mut ctx) } == TRUE {

                                let entry = hits.entry(insn_addr).or_insert_with(|| {

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

                                ctx.EFlags |= 0x00010000;
                                unsafe { SetThreadContext(h_thread, &ctx) };
                            }
                            unsafe { CloseHandle(h_thread) };
                        }
                    } else if code == EXCEPTION_BREAKPOINT {

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

        for &tid in &thread_ids {
            let _ = clear_hw_breakpoint_on_thread(tid, 0);
        }

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
    index: usize,
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

            match index {
                0 => ctx.Dr0 = address as u64,
                1 => ctx.Dr1 = address as u64,
                2 => ctx.Dr2 = address as u64,
                3 => ctx.Dr3 = address as u64,
                _ => {}
            }

            let enable_bit = 1 << (index * 2);
            let rw_shift = 16 + (index * 4);
            let len_shift = 18 + (index * 4);

            ctx.Dr7 |= enable_bit;

            ctx.Dr7 &= !((0b11 << rw_shift) | (0b11 << len_shift));

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

            let enable_bit = 1 << (index * 2);
            ctx.Dr7 &= !enable_bit;

            SetThreadContext(h_thread, &ctx);
        }

        ResumeThread(h_thread);
        CloseHandle(h_thread);
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub struct TraceRecord {
    pub step: usize,
    pub address: usize,
    pub instruction: String,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub eflags: u64,
}

#[derive(Debug, Clone)]
pub struct TraceConfig {
    pub max_steps: usize,
    pub stop_on_ret: bool,
    pub stop_address: Option<usize>,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            max_steps: 1000,
            stop_on_ret: false,
            stop_address: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CallStackFrame {
    pub frame_index: usize,
    pub address: usize,
    pub module_name: String,
    pub offset_in_module: usize,
}

impl HardwareBreakpointMonitor {

    pub fn break_and_trace(
        proc: &Process,
        start_addr: usize,
        config: &TraceConfig,
        stop_signal: Arc<AtomicBool>,
    ) -> Result<Vec<TraceRecord>, String> {
        let pid = proc.pid;
        let thread_ids = proc.threads()?;
        if thread_ids.is_empty() {
            return Err("No active threads in target process".to_string());
        }

        let attached = unsafe { DebugActiveProcess(pid) };
        if attached != TRUE {
            return Err(format!("DebugActiveProcess failed for PID {}", pid));
        }

        for &tid in &thread_ids {
            let _ = set_hw_breakpoint_on_thread(tid, 0, start_addr, BreakpointType::Execute, BreakpointSize::Byte1);
        }

        let mut traces = Vec::new();
        let mut in_trace_mode = false;
        let mut active_trace_thread: u32 = 0;
        let mut event: DEBUG_EVENT = unsafe { zeroed() };

        let max_steps = if config.max_steps == 0 { 1000 } else { config.max_steps };

        while !stop_signal.load(Ordering::Relaxed) {
            let got_event = unsafe { WaitForDebugEvent(&mut event, 100) };
            if got_event == TRUE {
                let mut continue_status = DBG_CONTINUE;

                if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
                    let ex = unsafe { event.u.Exception };
                    let code = ex.ExceptionRecord.ExceptionCode;

                    if code == EXCEPTION_SINGLE_STEP {
                        let h_thread = unsafe { OpenThread(THREAD_ALL_ACCESS, FALSE, event.dwThreadId) };
                        if !h_thread.is_null() && h_thread != INVALID_HANDLE_VALUE {
                            let mut ctx: CONTEXT = unsafe { zeroed() };
                            ctx.ContextFlags = CONTEXT_ALL;

                            if unsafe { GetThreadContext(h_thread, &mut ctx) } == TRUE {
                                let cur_ip = ctx.Rip as usize;

                                if !in_trace_mode {

                                    in_trace_mode = true;
                                    active_trace_thread = event.dwThreadId;

                                    for &tid in &thread_ids {
                                        let _ = clear_hw_breakpoint_on_thread(tid, 0);
                                    }

                                    ctx.EFlags |= 0x00010100;
                                    unsafe { SetThreadContext(h_thread, &ctx) };
                                } else if event.dwThreadId == active_trace_thread {

                                    let mut insn_bytes = [0u8; 15];
                                    let read = proc.read_raw(cur_ip, &mut insn_bytes).unwrap_or(0);
                                    let decoded = Disassembler::decode_one(cur_ip, &insn_bytes[..read]);

                                    let record = TraceRecord {
                                        step: traces.len() + 1,
                                        address: cur_ip,
                                        instruction: format!("{} {}", decoded.mnemonic, decoded.operands),
                                        rax: ctx.Rax,
                                        rbx: ctx.Rbx,
                                        rcx: ctx.Rcx,
                                        rdx: ctx.Rdx,
                                        rsi: ctx.Rsi,
                                        rdi: ctx.Rdi,
                                        rsp: ctx.Rsp,
                                        rbp: ctx.Rbp,
                                        r8: ctx.R8,
                                        r9: ctx.R9,
                                        r10: ctx.R10,
                                        r11: ctx.R11,
                                        r12: ctx.R12,
                                        r13: ctx.R13,
                                        r14: ctx.R14,
                                        r15: ctx.R15,
                                        eflags: ctx.EFlags as u64,
                                    };
                                    traces.push(record);

                                    let should_stop = traces.len() >= max_steps
                                        || (config.stop_on_ret && decoded.mnemonic == "ret")
                                        || (config.stop_address == Some(cur_ip));

                                    if should_stop {

                                        ctx.EFlags &= !0x00000100;
                                        ctx.EFlags |= 0x00010000;
                                        unsafe { SetThreadContext(h_thread, &ctx) };
                                        unsafe { CloseHandle(h_thread) };
                                        unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE) };
                                        break;
                                    } else {

                                        ctx.EFlags |= 0x00010100;
                                        unsafe { SetThreadContext(h_thread, &ctx) };
                                    }
                                }
                            }
                            unsafe { CloseHandle(h_thread) };
                        }
                    } else if code == EXCEPTION_BREAKPOINT {
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

        for &tid in &thread_ids {
            let _ = clear_hw_breakpoint_on_thread(tid, 0);
        }
        unsafe {
            DebugActiveProcessStop(pid);
        }

        Ok(traces)
    }

    pub fn walk_call_stack(proc: &Process, thread_id: u32, max_depth: usize) -> Result<Vec<CallStackFrame>, String> {
        let h_thread = unsafe { OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id) };
        if h_thread.is_null() || h_thread == INVALID_HANDLE_VALUE {
            return Err(format!("Could not open thread {}", thread_id));
        }

        let mut ctx: CONTEXT = unsafe { zeroed() };
        ctx.ContextFlags = CONTEXT_ALL;

        let got_ctx = unsafe {
            SuspendThread(h_thread);
            let ok = GetThreadContext(h_thread, &mut ctx);
            ResumeThread(h_thread);
            CloseHandle(h_thread);
            ok
        };

        if got_ctx != TRUE {
            return Err("Failed to retrieve thread context for stack walk".to_string());
        }

        let modules = proc.modules()?;
        let mut frames = Vec::new();

        let cur_rip = ctx.Rip as usize;
        let (mod_name, offset) = if let Some(m) = modules.iter().find(|m| cur_rip >= m.base && cur_rip < m.base + m.size) {
            (m.name.clone(), cur_rip - m.base)
        } else {
            ("Unknown".to_string(), cur_rip)
        };
        frames.push(CallStackFrame {
            frame_index: 0,
            address: cur_rip,
            module_name: mod_name,
            offset_in_module: offset,
        });

        const STACK_SCAN_BYTES: usize = 4096;
        let mut stack_buf = vec![0u8; STACK_SCAN_BYTES];
        let bytes_read = proc.read_raw(ctx.Rsp as usize, &mut stack_buf).unwrap_or(0);

        let ptr_size = std::mem::size_of::<usize>();
        if bytes_read >= ptr_size {
            let count = (bytes_read - ptr_size) / ptr_size;
            for i in 0..count {
                if frames.len() >= max_depth {
                    break;
                }
                let ptr_val = usize::from_ne_bytes(
                    stack_buf[i * ptr_size..(i + 1) * ptr_size].try_into().unwrap_or_default(),
                );

                if let Some(m) = modules.iter().find(|m| ptr_val >= m.base && ptr_val < m.base + m.size) {
                    frames.push(CallStackFrame {
                        frame_index: frames.len(),
                        address: ptr_val,
                        module_name: m.name.clone(),
                        offset_in_module: ptr_val - m.base,
                    });
                }
            }
        }

        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_stack_walk_current_thread() {
        let proc = Process::attach_current().expect("attach to current process");
        let threads = proc.threads().expect("threads");
        if let Some(&tid) = threads.first() {
            let frames = HardwareBreakpointMonitor::walk_call_stack(&proc, tid, 10);
            assert!(frames.is_ok());
            let list = frames.unwrap();
            assert!(!list.is_empty());
            assert_eq!(list[0].frame_index, 0);
        }
    }
}

