
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

impl BreakpointSize {
    /// Tamanho em bytes observado (1, 2, 4 ou 8), ao contrário do encoding de 2 bits
    /// usado em DR7.
    pub fn byte_size(self) -> usize {
        match self {
            BreakpointSize::Byte1 => 1,
            BreakpointSize::Byte2 => 2,
            BreakpointSize::Byte4 => 4,
            BreakpointSize::Byte8 => 8,
        }
    }
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
        slot: usize,
        watch_addr: usize,
        bp_type: BreakpointType,
        size: BreakpointSize,
        duration_secs: u64,
        stop_signal: Arc<AtomicBool>,
    ) -> Result<Vec<AccessHit>, String> {
        if slot >= HW_BREAKPOINT_SLOTS {
            return Err(format!(
                "hardware breakpoint slot {} out of range (0..{})",
                slot,
                HW_BREAKPOINT_SLOTS - 1
            ));
        }
        let pid = proc.pid;
        let thread_ids = proc.threads()?;
        if thread_ids.is_empty() {
            return Err("No active threads found in target process".to_string());
        }

        let attached = unsafe { DebugActiveProcess(pid) };
        if attached != TRUE {
            return Err(format!("DebugActiveProcess failed for PID {}", pid));
        }

        set_hw_breakpoint_for_threads(&thread_ids, slot, watch_addr, bp_type, size)?;

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

        let _ = clear_hw_breakpoint_from_threads(&thread_ids, slot);

        unsafe {
            DebugActiveProcessStop(pid);
        }

        let mut result: Vec<AccessHit> = hits.into_values().collect();
        result.sort_by(|a, b| b.count.cmp(&a.count));
        Ok(result)
    }
}

/// Estado dos registradores de depuração de uma thread (DR0..DR3, DR6, DR7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadDebugRegisters {
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
}

impl ThreadDebugRegisters {
    pub fn address(&self, index: usize) -> Option<u64> {
        match index {
            0 => Some(self.dr0),
            1 => Some(self.dr1),
            2 => Some(self.dr2),
            3 => Some(self.dr3),
            _ => None,
        }
    }

    pub fn slot_enabled(&self, index: usize) -> bool {
        index < HW_BREAKPOINT_SLOTS && (self.dr7 & (1u64 << (index * DR7_ENABLE_SHIFT_STEP))) != 0
    }
}

/// Lê DR0..DR3/DR6/DR7 de uma thread do alvo sem alterar nada.
/// Usado por diagnóstico (`examples/dr_dump.rs`) e pelos testes em VM.
pub fn read_thread_debug_registers(tid: u32) -> Result<ThreadDebugRegisters, String> {
    let handle = open_thread_handle(tid)?;

    let previous_count = unsafe { SuspendThread(handle) };
    if previous_count == u32::MAX {
        let error = unsafe { GetLastError() };
        unsafe { CloseHandle(handle) };
        return Err(format!(
            "SuspendThread failed for thread {} (error {})",
            tid, error
        ));
    }

    let context = read_debug_context(handle, tid);

    unsafe {
        ResumeThread(handle);
        CloseHandle(handle);
    }

    let ctx = context?;
    Ok(ThreadDebugRegisters {
        dr0: ctx.Dr0,
        dr1: ctx.Dr1,
        dr2: ctx.Dr2,
        dr3: ctx.Dr3,
        dr6: ctx.Dr6,
        dr7: ctx.Dr7,
    })
}

pub const HW_BREAKPOINT_SLOTS: usize = 4;

const DR7_ENABLE_SHIFT_STEP: usize = 2;
const DR7_RW_SHIFT_BASE: usize = 16;
const DR7_LEN_SHIFT_BASE: usize = 18;
const DR7_FIELD_MASK: u64 = 0b11;

fn check_slot(index: usize) -> Result<(), String> {
    if index >= HW_BREAKPOINT_SLOTS {
        return Err(format!(
            "Hardware breakpoint index must be 0..{}",
            HW_BREAKPOINT_SLOTS - 1
        ));
    }
    Ok(())
}

fn dr_slot_value(ctx: &CONTEXT, index: usize) -> u64 {
    match index {
        0 => ctx.Dr0,
        1 => ctx.Dr1,
        2 => ctx.Dr2,
        3 => ctx.Dr3,
        _ => 0,
    }
}

fn set_dr_slot_value(ctx: &mut CONTEXT, index: usize, value: u64) {
    match index {
        0 => ctx.Dr0 = value,
        1 => ctx.Dr1 = value,
        2 => ctx.Dr2 = value,
        3 => ctx.Dr3 = value,
        _ => {}
    }
}

fn dr_slot_enabled(ctx: &CONTEXT, index: usize) -> bool {
    ctx.Dr7 & (1u64 << (index * DR7_ENABLE_SHIFT_STEP)) != 0
}

fn dr_slot_matches(
    ctx: &CONTEXT,
    index: usize,
    address: usize,
    bp_type: BreakpointType,
    size: BreakpointSize,
) -> bool {
    if !dr_slot_enabled(ctx, index) {
        return false;
    }
    if dr_slot_value(ctx, index) != address as u64 {
        return false;
    }
    let rw = (ctx.Dr7 >> (DR7_RW_SHIFT_BASE + index * 4)) & DR7_FIELD_MASK;
    let len = (ctx.Dr7 >> (DR7_LEN_SHIFT_BASE + index * 4)) & DR7_FIELD_MASK;
    rw == bp_type as u64 && len == size as u64
}

fn apply_dr_slot(
    ctx: &mut CONTEXT,
    index: usize,
    address: usize,
    bp_type: BreakpointType,
    size: BreakpointSize,
) {
    set_dr_slot_value(ctx, index, address as u64);

    let enable_bit = 1u64 << (index * DR7_ENABLE_SHIFT_STEP);
    let rw_shift = DR7_RW_SHIFT_BASE + index * 4;
    let len_shift = DR7_LEN_SHIFT_BASE + index * 4;

    ctx.Dr7 |= enable_bit;
    ctx.Dr7 &= !((DR7_FIELD_MASK << rw_shift) | (DR7_FIELD_MASK << len_shift));
    ctx.Dr7 |= (bp_type as u64) << rw_shift;
    ctx.Dr7 |= (size as u64) << len_shift;
}

fn open_thread_handle(tid: u32) -> Result<HANDLE, String> {
    let handle = unsafe { OpenThread(THREAD_ALL_ACCESS, FALSE, tid) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "Failed to open thread ID {} (error {})",
            tid,
            unsafe { GetLastError() }
        ));
    }
    Ok(handle)
}

fn read_debug_context(handle: HANDLE, tid: u32) -> Result<CONTEXT, String> {
    let mut ctx: CONTEXT = unsafe { zeroed() };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if unsafe { GetThreadContext(handle, &mut ctx) } != TRUE {
        return Err(format!(
            "GetThreadContext failed for thread {} (error {})",
            tid,
            unsafe { GetLastError() }
        ));
    }
    Ok(ctx)
}

fn write_debug_context(handle: HANDLE, tid: u32, ctx: &CONTEXT) -> Result<(), String> {
    if unsafe { SetThreadContext(handle, ctx) } != TRUE {
        return Err(format!(
            "SetThreadContext failed for thread {} (error {})",
            tid,
            unsafe { GetLastError() }
        ));
    }
    Ok(())
}

/// Suspends `tid` for the duration of `op`, then always resumes it exactly once.
/// A thread that was already suspended is left at its previous suspend count.
fn with_suspended_thread<T, F>(tid: u32, op: F) -> Result<T, String>
where
    F: FnOnce(HANDLE) -> Result<T, String>,
{
    let handle = open_thread_handle(tid)?;

    let previous_count = unsafe { SuspendThread(handle) };
    if previous_count == u32::MAX {
        let error = unsafe { GetLastError() };
        unsafe { CloseHandle(handle) };
        return Err(format!(
            "SuspendThread failed for thread {} (error {})",
            tid, error
        ));
    }

    let result = op(handle);

    unsafe {
        ResumeThread(handle);
        CloseHandle(handle);
    }

    result
}

pub fn set_hw_breakpoint_on_thread(
    tid: u32,
    index: usize,
    address: usize,
    bp_type: BreakpointType,
    size: BreakpointSize,
) -> Result<(), String> {
    check_slot(index)?;

    with_suspended_thread(tid, |handle| {
        let mut ctx = read_debug_context(handle, tid)?;
        apply_dr_slot(&mut ctx, index, address, bp_type, size);
        write_debug_context(handle, tid, &ctx)
    })
}

/// Applies one hardware breakpoint slot to every thread, skipping threads that
/// already have the identical slot configured. Returns how many threads changed.
///
/// If a thread fails, the threads already updated by this call are rolled back,
/// so the caller never observes a half-applied breakpoint.
pub fn set_hw_breakpoint_for_threads(
    threads: &[u32],
    index: usize,
    address: usize,
    bp_type: BreakpointType,
    size: BreakpointSize,
) -> Result<usize, String> {
    check_slot(index)?;

    let mut applied: Vec<u32> = Vec::with_capacity(threads.len());

    for &tid in threads {
        let outcome = with_suspended_thread(tid, |handle| {
            let mut ctx = read_debug_context(handle, tid)?;

            if dr_slot_matches(&ctx, index, address, bp_type, size) {
                return Ok(false);
            }

            apply_dr_slot(&mut ctx, index, address, bp_type, size);
            write_debug_context(handle, tid, &ctx)?;
            Ok(true)
        });

        match outcome {
            Ok(true) => applied.push(tid),
            Ok(false) => {}
            Err(error) => {
                for &done in &applied {
                    let _ = clear_hw_breakpoint_on_thread(done, index);
                }
                return Err(error);
            }
        }
    }

    Ok(applied.len())
}

pub fn clear_hw_breakpoint_on_thread(tid: u32, index: usize) -> Result<(), String> {
    check_slot(index)?;

    with_suspended_thread(tid, |handle| {
        let mut ctx = read_debug_context(handle, tid)?;
        set_dr_slot_value(&mut ctx, index, 0);
        ctx.Dr7 &= !(1u64 << (index * DR7_ENABLE_SHIFT_STEP));
        write_debug_context(handle, tid, &ctx)
    })
}

/// Clears one hardware breakpoint slot from every thread. Threads that cannot be
/// updated are skipped, so an exited thread does not block cleanup.
/// Returns how many threads were updated.
pub fn clear_hw_breakpoint_from_threads(threads: &[u32], index: usize) -> Result<usize, String> {
    check_slot(index)?;

    let mut cleared = 0usize;
    for &tid in threads {
        if clear_hw_breakpoint_on_thread(tid, index).is_ok() {
            cleared += 1;
        }
    }
    Ok(cleared)
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
    fn breakpoint_size_reports_bytes() {
        assert_eq!(BreakpointSize::Byte1.byte_size(), 1);
        assert_eq!(BreakpointSize::Byte2.byte_size(), 2);
        assert_eq!(BreakpointSize::Byte4.byte_size(), 4);
        assert_eq!(BreakpointSize::Byte8.byte_size(), 8);
    }

    #[test]
    fn thread_debug_registers_read_slots_from_dr7() {
        let dr = ThreadDebugRegisters {
            dr0: 0x1000,
            dr1: 0x2000,
            dr2: 0x3000,
            dr3: 0x4000,
            dr6: 0,
            // habilita DR0 (bit 0) e DR2 (bit 4)
            dr7: 0b010001,
        };

        assert_eq!(dr.address(0), Some(0x1000));
        assert_eq!(dr.address(3), Some(0x4000));
        assert_eq!(dr.address(4), None);
        assert!(dr.slot_enabled(0));
        assert!(!dr.slot_enabled(1));
        assert!(dr.slot_enabled(2));
        assert!(!dr.slot_enabled(3));
    }

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

