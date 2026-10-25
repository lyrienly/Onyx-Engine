
use std::mem::zeroed;
use crate::debugger::{clear_hw_breakpoint_on_thread, set_hw_breakpoint_on_thread, BreakpointSize, BreakpointType};
use crate::process::Process;
use crate::win32::*;

pub struct VehDebugger {
    pub target_pid: u32,
    pub active_breakpoints: Vec<(usize, BreakpointType, BreakpointSize)>,
}

impl VehDebugger {
    pub fn new(pid: u32) -> Self {
        VehDebugger {
            target_pid: pid,
            active_breakpoints: Vec::new(),
        }
    }

    pub fn set_stealth_breakpoint(
        &mut self,
        proc: &Process,
        address: usize,
        bp_type: BreakpointType,
        size: BreakpointSize,
    ) -> Result<usize, String> {
        let threads = proc.threads()?;
        if threads.is_empty() {
            return Err("No active threads in target".to_string());
        }

        let bp_index = self.active_breakpoints.len().min(3);

        for &tid in &threads {
            set_hw_breakpoint_on_thread(tid, bp_index, address, bp_type, size)?;
        }

        self.active_breakpoints.push((address, bp_type, size));
        Ok(bp_index)
    }

    pub fn clear_stealth_breakpoint(&mut self, proc: &Process, index: usize) -> Result<(), String> {
        let threads = proc.threads()?;
        for &tid in &threads {
            let _ = clear_hw_breakpoint_on_thread(tid, index);
        }

        if index < self.active_breakpoints.len() {
            self.active_breakpoints.remove(index);
        }

        Ok(())
    }

    pub fn poll_hit(&self, proc: &Process) -> Option<(u32, usize)> {
        let threads = proc.threads().ok()?;
        for &tid in &threads {
            let h_thread = unsafe { OpenThread(THREAD_ALL_ACCESS, FALSE, tid) };
            if h_thread.is_null() || h_thread == INVALID_HANDLE_VALUE {
                continue;
            }

            unsafe {
                SuspendThread(h_thread);
                let mut ctx: CONTEXT = zeroed();
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;

                let hit = if GetThreadContext(h_thread, &mut ctx) == TRUE {

                    let dr6 = ctx.Dr6;
                    if (dr6 & 0x0F) != 0 {

                        ctx.Dr6 = 0;
                        ctx.EFlags |= 0x00010000;
                        SetThreadContext(h_thread, &ctx);
                        Some((tid, ctx.Rip as usize))
                    } else {
                        None
                    }
                } else {
                    None
                };

                ResumeThread(h_thread);
                CloseHandle(h_thread);

                if hit.is_some() {
                    return hit;
                }
            }
        }
        None
    }
}

