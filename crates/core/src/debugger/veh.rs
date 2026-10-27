
use std::mem::zeroed;
use crate::debugger::{
    clear_hw_breakpoint_from_threads, set_hw_breakpoint_for_threads, BreakpointSize,
    BreakpointType, HW_BREAKPOINT_SLOTS,
};
use crate::process::Process;
use crate::win32::*;

/// One of the four x86-64 hardware breakpoint slots (DR0..DR3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HwBreakpointSlot {
    pub address: usize,
    pub bp_type: BreakpointType,
    pub size: BreakpointSize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwBpError {
    /// All four DR slots are already assigned.
    NoFreeSlot,
    /// Slot index outside `0..HW_BREAKPOINT_SLOTS`.
    InvalidSlot,
    /// Target process has no threads to configure.
    NoThreads,
    /// A thread could not be opened, suspended or have its context updated.
    ThreadFailure,
}

impl HwBpError {
    /// Stable code shared with the Pascal frontend (`OnyxBackend.pas`).
    /// Keep in sync with `TOnyxVehSlotError` there.
    pub fn code(self) -> i32 {
        match self {
            HwBpError::NoFreeSlot => -2,
            HwBpError::InvalidSlot => -3,
            HwBpError::NoThreads => -4,
            HwBpError::ThreadFailure => -5,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            HwBpError::NoFreeSlot => "all 4 hardware breakpoint slots are in use",
            HwBpError::InvalidSlot => "hardware breakpoint slot must be 0..3",
            HwBpError::NoThreads => "target process has no active threads",
            HwBpError::ThreadFailure => "failed to update thread debug registers",
        }
    }
}

impl std::fmt::Display for HwBpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

pub struct VehDebugger {
    pub target_pid: u32,
    slots: [Option<HwBreakpointSlot>; HW_BREAKPOINT_SLOTS],
}

impl VehDebugger {
    pub fn new(pid: u32) -> Self {
        VehDebugger {
            target_pid: pid,
            slots: [None; HW_BREAKPOINT_SLOTS],
        }
    }

    pub fn slots(&self) -> &[Option<HwBreakpointSlot>; HW_BREAKPOINT_SLOTS] {
        &self.slots
    }

    pub fn used_slots(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    pub fn is_full(&self) -> bool {
        self.used_slots() == HW_BREAKPOINT_SLOTS
    }

    fn find_free_slot(&self) -> Option<usize> {
        self.slots.iter().position(|slot| slot.is_none())
    }

    /// Marks a slot as used without touching any thread. Used by callers that
    /// drive the debug registers themselves, such as `HardwareBreakpointMonitor`.
    pub fn reserve_slot(
        &mut self,
        address: usize,
        bp_type: BreakpointType,
        size: BreakpointSize,
    ) -> Result<usize, HwBpError> {
        let index = self.find_free_slot().ok_or(HwBpError::NoFreeSlot)?;
        self.slots[index] = Some(HwBreakpointSlot {
            address,
            bp_type,
            size,
        });
        Ok(index)
    }

    /// Releases a slot without touching any thread.
    pub fn release_slot(&mut self, index: usize) -> Result<(), HwBpError> {
        if index >= HW_BREAKPOINT_SLOTS {
            return Err(HwBpError::InvalidSlot);
        }
        self.slots[index] = None;
        Ok(())
    }

    pub fn set_stealth_breakpoint(
        &mut self,
        proc: &Process,
        address: usize,
        bp_type: BreakpointType,
        size: BreakpointSize,
    ) -> Result<usize, HwBpError> {
        let threads = proc.threads().map_err(|_| HwBpError::ThreadFailure)?;
        if threads.is_empty() {
            return Err(HwBpError::NoThreads);
        }

        // Report exhaustion before doing any work on the target.
        let index = self.find_free_slot().ok_or(HwBpError::NoFreeSlot)?;

        set_hw_breakpoint_for_threads(&threads, index, address, bp_type, size)
            .map_err(|_| HwBpError::ThreadFailure)?;

        self.slots[index] = Some(HwBreakpointSlot {
            address,
            bp_type,
            size,
        });

        Ok(index)
    }

    pub fn clear_stealth_breakpoint(
        &mut self,
        proc: &Process,
        index: usize,
    ) -> Result<(), HwBpError> {
        if index >= HW_BREAKPOINT_SLOTS {
            return Err(HwBpError::InvalidSlot);
        }

        // Already free: clearing is idempotent so a stale Lua handle is harmless.
        if self.slots[index].is_none() {
            return Ok(());
        }

        let threads = proc.threads().map_err(|_| HwBpError::ThreadFailure)?;
        let cleared = clear_hw_breakpoint_from_threads(&threads, index)
            .map_err(|_| HwBpError::ThreadFailure)?;

        // Every thread failed to update: keep the slot marked as used so the
        // registry never claims a slot is free while DR still references it.
        if cleared == 0 && !threads.is_empty() {
            return Err(HwBpError::ThreadFailure);
        }

        self.slots[index] = None;
        Ok(())
    }

    /// Clears every slot this instance owns. Used when the debug session ends.
    pub fn clear_all(&mut self, proc: &Process) {
        let threads = proc.threads().unwrap_or_default();
        for index in 0..HW_BREAKPOINT_SLOTS {
            if self.slots[index].is_some() {
                let _ = clear_hw_breakpoint_from_threads(&threads, index);
                self.slots[index] = None;
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn reserve_n(veh: &mut VehDebugger, count: usize) -> Vec<usize> {
        (0..count)
            .map(|i| {
                veh.reserve_slot(
                    0x1000 + i * 8,
                    BreakpointType::Write,
                    BreakpointSize::Byte4,
                )
                .expect("slot available")
            })
            .collect()
    }

    #[test]
    fn allocates_every_slot_then_reports_exhaustion() {
        let mut veh = VehDebugger::new(1234);
        assert!(!veh.is_full());

        let indices = reserve_n(&mut veh, HW_BREAKPOINT_SLOTS);
        assert_eq!(indices, vec![0, 1, 2, 3]);
        assert_eq!(veh.used_slots(), HW_BREAKPOINT_SLOTS);
        assert!(veh.is_full());

        let fifth = veh.reserve_slot(0x2000, BreakpointType::Execute, BreakpointSize::Byte1);
        assert_eq!(fifth, Err(HwBpError::NoFreeSlot));
    }

    #[test]
    fn released_slot_is_reused() {
        let mut veh = VehDebugger::new(1234);
        reserve_n(&mut veh, HW_BREAKPOINT_SLOTS);

        veh.release_slot(1).expect("slot 1 existed");
        assert_eq!(veh.used_slots(), 3);

        let reused = veh
            .reserve_slot(0x3000, BreakpointType::ReadWrite, BreakpointSize::Byte8)
            .expect("slot 1 is free again");
        assert_eq!(reused, 1);
        assert_eq!(
            veh.slots()[1],
            Some(HwBreakpointSlot {
                address: 0x3000,
                bp_type: BreakpointType::ReadWrite,
                size: BreakpointSize::Byte8,
            })
        );
    }

    #[test]
    fn rejects_out_of_range_slot() {
        let mut veh = VehDebugger::new(1234);
        assert_eq!(
            veh.release_slot(HW_BREAKPOINT_SLOTS),
            Err(HwBpError::InvalidSlot)
        );
    }

    #[test]
    fn error_codes_are_stable_for_the_pascal_side() {
        assert_eq!(HwBpError::NoFreeSlot.code(), -2);
        assert_eq!(HwBpError::InvalidSlot.code(), -3);
        assert_eq!(HwBpError::NoThreads.code(), -4);
        assert_eq!(HwBpError::ThreadFailure.code(), -5);
    }
}
