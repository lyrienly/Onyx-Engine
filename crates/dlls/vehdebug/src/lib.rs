#![allow(
    non_snake_case,
    non_camel_case_types,
    dead_code,
    unsafe_op_in_unsafe_fn
)]
#![allow(
    clippy::missing_safety_doc,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::upper_case_acronyms,
    clippy::too_many_arguments
)]
#![cfg(windows)]

pub mod debugger;
pub mod ffi;
pub mod veh;

use crate::debugger::{BpHit, HwBpAccess, HwBpSize, VehDebugger};
use crate::ffi::*;
use crate::veh::BreakpointId;

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

static DEBUGGER: OnceLock<Mutex<Option<VehDebugger>>> = OnceLock::new();
static HIT_QUEUE: OnceLock<Mutex<VecDeque<BpHit>>> = OnceLock::new();

fn debugger_slot() -> &'static Mutex<Option<VehDebugger>> {
    DEBUGGER.get_or_init(|| Mutex::new(None))
}
fn hit_queue() -> &'static Mutex<VecDeque<BpHit>> {
    HIT_QUEUE.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn push_hit(hit: BpHit) {
    if let Ok(mut q) = hit_queue().lock() {
        if q.len() >= 1024 {
            q.pop_front();
        }
        q.push_back(hit);
    }
}

fn make_sink() -> crate::debugger::HitSink {
    Box::new(push_hit)
}

#[unsafe(no_mangle)]
pub extern "system" fn InitializeVEH() -> BOOL {
    let mut slot = match debugger_slot().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    if slot.is_some() {
        return 1;
    }
    match VehDebugger::new() {
        Some(dbg) => {
            *slot = Some(dbg);
            1
        }
        None => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn UninitializeVEH() -> BOOL {
    let mut slot = match debugger_slot().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    *slot = None;
    1
}

#[unsafe(no_mangle)]
pub extern "system" fn UnloadVEH() -> BOOL {
    UninitializeVEH()
}

#[unsafe(no_mangle)]
pub extern "system" fn veh_set_sw_bp(address: u64) -> u64 {
    let slot = match debugger_slot().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    match slot.as_ref() {
        Some(dbg) => dbg
            .set_sw_bp(address as usize, Some(make_sink()))
            .map(|id| id.0)
            .unwrap_or(0),
        None => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn veh_set_hw_bp(address: u64, dr_index: u32, access: u32, size: u32) -> u64 {
    let slot = match debugger_slot().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let dbg = match slot.as_ref() {
        Some(d) => d,
        None => return 0,
    };
    let acc = match access {
        0 => HwBpAccess::Execute,
        1 => HwBpAccess::Write,
        3 => HwBpAccess::ReadWrite,
        _ => return 0,
    };
    let sz = match size {
        0 => HwBpSize::One,
        1 => HwBpSize::Two,
        2 => HwBpSize::Eight,
        3 => HwBpSize::Four,
        _ => return 0,
    };
    dbg.set_hw_bp(address, dr_index as u8, acc, sz, Some(make_sink()))
        .map(|id| id.0)
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "system" fn veh_remove_bp(id: u64) -> BOOL {
    let slot = match debugger_slot().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    match slot.as_ref() {
        Some(dbg) if dbg.remove(BreakpointId(id)) => 1,
        _ => 0,
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn veh_poll_hit(out: *mut BpHit) -> BOOL {
    if out.is_null() {
        return 0;
    }
    let mut q = match hit_queue().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    match q.pop_front() {
        Some(h) => {
            unsafe {
                std::ptr::write(out, h);
            }
            1
        }
        None => 0,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    hinstDLL: HMODULE,
    fdwReason: DWORD,
    _lpReserved: LPVOID,
) -> BOOL {
    if fdwReason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(hinstDLL);
    }
    1
}
