use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};
use onyx_core::debugger::{
    BreakpointSize, BreakpointType, HardwareBreakpointMonitor, HwBpError, VehDebugger,
};
use onyx_core::process::Process;
use crate::types::{OnyxVehHit, OnyxVehSlot};

static GLOBAL_VEH: Mutex<Option<VehDebugger>> = Mutex::new(None);

fn lock_veh() -> MutexGuard<'static, Option<VehDebugger>> {
    GLOBAL_VEH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn ensure_veh<'a>(
    guard: &'a mut MutexGuard<'static, Option<VehDebugger>>,
    pid: u32,
) -> &'a mut VehDebugger {
    let needs_reset = match guard.as_ref() {
        Some(veh) => veh.target_pid != pid,
        None => true,
    };

    if needs_reset {
        **guard = Some(VehDebugger::new(pid));
    }

    guard
        .as_mut()
        .expect("VehDebugger was created above when missing")
}

fn map_bp_type(val: i32) -> BreakpointType {
    match val {
        0 => BreakpointType::Execute,
        1 => BreakpointType::Write,
        _ => BreakpointType::ReadWrite,
    }
}

fn map_bp_size(val: i32) -> BreakpointSize {
    match val {
        1 => BreakpointSize::Byte1,
        2 => BreakpointSize::Byte2,
        8 => BreakpointSize::Byte8,
        _ => BreakpointSize::Byte4,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_veh_inject(
    process: *mut Process,
    dll_path: *const c_char,
) -> i32 {
    if process.is_null() {
        return 0;
    }
    let p = &*process;
    let path = if dll_path.is_null() {
        "vehdebug-x86_64.dll"
    } else {
        match CStr::from_ptr(dll_path).to_str() {
            Ok(s) if !s.is_empty() => s,
            _ => "vehdebug-x86_64.dll",
        }
    };

    match p.inject_dll(path) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_veh_init(process: *mut Process) -> i32 {
    if process.is_null() {
        return 0;
    }
    let p = &*process;
    let mut guard = lock_veh();
    *guard = Some(VehDebugger::new(p.pid));
    1
}

#[no_mangle]
pub unsafe extern "C" fn onyx_veh_set_hw_bp(
    process: *mut Process,
    address: usize,
    bp_type: i32,
    size: i32,
) -> i32 {
    if process.is_null() {
        return HwBpError::ThreadFailure.code();
    }
    let p = &*process;
    let b_type = map_bp_type(bp_type);
    let b_size = map_bp_size(size);

    let mut guard = lock_veh();
    let veh = ensure_veh(&mut guard, p.pid);

    match veh.set_stealth_breakpoint(p, address, b_type, b_size) {
        Ok(index) => index as i32,
        Err(error) => error.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_veh_clear_hw_bp(process: *mut Process, index: usize) -> i32 {
    if process.is_null() {
        return HwBpError::ThreadFailure.code();
    }
    let p = &*process;

    let mut guard = lock_veh();
    let veh = match guard.as_mut() {
        Some(veh) if veh.target_pid == p.pid => veh,
        _ => return HwBpError::InvalidSlot.code(),
    };

    match veh.clear_stealth_breakpoint(p, index) {
        Ok(_) => 1,
        Err(error) => error.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_veh_poll_hit(
    process: *mut Process,
    out_rip: *mut usize,
    out_thread_id: *mut u32,
) -> i32 {
    if process.is_null() {
        return 0;
    }
    let p = &*process;
    let guard = lock_veh();
    let veh = match guard.as_ref() {
        Some(veh) if veh.target_pid == p.pid => veh,
        _ => return 0,
    };

    if let Some((tid, rip)) = veh.poll_hit(p) {
        if !out_rip.is_null() {
            *out_rip = rip;
        }
        if !out_thread_id.is_null() {
            *out_thread_id = tid;
        }
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_veh_monitor_address(
    process: *mut Process,
    address: usize,
    bp_type: i32,
    size: i32,
    duration_secs: u64,
    out_hits: *mut OnyxVehHit,
    max_hits: u32,
    out_count: *mut u32,
) -> i32 {
    if process.is_null() || out_hits.is_null() || max_hits == 0 {
        return HwBpError::ThreadFailure.code();
    }
    let p = &*process;
    let b_type = map_bp_type(bp_type);
    let b_size = map_bp_size(size);
    let stop = Arc::new(AtomicBool::new(false));

    let slot = {
        let mut guard = lock_veh();
        let veh = ensure_veh(&mut guard, p.pid);
        veh.reserve_slot(address, b_type, b_size)
    };

    let slot = match slot {
        Ok(slot) => slot,
        Err(error) => return error.code(),
    };

    let monitored = HardwareBreakpointMonitor::monitor_address(
        p,
        slot,
        address,
        b_type,
        b_size,
        duration_secs,
        stop,
    );

    {
        let mut guard = lock_veh();
        if let Some(veh) = guard.as_mut() {
            if veh.target_pid == p.pid {
                let _ = veh.release_slot(slot);
            }
        }
    }

    match monitored {
        Ok(hits) => {
            let write_len = hits.len().min(max_hits as usize);
            for i in 0..write_len {
                let hit = &hits[i];
                let mut c_hit = OnyxVehHit::empty();
                c_hit.instruction_address = hit.instruction_address;
                c_hit.count = hit.count;
                c_hit.last_rax = hit.last_rax;
                c_hit.last_rbx = hit.last_rbx;
                c_hit.last_rcx = hit.last_rcx;
                c_hit.last_rdx = hit.last_rdx;
                c_hit.last_rsi = hit.last_rsi;
                c_hit.last_rdi = hit.last_rdi;
                c_hit.last_rsp = hit.last_rsp;
                c_hit.last_rbp = hit.last_rbp;

                let text_bytes = hit.instruction_text.as_bytes();
                let copy_len = text_bytes.len().min(63);
                c_hit.instruction_text[..copy_len].copy_from_slice(&text_bytes[..copy_len]);
                c_hit.instruction_text[copy_len] = 0;

                *out_hits.add(i) = c_hit;
            }

            if !out_count.is_null() {
                *out_count = hits.len() as u32;
            }
            1
        }
        Err(_) => HwBpError::ThreadFailure.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_veh_slot_status(
    process: *mut Process,
    out_slots: *mut OnyxVehSlot,
    max_slots: u32,
    out_count: *mut u32,
) -> i32 {
    if process.is_null() {
        return 0;
    }
    let p = &*process;

    let guard = lock_veh();
    let veh = match guard.as_ref() {
        Some(veh) if veh.target_pid == p.pid => veh,
        _ => {
            if !out_count.is_null() {
                *out_count = 0;
            }
            return 0;
        }
    };

    let mut used = 0u32;
    for (index, slot) in veh.slots().iter().enumerate() {
        let Some(slot) = slot else { continue };

        if used < max_slots && !out_slots.is_null() {
            *out_slots.add(used as usize) = OnyxVehSlot {
                index: index as u32,
                address: slot.address,
                bp_type: slot.bp_type as i32,
                size: slot.size.byte_size() as i32,
            };
        }
        used += 1;
    }

    if !out_count.is_null() {
        *out_count = used;
    }

    used as i32
}

#[no_mangle]
pub unsafe extern "C" fn onyx_veh_verify_slots(process: *mut Process) -> i32 {
    if process.is_null() {
        return HwBpError::ThreadFailure.code();
    }
    let p = &*process;

    let guard = lock_veh();
    let veh = match guard.as_ref() {
        Some(veh) if veh.target_pid == p.pid => veh,

        _ => return 1,
    };

    match veh.verify_slots(p) {
        Ok(mismatches) if mismatches.is_empty() => 1,
        Ok(_) => 0,
        Err(error) => error.code(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_veh_cleanup() {
    *lock_veh() = None;
}
