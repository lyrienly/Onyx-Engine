
use std::fs::OpenOptions;
use std::io::Write;
use onyx_core::process::Process;

#[no_mangle]
pub unsafe extern "C" fn onyx_speedhack_init(process: *mut Process, initial_speed: f32) -> i32 {
    if process.is_null() {
        return 0;
    }
    let p = &*process;
    match p.inject_dll("speedhack_dll.dll") {
        Ok(_) => {

            std::thread::sleep(std::time::Duration::from_millis(50));
            let _ = onyx_speedhack_set(process, initial_speed);
            1
        }
        Err(e) => {
            eprintln!("[Onyx Speedhack] Injection failed: {}", e);
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_speedhack_set(process: *mut Process, multiplier: f32) -> i32 {
    if process.is_null() {
        return 0;
    }
    let p = &*process;
    let pipe_name = format!("\\\\.\\pipe\\ce_speedhack_{}", p.pid);
    if let Ok(mut pipe) = OpenOptions::new().write(true).open(&pipe_name) {
        if pipe.write_all(&multiplier.to_le_bytes()).is_ok() {
            return 1;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn onyx_speedhack_is_active(process: *mut Process) -> i32 {
    if process.is_null() {
        return 0;
    }
    let p = &*process;
    let pipe_name = format!("\\\\.\\pipe\\ce_speedhack_{}", p.pid);
    if OpenOptions::new().write(true).open(&pipe_name).is_ok() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_speedhack_reset(process: *mut Process) -> i32 {
    onyx_speedhack_set(process, 1.0)
}

