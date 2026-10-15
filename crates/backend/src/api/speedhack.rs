// OnyxEngine Speedhack Backend API
// Multiplier injection and QPC frequency scaling

use onyx_core::process::Process;
use onyx_core::speedhack::SpeedhackInjector;

static mut SPEEDHACK_INJECTOR: Option<SpeedhackInjector> = None;

#[no_mangle]
pub unsafe extern "C" fn onyx_speedhack_set(process: *mut Process, multiplier: f32) -> i32 {
    if process.is_null() {
        return 0;
    }

    let proc = &*process;
    if SPEEDHACK_INJECTOR.is_none() {
        SPEEDHACK_INJECTOR = Some(SpeedhackInjector::new());
    }

    if let Some(injector) = &mut SPEEDHACK_INJECTOR {
        match injector.enable_speedhack(proc, multiplier) {
            Ok(_) => 1,
            Err(_) => 0,
        }
    } else {
        0
    }
}
