// OnyxEngine Mono & .NET CLR Dissector Backend API
// Runtime inspection, assembly dissection, and class hierarchy extraction

use onyx_core::mono::{MonoDissector, RuntimeType};
use onyx_core::process::Process;

static mut GLOBAL_DISSECTOR: Option<MonoDissector> = None;

/// Detect runtime type: 0 = None, 1 = Mono, 2 = .NET CLR, 3 = Unity IL2CPP
#[no_mangle]
pub unsafe extern "C" fn onyx_mono_detect(process: *mut Process) -> i32 {
    if process.is_null() {
        return 0;
    }

    let proc = &*process;
    let (rt, _) = MonoDissector::detect_runtime(proc);
    match rt {
        RuntimeType::None => 0,
        RuntimeType::Mono => 1,
        RuntimeType::DotNetClr => 2,
        RuntimeType::Il2Cpp => 3,
    }
}

/// Dissect assemblies and classes for the active runtime
/// Returns total number of classes discovered
#[no_mangle]
pub unsafe extern "C" fn onyx_mono_dissect(process: *mut Process) -> i32 {
    if process.is_null() {
        return 0;
    }

    let proc = &*process;
    let mut dissector = MonoDissector::new();
    let _ = dissector.attach(proc);
    match dissector.dissect(proc) {
        Ok(count) => {
            GLOBAL_DISSECTOR = Some(dissector);
            count as i32
        }
        Err(_) => 0,
    }
}

/// Get number of classes found in last dissection
#[no_mangle]
pub unsafe extern "C" fn onyx_mono_class_count() -> i32 {
    if let Some(d) = &GLOBAL_DISSECTOR {
        d.assemblies.iter().map(|a| a.classes.len()).sum::<usize>() as i32
    } else {
        0
    }
}
