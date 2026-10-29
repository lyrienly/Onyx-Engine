use onyx_core::mono::{MonoDissector, RuntimeType};
use onyx_core::process::Process;
use std::ffi::CStr;
use std::os::raw::c_char;

static mut GLOBAL_DISSECTOR: Option<MonoDissector> = None;

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

#[no_mangle]
pub unsafe extern "C" fn onyx_mono_class_count() -> i32 {
    if let Some(d) = &GLOBAL_DISSECTOR {
        d.assemblies.iter().map(|a| a.classes.len()).sum::<usize>() as i32
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_mono_get_class_info(
    index: i32,
    out_name: *mut c_char,
    max_len: u32,
    out_addr: *mut usize,
    out_fields_count: *mut u32,
) -> i32 {
    if out_name.is_null() || max_len == 0 || index < 0 {
        return 0;
    }

    let d = match &GLOBAL_DISSECTOR {
        Some(d) => d,
        None => return 0,
    };

    let mut cur = 0;
    for asm in &d.assemblies {
        for cls in &asm.classes {
            if cur == index {
                let bytes = cls.full_name.as_bytes();
                let copy_len = bytes.len().min((max_len - 1) as usize);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_name as *mut u8, copy_len);
                *out_name.add(copy_len) = 0;

                if !out_addr.is_null() {
                    *out_addr = cls.class_address;
                }
                if !out_fields_count.is_null() {
                    *out_fields_count = cls.fields.len() as u32;
                }
                return 1;
            }
            cur += 1;
        }
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn onyx_mono_find_field_offset(
    class_name: *const c_char,
    field_name: *const c_char,
) -> i32 {
    if class_name.is_null() || field_name.is_null() {
        return -1;
    }

    let d = match &GLOBAL_DISSECTOR {
        Some(d) => d,
        None => return -1,
    };

    let c_str = CStr::from_ptr(class_name).to_string_lossy().to_lowercase();
    let f_str = CStr::from_ptr(field_name).to_string_lossy().to_lowercase();

    for asm in &d.assemblies {
        for cls in &asm.classes {
            if cls.name.to_lowercase() == c_str || cls.full_name.to_lowercase() == c_str {
                for field in &cls.fields {
                    if field.name.to_lowercase() == f_str {
                        return field.offset as i32;
                    }
                }
            }
        }
    }

    -1
}

#[no_mangle]
pub unsafe extern "C" fn onyx_mono_find_method_address(
    class_name: *const c_char,
    method_name: *const c_char,
) -> usize {
    if class_name.is_null() || method_name.is_null() {
        return 0;
    }

    let d = match &GLOBAL_DISSECTOR {
        Some(d) => d,
        None => return 0,
    };

    let c_str = CStr::from_ptr(class_name).to_string_lossy().to_lowercase();
    let m_str = CStr::from_ptr(method_name).to_string_lossy().to_lowercase();

    for asm in &d.assemblies {
        for cls in &asm.classes {
            if cls.name.to_lowercase() == c_str || cls.full_name.to_lowercase() == c_str {
                for method in &cls.methods {
                    if method.name.to_lowercase() == m_str {
                        return method.address;
                    }
                }
            }
        }
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn onyx_mono_generate_hook(
    method_name: *const c_char,
    method_addr: usize,
    out_script: *mut c_char,
    max_len: u32,
) -> i32 {
    if method_name.is_null() || out_script.is_null() || max_len == 0 {
        return 0;
    }

    let m_name = CStr::from_ptr(method_name).to_string_lossy();
    let script = MonoDissector::generate_method_hook_script(&m_name, method_addr);
    let bytes = script.as_bytes();
    let copy_len = bytes.len().min((max_len - 1) as usize);

    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_script as *mut u8, copy_len);
    *out_script.add(copy_len) = 0;
    1
}

#[no_mangle]
pub unsafe extern "C" fn onyx_mono_compile_method(
    process: *mut Process,
    class_name: *const c_char,
    method_name: *const c_char,
) -> usize {
    if class_name.is_null() || method_name.is_null() {
        return 0;
    }

    let d = match &GLOBAL_DISSECTOR {
        Some(d) => d,
        None => return 0,
    };

    let c_str = CStr::from_ptr(class_name).to_string_lossy();
    let m_str = CStr::from_ptr(method_name).to_string_lossy();

    if !process.is_null() {
        let proc = &*process;
        d.force_jit_compile(proc, &c_str, &m_str).unwrap_or(0)
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_mono_read_field_value(
    process: *mut Process,
    instance_address: usize,
    class_name: *const c_char,
    field_name: *const c_char,
    out_val: *mut c_char,
    max_len: u32,
) -> i32 {
    if process.is_null()
        || class_name.is_null()
        || field_name.is_null()
        || out_val.is_null()
        || max_len == 0
    {
        return 0;
    }

    let d = match &GLOBAL_DISSECTOR {
        Some(d) => d,
        None => return 0,
    };

    let proc = &*process;
    let c_str = CStr::from_ptr(class_name).to_string_lossy().to_lowercase();
    let f_str = CStr::from_ptr(field_name).to_string_lossy().to_lowercase();

    for asm in &d.assemblies {
        for cls in &asm.classes {
            if cls.name.to_lowercase() == c_str || cls.full_name.to_lowercase() == c_str {
                for field in &cls.fields {
                    if field.name.to_lowercase() == f_str {
                        let val_str =
                            MonoDissector::read_field_value(proc, instance_address, field);
                        let bytes = val_str.as_bytes();
                        let copy_len = bytes.len().min((max_len - 1) as usize);
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_val as *mut u8, copy_len);
                        *out_val.add(copy_len) = 0;
                        return 1;
                    }
                }
            }
        }
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn onyx_mono_get_assembly_count() -> i32 {
    if let Some(d) = &GLOBAL_DISSECTOR {
        d.assemblies.len() as i32
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_mono_get_assembly_name(
    index: i32,
    out_name: *mut c_char,
    max_len: u32,
) -> i32 {
    if out_name.is_null() || max_len == 0 || index < 0 {
        return 0;
    }

    let d = match &GLOBAL_DISSECTOR {
        Some(d) => d,
        None => return 0,
    };

    if let Some(asm) = d.assemblies.get(index as usize) {
        let bytes = asm.name.as_bytes();
        let copy_len = bytes.len().min((max_len - 1) as usize);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_name as *mut u8, copy_len);
        *out_name.add(copy_len) = 0;
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_mono_dissect_clr_object(
    process: *mut Process,
    object_address: usize,
    out_mt: *mut usize,
    out_eeclass: *mut usize,
    out_size: *mut u32,
) -> i32 {
    if process.is_null() || object_address == 0 {
        return 0;
    }

    let proc = &*process;
    match MonoDissector::dissect_clr_object(proc, object_address) {
        Ok(info) => {
            if !out_mt.is_null() {
                *out_mt = info.address;
            }
            if !out_eeclass.is_null() {
                *out_eeclass = info.ee_class;
            }
            if !out_size.is_null() {
                *out_size = info.base_size;
            }
            1
        }
        Err(_) => 0,
    }
}
