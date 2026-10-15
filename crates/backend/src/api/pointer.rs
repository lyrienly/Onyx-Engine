// OnyxEngine Pointer Scanner Backend API
// Multilevel pointer path resolution and deep scanning

use onyx_core::process::Process;
use onyx_core::pointer_scanner::{PointerPath, PointerScanner};

/// Resolves a pointer chain (base_addr + offsets)
/// Returns final resolved virtual address, or 0 if pointer chain is broken
#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_resolve(
    proc: *mut Process,
    base_addr: usize,
    offsets: *const usize,
    offset_count: usize,
) -> usize {
    if proc.is_null() || base_addr == 0 {
        return 0;
    }

    let p = &*proc;
    let mut current = base_addr;

    if offsets.is_null() || offset_count == 0 {
        return current;
    }

    let slice = std::slice::from_raw_parts(offsets, offset_count);
    for &offset in slice {
        match p.read::<usize>(current) {
            Ok(next_ptr) if next_ptr != 0 => {
                current = next_ptr + offset;
            }
            _ => return 0,
        }
    }

    current
}

/// Evaluates a PointerPath against the process
#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_eval_path(
    proc: *mut Process,
    module_name_ptr: *const std::os::raw::c_char,
    base_offset: usize,
    offsets: *const usize,
    offset_count: usize,
) -> usize {
    if proc.is_null() || module_name_ptr.is_null() {
        return 0;
    }

    let p = &*proc;
    let mod_name = std::ffi::CStr::from_ptr(module_name_ptr).to_string_lossy();
    let offset_slice = if offsets.is_null() || offset_count == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(offsets, offset_count).to_vec()
    };

    let path = PointerPath {
        module_name: mod_name.to_string(),
        base_offset,
        offsets: offset_slice,
        final_address: 0,
    };

    PointerScanner::evaluate_path(p, &path).unwrap_or(0)
}
