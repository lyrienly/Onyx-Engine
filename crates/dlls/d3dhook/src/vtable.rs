use std::ffi::c_void;
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect,
};

pub unsafe fn patch_slot(slot: *mut *mut c_void, detour: *mut c_void) -> *mut c_void {
    let orig = *slot;
    let mut old = PAGE_PROTECTION_FLAGS(0);
    let _ = VirtualProtect(
        slot as *const c_void,
        size_of::<*mut c_void>(),
        PAGE_EXECUTE_READWRITE,
        &mut old,
    );
    *slot = detour;
    let mut back = PAGE_PROTECTION_FLAGS(0);
    let _ = VirtualProtect(slot as *const c_void, size_of::<*mut c_void>(), old, &mut back);
    orig
}

pub unsafe fn restore_slot(slot: *mut *mut c_void, original: *mut c_void) {
    let _ = patch_slot(slot, original);
}

pub unsafe fn vtable_of<T>(obj: *mut T) -> *mut *mut c_void {
    *(obj as *mut *mut *mut c_void)
}
