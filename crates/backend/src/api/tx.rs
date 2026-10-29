use onyx_core::memory::transaction::MemoryTransaction;
use std::ffi::c_void;

#[no_mangle]
pub unsafe extern "C" fn onyx_tx_begin(pid: u32) -> *mut MemoryTransaction {
    match MemoryTransaction::begin(pid) {
        Ok(tx) => Box::into_raw(Box::new(tx)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_tx_write(
    tx: *mut MemoryTransaction,
    address: usize,
    buffer: *const c_void,
    size: usize,
) -> i32 {
    if tx.is_null() || buffer.is_null() || size == 0 {
        return 0;
    }
    let slice = std::slice::from_raw_parts(buffer as *const u8, size);
    match (*tx).write(address, slice) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_tx_protect(
    tx: *mut MemoryTransaction,
    address: usize,
    size: usize,
    new_protect: u32,
    out_old_protect: *mut u32,
) -> i32 {
    if tx.is_null() {
        return 0;
    }
    match (*tx).protect(address, size, new_protect) {
        Ok(old) => {
            if !out_old_protect.is_null() {
                *out_old_protect = old;
            }
            1
        }
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_tx_log_len(tx: *mut MemoryTransaction) -> u32 {
    if tx.is_null() {
        return 0;
    }
    (*tx).len() as u32
}

#[no_mangle]
pub unsafe extern "C" fn onyx_tx_commit(tx: *mut MemoryTransaction) -> i32 {
    if tx.is_null() {
        return 0;
    }
    let boxed = Box::from_raw(tx);
    boxed.commit();
    1
}

#[no_mangle]
pub unsafe extern "C" fn onyx_tx_rollback(tx: *mut MemoryTransaction) -> i32 {
    if tx.is_null() {
        return 0;
    }
    let boxed = Box::from_raw(tx);
    match boxed.rollback() {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_tx_free(tx: *mut MemoryTransaction) {
    if !tx.is_null() {
        drop(Box::from_raw(tx));
    }
}
