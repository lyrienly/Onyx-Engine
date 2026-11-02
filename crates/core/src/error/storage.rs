//! OnyxEngine - Thread-Safe Error State and Active Locale Management

use super::codes::OnyxErrorCode;
use super::context::OnyxError;
use super::locale::OnyxLocale;
use std::cell::RefCell;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

static GLOBAL_LOCALE: AtomicU32 = AtomicU32::new(1); // 1 = PtBr (default)
static GLOBAL_LAST_ERROR: Mutex<Option<OnyxError>> = Mutex::new(None);

thread_local! {
    static TL_LAST_ERROR: RefCell<Option<OnyxError>> = const { RefCell::new(None) };
}

/// Set active language for error formatting (0 = EnUs, 1 = PtBr).
pub fn set_locale(locale: OnyxLocale) {
    GLOBAL_LOCALE.store(locale.as_u32(), Ordering::Relaxed);
}

/// Get active language for error formatting.
pub fn get_locale() -> OnyxLocale {
    OnyxLocale::from_u32(GLOBAL_LOCALE.load(Ordering::Relaxed))
}

/// Record an error into thread-local and global storage.
pub fn set_last_error(err: OnyxError) {
    TL_LAST_ERROR.with(|tl| {
        *tl.borrow_mut() = Some(err.clone());
    });
    if let Ok(mut lock) = GLOBAL_LAST_ERROR.lock() {
        *lock = Some(err);
    }
}

/// Get the most recent error from thread-local storage, falling back to global.
pub fn get_last_error() -> Option<OnyxError> {
    let tl = TL_LAST_ERROR.with(|tl| tl.borrow().clone());
    if tl.is_some() {
        return tl;
    }
    GLOBAL_LAST_ERROR.lock().ok().and_then(|guard| guard.clone())
}

/// Get the most recent error code.
pub fn get_last_error_code() -> OnyxErrorCode {
    get_last_error()
        .map(|e| e.code)
        .unwrap_or(OnyxErrorCode::Success)
}

/// Clear thread-local and global error states.
pub fn clear_last_error() {
    TL_LAST_ERROR.with(|tl| {
        *tl.borrow_mut() = None;
    });
    if let Ok(mut lock) = GLOBAL_LAST_ERROR.lock() {
        *lock = None;
    }
}
