//! OnyxEngine - Error Management C-ABI Interface
//! Exposes error query, formatting, and localization services to the Lazarus/Pascal UI and external clients.

use onyx_core::error::{
    clear_last_error, get_last_error, get_last_error_code, get_locale, set_last_error, set_locale,
    OnyxError, OnyxErrorCode, OnyxLocale,
};
use std::ffi::{c_char, CStr};
use std::slice;

/// Get the code of the most recent error.
#[no_mangle]
pub unsafe extern "C" fn onyx_error_get_last_code() -> u32 {
    get_last_error_code().as_u32()
}

/// Retrieve the localized message of the most recent error.
/// Returns the number of bytes written to `out_buf` (including null terminator).
#[no_mangle]
pub unsafe extern "C" fn onyx_error_get_last_message(
    out_buf: *mut c_char,
    max_len: u32,
) -> u32 {
    if out_buf.is_null() || max_len == 0 {
        return 0;
    }

    let locale = get_locale();
    let msg = match get_last_error() {
        Some(err) => err.message(locale).to_string(),
        None => match locale {
            OnyxLocale::PtBr => "Operação concluída com sucesso.".to_string(),
            OnyxLocale::EnUs => "Operation completed successfully.".to_string(),
        },
    };

    let bytes = msg.as_bytes();
    let write_len = bytes.len().min((max_len as usize) - 1);
    let slice_out = slice::from_raw_parts_mut(out_buf as *mut u8, max_len as usize);
    slice_out[..write_len].copy_from_slice(&bytes[..write_len]);
    slice_out[write_len] = 0;

    (write_len + 1) as u32
}

/// Retrieve the full formatted diagnostic string of the most recent error (code, message, context, Win32 status).
#[no_mangle]
pub unsafe extern "C" fn onyx_error_get_last_formatted(
    out_buf: *mut c_char,
    max_len: u32,
) -> u32 {
    if out_buf.is_null() || max_len == 0 {
        return 0;
    }

    let locale = get_locale();
    let formatted = match get_last_error() {
        Some(err) => err.format(locale),
        None => match locale {
            OnyxLocale::PtBr => "[SUCESSO 0000] Nenhuma falha registrada.".to_string(),
            OnyxLocale::EnUs => "[SUCCESS 0000] No error recorded.".to_string(),
        },
    };

    let bytes = formatted.as_bytes();
    let write_len = bytes.len().min((max_len as usize) - 1);
    let slice_out = slice::from_raw_parts_mut(out_buf as *mut u8, max_len as usize);
    slice_out[..write_len].copy_from_slice(&bytes[..write_len]);
    slice_out[write_len] = 0;

    (write_len + 1) as u32
}

/// Set the active locale: 0 = en-US, 1 = pt-BR (default).
#[no_mangle]
pub unsafe extern "C" fn onyx_error_set_locale(locale_code: u32) {
    set_locale(OnyxLocale::from_u32(locale_code));
}

/// Get the active locale: 0 = en-US, 1 = pt-BR.
#[no_mangle]
pub unsafe extern "C" fn onyx_error_get_locale() -> u32 {
    get_locale().as_u32()
}

/// Clear the last error state.
#[no_mangle]
pub unsafe extern "C" fn onyx_error_clear() {
    clear_last_error();
}

/// Set a custom error from external plugins or UI.
#[no_mangle]
pub unsafe extern "C" fn onyx_error_set_custom(
    code: u32,
    msg_en: *const c_char,
    msg_pt: *const c_char,
) {
    let en = if !msg_en.is_null() {
        CStr::from_ptr(msg_en).to_string_lossy().to_string()
    } else {
        "Unknown error".to_string()
    };

    let pt = if !msg_pt.is_pt_null_check(msg_pt) {
        CStr::from_ptr(msg_pt).to_string_lossy().to_string()
    } else {
        "Erro desconhecido".to_string()
    };

    let err = OnyxError::new(OnyxErrorCode::from_u32(code), en, pt);
    set_last_error(err);
}

trait PtrNullExt {
    fn is_pt_null_check(&self, ptr: *const c_char) -> bool;
}

impl PtrNullExt for *const c_char {
    fn is_pt_null_check(&self, ptr: *const c_char) -> bool {
        ptr.is_null()
    }
}
