//! OnyxEngine - Centralized Unified Error System
//! Standardized error codes, contextual error structs, PT-BR and EN localization.

pub mod codes;
pub mod context;
pub mod locale;
pub mod storage;

pub use codes::OnyxErrorCode;
pub use context::OnyxError;
pub use locale::OnyxLocale;
pub use storage::*;

pub type OnyxResult<T> = Result<T, OnyxError>;
#[cfg(test)]
mod tests {
    use crate::error::*;

    #[test]
    fn test_error_code_mapping() {
        assert_eq!(OnyxErrorCode::ProcessNotFound.as_u32(), 1001);
        assert_eq!(OnyxErrorCode::from_u32(1001), OnyxErrorCode::ProcessNotFound);
        assert_eq!(OnyxErrorCode::DriverNotConnected.as_u32(), 2001);
        assert_eq!(OnyxErrorCode::from_u32(2001), OnyxErrorCode::DriverNotConnected);
    }

    #[test]
    fn test_error_ptbr_and_en_localization() {
        let err = OnyxError::process_access_denied(1234, 5);
        assert_eq!(err.code, OnyxErrorCode::ProcessAccessDenied);
        assert!(err.message(OnyxLocale::PtBr).contains("Acesso negado"));
        assert!(err.message(OnyxLocale::EnUs).contains("Access denied"));

        let formatted_pt = err.format(OnyxLocale::PtBr);
        assert!(formatted_pt.starts_with("[ERRO 1002]"));
        assert!(formatted_pt.contains("Win32/NT: 0x5"));
    }

    #[test]
    fn test_thread_local_error_storage() {
        clear_last_error();
        assert_eq!(get_last_error_code(), OnyxErrorCode::Success);

        let err = OnyxError::memory_read_failed(0x7FFE0000, 64, 0x1E7);
        set_last_error(err.clone());

        assert_eq!(get_last_error_code(), OnyxErrorCode::MemoryReadFailed);
        let retrieved = get_last_error().expect("Should have last error");
        assert_eq!(retrieved.address, Some(0x7FFE0000));

        clear_last_error();
        assert_eq!(get_last_error_code(), OnyxErrorCode::Success);
        assert!(get_last_error().is_none());
    }

    #[test]
    fn test_from_onyx_error_to_string() {
        set_locale(OnyxLocale::PtBr);
        let err = OnyxError::driver_not_connected();
        let s: String = err.into();
        assert!(s.contains("[ERRO 2001]"));
        assert!(s.contains("OwMemDriver não está conectado"));
    }
}
