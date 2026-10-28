pub mod taskmgr_cloak;
pub mod anti_attach;
pub mod anti_debug;
pub mod anti_dump;

pub use taskmgr_cloak::{TaskmgrCloakManager, filter_system_process_information};
pub use anti_attach::AntiAttach;
pub use anti_debug::{AntiDebug, AntiDebugReport};
pub use anti_dump::AntiDump;

pub fn activate_process_shield() -> Result<(), String> {
    AntiAttach::enable()?;
    let _ = AntiDebug::hide_current_thread();
    let _ = AntiDump::distort_peb_size_of_image(0x100000);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activate_process_shield() {
        let res = activate_process_shield();
        assert!(res.is_ok());
    }
}
