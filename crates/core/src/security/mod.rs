pub mod analysis_hunter;
pub mod anomaly_scanner;
pub mod anti_attach;
pub mod anti_debug;
pub mod anti_dump;
pub mod hook_detection;
pub mod pe_remap;
pub mod sk_crypt;
pub mod taskmgr_cloak;
pub mod window_shield;

pub use analysis_hunter::AnalysisHunter;
pub use anomaly_scanner::{AnomalyKind, MemoryAnomalyScanner, RegionAnomaly};
pub use anti_attach::AntiAttach;
pub use anti_debug::{AntiDebug, AntiDebugReport};
pub use anti_dump::AntiDump;
pub use hook_detection::{
    HookKind, HookReport, PatchRange, classify_hook, detect_patches, find_embedded_pe,
    scan_module_hooks,
};
pub use pe_remap::{PeRemap, SectionBounds};
pub use sk_crypt::SkCrypt;
pub use taskmgr_cloak::{TaskmgrCloakManager, filter_system_process_information};
pub use window_shield::WindowShield;

pub fn activate_process_shield() -> Result<(), String> {
    AntiAttach::enable()?;
    let _ = AntiDebug::hide_current_thread();
    let _ = AntiDump::distort_peb_size_of_image(0x100000);
    TaskmgrCloakManager::start_watcher();
    AnalysisHunter::start_monitor();
    WindowShield::protect_current_process(None);
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
