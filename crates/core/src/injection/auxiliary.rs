use crate::injection::manual_map::{ManualMapOptions, ManualMapResult, ManualMapper};
use crate::process::Process;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuxiliaryModule {
    VehDebug,
    Speedhack,
    D3dHook,
    AllocHook,
}

impl AuxiliaryModule {
    pub fn default_filename(&self) -> &'static str {
        match self {
            Self::VehDebug => "vehdebug.dll",
            Self::Speedhack => "speedhack.dll",
            Self::D3dHook => "d3dhook.dll",
            Self::AllocHook => "allochook.dll",
        }
    }
}

pub struct AuxiliaryInjector;

impl AuxiliaryInjector {
    pub fn default_evasive_options() -> ManualMapOptions {
        ManualMapOptions {
            wipe_headers: true,
            erase_discardable_sections: true,
            execute_tls: true,
            call_dllmain: true,
            protect_sections: true,
            timeout_ms: 5000,
        }
    }

    pub fn inject_payload(
        proc: &Process,
        dll_bytes: &[u8],
        options: Option<ManualMapOptions>,
    ) -> Result<ManualMapResult, String> {
        let opts = options.unwrap_or_else(Self::default_evasive_options);
        ManualMapper::inject(proc, dll_bytes, &opts)
    }

    pub fn inject_from_file(
        proc: &Process,
        dll_path: &str,
        options: Option<ManualMapOptions>,
    ) -> Result<ManualMapResult, String> {
        let bytes = std::fs::read(dll_path)
            .map_err(|e| format!("Failed to read auxiliary DLL '{}': {}", dll_path, e))?;
        Self::inject_payload(proc, &bytes, options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auxiliary_filenames() {
        assert_eq!(AuxiliaryModule::VehDebug.default_filename(), "vehdebug.dll");
        assert_eq!(
            AuxiliaryModule::Speedhack.default_filename(),
            "speedhack.dll"
        );
        assert_eq!(AuxiliaryModule::D3dHook.default_filename(), "d3dhook.dll");
        assert_eq!(
            AuxiliaryModule::AllocHook.default_filename(),
            "allochook.dll"
        );
    }

    #[test]
    fn test_default_evasive_options() {
        let opts = AuxiliaryInjector::default_evasive_options();
        assert!(opts.wipe_headers);
        assert!(opts.erase_discardable_sections);
        assert!(opts.execute_tls);
        assert!(opts.call_dllmain);
        assert!(opts.protect_sections);
        assert_eq!(opts.timeout_ms, 5000);
    }
}
