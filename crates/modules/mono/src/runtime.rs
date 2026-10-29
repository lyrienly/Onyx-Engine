//! Deteccao de runtime (Mono classic, IL2CPP, UnityPlayer, nenhum).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonoRuntime {
    /// Mono tradicional, com DLL exportando mono_* APIs.
    MonoClassic {
        /// Nome do modulo (mono.dll / mono-2.0-bdwgc.dll / mono-2.0-sgen.dll / mono-2.0.dll).
        module: String,
        /// Versao do runtime quando pode ser inferida a partir do nome; None caso contrario.
        version: Option<String>,
    },
    /// Jogo Unity compilado via IL2CPP: contem GameAssembly.dll e NAO expoe mono-*.
    Il2Cpp {
        /// Normalmente "GameAssembly.dll".
        module: String,
        /// Nome do modulo UnityPlayer quando presente.
        unity_player: Option<String>,
    },
    /// Processo Unity sem managed runtime detectavel (so UnityPlayer).
    UnityPlayer { module: String },
    /// Nenhum runtime gerenciado detectado.
    None,
}

impl MonoRuntime {
    pub fn label(&self) -> &'static str {
        match self {
            MonoRuntime::MonoClassic { .. } => "Mono Classic",
            MonoRuntime::Il2Cpp { .. } => "IL2CPP",
            MonoRuntime::UnityPlayer { .. } => "UnityPlayer",
            MonoRuntime::None => "None",
        }
    }
}

/// Lista de nomes de DLL do Mono classic reconhecidos.
pub const MONO_MODULE_CANDIDATES: &[&str] = &[
    "mono-2.0-bdwgc.dll",
    "mono-2.0-sgen.dll",
    "mono-2.0.dll",
    "mono.dll",
];

/// Nome da DLL de codigo nativo gerada pelo compilador IL2CPP.
pub const IL2CPP_MODULE: &str = "GameAssembly.dll";

/// DLL do runtime proprio da Unity.
pub const UNITY_PLAYER_MODULE: &str = "UnityPlayer.dll";

fn eq_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Deteccao pura (sem Win32): recebe os nomes dos modulos carregados pelo alvo
/// e devolve o veredito. Util para testar sem precisar de processo real.
pub fn detect_from_module_names<I, S>(modules: I) -> MonoRuntime
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let names: Vec<String> = modules
        .into_iter()
        .map(|s| s.as_ref().to_string())
        .collect();

    let has_mono = names
        .iter()
        .find(|n| MONO_MODULE_CANDIDATES.iter().any(|c| eq_ci(n, c)));
    let has_il2cpp = names.iter().find(|n| eq_ci(n, IL2CPP_MODULE));
    let has_unity = names.iter().find(|n| eq_ci(n, UNITY_PLAYER_MODULE));

    // IL2CPP so e valido na ausencia de mono-*: a existencia de uma DLL do Mono
    // sinaliza que o runtime real e o Mono classic (jogo pre-IL2CPP).
    if let Some(m) = has_il2cpp {
        if has_mono.is_none() {
            return MonoRuntime::Il2Cpp {
                module: m.clone(),
                unity_player: has_unity.cloned(),
            };
        }
    }

    if let Some(m) = has_mono {
        let version = infer_mono_version(m);
        return MonoRuntime::MonoClassic {
            module: m.clone(),
            version,
        };
    }

    if let Some(m) = has_unity {
        return MonoRuntime::UnityPlayer { module: m.clone() };
    }

    MonoRuntime::None
}

fn infer_mono_version(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    if lower.contains("2.0-bdwgc") {
        Some("2.0 (bdwgc)".to_string())
    } else if lower.contains("2.0-sgen") {
        Some("2.0 (sgen)".to_string())
    } else if lower.contains("2.0") {
        Some("2.0".to_string())
    } else {
        None
    }
}

/// Enumera os modulos carregados por um PID.
#[cfg(windows)]
pub fn module_names_of_pid(pid: u32) -> Result<Vec<String>, String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };

    unsafe {
        let snap: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap == INVALID_HANDLE_VALUE {
            return Err(format!("CreateToolhelp32Snapshot failed for pid {}", pid));
        }
        let mut me: MODULEENTRY32W = std::mem::zeroed();
        me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        let mut out = Vec::new();
        if Module32FirstW(snap, &mut me) != 0 {
            loop {
                let len = me
                    .szModule
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(me.szModule.len());
                let name = OsString::from_wide(&me.szModule[..len])
                    .to_string_lossy()
                    .to_string();
                if !name.is_empty() {
                    out.push(name);
                }
                if Module32NextW(snap, &mut me) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
        Ok(out)
    }
}

#[cfg(not(windows))]
pub fn module_names_of_pid(_pid: u32) -> Result<Vec<String>, String> {
    Err("module enumeration only implemented for Windows".to_string())
}

/// Detecta o runtime de um processo alvo pelo PID.
pub fn detect_mono_runtime(pid: u32) -> MonoRuntime {
    match module_names_of_pid(pid) {
        Ok(names) => detect_from_module_names(names),
        Err(_) => MonoRuntime::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_when_empty() {
        let r = detect_from_module_names::<_, &str>(std::iter::empty());
        assert_eq!(r, MonoRuntime::None);
    }

    #[test]
    fn detects_mono_classic_bdwgc() {
        let modules = vec!["kernel32.dll", "mono-2.0-bdwgc.dll", "UnityPlayer.dll"];
        let r = detect_from_module_names(modules);
        match r {
            MonoRuntime::MonoClassic { module, version } => {
                assert!(module.eq_ignore_ascii_case("mono-2.0-bdwgc.dll"));
                assert_eq!(version.as_deref(), Some("2.0 (bdwgc)"));
            }
            other => panic!("expected MonoClassic, got {:?}", other),
        }
    }

    #[test]
    fn detects_il2cpp_when_no_mono() {
        let modules = vec!["GameAssembly.dll", "UnityPlayer.dll", "kernel32.dll"];
        let r = detect_from_module_names(modules);
        match r {
            MonoRuntime::Il2Cpp {
                module,
                unity_player,
            } => {
                assert!(module.eq_ignore_ascii_case("GameAssembly.dll"));
                assert_eq!(
                    unity_player.as_deref().map(|s| s.to_ascii_lowercase()),
                    Some("unityplayer.dll".to_string())
                );
            }
            other => panic!("expected Il2Cpp, got {:?}", other),
        }
    }

    #[test]
    fn mono_wins_over_il2cpp() {
        // Alguns jogos trazem GameAssembly.dll como leftover; prevalece mono.
        let modules = vec!["GameAssembly.dll", "mono-2.0-sgen.dll"];
        let r = detect_from_module_names(modules);
        assert!(matches!(r, MonoRuntime::MonoClassic { .. }));
    }

    #[test]
    fn detects_unity_player_only() {
        let modules = vec!["UnityPlayer.dll", "kernel32.dll"];
        let r = detect_from_module_names(modules);
        assert!(matches!(r, MonoRuntime::UnityPlayer { .. }));
    }

    #[test]
    fn case_insensitive_match() {
        let modules = vec!["GAMEASSEMBLY.DLL"];
        let r = detect_from_module_names(modules);
        assert!(matches!(r, MonoRuntime::Il2Cpp { .. }));
    }
}
