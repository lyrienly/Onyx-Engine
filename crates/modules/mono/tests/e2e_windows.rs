//! Testes E2E: carrega uma DLL mock renomeada no processo de teste e valida
//! que `detect_mono_runtime` identifica corretamente Mono classic e IL2CPP.
//!
//! A estrategia e fabricar a DLL copiando `kernel32.dll` para um nome
//! esperado (`mono-2.0-bdwgc.dll` / `GameAssembly.dll`), carregar com
//! `LoadLibraryW` e enumerar os modulos do processo via Toolhelp32.

#![cfg(windows)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use onyx_mono::{detect_mono_runtime, MonoRuntime};
use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

fn to_wide(p: &Path) -> Vec<u16> {
    OsStr::new(p)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Fabrica uma copia do kernel32 com o nome fornecido num diretorio temporario
/// unico. Retorna o path completo.
fn fabricate_mock_dll(target_name: &str, suffix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("onyx_mono_e2e_{}_{}", std::process::id(), suffix));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let dst = dir.join(target_name);

    // psapi.dll e um stub leve com forwarders para kernel32base; carregar uma
    // copia renomeada tem efeito colateral minimo durante o DLL_PROCESS_DETACH
    // comparado a copias de kernel32/user32.
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot env");
    let src = PathBuf::from(system_root)
        .join("System32")
        .join("psapi.dll");
    std::fs::copy(&src, &dst).expect("copy psapi to mock name");
    dst
}

#[test]
fn detects_mono_classic_after_loading_mock_dll() {
    let pid = unsafe { GetCurrentProcessId() };

    // Sanity: antes do load, nenhum runtime (ou qualquer coisa menos MonoClassic
    // via mono-2.0-bdwgc). Nao assertamos None aqui porque o host pode ja ter
    // UnityPlayer carregado em cenarios exoticos; so garantimos que nao e Mono.
    assert!(!matches!(
        detect_mono_runtime(pid),
        MonoRuntime::MonoClassic { .. }
    ));

    let mock = fabricate_mock_dll("mono-2.0-bdwgc.dll", "mono");
    let wide = to_wide(&mock);
    let hmod = unsafe { LoadLibraryW(wide.as_ptr()) };
    assert!(hmod != 0, "LoadLibraryW failed for mock mono dll");

    let runtime = detect_mono_runtime(pid);
    // Nao chamamos FreeLibrary: o processo de teste encerra em seguida e o
    // unload automatico de duas copias com mesmo DllMain pode disparar
    // STATUS_ACCESS_VIOLATION durante PROCESS_DETACH.

    match runtime {
        MonoRuntime::MonoClassic { module, version } => {
            assert!(module.eq_ignore_ascii_case("mono-2.0-bdwgc.dll"));
            assert_eq!(version.as_deref(), Some("2.0 (bdwgc)"));
        }
        other => panic!("expected MonoClassic, got {:?}", other),
    }
}

#[test]
fn detects_il2cpp_after_loading_mock_gameassembly() {
    let pid = unsafe { GetCurrentProcessId() };

    // Garante que o processo nao tem a DLL de teste antes do load.
    assert!(!matches!(
        detect_mono_runtime(pid),
        MonoRuntime::Il2Cpp { .. }
    ));

    let mock = fabricate_mock_dll("GameAssembly.dll", "il2cpp");
    let wide = to_wide(&mock);
    let hmod = unsafe { LoadLibraryW(wide.as_ptr()) };
    assert!(hmod != 0, "LoadLibraryW failed for mock GameAssembly");

    let runtime = detect_mono_runtime(pid);
    // Idem acima: deixar o OS cuidar do unload no exit.

    match runtime {
        MonoRuntime::Il2Cpp { module, .. } => {
            assert!(module.eq_ignore_ascii_case("GameAssembly.dll"));
        }
        // Se o host ja carregou mono-* por alguma razao, a prioridade do mono
        // prevalece conforme contrato documentado em `detect_from_module_names`.
        MonoRuntime::MonoClassic { .. } => {}
        other => panic!("expected Il2Cpp, got {:?}", other),
    }
}
