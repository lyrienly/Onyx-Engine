//! E2E: spawnar um processo .NET real e validar detect_runtime + enumeracao.
//!
//! Estrategia:
//! 1. Tenta `pwsh.exe` (PowerShell 7, .NET 7/8/9 CoreCLR).
//! 2. Tenta `powershell.exe` (Windows PowerShell 5.1, .NET Framework 4.x clr.dll).
//! 3. Se nenhum existir no PATH: teste e marcado como ignored.
//!
//! O helper executa um loop infinito curto; matamos o processo ao fim do teste.

#![cfg(windows)]

use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use onyx_dotnet::{detect_runtime, enumerate_assemblies, enumerate_modules, ClrKind};

fn spawn_dotnet_proc() -> Option<(Child, &'static str)> {
    // Script que mantem processo vivo sem imprimir nada.
    let script = "while($true){Start-Sleep -Milliseconds 500}";
    for exe in ["pwsh.exe", "powershell.exe"] {
        if let Ok(child) = Command::new(exe)
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
        {
            return Some((child, exe));
        }
    }
    None
}

#[test]
fn e2e_detect_runtime_in_powershell() {
    let (mut child, exe) = match spawn_dotnet_proc() {
        Some(x) => x,
        None => {
            eprintln!("[ignored] nenhum shell PowerShell/pwsh encontrado no PATH");
            return;
        }
    };

    // Da tempo pro CLR carregar.
    sleep(Duration::from_millis(1500));

    let pid = child.id();
    eprintln!("spawnou {} (pid={})", exe, pid);

    let modules = enumerate_modules(pid);
    assert!(!modules.is_empty(), "modulos nao devem estar vazios");
    eprintln!("modulos detectados: {}", modules.len());

    let rt = detect_runtime(pid);
    // Tentamos ate 10x com delay para dar tempo ao JIT inicializar o CLR.
    let rt = if rt.is_none() {
        let mut r = None;
        for _ in 0..10 {
            sleep(Duration::from_millis(500));
            r = detect_runtime(pid);
            if r.is_some() {
                break;
            }
        }
        r
    } else {
        rt
    };

    let _ = child.kill();
    let _ = child.wait();

    let rt = rt.expect("CLR deveria estar carregado no PowerShell");
    eprintln!(
        "runtime: kind={:?} version={} base=0x{:X} path={}",
        rt.kind,
        rt.version,
        rt.module_base,
        rt.module_path.display()
    );
    assert!(rt.module_base != 0);
    assert!(matches!(
        rt.kind,
        ClrKind::CoreClr | ClrKind::FrameworkV4 | ClrKind::FrameworkV2
    ));
    assert_ne!(rt.version, "");
}

#[test]
fn e2e_enumerate_assemblies_in_powershell() {
    let (mut child, exe) = match spawn_dotnet_proc() {
        Some(x) => x,
        None => {
            eprintln!("[ignored] nenhum shell PowerShell/pwsh encontrado no PATH");
            return;
        }
    };
    sleep(Duration::from_millis(1500));
    let pid = child.id();
    eprintln!("spawnou {} (pid={})", exe, pid);

    let rt = {
        let mut r = None;
        for _ in 0..10 {
            r = detect_runtime(pid);
            if r.is_some() {
                break;
            }
            sleep(Duration::from_millis(500));
        }
        r
    };

    let rt = match rt {
        Some(r) => r,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("[ignored] nao foi possivel detectar CLR");
            return;
        }
    };

    let assemblies = enumerate_assemblies(pid, &rt);
    let _ = child.kill();
    let _ = child.wait();

    eprintln!(
        "assemblies detectados ({}): {}",
        assemblies.len(),
        assemblies
            .iter()
            .take(10)
            .map(|a| a.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert!(
        !assemblies.is_empty(),
        "deve haver pelo menos um assembly .NET"
    );
}
