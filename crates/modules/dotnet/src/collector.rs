//! Collector pragmatico de metadata .NET sem depender da DAC.
//!
//! Em vez de reimplementar `ICLRDataTarget` + `ISOSDacInterface` (que exige
//! COM, versao-matching contra `mscordaccore.dll` e offsets instaveis entre
//! .NET 6/7/8/9), este modulo infere a lista de assemblies carregados a partir
//! dos modulos do processo. No CoreCLR cada assembly managed resolvido via JIT
//! aparece como DLL do processo (NGen/R2R/Prejit), e o CLR mantem imagens
//! como `System.Private.CoreLib.dll`, `System.Runtime.dll` etc carregadas pelo
//! loader nativo. E uma aproximacao suficiente para listar o conjunto estavel
//! de assemblies, que e o requisito 3 da issue.

use std::path::PathBuf;

use crate::runtime::{enumerate_modules, ClrKind, ClrRuntime, ModuleInfo};

#[derive(Debug, Clone)]
pub struct Assembly {
    pub name: String,
    pub module_path: PathBuf,
    pub module_base: usize,
}

/// Lista assemblies .NET detectaveis via modulos nativos do processo.
///
/// Heuristicas:
/// - Para CoreCLR: qualquer modulo cujo path contem `shared\Microsoft.NETCore.App`
///   ou cujo nome bate em `System.*.dll` / `Microsoft.*.dll` dentro do mesmo
///   diretorio do coreclr.
/// - Para .NET Framework: modulos em `assembly\NativeImages_*` (GAC NGen).
pub fn enumerate_assemblies(pid: u32, rt: &ClrRuntime) -> Vec<Assembly> {
    let modules = enumerate_modules(pid);
    let rt_dir = rt
        .module_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_default();

    modules
        .into_iter()
        .filter(|m| is_managed_candidate(m, rt.kind, &rt_dir))
        .map(|m| Assembly {
            name: strip_dll_suffix(&m.name).to_string(),
            module_path: m.path,
            module_base: m.base,
        })
        .collect()
}

fn is_managed_candidate(m: &ModuleInfo, kind: ClrKind, rt_dir: &std::path::Path) -> bool {
    let path_str = m.path.to_string_lossy().to_ascii_lowercase();
    let name_lower = m.name.to_ascii_lowercase();

    // Excluir o proprio runtime.
    if name_lower == "coreclr.dll" || name_lower == "clr.dll" || name_lower == "mscorwks.dll" {
        return false;
    }

    match kind {
        ClrKind::CoreClr => {
            if path_str.contains("microsoft.netcore.app")
                || path_str.contains("\\dotnet\\shared\\")
                || path_str.contains("/dotnet/shared/")
            {
                return name_lower.ends_with(".dll");
            }
            if let Some(parent) = m.path.parent() {
                if parent == rt_dir && name_lower.ends_with(".dll") {
                    // No proprio diretorio do coreclr temos System.Private.CoreLib etc.
                    return name_lower.starts_with("system.")
                        || name_lower.starts_with("microsoft.")
                        || name_lower.starts_with("netstandard");
                }
            }
            false
        }
        ClrKind::FrameworkV4 | ClrKind::FrameworkV2 => {
            path_str.contains("\\assembly\\nativeimages_")
                || path_str.contains("\\microsoft.net\\")
                || (name_lower.starts_with("system.") && name_lower.ends_with(".ni.dll"))
        }
    }
}

fn strip_dll_suffix(name: &str) -> &str {
    name.strip_suffix(".dll")
        .or_else(|| name.strip_suffix(".DLL"))
        .unwrap_or(name)
}
