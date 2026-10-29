//! Camada de coleta: enumera assemblies/classes dado um runtime detectado.
//!
//! Para Mono classic a enumeracao real exige executar `mono_assembly_foreach`
//! no contexto do alvo (via DLL injection ou chamada remota). Este modulo
//! fornece uma API consistente que:
//! - Resolve os exports necessarios (via `MonoApi`).
//! - Lista as DLLs anexas ao processo (assemblies candidatos).
//! - Para IL2CPP, carrega e parseia `global-metadata.dat` do pacote do jogo
//!   quando o caminho e conhecido.
//!
//! Enumeracao plena de campos/metodos esta marcada como TODO: requer
//! `CreateRemoteThread` + helper DLL, fora do escopo da issue #10 nesta fase.

use crate::api::{MonoApi, IL2CPP_ESSENTIAL_EXPORTS, MONO_ESSENTIAL_EXPORTS};
use crate::il2cpp::{parse_global_metadata_header, Il2CppMetadataHeader};
use crate::runtime::MonoRuntime;

#[derive(Debug, Clone)]
pub struct MonoAssembly {
    pub name: String,
    pub image_base: usize,
    pub notes: String,
}

#[derive(Debug, Clone)]
pub struct MonoClass {
    pub namespace: String,
    pub name: String,
    pub token: u32,
}

/// Resultado da enumeracao: pode indicar que a lista e parcial (ex: IL2CPP
/// sem metadata disponivel).
#[derive(Debug, Clone)]
pub struct EnumerationResult {
    pub assemblies: Vec<MonoAssembly>,
    pub il2cpp_header: Option<Il2CppMetadataHeader>,
    pub resolved_api: Option<MonoApi>,
    pub partial: bool,
    pub reason: String,
}

/// Lista assemblies candidatos para o runtime detectado.
///
/// Para Mono classic, usa os modulos carregados pelo processo (via Toolhelp)
/// como aproximacao: cada DLL managed termina em `.dll` e tipicamente carrega
/// as mesmas DLLs que o `mono_assembly_foreach` listaria, embora misture
/// DLLs nativas. Essa heuristica funciona offline, sem injecao.
pub fn enumerate_assemblies(pid: u32, runtime: &MonoRuntime) -> EnumerationResult {
    match runtime {
        MonoRuntime::MonoClassic { module, .. } => {
            let api = MonoApi::resolve_local(module, MONO_ESSENTIAL_EXPORTS).ok();
            let names = crate::runtime::module_names_of_pid(pid).unwrap_or_default();
            let assemblies: Vec<MonoAssembly> = names
                .into_iter()
                .filter(|n| n.to_ascii_lowercase().ends_with(".dll"))
                .map(|name| MonoAssembly {
                    name,
                    image_base: 0,
                    notes: "listed via Toolhelp32; use mono_assembly_foreach for full set"
                        .to_string(),
                })
                .collect();
            EnumerationResult {
                assemblies,
                il2cpp_header: None,
                resolved_api: api,
                partial: true,
                reason: "full enumeration requires remote mono_assembly_foreach invocation"
                    .to_string(),
            }
        }
        MonoRuntime::Il2Cpp { module, .. } => {
            let api = MonoApi::resolve_local(module, IL2CPP_ESSENTIAL_EXPORTS).ok();
            EnumerationResult {
                assemblies: Vec::new(),
                il2cpp_header: None,
                resolved_api: api,
                partial: true,
                reason: "IL2CPP enumeration requires global-metadata.dat (use enumerate_il2cpp_from_metadata)"
                    .to_string(),
            }
        }
        MonoRuntime::UnityPlayer { .. } | MonoRuntime::None => EnumerationResult {
            assemblies: Vec::new(),
            il2cpp_header: None,
            resolved_api: None,
            partial: true,
            reason: "no managed runtime".to_string(),
        },
    }
}

/// Variante IL2CPP: parseia `global-metadata.dat` quando o conteudo e passado
/// pelo chamador (lido a partir do disco do jogo).
pub fn enumerate_il2cpp_from_metadata(bytes: &[u8]) -> EnumerationResult {
    match parse_global_metadata_header(bytes) {
        Some(header) => EnumerationResult {
            assemblies: Vec::new(),
            il2cpp_header: Some(header),
            resolved_api: None,
            partial: true,
            reason: "header parsed; class/method enumeration pending (TODO)".to_string(),
        },
        None => EnumerationResult {
            assemblies: Vec::new(),
            il2cpp_header: None,
            resolved_api: None,
            partial: true,
            reason: "invalid global-metadata.dat".to_string(),
        },
    }
}

/// Enumeracao plena de classes (TODO: exige injecao). Hoje devolve lista vazia
/// com `partial = true`, mantendo a interface pronta para o backend remoto.
pub fn enumerate_classes(_pid: u32, _assembly: &MonoAssembly) -> Vec<MonoClass> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::MonoRuntime;

    #[test]
    fn none_runtime_returns_empty_partial() {
        let r = enumerate_assemblies(0, &MonoRuntime::None);
        assert!(r.assemblies.is_empty());
        assert!(r.partial);
    }

    #[test]
    fn il2cpp_metadata_parses_synth_bytes() {
        let mut bytes = vec![0u8; 0x90];
        bytes[0..4].copy_from_slice(&crate::il2cpp::GLOBAL_METADATA_MAGIC.to_le_bytes());
        bytes[4..8].copy_from_slice(&29i32.to_le_bytes());
        let r = enumerate_il2cpp_from_metadata(&bytes);
        assert!(r.il2cpp_header.is_some());
        assert_eq!(r.il2cpp_header.as_ref().unwrap().version, 29);
    }
}
