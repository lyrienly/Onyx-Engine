//! onyx_mono: deteccao e enumeracao de runtimes Mono/IL2CPP em processos alvo.
//!
//! Capacidades:
//! - Deteccao automatica de runtime (Mono classic, IL2CPP, UnityPlayer puro, nenhum)
//!   a partir dos modulos carregados pelo processo.
//! - Resolucao de exports do runtime Mono (mono_get_root_domain,
//!   mono_domain_get_assemblies, mono_class_get_fields, mono_thread_attach, etc.)
//!   via GetProcAddress sobre o modulo carregado localmente, com variante remota
//!   baseada em caminhada da export directory.
//! - Parse do cabecalho `global-metadata.dat` do IL2CPP (magic 0xFAB11BAF,
//!   versoes 24-29 cobrem Unity 2018-2023).
//! - API `enumerate_assemblies` / `enumerate_classes` com stub para IL2CPP.

pub mod api;
pub mod collector;
pub mod il2cpp;
pub mod runtime;

pub use api::{MonoApi, IL2CPP_ESSENTIAL_EXPORTS, MONO_ESSENTIAL_EXPORTS};
pub use collector::{enumerate_assemblies, enumerate_classes, MonoAssembly, MonoClass};
pub use il2cpp::{parse_global_metadata_header, Il2CppMetadataHeader, GLOBAL_METADATA_MAGIC};
pub use runtime::{
    detect_from_module_names, detect_mono_runtime, module_names_of_pid, MonoRuntime,
};
