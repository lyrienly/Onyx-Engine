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

pub mod runtime;
pub mod api;
pub mod il2cpp;
pub mod collector;

pub use runtime::{MonoRuntime, detect_from_module_names, module_names_of_pid, detect_mono_runtime};
pub use api::{MonoApi, MONO_ESSENTIAL_EXPORTS, IL2CPP_ESSENTIAL_EXPORTS};
pub use il2cpp::{Il2CppMetadataHeader, parse_global_metadata_header, GLOBAL_METADATA_MAGIC};
pub use collector::{MonoAssembly, MonoClass, enumerate_assemblies, enumerate_classes};
