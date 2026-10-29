//! DotNet runtime collector: detecta e enumera CLRs modernos (.NET Framework
//! 2.0-4.x e .NET Core / .NET 5-9) carregados em processos Windows.
//!
//! Escopo pragmatico: identificacao do runtime, versao do coreclr/clr,
//! enumeracao dos modulos .NET (assemblies carregados no processo).

pub mod runtime;
pub mod collector;

pub use runtime::{detect_runtime, enumerate_modules, ClrKind, ClrRuntime, ModuleInfo};
pub use collector::{enumerate_assemblies, Assembly};

#[no_mangle]
pub extern "C" fn onyx_dotnet_module_ping() -> i32 {
    1
}
