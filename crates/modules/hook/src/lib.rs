//! onyx_hook — motor de detour e code cave em Rust puro.
//!
//! Equivalente leve a MinHook: patcha prologue com `JMP [RIP+0]; qword hook`
//! (14 bytes) e constroi um trampolim que executa as instrucoes originais
//! deslocadas (com reajuste automatico de operandos RIP-relative) antes de
//! retornar para o endereco imediatamente apos o patch.
//!
//! API publica:
//! * [`Hook`] - um hook individual.
//! * [`HookEngine`] - gerencia multiplos hooks e evita conflitos.

pub mod trampoline;
pub mod detour;
pub mod engine;

pub use detour::{Hook, HookError};
pub use engine::HookEngine;
pub use trampoline::{build_trampoline, RelocationInfo, PATCH_SIZE};
