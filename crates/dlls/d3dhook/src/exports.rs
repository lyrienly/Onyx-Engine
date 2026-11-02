//! ABI preservada para o frontend Pascal/Lazarus.
//!
//! A partir da adoção do `hudhook`, o overlay é renderizado inteiramente
//! em Rust e as funções abaixo tornam-se stubs de compatibilidade — o
//! frontend pode continuar chamando `D3DHook_Initialize` sem efeito
//! colateral, enquanto o overlay já roda via `DllMain` gerado pelo macro
//! `hudhook!`.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

pub const MAX_COMMANDS: usize = 256;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RenderCommand {
    pub cmd_type: u32,
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
    pub color_rgba: u32,
    pub text_len: u32,
    pub text_buf: [u8; 64],
}

static COMMAND_COUNT: AtomicU32 = AtomicU32::new(0);
static HOOK_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Stub: o overlay inicializa automaticamente no `DLL_PROCESS_ATTACH`
/// gerado pelo `hudhook!`. Mantido para compatibilidade com o frontend.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn D3DHook_Initialize() -> i32 {
    HOOK_INITIALIZED.store(true, Ordering::SeqCst);
    1
}

/// Stub: o unhook é feito pelo próprio `hudhook` no `DLL_PROCESS_DETACH`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn D3DHook_Shutdown() -> i32 {
    HOOK_INITIALIZED.store(false, Ordering::SeqCst);
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn D3DHook_GetCommandCount() -> u32 {
    COMMAND_COUNT.load(Ordering::Relaxed)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn D3DHook_ClearCommands() {
    COMMAND_COUNT.store(0, Ordering::SeqCst);
}
