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

pub static mut COMMAND_BUFFER: [RenderCommand; MAX_COMMANDS] = [RenderCommand {
    cmd_type: 0,
    x: 0.0,
    y: 0.0,
    w: 0.0,
    h: 0.0,
    color_rgba: 0,
    text_len: 0,
    text_buf: [0u8; 64],
}; MAX_COMMANDS];

pub static COMMAND_COUNT: AtomicU32 = AtomicU32::new(0);
pub static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

#[unsafe(no_mangle)]
pub unsafe extern "system" fn D3DHook_Initialize() -> i32 {
    if HOOK_INSTALLED.load(Ordering::SeqCst) {
        return 1;
    }
    crate::pipe::spawn_pipe_server();
    crate::manager::install_all();
    HOOK_INSTALLED.store(true, Ordering::SeqCst);
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn D3DHook_Shutdown() -> i32 {
    if !HOOK_INSTALLED.load(Ordering::SeqCst) {
        return 1;
    }
    crate::manager::uninstall_all();
    crate::pipe::stop_pipe_server();
    HOOK_INSTALLED.store(false, Ordering::SeqCst);
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
