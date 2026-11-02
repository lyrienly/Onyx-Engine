//! Orquestra install / uninstall dos hooks nas três APIs gráficas.
//!
//! O unhook precisa ser **race-safe**: se o jogo estiver no meio de um
//! `Present` / `ExecuteCommandLists` / `vkQueuePresentKHR` quando a DLL
//! for descarregada, restaurar a VTable prematuramente causa pulo para
//! código morto (`0xC0000005` — access violation). Cada trampolim
//! incrementa seu `IN_HOOK` ao entrar e decrementa ao sair; aqui esperamos
//! esses contadores zerarem com timeout curto antes de restaurar.

use crate::hooks::{d3d12, dxgi, vulkan};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// Timeout para esperar os trampolins terminarem antes do unhook. Se não
/// zerar nesse prazo, prosseguimos mesmo assim — a alternativa é vazar
/// a DLL, pior cenário.
const UNHOOK_WAIT_TIMEOUT_MS: u64 = 500;

pub struct HookManager {
    pub dxgi_installed: bool,
    pub d3d12_installed: bool,
    pub vulkan_installed: bool,
}

impl HookManager {
    const fn new() -> Self {
        Self {
            dxgi_installed: false,
            d3d12_installed: false,
            vulkan_installed: false,
        }
    }
}

pub static MANAGER: Mutex<HookManager> = Mutex::new(HookManager::new());

pub unsafe fn install_all() {
    let mut mgr = MANAGER.lock();
    mgr.dxgi_installed = dxgi::install().is_ok();
    mgr.d3d12_installed = d3d12::install().is_ok();
    mgr.vulkan_installed = vulkan::install().is_ok();
}

pub unsafe fn uninstall_all() {
    let mut mgr = MANAGER.lock();

    // Ordem reversa de instalação. Para cada API, esperamos o contador
    // de entradas no trampolim zerar (ou timeout) antes de restaurar a
    // VTable — evita que um `Present` em andamento salte para memória
    // morta depois do unload da DLL.
    if mgr.vulkan_installed {
        wait_for_counter_zero(&vulkan::IN_HOOK, "vulkan");
        vulkan::uninstall();
        mgr.vulkan_installed = false;
    }
    if mgr.d3d12_installed {
        wait_for_counter_zero(&d3d12::IN_HOOK, "d3d12");
        d3d12::uninstall();
        mgr.d3d12_installed = false;
    }
    if mgr.dxgi_installed {
        wait_for_counter_zero(&dxgi::IN_HOOK, "dxgi");
        dxgi::uninstall();
        mgr.dxgi_installed = false;
    }

    // Estado capturado também é limpo — próxima inicialização recomeça do zero.
    crate::state::clear();
}

/// Espera o contador zerar com timeout. Retorna `true` se zerou, `false`
/// se expirou (nesse caso prosseguimos — melhor do que travar o unload).
fn wait_for_counter_zero(counter: &AtomicU32, _label: &str) -> bool {
    let start = Instant::now();
    while counter.load(Ordering::SeqCst) > 0 {
        if start.elapsed() > Duration::from_millis(UNHOOK_WAIT_TIMEOUT_MS) {
            return false;
        }
        thread::yield_now();
    }
    true
}
