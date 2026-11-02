//! Hook de `vkQueuePresentKHR` em `vulkan-1.dll`.
//!
//! Diferente do DXGI/DX12, Vulkan não expõe VTables COM. A estratégia aqui é:
//! - Carregar `vulkan-1.dll` com `ash::Entry::load()`.
//! - Resolver `vkQueuePresentKHR` via `vkGetDeviceProcAddr` quando um device
//!   do jogo for conhecido (ou via `vkGetInstanceProcAddr` para resolução
//!   estática via loader).
//! - Inline-hook com `retour::RawDetour`.
//!
//! Scaffold: carregamento do loader e detour real virão no próximo PR.

use super::{HookError, HookResult};

pub unsafe fn install() -> HookResult {
    let _entry = ash::Entry::load().map_err(|_| HookError::ModuleNotLoaded("vulkan-1.dll"))?;
    // TODO(issue-8): resolver vkQueuePresentKHR e instalar RawDetour.
    Err(HookError::Unimplemented)
}

pub unsafe fn uninstall() {
    // TODO(issue-8): remover o RawDetour instalado em `install`.
}
