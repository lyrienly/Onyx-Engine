//! Hook de `vkQueuePresentKHR` em `vulkan-1.dll`.
//!
//! Diferente do DXGI/DX12, Vulkan não expõe VTables COM. A hookagem precisa
//! ser por **inline hook** (patch do prólogo da função) ou por **Vulkan layer
//! registration** (via `VK_INSTANCE_LAYERS` + manifesto JSON).
//!
//! Esta implementação prepara toda a infraestrutura (verificação de que
//! `vulkan-1.dll` carrega via `ash::Entry::load`, resolução de
//! `vkGetInstanceProcAddr` via `GetProcAddress`, marcação de estado) e deixa
//! o patch do prólogo como TODO porque exige uma dependência de hook
//! (`minhook`, `funchook`, ou trampolim manual com disassembler) que será
//! decidida em um PR dedicado.

use super::{HookError, HookResult};
use crate::state;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::core::PCSTR;

pub static IN_HOOK: AtomicU32 = AtomicU32::new(0);

/// Ponteiro para `vkGetInstanceProcAddr` exportado por `vulkan-1.dll`.
/// Resolvido no `install()`; usado depois para pegar `vkQueuePresentKHR`
/// a partir do VkInstance que o jogo criar.
static VK_GET_INSTANCE_PROC_ADDR: AtomicUsize = AtomicUsize::new(0);

/// Ponteiro original de `vkQueuePresentKHR`, preenchido quando o inline
/// hook for instalado (TODO).
static ORIG_QUEUE_PRESENT_KHR: AtomicUsize = AtomicUsize::new(0);

pub unsafe fn install() -> HookResult {
    // Verifica que vulkan-1.dll está no processo via ash loader. Se não
    // estiver, provavelmente o jogo não é Vulkan — não é erro, só não hooka.
    let _entry = ash::Entry::load().map_err(|_| HookError::ModuleNotLoaded("vulkan-1.dll"))?;

    // Resolve vkGetInstanceProcAddr via GetProcAddress direto no módulo —
    // mais confiável do que depender dos campos internos do ash::Entry
    // entre versões diferentes do crate.
    let module =
        LoadLibraryA(PCSTR(b"vulkan-1.dll\0".as_ptr())).map_err(|_| HookError::ModuleNotLoaded("vulkan-1.dll"))?;
    let fp = GetProcAddress(module, PCSTR(b"vkGetInstanceProcAddr\0".as_ptr()))
        .ok_or(HookError::SymbolNotFound("vkGetInstanceProcAddr"))?;
    VK_GET_INSTANCE_PROC_ADDR.store(fp as usize, Ordering::SeqCst);

    state::mark_vulkan();

    // TODO(PR dedicado): instalar inline hook no prólogo de vkQueuePresentKHR.
    //
    // Opções consideradas:
    //  a) minhook (crate `minhook-sys` ou binding manual) — mais usado, C.
    //  b) funchook-sys — biblioteca C portável.
    //  c) Vulkan layer registration (sem patch de código, exige manifesto
    //     JSON + chave de registro em HKLM/HKCU\Software\Khronos\Vulkan).
    //  d) Trampolim manual: alocar página RWX, escrever JMP absoluto
    //     (14 bytes: FF 25 00 00 00 00 + endereço), salvar prólogo original
    //     em trampolim com `iced-x86` para instrução boundary.
    //
    // Preferência: minhook em PR separado quando a crate for aprovada.
    Err(HookError::Unimplemented)
}

pub unsafe fn uninstall() {
    // TODO: remover o inline hook quando ele for implementado.
    VK_GET_INSTANCE_PROC_ADDR.store(0, Ordering::SeqCst);
    ORIG_QUEUE_PRESENT_KHR.store(0, Ordering::SeqCst);
}

/// Helper exposto para quando o hook de `vkCreateInstance` for implementado:
/// resolve `vkQueuePresentKHR` a partir do VkInstance real do jogo.
#[allow(dead_code)]
pub unsafe fn resolve_present_from_instance(instance_handle: u64) {
    let getter_addr = VK_GET_INSTANCE_PROC_ADDR.load(Ordering::SeqCst);
    if getter_addr == 0 {
        return;
    }
    type FnGetInstanceProcAddr =
        unsafe extern "system" fn(instance: u64, name: *const u8) -> *mut c_void;
    let getter: FnGetInstanceProcAddr = std::mem::transmute(getter_addr);
    let p = getter(instance_handle, b"vkQueuePresentKHR\0".as_ptr());
    if !p.is_null() {
        ORIG_QUEUE_PRESENT_KHR.store(p as usize, Ordering::SeqCst);
    }
}
