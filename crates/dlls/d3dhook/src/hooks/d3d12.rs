//! Hook de `ID3D12CommandQueue::ExecuteCommandLists`.
//!
//! Em DX12 o overlay precisa ser gravado no CommandQueue que o jogo usa, antes
//! dos comandos originais, para aparecer no mesmo frame buffer. Como o jogo
//! pode usar múltiplos CommandQueues (compute, copy, direct), capturamos o
//! primeiro `DIRECT` que executa comandos — tipicamente o queue de render.
//!
//! Estratégia:
//! 1. Criar um ID3D12Device dummy via `D3D12CreateDevice`.
//! 2. Criar um ID3D12CommandQueue dummy via `CreateCommandQueue`.
//! 3. Ler VTable[10] (`ExecuteCommandLists`) do queue dummy.
//! 4. Patchar com o trampolim.
//! 5. No trampolim, se o queue capturado em state ainda não existe, armazenar
//!    o deste call — ele é o queue do render do jogo.

use super::{HookError, HookResult};
use crate::state;
use crate::vtable::{patch_slot, vtable_of};
use parking_lot::Mutex;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use windows::Win32::Graphics::Direct3D::D3D_FEATURE_LEVEL_11_0;
use windows::Win32::Graphics::Direct3D12::{
    D3D12_COMMAND_LIST_TYPE_DIRECT, D3D12_COMMAND_QUEUE_DESC, D3D12_COMMAND_QUEUE_FLAG_NONE,
    D3D12CreateDevice, ID3D12CommandQueue, ID3D12Device,
};
use windows::core::Interface;

const EXECUTE_COMMAND_LISTS_VTABLE_INDEX: usize = 10;

type FnExecuteCommandLists = unsafe extern "system" fn(
    this: *mut c_void,
    num_lists: u32,
    lists: *const *mut c_void,
);

static ORIG_EXECUTE: Mutex<Option<FnExecuteCommandLists>> = Mutex::new(None);
static EXECUTE_SLOT: Mutex<Option<usize>> = Mutex::new(None);

/// Mesma convenção do hook DXGI — permite ao PR #13 esperar a saída
/// do trampolim antes de restaurar a VTable.
pub static IN_HOOK: AtomicU32 = AtomicU32::new(0);

unsafe extern "system" fn hook_execute_command_lists(
    queue: *mut c_void,
    num_lists: u32,
    lists: *const *mut c_void,
) {
    IN_HOOK.fetch_add(1, Ordering::SeqCst);
    capture_queue_once(queue);
    // TODO(PR #12): injetar command list do overlay ImGui antes dos lists do jogo.
    if let Some(orig) = *ORIG_EXECUTE.lock() {
        orig(queue, num_lists, lists);
    }
    IN_HOOK.fetch_sub(1, Ordering::SeqCst);
}

unsafe fn capture_queue_once(queue_raw: *mut c_void) {
    if let Some(queue) = ID3D12CommandQueue::from_raw_borrowed(&queue_raw) {
        // Apenas direct queues interessam ao overlay — compute/copy ignorados.
        let desc = queue.GetDesc();
        if desc.Type == D3D12_COMMAND_LIST_TYPE_DIRECT {
            state::set_d3d12_queue(queue.clone());
        }
    }
}

pub unsafe fn install() -> HookResult {
    let queue = create_dummy_queue()?;
    let vt = vtable_of(queue.as_raw() as *mut c_void);
    let slot = vt.add(EXECUTE_COMMAND_LISTS_VTABLE_INDEX);
    let orig = patch_slot(slot, hook_execute_command_lists as *mut c_void);
    *ORIG_EXECUTE.lock() = Some(std::mem::transmute::<*mut c_void, FnExecuteCommandLists>(orig));
    *EXECUTE_SLOT.lock() = Some(slot as usize);
    Ok(())
}

pub unsafe fn uninstall() {
    if let (Some(slot_addr), Some(orig)) = (*EXECUTE_SLOT.lock(), *ORIG_EXECUTE.lock()) {
        let slot = slot_addr as *mut *mut c_void;
        patch_slot(slot, orig as *mut c_void);
    }
    *ORIG_EXECUTE.lock() = None;
    *EXECUTE_SLOT.lock() = None;
}

unsafe fn create_dummy_queue() -> HookResult<ID3D12CommandQueue> {
    let mut device: Option<ID3D12Device> = None;
    D3D12CreateDevice(None, D3D_FEATURE_LEVEL_11_0, &mut device)
        .map_err(|_| HookError::DummyDeviceFailed)?;
    let device = device.ok_or(HookError::DummyDeviceFailed)?;

    let desc = D3D12_COMMAND_QUEUE_DESC {
        Type: D3D12_COMMAND_LIST_TYPE_DIRECT,
        Priority: 0,
        Flags: D3D12_COMMAND_QUEUE_FLAG_NONE,
        NodeMask: 0,
    };
    device
        .CreateCommandQueue::<ID3D12CommandQueue>(&desc)
        .map_err(|_| HookError::DummyDeviceFailed)
}
