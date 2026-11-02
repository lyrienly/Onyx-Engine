//! Hook de `ID3D12CommandQueue::ExecuteCommandLists`.
//!
//! Em DX12 o overlay precisa ser gravado no `CommandQueue` ativo antes dos
//! comandos do jogo. A estratégia aqui é criar um device D3D12 dummy, obter
//! um `ID3D12CommandQueue`, ler o slot da VTable e patchar.
//!
//! Scaffold: discovery do slot e install real serão feitos no próximo PR.

use super::{HookError, HookResult};
use parking_lot::Mutex;
use std::ffi::c_void;

#[allow(dead_code)]
const EXECUTE_COMMAND_LISTS_VTABLE_INDEX: usize = 10;

type FnExecuteCommandLists =
    unsafe extern "system" fn(queue: *mut c_void, num_lists: u32, lists: *const *mut c_void);

static ORIG_EXECUTE: Mutex<Option<FnExecuteCommandLists>> = Mutex::new(None);
static EXECUTE_SLOT: Mutex<Option<usize>> = Mutex::new(None);

#[allow(dead_code)]
unsafe extern "system" fn hook_execute_command_lists(
    queue: *mut c_void,
    num_lists: u32,
    lists: *const *mut c_void,
) {
    // TODO(issue-8): registrar o CommandQueue para o backend DX12 (ImGui).
    if let Some(orig) = *ORIG_EXECUTE.lock() {
        orig(queue, num_lists, lists);
    }
}

pub unsafe fn install() -> HookResult {
    // TODO(issue-8): criar device D3D12 dummy + CommandQueue, ler VTable[10],
    // patchar com `hook_execute_command_lists`.
    Err(HookError::Unimplemented)
}

pub unsafe fn uninstall() {
    let (Some(slot_addr), Some(orig)) = (*EXECUTE_SLOT.lock(), *ORIG_EXECUTE.lock()) else {
        return;
    };
    let slot = slot_addr as *mut *mut c_void;
    crate::vtable::patch_slot(slot, orig as *mut c_void);
    *ORIG_EXECUTE.lock() = None;
    *EXECUTE_SLOT.lock() = None;
}
