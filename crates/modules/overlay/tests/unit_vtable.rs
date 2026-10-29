#![cfg(windows)]

use onyx_overlay::{resolve_present_slot, PRESENT_VTABLE_INDEX};

#[test]
fn present_vtable_index_e_oito() {
    // IUnknown (3) + IDXGIObject (4) + IDXGIDeviceSubObject (1) = slot 8 para Present.
    assert_eq!(PRESENT_VTABLE_INDEX, 8);
}

#[test]
fn resolve_present_slot_retorna_ponteiro_valido() {
    let present = resolve_present_slot().expect("resolver Present via dummy swapchain");
    assert!(!present.is_null(), "Present nao pode ser nulo");
    let addr = present as usize;
    assert!(addr > 0x1000, "endereco suspeito: {:#x}", addr);
}
