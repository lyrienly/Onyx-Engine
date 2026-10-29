//! Testes unitarios do construtor de trampolim (sem tocar o SO).

use onyx_hook::trampoline::{build_trampoline, RelocationKind, PATCH_SIZE};

/// Prologue com instrucoes "neutras" (sem RIP-relative, sem branches).
/// Deve produzir trampolim que simplesmente copia bytes + JMP absoluto.
#[test]
fn trampolim_sem_rip_relative_apenas_copia_bytes() {
    // 48 8D 04 11       lea rax, [rcx+rdx]      (4)
    // 48 83 C0 00       add rax, 0              (4)
    // 48 83 C0 00       add rax, 0              (4)
    // 48 83 C0 00       add rax, 0              (4)
    // C3                ret
    let prologue: Vec<u8> = vec![
        0x48, 0x8D, 0x04, 0x11, 0x48, 0x83, 0xC0, 0x00, 0x48, 0x83, 0xC0, 0x00, 0x48, 0x83, 0xC0,
        0x00, 0xC3,
    ];
    let target_addr: u64 = 0x1_0000_0000;
    let tramp_addr: u64 = 0x2_0000_0000;

    let t = build_trampoline(&prologue, target_addr, tramp_addr).expect("trampolim");
    assert!(t.consumed >= PATCH_SIZE);
    assert_eq!(t.consumed, 16);
    assert_eq!(t.bytes.len(), 16 + PATCH_SIZE);

    // Nenhuma relocacao RIP-relative esperada.
    for r in &t.relocations {
        assert_eq!(r.kind, RelocationKind::None);
    }

    // Verifica JMP absoluto no fim.
    let jmp = &t.bytes[16..];
    assert_eq!(jmp[0], 0xFF);
    assert_eq!(jmp[1], 0x25);
    assert_eq!(&jmp[2..6], &[0, 0, 0, 0]);
    let dest = u64::from_le_bytes(jmp[6..14].try_into().unwrap());
    assert_eq!(dest, target_addr + 16);
}

/// Prologue com `mov rax, [rip+disp]` deve ser relocado: o novo disp32
/// precisa continuar apontando para o mesmo endereco absoluto.
#[test]
fn trampolim_relocaliza_rip_relative() {
    // Insn de 7 bytes: 48 8B 05 ?? ?? ?? ??
    // target em 0x1000, const alvo em 0x2000.
    // Em `rip` apos a insn (= target + 7) o disp aponta para 0x2000.
    // disp32 = 0x2000 - (0x1000 + 7) = 0x0FF9
    let target_addr: u64 = 0x1000;
    let const_addr: u64 = 0x2000;
    let old_disp: i32 = (const_addr as i64 - (target_addr as i64 + 7)) as i32;
    let disp_bytes = old_disp.to_le_bytes();

    let mut prologue: Vec<u8> = vec![
        0x48, 0x8B, 0x05, disp_bytes[0], disp_bytes[1], disp_bytes[2], disp_bytes[3], // mov rax, [rip+disp]
        0x48, 0x03, 0xC1, // add rax, rcx
        0x48, 0x03, 0xC2, // add rax, rdx
        0x48, 0x83, 0xC0, 0x00, // add rax, 0
        0xC3, // ret
    ];
    // Garante tamanho de probe.
    prologue.resize(PATCH_SIZE + 16, 0x90);

    // Trampolim precisa estar a <2GB para o novo disp32 caber em i32.
    let tramp_addr: u64 = 0x1000_0000;
    let t = build_trampoline(&prologue, target_addr, tramp_addr).expect("trampolim");

    assert_eq!(t.consumed, 17);
    assert!(matches!(t.relocations[0].kind, RelocationKind::RipRelative { .. }));
    if let RelocationKind::RipRelative { old_disp: od, new_disp: nd } = t.relocations[0].kind.clone() {
        assert_eq!(od, old_disp);
        // Novo disp aponta para 0x2000 a partir de (tramp_addr + 7).
        let expected = (const_addr as i128 - (tramp_addr as i128 + 7)) as i32;
        assert_eq!(nd, expected);
        // Os bytes da instrucao copiada devem conter o novo disp.
        let patched = &t.bytes[3..7];
        assert_eq!(patched, nd.to_le_bytes());
    } else {
        panic!("esperado RipRelative");
    }
}

/// Prologue com branch relativo (JMP rel8) deve ser rejeitado.
#[test]
fn trampolim_rejeita_branch_relativo() {
    // EB 10   jmp short +0x10 — e 0x90 de padding ate completar PATCH_SIZE.
    let mut prologue: Vec<u8> = vec![0xEB, 0x10];
    prologue.resize(PATCH_SIZE + 16, 0x90);

    let r = build_trampoline(&prologue, 0x1000, 0x9000);
    assert!(r.is_err(), "deveria rejeitar branch relativo");
}
