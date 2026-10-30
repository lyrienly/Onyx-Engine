#![cfg(all(windows, target_arch = "x86_64"))]

use core::arch::global_asm;

// onyx_callstack_gate(target_fn, gadget, a1, a2, a3, a4) -> usize
//
// Executa `target_fn(a1, a2, a3, a4)` com a pilha preparada de forma que o
// primeiro frame de retorno visto pela funcao alvo aponte para dentro de
// `ntdll.dll`. O "gadget" eh o endereco de uma sequencia
// `add rsp, 0x28 ; ret` dentro da .text da ntdll, descoberta em runtime.
//
// Layout da pilha preparada antes do `jmp` para o alvo (Y = rsp na entrada
// do gate; rsp em Y, mod 16 == 8):
//
//     saved rbx, rsi, rdi, rbp      [Y-0x08..Y-0x20]
//     reservado                     [Y-0x20..Y-0x58]  (sub rsp, 0x38)
//        onde [Y-0x30] = wrap_back  (gravado via mov)
//     gadget                        [Y-0x60]          (push rsi)
//
// Alvo entra em rsp = Y-0x60 (mod 16 == 8 ✓).
// Home space do alvo = [rsp+0x08..rsp+0x28] = [Y-0x58..Y-0x38] (sem
// colidir com wrap_back em Y-0x30).
//
// Fluxo de retorno:
//   target `ret`              -> pop gadget, rsp=Y-0x58, pc=gadget
//   gadget `add rsp, 0x28`    -> rsp=Y-0x30
//   gadget `ret`              -> pop wrap_back, rsp=Y-0x28, pc=wrap_back
//
// wrap_back ajusta rsp de volta pros slots de saved regs e retorna ao
// chamador original.

global_asm!(
    r#"
.globl onyx_callstack_gate
onyx_callstack_gate:
    push rbx
    push rsi
    push rdi
    push rbp

    mov rbx, rcx
    mov rsi, rdx
    mov rbp, rsp

    mov r10, [rbp + 0x48]
    mov r11, [rbp + 0x50]

    mov rcx, r8
    mov rdx, r9
    mov r8,  r10
    mov r9,  r11

    sub rsp, 0x38
    lea rax, [rip + 2f]
    mov [rsp + 0x28], rax
    push rsi

    jmp rbx

2:
    add rsp, 8
    pop rbp
    pop rdi
    pop rsi
    pop rbx
    ret
"#
);

extern "C" {
    pub fn onyx_callstack_gate(
        target_fn: *const u8,
        gadget: *const u8,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
    ) -> usize;
}
