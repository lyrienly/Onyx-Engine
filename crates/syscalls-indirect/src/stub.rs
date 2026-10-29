#![cfg(all(windows, target_arch = "x86_64"))]

use core::arch::global_asm;

global_asm!(
    r#"
.globl onyx_syscall_gate
onyx_syscall_gate:
    mov eax, ecx
    mov r11, rdx
    mov r10, r8
    mov rdx, r9
    mov r8,  [rsp+0x28]
    mov r9,  [rsp+0x30]
    mov rcx, [rsp+0x38]
    mov [rsp+0x28], rcx
    mov rcx, [rsp+0x40]
    mov [rsp+0x30], rcx
    mov rcx, [rsp+0x48]
    mov [rsp+0x38], rcx
    mov rcx, [rsp+0x50]
    mov [rsp+0x40], rcx
    mov rcx, [rsp+0x58]
    mov [rsp+0x48], rcx
    mov rcx, [rsp+0x60]
    mov [rsp+0x50], rcx
    mov rcx, [rsp+0x68]
    mov [rsp+0x58], rcx
    jmp r11
"#
);

extern "C" {
    pub fn onyx_syscall_gate(
        ssn: u32,
        gadget: *const u8,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
        a5: usize,
        a6: usize,
        a7: usize,
        a8: usize,
        a9: usize,
        a10: usize,
        a11: usize,
    ) -> i32;
}
