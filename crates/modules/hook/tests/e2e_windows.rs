//! Testes E2E in-process: aloca uma funcao sintetica em memoria executavel,
//! instala um hook via `onyx_hook::Hook`, verifica desvio + chamada ao
//! original pelo trampolim, e valida a restauracao.
//!
//! Executado apenas em Windows (API de memoria usada e a do Win32).

#![cfg(windows)]

use std::sync::atomic::{AtomicUsize, Ordering};

use onyx_hook::Hook;
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};

type AddFn = extern "C" fn(i32, i32) -> i32;

static TRAMP_SIMPLE: AtomicUsize = AtomicUsize::new(0);
static TRAMP_RIP: AtomicUsize = AtomicUsize::new(0);

extern "C" fn hook_simple(a: i32, b: i32) -> i32 {
    let p = TRAMP_SIMPLE.load(Ordering::Relaxed) as *const u8;
    let f: AddFn = unsafe { std::mem::transmute(p) };
    f(a, b) * 10
}

extern "C" fn hook_rip(a: i32, b: i32) -> i32 {
    let p = TRAMP_RIP.load(Ordering::Relaxed) as *const u8;
    let f: AddFn = unsafe { std::mem::transmute(p) };
    f(a, b) + 7
}

fn alloc_rwx(size: usize) -> *mut u8 {
    unsafe {
        VirtualAlloc(
            core::ptr::null(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ) as *mut u8
    }
}

fn free_rwx(p: *mut u8) {
    unsafe {
        VirtualFree(p as *mut _, 0, MEM_RELEASE);
    }
}

/// Escreve `target_add` sintetico em `page`.
///
/// Prologue:
/// ```text
///   48 8D 04 11       lea rax, [rcx+rdx]
///   48 83 C0 00       add rax, 0
///   48 83 C0 00       add rax, 0
///   48 83 C0 00       add rax, 0
///   C3                ret
/// ```
fn write_simple_add(page: *mut u8) {
    let code: [u8; 17] = [
        0x48, 0x8D, 0x04, 0x11, 0x48, 0x83, 0xC0, 0x00, 0x48, 0x83, 0xC0, 0x00, 0x48, 0x83, 0xC0,
        0x00, 0xC3,
    ];
    unsafe {
        core::ptr::copy_nonoverlapping(code.as_ptr(), page, code.len());
    }
}

/// Escreve `target_add` sintetico com RIP-relative load de constante 100.
///
/// Layout da pagina:
/// ```text
///   [0]     mov rax, [rip + disp]  (7)
///   [7]     add rax, rcx            (3)
///   [10]    add rax, rdx            (3)
///   [13]    add rax, 0              (4)
///   [17]    ret                     (1)
///   ...
///   [128]   i64 constante = 100
/// ```
///
/// Retorna o offset onde a constante foi gravada (128).
fn write_rip_add(page: *mut u8) -> usize {
    let const_offset: usize = 128;
    unsafe {
        let const_ptr = page.add(const_offset) as *mut i64;
        *const_ptr = 100i64;
    }

    // disp32 = const_addr - (rip_after_insn)
    //        = (page + const_offset) - (page + 7)
    //        = const_offset - 7
    let disp: i32 = (const_offset as i32) - 7;
    let d = disp.to_le_bytes();

    let code: [u8; 18] = [
        0x48, 0x8B, 0x05, d[0], d[1], d[2], d[3], // mov rax, [rip+disp]
        0x48, 0x03, 0xC1, // add rax, rcx
        0x48, 0x03, 0xC2, // add rax, rdx
        0x48, 0x83, 0xC0, 0x00, // add rax, 0
        0xC3, // ret
    ];
    unsafe {
        core::ptr::copy_nonoverlapping(code.as_ptr(), page, code.len());
    }
    const_offset
}

#[test]
fn e2e_hook_desvia_e_restaura_simples() {
    let page = alloc_rwx(4096);
    assert!(!page.is_null());
    write_simple_add(page);

    let f: AddFn = unsafe { std::mem::transmute(page) };
    assert_eq!(f(2, 3), 5, "pre-hook deve retornar soma simples");

    let hook = Hook::new(page as *const u8, hook_simple as *const u8).expect("instalar hook");
    TRAMP_SIMPLE.store(hook.original() as usize, Ordering::Relaxed);

    assert_eq!(f(2, 3), 50, "pos-hook deve ser (a+b)*10");
    assert_eq!(f(10, 15), 250);

    hook.remove().expect("remover hook");
    assert_eq!(f(2, 3), 5, "pos-remove deve voltar ao comportamento original");

    free_rwx(page);
}

#[test]
fn e2e_hook_prologue_rip_relative() {
    let page = alloc_rwx(4096);
    assert!(!page.is_null());
    write_rip_add(page);

    let f: AddFn = unsafe { std::mem::transmute(page) };
    assert_eq!(f(2, 3), 105, "100 + 2 + 3");

    let hook = Hook::new(page as *const u8, hook_rip as *const u8).expect("instalar hook rip");
    TRAMP_RIP.store(hook.original() as usize, Ordering::Relaxed);

    // Hook soma 7 ao resultado do original (que ainda deve ler 100 via RIP
    // relocado), portanto 100 + 2 + 3 + 7 = 112.
    assert_eq!(f(2, 3), 112, "trampolim rip-relative deve ler constante 100");
    assert_eq!(f(20, 30), 157, "100 + 20 + 30 + 7");

    hook.remove().expect("remover hook rip");
    assert_eq!(f(2, 3), 105);

    free_rwx(page);
}
