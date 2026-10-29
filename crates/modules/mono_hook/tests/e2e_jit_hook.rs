#![cfg(windows)]

use std::sync::atomic::{AtomicUsize, Ordering};

use onyx_mono_hook::mono_jit::{MonoApi, MonoRuntime};
use onyx_mono_hook::{JitHookManager, MethodId};

static DISABLES: AtomicUsize = AtomicUsize::new(0);
static ENABLES: AtomicUsize = AtomicUsize::new(0);
static TRAMP: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn fake_mono_gc_disable() {
    DISABLES.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn fake_mono_gc_enable() {
    ENABLES.fetch_add(1, Ordering::SeqCst);
}

type JitFn = extern "C" fn(i32) -> i32;

#[inline(never)]
#[no_mangle]
pub extern "C" fn fake_jit_method(x: i32) -> i32 {
    std::hint::black_box(x) * 10
}

extern "C" fn hook_fn(x: i32) -> i32 {
    let p = TRAMP.load(Ordering::SeqCst) as *const u8;
    let orig: JitFn = unsafe { std::mem::transmute(p) };
    orig(x) + 100
}

#[test]
fn e2e_jit_hook_com_gc_lifecycle() {
    DISABLES.store(0, Ordering::SeqCst);
    ENABLES.store(0, Ordering::SeqCst);

    assert_eq!(fake_jit_method(5), 50);

    let mut api = MonoApi::new(MonoRuntime::MonoClassic);
    api.gc_disable = Some(fake_mono_gc_disable);
    api.gc_enable = Some(fake_mono_gc_enable);

    let mut mgr = JitHookManager::new(api);

    let jit_ptr = fake_jit_method as *mut u8;
    let id: MethodId = mgr
        .hook_method_by_ptr(jit_ptr, hook_fn as *const u8)
        .expect("hook deve instalar");

    let tramp = mgr.original(id).expect("trampolim deve existir");
    TRAMP.store(tramp as usize, Ordering::SeqCst);

    assert_eq!(
        DISABLES.load(Ordering::SeqCst),
        1,
        "GC disable deve ter sido chamado antes do patch"
    );
    assert_eq!(
        ENABLES.load(Ordering::SeqCst),
        1,
        "GC enable deve ter sido chamado apos o patch"
    );

    let out = fake_jit_method(5);
    assert_eq!(out, 150, "hook deve interceptar e somar 100 ao original");

    mgr.remove(id).expect("remove deve restaurar");

    assert_eq!(DISABLES.load(Ordering::SeqCst), 2);
    assert_eq!(ENABLES.load(Ordering::SeqCst), 2);

    assert_eq!(
        fake_jit_method(5),
        50,
        "funcao original deve voltar ao normal"
    );
    assert!(mgr.is_empty());
}
