use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use onyx_mono_hook::mono_jit::{MonoApi, MonoRuntime};
use onyx_mono_hook::GcGuard;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static DISABLES: AtomicUsize = AtomicUsize::new(0);
static ENABLES: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn fake_disable() {
    DISABLES.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn fake_enable() {
    ENABLES.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn gc_guard_disables_and_enables() {
    let _lock = TEST_LOCK.lock().unwrap();
    DISABLES.store(0, Ordering::SeqCst);
    ENABLES.store(0, Ordering::SeqCst);
    let mut api = MonoApi::new(MonoRuntime::MonoClassic);
    api.gc_disable = Some(fake_disable);
    api.gc_enable = Some(fake_enable);

    {
        let g = GcGuard::new(&api);
        assert!(g.is_engaged());
        assert_eq!(DISABLES.load(Ordering::SeqCst), 1);
        assert_eq!(ENABLES.load(Ordering::SeqCst), 0);
    }
    assert_eq!(DISABLES.load(Ordering::SeqCst), 1);
    assert_eq!(ENABLES.load(Ordering::SeqCst), 1);
}

#[test]
fn gc_guard_noop_quando_api_vazia() {
    let _lock = TEST_LOCK.lock().unwrap();
    DISABLES.store(0, Ordering::SeqCst);
    ENABLES.store(0, Ordering::SeqCst);
    let api = MonoApi::new(MonoRuntime::Il2Cpp);
    {
        let g = GcGuard::new(&api);
        assert!(!g.is_engaged());
    }
    assert_eq!(DISABLES.load(Ordering::SeqCst), 0);
    assert_eq!(ENABLES.load(Ordering::SeqCst), 0);
}
