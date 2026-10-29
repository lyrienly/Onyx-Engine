#![cfg(windows)]
#![cfg(target_arch = "x86_64")]

use vehdebug_dll::debugger::VehDebugger;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[inline(never)]
#[unsafe(no_mangle)]
extern "C" fn vehdebug_test_target(x: u64) -> u64 {
    let mut r = x.wrapping_add(1);
    r = r.wrapping_mul(3);
    std::hint::black_box(r)
}

#[test]
fn sw_breakpoint_hits_then_continues_then_disarms() {
    let dbg = VehDebugger::new().expect("install dispatcher");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_cb = hits.clone();

    let target_addr = vehdebug_test_target as *const () as usize;

    let bp = dbg
        .set_sw_bp(
            target_addr,
            Some(Box::new(move |hit| {
                eprintln!(
                    "[veh][sw-bp] hit id={} rip={:#x} tid={}",
                    hit.id, hit.rip, hit.thread_id
                );
                hits_cb.fetch_add(1, Ordering::SeqCst);
            })),
        )
        .expect("sw bp armed");

    let r1 = vehdebug_test_target(10);
    assert_eq!(r1, (10u64 + 1).wrapping_mul(3));
    assert!(
        hits.load(Ordering::SeqCst) >= 1,
        "veh deveria ter capturado pelo menos 1 hit"
    );

    let hits_before_remove = hits.load(Ordering::SeqCst);
    assert!(dbg.remove(bp));

    let r2 = vehdebug_test_target(20);
    assert_eq!(r2, (20u64 + 1).wrapping_mul(3));

    let hits_after = hits.load(Ordering::SeqCst);

    assert!(
        hits_after - hits_before_remove <= 1,
        "handler nao deveria continuar refirando (antes={}, depois={})",
        hits_before_remove,
        hits_after
    );
}
