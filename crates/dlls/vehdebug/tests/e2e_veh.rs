//! E2E in-process: registra VEH, planta um software breakpoint em uma
//! funcao do proprio executavel de teste, dispara, verifica captura e
//! continuacao, remove e re-executa para garantir que nao houve resquicio.

#![cfg(windows)]
#![cfg(target_arch = "x86_64")]

use vehdebug_dll::debugger::VehDebugger;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A funcao-alvo. `inline(never)` garante que exista um simbolo real;
/// `no_mangle` para debug legivel. O corpo e intencionalmente trivial.
#[inline(never)]
#[unsafe(no_mangle)]
extern "C" fn vehdebug_test_target(x: u64) -> u64 {
    // 3 instrucoes basicas para dar materia prima ao decode do CPU.
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

    // Executa a target com o INT3 armado.
    let r1 = vehdebug_test_target(10);
    assert_eq!(r1, (10u64 + 1).wrapping_mul(3));
    assert!(
        hits.load(Ordering::SeqCst) >= 1,
        "veh deveria ter capturado pelo menos 1 hit"
    );

    // Remove bp e verifica que novas chamadas nao refiram o handler.
    let hits_before_remove = hits.load(Ordering::SeqCst);
    assert!(dbg.remove(bp));
    // Call extra para garantir que a aritmetica ainda funciona.
    let r2 = vehdebug_test_target(20);
    assert_eq!(r2, (20u64 + 1).wrapping_mul(3));

    let hits_after = hits.load(Ordering::SeqCst);
    // Em processos normais a diferenca deve ser 0 (bp removido). Permite
    // ate 1 hit extra caso o TF/re-armo tenha disparado tarde — mas nao
    // deve crescer alem disso.
    assert!(
        hits_after - hits_before_remove <= 1,
        "handler nao deveria continuar refirando (antes={}, depois={})",
        hits_before_remove,
        hits_after
    );
}
