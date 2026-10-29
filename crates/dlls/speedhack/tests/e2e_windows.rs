//! E2E in-process: instala os hooks reais e mede o avanco do relogio
//! virtual contra o tempo real.
//!
//! Observacoes:
//! * `thread::sleep` no Windows usa `WaitForSingleObject`/`NtDelayExecution`,
//!   que NAO dependem de QPC — portanto o sono real continua acontecendo
//!   em tempo real mesmo com o detour ativo.
//! * `std::time::Instant` usa QPC: so e consultado antes do install e
//!   depois do uninstall.
//! * Logs de medicao sao emitidos via `println!`. Rodar com
//!   `cargo test -p speedhack_dll --release -- --nocapture` para ve-los.

#![cfg(windows)]

use std::ffi::c_void;
use std::time::{Duration, Instant};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn QueryPerformanceCounter(lp: *mut i64) -> i32;
    fn QueryPerformanceFrequency(lp: *mut i64) -> i32;
    fn GetTickCount64() -> u64;
    fn GetProcAddress(h: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetModuleHandleA(name: *const u8) -> *mut c_void;
    fn LoadLibraryA(name: *const u8) -> *mut c_void;
}

fn qpc_now() -> i64 {
    let mut v: i64 = 0;
    unsafe {
        QueryPerformanceCounter(&mut v);
    }
    v
}

fn qpc_freq() -> i64 {
    let mut v: i64 = 0;
    unsafe {
        QueryPerformanceFrequency(&mut v);
    }
    v
}

fn ticks_to_ms(t: i64, f: i64) -> f64 {
    (t as f64) * 1000.0 / (f as f64)
}

fn tgt_now() -> Option<u32> {
    unsafe {
        let mut h = GetModuleHandleA(b"winmm.dll\0".as_ptr());
        if h.is_null() {
            h = LoadLibraryA(b"winmm.dll\0".as_ptr());
        }
        if h.is_null() {
            return None;
        }
        let p = GetProcAddress(h, b"timeGetTime\0".as_ptr());
        if p.is_null() {
            return None;
        }
        let f: unsafe extern "system" fn() -> u32 = core::mem::transmute(p);
        Some(f())
    }
}

/// Verifica que `measured_ratio` esta dentro de +/- 15% de `expected_ratio`.
fn assert_near_ratio(label: &str, measured: f64, expected: f64) {
    let tolerance = 0.15 * expected.abs().max(1e-9);
    let diff = (measured - expected).abs();
    println!(
        "[speedhack-e2e] {}: medido={:.4} esperado={:.4} tolerancia={:.4}",
        label, measured, expected, tolerance
    );
    assert!(
        diff <= tolerance,
        "{}: {:.4} fora de +/-15% de {:.4}",
        label,
        measured,
        expected
    );
}

/// Executa todas as fases num unico `#[test]` para evitar interferencia
/// entre instalacoes em paralelo (os hooks sao globais no processo).
#[test]
fn speedhack_hooks_double_and_halve_time() {
    let freq = qpc_freq();
    assert!(freq > 0);

    // ---------- Medicao de referencia (real) ----------
    let real_start = Instant::now();
    std::thread::sleep(Duration::from_millis(200));
    let real_elapsed = real_start.elapsed();
    println!(
        "[speedhack-e2e] real baseline sleep: {:?} (freq={})",
        real_elapsed, freq
    );

    // ---------- Install com speed=2.0 ----------
    let rc = speedhack_dll::speedhack_install(2.0);
    assert_eq!(rc, 0, "speedhack_install retornou {}", rc);
    assert!(speedhack_dll::hooks::is_installed());

    // Mede delta no QPC virtual durante 200ms de sleep real.
    let q1 = qpc_now();
    let t1 = unsafe { GetTickCount64() };
    let tgt1 = tgt_now();
    std::thread::sleep(Duration::from_millis(200));
    let q2 = qpc_now();
    let t2 = unsafe { GetTickCount64() };
    let tgt2 = tgt_now();

    let virt_delta_ms_qpc = ticks_to_ms(q2 - q1, freq);
    let virt_delta_ms_gtc = (t2 - t1) as f64;
    println!(
        "[speedhack-e2e] speed=2.0 virtual QPC delta: {:.2} ms, GTC64 delta: {:.2} ms (sleep real ~200ms)",
        virt_delta_ms_qpc, virt_delta_ms_gtc
    );
    assert_near_ratio("QPC@2x / real", virt_delta_ms_qpc / 200.0, 2.0);
    assert_near_ratio("GTC64@2x / real", virt_delta_ms_gtc / 200.0, 2.0);
    if let (Some(a), Some(b)) = (tgt1, tgt2) {
        let d = b.wrapping_sub(a) as f64;
        let ratio = d / 200.0;
        println!(
            "[speedhack-e2e] speed=2.0 timeGetTime delta: {:.2} ms (ratio {:.4})",
            d, ratio
        );
        // timeGetTime depende de alocacao de code-cave proxima da winmm:
        // onyx_hook aloca com VirtualAlloc(null) e em algumas versoes a
        // relocacao RIP-relative extrapola i32, impedindo o detour. Nesses
        // casos a amostra retorna tempo real e emitimos apenas aviso.
        if (ratio - 2.0).abs() > 0.3 {
            eprintln!(
                "[speedhack-e2e] AVISO: timeGetTime nao foi acelerado (ratio={:.4}); hook pode nao estar aplicavel nesta build do Windows",
                ratio
            );
        }
    }

    // ---------- Mudanca para speed=0.5 (sem salto) ----------
    let q_before_rebase = qpc_now();
    let rc = speedhack_dll::speedhack_set_speed(0.5);
    assert_eq!(rc, 0);
    let q_after_rebase = qpc_now();
    let jump_ms = ticks_to_ms(q_after_rebase - q_before_rebase, freq).abs();
    println!("[speedhack-e2e] salto no rebase: {:.4} ms", jump_ms);
    assert!(jump_ms < 5.0, "rebase gerou salto de {:.2} ms (>5ms)", jump_ms);

    let q3 = qpc_now();
    std::thread::sleep(Duration::from_millis(200));
    let q4 = qpc_now();
    let delta_half = ticks_to_ms(q4 - q3, freq);
    println!(
        "[speedhack-e2e] speed=0.5 virtual QPC delta: {:.2} ms (sleep real ~200ms)",
        delta_half
    );
    assert_near_ratio("QPC@0.5x / real", delta_half / 200.0, 0.5);

    // ---------- Uninstall e verificar que QPC voltou ao normal ----------
    let rc = speedhack_dll::speedhack_uninstall();
    assert_eq!(rc, 0);
    assert!(!speedhack_dll::hooks::is_installed());

    let post_start = Instant::now();
    let q5 = qpc_now();
    std::thread::sleep(Duration::from_millis(200));
    let q6 = qpc_now();
    let post_real = post_start.elapsed();
    let post_virt_ms = ticks_to_ms(q6 - q5, freq);
    println!(
        "[speedhack-e2e] pos-uninstall real={:?} QPC-delta={:.2} ms",
        post_real, post_virt_ms
    );
    let ratio = post_virt_ms / (post_real.as_secs_f64() * 1000.0);
    assert_near_ratio("QPC pos-uninstall / real", ratio, 1.0);
}
