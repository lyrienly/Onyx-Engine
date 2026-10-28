//! Processo-alvo do harness de hardware breakpoints (issue #16).
//!
//! Uso:
//!   cargo run -p onyx_core --example hw_bp_target -- [threads]
//!
//! Imprime `PID`, `ADDR` e `THREADS` na inicializacao e depois aceita comandos
//! pelo stdin:
//!   GO    - as threads passam a escrever no contador
//!   STOP  - as threads param de escrever
//!   QUIT  - encerra o processo
//!
//! As threads ficam ociosas ate receber `GO`, o que permite configurar e
//! remover breakpoints de escrita sem que o alvo seja atingido.

use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

static COUNTER: AtomicU64 = AtomicU64::new(0);
static RUN: AtomicBool = AtomicBool::new(false);
static QUIT: AtomicBool = AtomicBool::new(false);

fn main() {
    let thread_count = std::env::args()
        .nth(1)
        .and_then(|arg| arg.parse::<usize>().ok())
        .unwrap_or(8);

    for _ in 0..thread_count {
        thread::spawn(|| {
            while !QUIT.load(Ordering::Relaxed) {
                if RUN.load(Ordering::Relaxed) {
                    COUNTER.fetch_add(1, Ordering::Relaxed);
                } else {
                    thread::sleep(Duration::from_millis(2));
                }
            }
        });
    }

    println!("PID={}", std::process::id());
    println!("ADDR={:#x}", &COUNTER as *const AtomicU64 as usize);
    println!("THREADS={thread_count}");
    let _ = io::stdout().flush();

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        match line.as_deref() {
            Ok("GO") => RUN.store(true, Ordering::Relaxed),
            Ok("STOP") => RUN.store(false, Ordering::Relaxed),
            Ok("QUIT") => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    QUIT.store(true, Ordering::Relaxed);
    thread::sleep(Duration::from_millis(50));
}
