//! `VirtualClock` — relogio virtual que interpola QPC em ponto flutuante.
//!
//! A implementacao mantem uma base real (ticks QPC lidos sem modificacao
//! pelo chamador) e uma base virtual (ticks reportados pelas APIs
//! hookadas). Toda consulta recalcula
//! `base_virtual + (real_now - base_real) * speed`, mantendo a
//! aceleracao linear.
//!
//! Trocas de velocidade reancoram as bases para `now()`, impedindo saltos
//! discretos (stuttering) comuns em motores que dependem de deltas pequenos
//! entre quadros.
//!
//! Nenhuma funcao deste modulo chama APIs do SO: isso evita recursao caso
//! as proprias APIs de temporizacao estejam hookadas. Quem precisa do
//! `real_now` repassa a leitura obtida pelo trampolim.

use std::sync::Mutex;

#[cfg(windows)]
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

#[derive(Debug, Clone)]
pub struct VirtualClock {
    pub base_real: i64,
    pub base_virtual: i64,
    pub speed: f64,
    pub freq: i64,
}

impl VirtualClock {
    pub fn new(real_now: i64, freq: i64, speed: f64) -> Self {
        Self {
            base_real: real_now,
            base_virtual: real_now,
            speed: speed.max(0.0),
            freq: freq.max(1),
        }
    }

    #[inline]
    pub fn virtual_from_real(&self, real_now: i64) -> i64 {
        let delta = real_now.wrapping_sub(self.base_real);
        let scaled = (delta as f64) * self.speed;
        self.base_virtual.wrapping_add(scaled as i64)
    }

    /// Rebase mantem continuidade: `virtual_from_real(real_now)` imediatamente
    /// antes e imediatamente depois da chamada retorna o mesmo valor.
    #[inline]
    pub fn rebase(&mut self, real_now: i64) {
        self.base_virtual = self.virtual_from_real(real_now);
        self.base_real = real_now;
    }

    #[inline]
    pub fn ticks_to_ms(&self, ticks: i64) -> i64 {
        if self.freq <= 0 {
            return 0;
        }
        ((ticks as f64) * 1000.0 / (self.freq as f64)) as i64
    }
}

static CLOCK: Mutex<Option<VirtualClock>> = Mutex::new(None);

#[cfg(windows)]
pub fn raw_qpc_freq() -> i64 {
    let mut f: i64 = 0;
    unsafe {
        QueryPerformanceFrequency(&mut f);
    }
    if f <= 0 { 10_000_000 } else { f }
}

#[cfg(windows)]
pub fn raw_qpc_now() -> i64 {
    let mut t: i64 = 0;
    unsafe {
        QueryPerformanceCounter(&mut t);
    }
    t
}

#[cfg(not(windows))]
pub fn raw_qpc_freq() -> i64 {
    10_000_000
}

#[cfg(not(windows))]
pub fn raw_qpc_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    dur.as_nanos() as i64 / 100
}

/// Inicializa o relogio com uma leitura externa de QPC real.
pub fn init_with(real_now: i64, freq: i64, speed: f64) {
    let mut guard = CLOCK.lock().unwrap();
    *guard = Some(VirtualClock::new(real_now, freq, speed));
}

/// Troca a velocidade preservando continuidade; `real_now` e o QPC real
/// medido pelo chamador (normalmente via trampolim).
pub fn set_speed_with(real_now: i64, speed: f64) {
    let mut guard = CLOCK.lock().unwrap();
    if let Some(c) = guard.as_mut() {
        c.rebase(real_now);
        c.speed = speed.max(0.0);
    }
}

pub fn deinit() {
    let mut guard = CLOCK.lock().unwrap();
    *guard = None;
}

/// Converte `real_now` em QPC virtual segundo o estado atual.
#[inline]
pub fn virtual_from_real(real_now: i64) -> i64 {
    let guard = CLOCK.lock().unwrap();
    match guard.as_ref() {
        Some(c) => c.virtual_from_real(real_now),
        None => real_now,
    }
}

/// Converte `real_now` em milissegundos virtuais absolutos.
#[inline]
pub fn virtual_ms_from_real(real_now: i64) -> u64 {
    let guard = CLOCK.lock().unwrap();
    match guard.as_ref() {
        Some(c) => {
            let v = c.virtual_from_real(real_now);
            let ms = (v as f64) * 1000.0 / (c.freq as f64);
            ms as u64
        }
        None => {
            let freq = raw_qpc_freq();
            ((real_now as f64) * 1000.0 / (freq as f64)) as u64
        }
    }
}

pub fn snapshot() -> Option<VirtualClock> {
    CLOCK.lock().unwrap().clone()
}

pub fn is_initialized() -> bool {
    CLOCK.lock().unwrap().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speed_two_doubles_delta() {
        let freq = 10_000_000i64;
        let base = 1_000_000i64;
        let c = VirtualClock::new(base, freq, 2.0);
        let real_later = base + freq / 10; // +100ms reais
        let delta = c.virtual_from_real(real_later) - base;
        assert_eq!(delta, 2 * (freq / 10));
    }

    #[test]
    fn speed_half_halves_delta() {
        let freq = 10_000_000i64;
        let c = VirtualClock::new(0, freq, 0.5);
        assert_eq!(c.virtual_from_real(freq), freq / 2);
    }

    #[test]
    fn rebase_is_continuous() {
        let freq = 10_000_000i64;
        let mut c = VirtualClock::new(0, freq, 2.0);
        let t1 = freq;
        let before = c.virtual_from_real(t1);
        c.rebase(t1);
        let after = c.virtual_from_real(t1);
        assert_eq!(before, after);
        c.speed = 0.5;
        assert_eq!(c.virtual_from_real(t1), after);
        // 1s depois, com speed=0.5, soma 0.5s virtuais.
        assert_eq!(c.virtual_from_real(t1 + freq), after + freq / 2);
    }

    #[test]
    fn ticks_to_ms_conversion() {
        let c = VirtualClock::new(0, 10_000_000, 1.0);
        assert_eq!(c.ticks_to_ms(10_000_000), 1000);
        assert_eq!(c.ticks_to_ms(1_000_000), 100);
    }

    #[test]
    fn global_api_round_trip() {
        init_with(0, 10_000_000, 2.0);
        let v = virtual_from_real(1_000_000); // 100ms reais
        assert_eq!(v, 2_000_000);
        set_speed_with(1_000_000, 0.5);
        let v2 = virtual_from_real(1_000_000);
        assert_eq!(v2, 2_000_000); // sem salto
        let v3 = virtual_from_real(2_000_000);
        assert_eq!(v3, 2_000_000 + 500_000);
        deinit();
    }
}
