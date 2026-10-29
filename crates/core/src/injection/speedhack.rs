use std::time::Instant;
use crate::hook::Hook;
use crate::process::Process;
use crate::symbol::SymbolResolver;
use crate::win32::*;

#[derive(Debug, Clone)]
pub struct SpeedController {
    pub multiplier: f32,
    pub is_enabled: bool,
    start_real_time: Instant,
    last_virtual_time_ms: u64,
}

impl SpeedController {
    pub fn new(multiplier: f32) -> Self {
        SpeedController {
            multiplier,
            is_enabled: true,
            start_real_time: Instant::now(),
            last_virtual_time_ms: 0,
        }
    }

    pub fn set_speed(&mut self, speed: f32) {

        let current_real_elapsed = self.start_real_time.elapsed().as_millis() as f64;
        self.last_virtual_time_ms += (current_real_elapsed * (self.multiplier as f64)) as u64;
        self.start_real_time = Instant::now();
        self.multiplier = speed.max(0.0);
    }

    pub fn get_scaled_time_ms(&self) -> u64 {
        if self.multiplier <= 0.0 {

            return self.last_virtual_time_ms;
        }
        let current_real_elapsed = self.start_real_time.elapsed().as_millis() as f64;
        let scaled_delta = (current_real_elapsed * (self.multiplier as f64)) as u64;
        self.last_virtual_time_ms + scaled_delta
    }
}

pub struct SpeedhackInjector {
    installed_hooks: Vec<Hook>,
}

impl SpeedhackInjector {
    pub fn new() -> Self {
        SpeedhackInjector {
            installed_hooks: Vec::new(),
        }
    }

    pub fn enable_speedhack(
        &mut self,
        proc: &Process,
        multiplier: f32,
    ) -> Result<(), String> {
        let mut resolver = SymbolResolver::new();
        let qpc_addr = resolver
            .resolve(proc, "kernel32.dll!QueryPerformanceCounter")
            .ok_or_else(|| "Could not resolve QueryPerformanceCounter".to_string())?;

        let state_addr = proc.alloc(64, PAGE_READWRITE)?;
        let mult_bytes = multiplier.to_ne_bytes();
        proc.write_raw(state_addr, &mult_bytes)?;

        let mut payload = Vec::new();

        payload.extend_from_slice(&[0x53, 0x51, 0x52]);

        payload.extend_from_slice(&[0x5A, 0x59, 0x5B]);

        println!("[+] Speedhack state block allocated at 0x{:016X} (Speed: {}x)", state_addr, multiplier);
        println!("[+] QueryPerformanceCounter located at 0x{:016X}", qpc_addr);

        Ok(())
    }

    pub fn is_active(&self) -> bool {
        !self.installed_hooks.is_empty()
    }
}
