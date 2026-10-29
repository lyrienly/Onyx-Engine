//! Motor atomico de congelamento de valores.
//!
//! Mantem enderecos remotos reescritos continuamente por uma thread dedicada
//! de alta prioridade, usando estrutura concorrente baseada em `DashMap` para
//! insercao/remocao dinamica sem lock global, resolucao de temporizador de 1ms
//! via `timeBeginPeriod` e cache do ultimo valor para evitar escritas
//! redundantes.

use dashmap::DashMap;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

type HANDLE = *mut c_void;
type DWORD = u32;
type BOOL = i32;
#[allow(non_camel_case_types)]
type SIZE_T = usize;

const FALSE: BOOL = 0;

const PROCESS_VM_READ: DWORD = 0x0010;
const PROCESS_VM_WRITE: DWORD = 0x0020;
const PROCESS_VM_OPERATION: DWORD = 0x0008;
const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;

const THREAD_PRIORITY_HIGHEST: i32 = 2;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(access: DWORD, inherit: BOOL, pid: DWORD) -> HANDLE;
    fn CloseHandle(h: HANDLE) -> BOOL;
    fn WriteProcessMemory(
        h: HANDLE,
        addr: *mut c_void,
        buf: *const c_void,
        size: SIZE_T,
        written: *mut SIZE_T,
    ) -> BOOL;
    fn ReadProcessMemory(
        h: HANDLE,
        addr: *const c_void,
        buf: *mut c_void,
        size: SIZE_T,
        read: *mut SIZE_T,
    ) -> BOOL;
    fn GetCurrentThread() -> HANDLE;
    fn SetThreadPriority(h: HANDLE, prio: i32) -> BOOL;
}

#[link(name = "winmm")]
unsafe extern "system" {
    fn timeBeginPeriod(uPeriod: u32) -> u32;
    fn timeEndPeriod(uPeriod: u32) -> u32;
}

pub type FreezeId = u64;

/// Modo de evolucao do valor congelado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreezeMode {
    /// Mantem o valor exato indefinidamente.
    Normal,
    /// Incrementa o valor a cada tick do worker (little-endian com sinal).
    Increment(i64),
    /// Decrementa o valor a cada tick do worker.
    Decrement(i64),
}

#[derive(Clone, Debug)]
pub struct FreezeEntry {
    pub id: FreezeId,
    pub address: usize,
    pub value: Vec<u8>,
    pub mode: FreezeMode,
}

struct EntrySlot {
    address: usize,
    value: Vec<u8>,
    mode: FreezeMode,
    last_written: Option<Vec<u8>>,
}

/// Estatisticas acumuladas pelo worker.
#[derive(Debug, Clone, Copy, Default)]
pub struct FreezerStats {
    pub writes: u64,
    pub reads: u64,
    pub cache_hits: u64,
    pub errors: u64,
}

pub struct AtomicFreezer {
    pid: Arc<AtomicU32>,
    entries: Arc<DashMap<FreezeId, EntrySlot>>,
    next_id: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    interval_us: Arc<AtomicU64>,
    writes: Arc<AtomicU64>,
    reads: Arc<AtomicU64>,
    cache_hits: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl AtomicFreezer {
    pub fn new() -> Self {
        AtomicFreezer {
            pid: Arc::new(AtomicU32::new(0)),
            entries: Arc::new(DashMap::new()),
            next_id: Arc::new(AtomicU64::new(1)),
            stop: Arc::new(AtomicBool::new(false)),
            running: Arc::new(AtomicBool::new(false)),
            interval_us: Arc::new(AtomicU64::new(10_000)),
            writes: Arc::new(AtomicU64::new(0)),
            reads: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            errors: Arc::new(AtomicU64::new(0)),
            worker: Mutex::new(None),
        }
    }

    /// Define o processo alvo pelo PID.
    pub fn attach(&self, pid: u32) {
        self.pid.store(pid, Ordering::SeqCst);
    }

    /// Ajusta o intervalo entre ticks do worker.
    pub fn set_interval(&self, interval: Duration) {
        let us = interval.as_micros() as u64;
        self.interval_us
            .store(us.max(1_000), Ordering::SeqCst);
    }

    /// Congela um endereco; se o worker ainda nao estiver rodando, inicia-o.
    pub fn freeze(&self, address: usize, value: Vec<u8>, mode: FreezeMode) -> FreezeId {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.entries.insert(
            id,
            EntrySlot {
                address,
                value,
                mode,
                last_written: None,
            },
        );
        self.ensure_worker();
        id
    }

    pub fn unfreeze(&self, id: FreezeId) -> bool {
        self.entries.remove(&id).is_some()
    }

    pub fn unfreeze_all(&self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn list(&self) -> Vec<FreezeEntry> {
        let mut v: Vec<FreezeEntry> = self
            .entries
            .iter()
            .map(|r| FreezeEntry {
                id: *r.key(),
                address: r.value().address,
                value: r.value().value.clone(),
                mode: r.value().mode,
            })
            .collect();
        v.sort_by_key(|e| e.id);
        v
    }

    pub fn stats(&self) -> FreezerStats {
        FreezerStats {
            writes: self.writes.load(Ordering::Relaxed),
            reads: self.reads.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }

    pub fn reset_stats(&self) {
        self.writes.store(0, Ordering::Relaxed);
        self.reads.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
    }

    fn ensure_worker(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        self.stop.store(false, Ordering::SeqCst);

        let entries = Arc::clone(&self.entries);
        let stop = Arc::clone(&self.stop);
        let running = Arc::clone(&self.running);
        let pid = Arc::clone(&self.pid);
        let interval_us = Arc::clone(&self.interval_us);
        let writes = Arc::clone(&self.writes);
        let reads = Arc::clone(&self.reads);
        let cache_hits = Arc::clone(&self.cache_hits);
        let errors = Arc::clone(&self.errors);

        let handle = thread::Builder::new()
            .name("onyx-freezer".into())
            .spawn(move || {
                worker_main(
                    entries,
                    stop,
                    pid,
                    interval_us,
                    writes,
                    reads,
                    cache_hits,
                    errors,
                );
                running.store(false, Ordering::SeqCst);
            })
            .expect("spawn freezer worker");

        *self.worker.lock().unwrap() = Some(handle);
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let handle = self.worker.lock().unwrap().take();
        if let Some(h) = handle {
            let _ = h.join();
        }
        self.running.store(false, Ordering::SeqCst);
    }
}

impl Default for AtomicFreezer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AtomicFreezer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn worker_main(
    entries: Arc<DashMap<FreezeId, EntrySlot>>,
    stop: Arc<AtomicBool>,
    pid_atom: Arc<AtomicU32>,
    interval_us: Arc<AtomicU64>,
    writes: Arc<AtomicU64>,
    reads: Arc<AtomicU64>,
    cache_hits: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
) {
    unsafe {
        timeBeginPeriod(1);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    }

    let mut current_pid: u32 = 0;
    let mut handle: HANDLE = std::ptr::null_mut();

    while !stop.load(Ordering::Relaxed) {
        let desired_pid = pid_atom.load(Ordering::Relaxed);

        if desired_pid != current_pid {
            if !handle.is_null() {
                unsafe { CloseHandle(handle) };
                handle = std::ptr::null_mut();
            }
            current_pid = desired_pid;
            if current_pid != 0 {
                let access = PROCESS_VM_READ
                    | PROCESS_VM_WRITE
                    | PROCESS_VM_OPERATION
                    | PROCESS_QUERY_INFORMATION;
                let h = unsafe { OpenProcess(access, FALSE, current_pid) };
                if !h.is_null() {
                    handle = h;
                }
            }
        }

        if !handle.is_null() && !entries.is_empty() {
            for mut slot in entries.iter_mut() {
                let desired = compute_desired(slot.value().value.as_slice(), slot.value().mode);
                let address = slot.value().address;

                let mut current = vec![0u8; desired.len()];
                let mut read_bytes: SIZE_T = 0;
                let read_ok = unsafe {
                    ReadProcessMemory(
                        handle,
                        address as *const c_void,
                        current.as_mut_ptr() as *mut c_void,
                        current.len(),
                        &mut read_bytes,
                    )
                };
                reads.fetch_add(1, Ordering::Relaxed);

                let needs_write = if read_ok != 0 && read_bytes == desired.len() {
                    current != desired
                } else {
                    true
                };

                if !needs_write {
                    if let Some(ref last) = slot.value().last_written {
                        if last.as_slice() == desired.as_slice() {
                            cache_hits.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    slot.value_mut().last_written = Some(desired.clone());
                } else {
                    let mut written: SIZE_T = 0;
                    let ok = unsafe {
                        WriteProcessMemory(
                            handle,
                            address as *mut c_void,
                            desired.as_ptr() as *const c_void,
                            desired.len(),
                            &mut written,
                        )
                    };
                    if ok != 0 && written == desired.len() {
                        writes.fetch_add(1, Ordering::Relaxed);
                        slot.value_mut().last_written = Some(desired.clone());
                    } else {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // Avanca o valor para os modos incrementais.
                match slot.value().mode {
                    FreezeMode::Normal => {}
                    FreezeMode::Increment(step) => {
                        slot.value_mut().value = add_step(&desired, step);
                    }
                    FreezeMode::Decrement(step) => {
                        slot.value_mut().value = add_step(&desired, -step);
                    }
                }
            }
        }

        let us = interval_us.load(Ordering::Relaxed).max(1_000);
        thread::sleep(Duration::from_micros(us));
    }

    if !handle.is_null() {
        unsafe { CloseHandle(handle) };
    }

    unsafe { timeEndPeriod(1) };
}

fn compute_desired(current_stored: &[u8], _mode: FreezeMode) -> Vec<u8> {
    current_stored.to_vec()
}

/// Soma `step` ao valor little-endian em `bytes` (interpretado como inteiro
/// com sinal da largura dada), devolvendo um buffer do mesmo tamanho.
fn add_step(bytes: &[u8], step: i64) -> Vec<u8> {
    let width = bytes.len();
    let mut buf = [0u8; 8];
    let copy_len = width.min(8);
    buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
    let signed = i64::from_le_bytes(buf);
    let next = signed.wrapping_add(step);
    let out_bytes = next.to_le_bytes();
    let mut out = vec![0u8; width];
    let copy_len = width.min(8);
    out[..copy_len].copy_from_slice(&out_bytes[..copy_len]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_step_i32() {
        let v = 100i32.to_le_bytes().to_vec();
        let n = add_step(&v, 1);
        let got = i32::from_le_bytes(n.try_into().unwrap());
        assert_eq!(got, 101);
    }

    #[test]
    fn add_step_negative() {
        let v = 100i32.to_le_bytes().to_vec();
        let n = add_step(&v, -5);
        let got = i32::from_le_bytes(n.try_into().unwrap());
        assert_eq!(got, 95);
    }
}
