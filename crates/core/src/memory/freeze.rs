use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use crate::process::Process;
use crate::scanner::ScanValue;

#[derive(Debug, Clone)]
pub struct FrozenEntry {
    pub id: usize,
    pub address: usize,
    pub value: ScanValue,
    pub description: String,
}

pub struct Freezer {
    next_id: usize,
    entries: Arc<Mutex<HashMap<usize, FrozenEntry>>>,
    running: Arc<AtomicBool>,
    handle: Arc<AtomicUsize>,
    pid: Arc<AtomicUsize>,
}

impl Freezer {
    pub fn new() -> Self {
        Freezer {
            next_id: 1,
            entries: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(AtomicBool::new(false)),
            handle: Arc::new(AtomicUsize::new(0)),
            pid: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn update_process(&self, proc: &Process) {
        self.handle.store(proc.handle as usize, Ordering::SeqCst);
        self.pid.store(proc.pid as usize, Ordering::SeqCst);
    }

    pub fn start(&self, proc: &Process, interval_ms: u64) {
        self.update_process(proc);

        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }

        let entries_clone = Arc::clone(&self.entries);
        let running_clone = Arc::clone(&self.running);
        let handle_clone = Arc::clone(&self.handle);
        let pid_clone = Arc::clone(&self.pid);
        let proc_mode = proc.access_mode;
        let proc_dbk = proc.dbk.clone();

        thread::spawn(move || {
            while running_clone.load(Ordering::Relaxed) {
                let cur_handle = handle_clone.load(Ordering::Relaxed);
                let cur_pid = pid_clone.load(Ordering::Relaxed) as u32;

                if cur_handle != 0 {
                    let dummy_proc = Process {
                        pid: cur_pid,
                        handle: cur_handle as crate::win32::HANDLE,
                        name: String::new(),
                        access_mode: proc_mode,
                        dbk: proc_dbk.clone(),
                    };

                    {
                        let lock = entries_clone.lock().unwrap();
                        for entry in lock.values() {
                            let bytes = entry.value.to_bytes();
                            let _ = dummy_proc.write_raw(entry.address, &bytes);
                        }
                    }

                    std::mem::forget(dummy_proc);
                }

                thread::sleep(Duration::from_millis(if interval_ms == 0 { 50 } else { interval_ms }));
            }
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn freeze(&mut self, address: usize, value: ScanValue, desc: &str) -> usize {
        let mut lock = self.entries.lock().unwrap();

        for entry in lock.values_mut() {
            if entry.address == address {
                entry.value = value;
                entry.description = desc.to_string();
                return entry.id;
            }
        }

        let id = self.next_id;
        self.next_id += 1;

        lock.insert(
            id,
            FrozenEntry {
                id,
                address,
                value,
                description: desc.to_string(),
            },
        );
        id
    }

    pub fn update(&self, id: usize, value: ScanValue) -> bool {
        let mut lock = self.entries.lock().unwrap();
        if let Some(entry) = lock.get_mut(&id) {
            entry.value = value;
            true
        } else {
            false
        }
    }

    pub fn update_by_address(&self, address: usize, value: ScanValue) -> bool {
        let mut lock = self.entries.lock().unwrap();
        for entry in lock.values_mut() {
            if entry.address == address {
                entry.value = value;
                return true;
            }
        }
        false
    }

    pub fn unfreeze(&self, id: usize) -> bool {
        let mut lock = self.entries.lock().unwrap();
        lock.remove(&id).is_some()
    }

    pub fn unfreeze_by_address(&self, address: usize) -> bool {
        let mut lock = self.entries.lock().unwrap();
        let to_remove: Vec<usize> = lock.values()
            .filter(|e| e.address == address)
            .map(|e| e.id)
            .collect();
        let found = !to_remove.is_empty();
        for id in to_remove {
            lock.remove(&id);
        }
        found
    }

    pub fn list(&self) -> Vec<FrozenEntry> {
        let lock = self.entries.lock().unwrap();
        let mut list: Vec<FrozenEntry> = lock.values().cloned().collect();
        list.sort_by_key(|e| e.id);
        list
    }

    pub fn clear(&self) {
        let mut lock = self.entries.lock().unwrap();
        lock.clear();
    }
}

impl Default for Freezer {
    fn default() -> Self {
        Self::new()
    }
}
