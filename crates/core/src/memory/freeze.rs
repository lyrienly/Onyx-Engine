// language: Rust, file: freeze.rs, target: Windows 11, MSVC
// Address value freezing / locking engine with background refresh thread

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
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
}

impl Freezer {
    pub fn new() -> Self {
        Freezer {
            next_id: 1,
            entries: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&self, proc: &Process, interval_ms: u64) {
        if self.running.swap(true, Ordering::SeqCst) {
            return; // Already running
        }

        let entries_clone = Arc::clone(&self.entries);
        let running_clone = Arc::clone(&self.running);
        let proc_handle = proc.handle as usize;
        let proc_pid = proc.pid;
        let proc_mode = proc.access_mode;
        let proc_dbk = proc.dbk.clone();

        thread::spawn(move || {
            let dummy_proc = Process {
                pid: proc_pid,
                handle: proc_handle as crate::win32::HANDLE,
                name: String::new(),
                access_mode: proc_mode,
                dbk: proc_dbk,
            };

            while running_clone.load(Ordering::Relaxed) {
                {
                    let lock = entries_clone.lock().unwrap();
                    for entry in lock.values() {
                        let bytes = entry.value.to_bytes();
                        let _ = dummy_proc.write_raw(entry.address, &bytes);
                    }
                }
                thread::sleep(Duration::from_millis(interval_ms));
            }

            std::mem::forget(dummy_proc);
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn freeze(&mut self, address: usize, value: ScanValue, desc: &str) -> usize {
        let id = self.next_id;
        self.next_id += 1;

        let mut lock = self.entries.lock().unwrap();
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

    pub fn unfreeze(&self, id: usize) -> bool {
        let mut lock = self.entries.lock().unwrap();
        lock.remove(&id).is_some()
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
