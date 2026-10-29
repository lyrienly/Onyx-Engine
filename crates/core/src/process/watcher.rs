use crate::process::{Process, ProcessEntry};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum ProcessWatchEvent {
    Created(ProcessEntry),
    Terminated(u32),
}

pub struct ProcessWatcher {
    running: Arc<AtomicBool>,
    target_names: Arc<Mutex<HashSet<String>>>,
    events: Arc<Mutex<VecDeque<ProcessWatchEvent>>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ProcessWatcher {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            target_names: Arc::new(Mutex::new(HashSet::new())),
            events: Arc::new(Mutex::new(VecDeque::new())),
            worker: None,
        }
    }

    pub fn add_target(&self, name: &str) {
        if let Ok(mut set) = self.target_names.lock() {
            set.insert(name.to_lowercase());
        }
    }

    pub fn remove_target(&self, name: &str) {
        if let Ok(mut set) = self.target_names.lock() {
            set.remove(&name.to_lowercase());
        }
    }

    pub fn clear_targets(&self) {
        if let Ok(mut set) = self.target_names.lock() {
            set.clear();
        }
    }

    pub fn start(&mut self, poll_interval_ms: u64) -> Result<(), String> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        self.running.store(true, Ordering::SeqCst);
        let running_flag = self.running.clone();
        let targets_lock = self.target_names.clone();
        let events_lock = self.events.clone();

        let handle = thread::Builder::new()
            .name("OnyxProcessWatcher".to_string())
            .spawn(move || {
                let mut known_pids: HashMap<u32, ProcessEntry> = HashMap::new();

                if let Ok(initial_list) = Process::list_all_nt() {
                    for p in initial_list {
                        known_pids.insert(p.pid, p);
                    }
                }

                while running_flag.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(poll_interval_ms.max(20)));

                    if !running_flag.load(Ordering::SeqCst) {
                        break;
                    }

                    let current_list = match Process::list_all_nt() {
                        Ok(list) => list,
                        Err(_) => continue,
                    };

                    let mut current_map: HashMap<u32, ProcessEntry> = HashMap::new();
                    let targets = targets_lock
                        .lock()
                        .ok()
                        .map(|t| t.clone())
                        .unwrap_or_default();

                    for p in current_list {
                        let pid = p.pid;
                        let p_name_lower = p.name.to_lowercase();

                        if !known_pids.contains_key(&pid) {
                            let is_target = targets.is_empty() || targets.contains(&p_name_lower);
                            if is_target && let Ok(mut q) = events_lock.lock() {
                                q.push_back(ProcessWatchEvent::Created(p.clone()));
                            }
                        }
                        current_map.insert(pid, p);
                    }

                    for (&pid, old_proc) in &known_pids {
                        if !current_map.contains_key(&pid) {
                            let old_name_lower = old_proc.name.to_lowercase();
                            let is_target = targets.is_empty() || targets.contains(&old_name_lower);
                            if is_target && let Ok(mut q) = events_lock.lock() {
                                q.push_back(ProcessWatchEvent::Terminated(pid));
                            }
                        }
                    }

                    known_pids = current_map;
                }
            })
            .map_err(|e| format!("Failed to spawn process watcher thread: {}", e))?;

        self.worker = Some(handle);
        Ok(())
    }

    pub fn poll_event(&self) -> Option<ProcessWatchEvent> {
        let mut q = self.events.lock().ok()?;
        q.pop_front()
    }

    pub fn stop(&mut self) {
        if self.running.load(Ordering::SeqCst) {
            self.running.store(false, Ordering::SeqCst);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

impl Default for ProcessWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ProcessWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_watcher_lifecycle() {
        let mut watcher = ProcessWatcher::new();
        assert!(!watcher.is_running());

        watcher.add_target("nonexistent_test_proc.exe");
        assert!(watcher.start(50).is_ok());
        assert!(watcher.is_running());

        assert!(watcher.poll_event().is_none());

        watcher.stop();
        assert!(!watcher.is_running());
    }
}
