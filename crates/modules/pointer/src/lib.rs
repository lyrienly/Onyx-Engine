
use std::ffi::{c_char, CStr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;

use onyx_core::pointer_scanner::{PointerPath, PointerScanConfig, PointerScanner};
use onyx_core::process::{ModuleEntry, Process};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnyxPointerScanPhase {
    Idle = 0,
    GeneratingMap = 1,
    SearchingPaths = 2,
    Rescanning = 3,
    Completed = 4,
    Cancelled = 5,
    Failed = 6,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OnyxPointerPathRecord {
    pub module_name: [c_char; 260],
    pub base_offset: usize,
    pub offsets: [usize; 16],
    pub offset_count: u32,
    pub final_address: usize,
}

impl Default for OnyxPointerPathRecord {
    fn default() -> Self {
        Self {
            module_name: [0; 260],
            base_offset: 0,
            offsets: [0; 16],
            offset_count: 0,
            final_address: 0,
        }
    }
}

pub struct PointerScannerSession {
    pub scanner: Arc<Mutex<PointerScanner>>,
    pub results: Arc<RwLock<Vec<PointerPath>>>,
    pub loaded_modules: Arc<RwLock<Vec<ModuleEntry>>>,
    pub phase: Arc<AtomicU32>,
    pub progress_pct: Arc<Mutex<f32>>,
    pub found_count: Arc<AtomicUsize>,
    pub cancel_flag: Arc<AtomicBool>,
    pub worker_handle: Option<JoinHandle<()>>,
}

impl PointerScannerSession {
    pub fn new() -> Self {
        Self {
            scanner: Arc::new(Mutex::new(PointerScanner::new())),
            results: Arc::new(RwLock::new(Vec::new())),
            loaded_modules: Arc::new(RwLock::new(Vec::new())),
            phase: Arc::new(AtomicU32::new(OnyxPointerScanPhase::Idle as u32)),
            progress_pct: Arc::new(Mutex::new(0.0)),
            found_count: Arc::new(AtomicUsize::new(0)),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            worker_handle: None,
        }
    }

    pub fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::SeqCst);
    }
}

#[no_mangle]
pub extern "C" fn onyx_pointer_module_ping() -> i32 {
    1
}

#[no_mangle]
pub extern "C" fn onyx_pointer_scanner_create() -> *mut PointerScannerSession {
    Box::into_raw(Box::new(PointerScannerSession::new()))
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_scanner_destroy(session: *mut PointerScannerSession) {
    if session.is_null() {
        return;
    }
    let mut s = Box::from_raw(session);
    s.cancel();
    if let Some(h) = s.worker_handle.take() {
        let _ = h.join();
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_scanner_start_scan(
    session: *mut PointerScannerSession,
    proc: *mut Process,
    target_addr: usize,
    max_depth: usize,
    max_offset: usize,
    alignment: usize,
    max_results: usize,
) -> i32 {
    if session.is_null() || proc.is_null() || target_addr == 0 {
        return 0;
    }

    let s = &mut *session;
    s.cancel();
    if let Some(h) = s.worker_handle.take() {
        let _ = h.join();
    }

    s.cancel_flag.store(false, Ordering::SeqCst);
    s.phase.store(OnyxPointerScanPhase::GeneratingMap as u32, Ordering::SeqCst);
    if let Ok(mut pct) = s.progress_pct.lock() {
        *pct = 0.0;
    }
    s.found_count.store(0, Ordering::SeqCst);
    if let Ok(mut res) = s.results.write() {
        res.clear();
    }

    let scanner_arc = Arc::clone(&s.scanner);
    let results_arc = Arc::clone(&s.results);
    let phase_arc = Arc::clone(&s.phase);
    let progress_arc = Arc::clone(&s.progress_pct);
    let count_arc = Arc::clone(&s.found_count);
    let cancel_arc = Arc::clone(&s.cancel_flag);

    let pid = (*proc).pid;

    s.worker_handle = Some(std::thread::spawn(move || {
        let process_res = Process::attach(pid);
        let process = match process_res {
            Ok(p) => p,
            Err(_) => {
                phase_arc.store(OnyxPointerScanPhase::Failed as u32, Ordering::SeqCst);
                return;
            }
        };

        let mut config = PointerScanConfig::default();
        config.max_depth = if max_depth == 0 { 5 } else { max_depth };
        config.max_offset = if max_offset == 0 { 0x1000 } else { max_offset };
        config.alignment = if alignment == 0 { 4 } else { alignment };
        config.max_results = if max_results == 0 { 20000 } else { max_results };

        {
            let mut scanner = match scanner_arc.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };

            let map_res = scanner.generate_map_with_progress(&process, &config, &mut |pct, _| {
                if cancel_arc.load(Ordering::Relaxed) {
                    return false;
                }
                if let Ok(mut guard) = progress_arc.lock() {
                    *guard = pct * 0.5;
                }
                true
            });

            if map_res.is_err() {
                if cancel_arc.load(Ordering::Relaxed) {
                    phase_arc.store(OnyxPointerScanPhase::Cancelled as u32, Ordering::SeqCst);
                } else {
                    phase_arc.store(OnyxPointerScanPhase::Failed as u32, Ordering::SeqCst);
                }
                return;
            }
        }

        if cancel_arc.load(Ordering::Relaxed) {
            phase_arc.store(OnyxPointerScanPhase::Cancelled as u32, Ordering::SeqCst);
            return;
        }

        phase_arc.store(OnyxPointerScanPhase::SearchingPaths as u32, Ordering::SeqCst);

        let scanner = match scanner_arc.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let scan_res = scanner.scan_paths_with_progress(&process, target_addr, &config, &mut |pct, found| {
            if cancel_arc.load(Ordering::Relaxed) {
                return false;
            }
            if let Ok(mut guard) = progress_arc.lock() {
                *guard = 50.0 + (pct * 0.5);
            }
            count_arc.store(found, Ordering::Relaxed);
            true
        });

        match scan_res {
            Ok(paths) => {
                count_arc.store(paths.len(), Ordering::SeqCst);
                if let Ok(mut res) = results_arc.write() {
                    *res = paths;
                }
                if let Ok(mut guard) = progress_arc.lock() {
                    *guard = 100.0;
                }
                phase_arc.store(OnyxPointerScanPhase::Completed as u32, Ordering::SeqCst);
            }
            Err(_) => {
                if cancel_arc.load(Ordering::Relaxed) {
                    phase_arc.store(OnyxPointerScanPhase::Cancelled as u32, Ordering::SeqCst);
                } else {
                    phase_arc.store(OnyxPointerScanPhase::Failed as u32, Ordering::SeqCst);
                }
            }
        }
    }));

    1
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_scanner_start_rescan(
    session: *mut PointerScannerSession,
    proc: *mut Process,
    new_target_addr: usize,
) -> i32 {
    if session.is_null() || proc.is_null() || new_target_addr == 0 {
        return 0;
    }

    let s = &mut *session;
    s.cancel();
    if let Some(h) = s.worker_handle.take() {
        let _ = h.join();
    }

    s.cancel_flag.store(false, Ordering::SeqCst);
    s.phase.store(OnyxPointerScanPhase::Rescanning as u32, Ordering::SeqCst);
    if let Ok(mut pct) = s.progress_pct.lock() {
        *pct = 0.0;
    }

    let results_arc = Arc::clone(&s.results);
    let phase_arc = Arc::clone(&s.phase);
    let progress_arc = Arc::clone(&s.progress_pct);
    let count_arc = Arc::clone(&s.found_count);
    let cancel_arc = Arc::clone(&s.cancel_flag);

    let pid = (*proc).pid;

    s.worker_handle = Some(std::thread::spawn(move || {
        let process_res = Process::attach(pid);
        let process = match process_res {
            Ok(p) => p,
            Err(_) => {
                phase_arc.store(OnyxPointerScanPhase::Failed as u32, Ordering::SeqCst);
                return;
            }
        };

        let current_paths = {
            match results_arc.read() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        };

        let valid_paths = PointerScanner::rescan_paths_with_progress(
            &process,
            &current_paths,
            new_target_addr,
            &mut |pct, found| {
                if cancel_arc.load(Ordering::Relaxed) {
                    return false;
                }
                if let Ok(mut guard) = progress_arc.lock() {
                    *guard = pct;
                }
                count_arc.store(found, Ordering::Relaxed);
                true
            },
        );

        if cancel_arc.load(Ordering::Relaxed) {
            phase_arc.store(OnyxPointerScanPhase::Cancelled as u32, Ordering::SeqCst);
        } else {
            count_arc.store(valid_paths.len(), Ordering::SeqCst);
            if let Ok(mut res) = results_arc.write() {
                *res = valid_paths;
            }
            if let Ok(mut guard) = progress_arc.lock() {
                *guard = 100.0;
            }
            phase_arc.store(OnyxPointerScanPhase::Completed as u32, Ordering::SeqCst);
        }
    }));

    1
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_scanner_start_value_rescan(
    session: *mut PointerScannerSession,
    proc: *mut Process,
    val_bytes: *const u8,
    val_len: u32,
) -> i32 {
    if session.is_null() || proc.is_null() || val_bytes.is_null() || val_len == 0 {
        return 0;
    }

    let s = &mut *session;

    if let Some(h) = s.worker_handle.take() {
        let _ = h.join();
    }

    s.cancel_flag.store(false, Ordering::SeqCst);
    s.phase.store(OnyxPointerScanPhase::Rescanning as u32, Ordering::SeqCst);
    if let Ok(mut pct) = s.progress_pct.lock() {
        *pct = 0.0;
    }

    let results_arc = Arc::clone(&s.results);
    let phase_arc = Arc::clone(&s.phase);
    let progress_arc = Arc::clone(&s.progress_pct);
    let count_arc = Arc::clone(&s.found_count);
    let cancel_arc = Arc::clone(&s.cancel_flag);

    let pid = (*proc).pid;
    let expected = std::slice::from_raw_parts(val_bytes, val_len as usize).to_vec();

    s.worker_handle = Some(std::thread::spawn(move || {
        let process_res = Process::attach(pid);
        let process = match process_res {
            Ok(p) => p,
            Err(_) => {
                phase_arc.store(OnyxPointerScanPhase::Failed as u32, Ordering::SeqCst);
                return;
            }
        };

        let current_paths = {
            match results_arc.read() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        };

        let valid_paths = PointerScanner::rescan_paths_by_value_with_progress(
            &process,
            &current_paths,
            &expected,
            &mut |pct, found| {
                if cancel_arc.load(Ordering::Relaxed) {
                    return false;
                }
                if let Ok(mut guard) = progress_arc.lock() {
                    *guard = pct;
                }
                count_arc.store(found, Ordering::Relaxed);
                true
            },
        );

        if cancel_arc.load(Ordering::Relaxed) {
            phase_arc.store(OnyxPointerScanPhase::Cancelled as u32, Ordering::SeqCst);
        } else {
            count_arc.store(valid_paths.len(), Ordering::SeqCst);
            if let Ok(mut res) = results_arc.write() {
                *res = valid_paths;
            }
            if let Ok(mut guard) = progress_arc.lock() {
                *guard = 100.0;
            }
            phase_arc.store(OnyxPointerScanPhase::Completed as u32, Ordering::SeqCst);
        }
    }));

    1
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_scanner_cancel(session: *mut PointerScannerSession) -> i32 {
    if session.is_null() {
        return 0;
    }
    (*session).cancel();
    1
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_scanner_get_status(
    session: *mut PointerScannerSession,
    out_phase: *mut u32,
    out_progress: *mut f32,
    out_found_count: *mut usize,
) -> i32 {
    if session.is_null() {
        return 0;
    }
    let s = &*session;

    if !out_phase.is_null() {
        *out_phase = s.phase.load(Ordering::Relaxed);
    }
    if !out_progress.is_null() {
        *out_progress = s.progress_pct.lock().map(|g| *g).unwrap_or(0.0);
    }
    if !out_found_count.is_null() {
        *out_found_count = s.found_count.load(Ordering::Relaxed);
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_scanner_get_count(session: *mut PointerScannerSession) -> usize {
    if session.is_null() {
        return 0;
    }
    let s = &*session;
    s.found_count.load(Ordering::SeqCst)
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_scanner_get_path(
    session: *mut PointerScannerSession,
    index: usize,
    out_record: *mut OnyxPointerPathRecord,
) -> i32 {
    if session.is_null() || out_record.is_null() {
        return 0;
    }
    let s = &*session;
    let guard = match s.results.read() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };

    if index >= guard.len() {
        return 0;
    }

    let p = &guard[index];
    let mut rec = OnyxPointerPathRecord::default();

    let mod_bytes = p.module_name.as_bytes();
    let copy_len = mod_bytes.len().min(259);
    for i in 0..copy_len {
        rec.module_name[i] = mod_bytes[i] as c_char;
    }
    rec.module_name[copy_len] = 0;

    rec.base_offset = p.base_offset;
    rec.offset_count = p.offsets.len().min(16) as u32;
    for i in 0..rec.offset_count as usize {
        rec.offsets[i] = p.offsets[i];
    }
    rec.final_address = p.final_address;

    *out_record = rec;
    1
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_scanner_save_results(
    session: *mut PointerScannerSession,
    file_path: *const c_char,
) -> i32 {
    if session.is_null() || file_path.is_null() {
        return 0;
    }
    let path_str = match CStr::from_ptr(file_path).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let s = &*session;
    let guard = match s.results.read() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };

    match PointerScanner::save_to_file(&guard, path_str) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_scanner_load_results(
    session: *mut PointerScannerSession,
    file_path: *const c_char,
) -> i32 {
    if session.is_null() || file_path.is_null() {
        return 0;
    }
    let path_str = match CStr::from_ptr(file_path).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    match PointerScanner::load_from_file(path_str) {
        Ok(paths) => {
            let s = &*session;
            s.found_count.store(paths.len(), Ordering::SeqCst);
            if let Ok(mut guard) = s.results.write() {
                *guard = paths;
            }
            s.phase.store(OnyxPointerScanPhase::Completed as u32, Ordering::SeqCst);
            1
        }
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_resolve(
    proc: *mut Process,
    base_addr: usize,
    offsets: *const usize,
    offset_count: usize,
) -> usize {
    if proc.is_null() || base_addr == 0 {
        return 0;
    }

    let p = &*proc;
    let mut current = base_addr;

    if offsets.is_null() || offset_count == 0 {
        return current;
    }

    let slice = std::slice::from_raw_parts(offsets, offset_count);
    for &offset in slice {
        match p.read::<usize>(current) {
            Ok(next_ptr) if next_ptr != 0 => {
                current = next_ptr + offset;
            }
            _ => return 0,
        }
    }

    current
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_eval_path(
    proc: *mut Process,
    module_name_ptr: *const c_char,
    base_offset: usize,
    offsets: *const usize,
    offset_count: usize,
) -> usize {
    if proc.is_null() || module_name_ptr.is_null() {
        return 0;
    }

    let p = &*proc;
    let mod_name = CStr::from_ptr(module_name_ptr).to_string_lossy();
    let offset_slice = if offsets.is_null() || offset_count == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(offsets, offset_count).to_vec()
    };

    let path = PointerPath {
        module_name: mod_name.to_string(),
        base_offset,
        offsets: offset_slice,
        final_address: 0,
    };

    PointerScanner::evaluate_path(p, &path).unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_scanner_save_map(
    session: *mut PointerScannerSession,
    proc: *mut Process,
    file_path: *const c_char,
) -> i32 {
    if session.is_null() || file_path.is_null() {
        return 0;
    }
    let path_str = match CStr::from_ptr(file_path).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let s = &*session;
    let modules = if !proc.is_null() {
        (*proc).modules().unwrap_or_default()
    } else {
        s.loaded_modules.read().map(|g| g.clone()).unwrap_or_default()
    };
    let scanner = match s.scanner.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    match scanner.save_map_to_file(path_str, &modules) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_scanner_load_map(
    session: *mut PointerScannerSession,
    file_path: *const c_char,
) -> i32 {
    if session.is_null() || file_path.is_null() {
        return 0;
    }
    let path_str = match CStr::from_ptr(file_path).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    match PointerScanner::load_map_from_file(path_str) {
        Ok((loaded_scanner, loaded_mods)) => {
            let s = &*session;
            if let Ok(mut g) = s.scanner.lock() {
                *g = loaded_scanner;
            }
            if let Ok(mut g) = s.loaded_modules.write() {
                *g = loaded_mods;
            }
            1
        }
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_scanner_start_offline_scan(
    session: *mut PointerScannerSession,
    target_addr: usize,
    max_depth: usize,
    max_offset: usize,
    alignment: usize,
    max_results: usize,
) -> i32 {
    if session.is_null() || target_addr == 0 {
        return 0;
    }
    let s = &mut *session;
    s.cancel();
    if let Some(h) = s.worker_handle.take() {
        let _ = h.join();
    }
    s.cancel_flag.store(false, Ordering::SeqCst);
    s.phase.store(OnyxPointerScanPhase::SearchingPaths as u32, Ordering::SeqCst);
    if let Ok(mut pct) = s.progress_pct.lock() {
        *pct = 0.0;
    }
    s.found_count.store(0, Ordering::SeqCst);
    if let Ok(mut res) = s.results.write() {
        res.clear();
    }

    let scanner_arc = Arc::clone(&s.scanner);
    let results_arc = Arc::clone(&s.results);
    let phase_arc = Arc::clone(&s.phase);
    let progress_arc = Arc::clone(&s.progress_pct);
    let count_arc = Arc::clone(&s.found_count);
    let cancel_arc = Arc::clone(&s.cancel_flag);
    let modules_arc = Arc::clone(&s.loaded_modules);

    s.worker_handle = Some(std::thread::spawn(move || {
        let mut config = PointerScanConfig::default();
        config.max_depth = if max_depth == 0 { 5 } else { max_depth };
        config.max_offset = if max_offset == 0 { 0x1000 } else { max_offset };
        config.alignment = if alignment == 0 { 4 } else { alignment };
        config.max_results = if max_results == 0 { 20000 } else { max_results };

        let mods = match modules_arc.read() {
            Ok(g) => g.clone(),
            Err(e) => e.into_inner().clone(),
        };

        let scanner = match scanner_arc.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        let scan_res = scanner.scan_paths_offline(&mods, target_addr, &config, &mut |pct, found| {
            if cancel_arc.load(Ordering::Relaxed) {
                return false;
            }
            if let Ok(mut g) = progress_arc.lock() {
                *g = pct;
            }
            count_arc.store(found, Ordering::Relaxed);
            true
        });

        match scan_res {
            Ok(paths) => {
                count_arc.store(paths.len(), Ordering::SeqCst);
                if let Ok(mut res) = results_arc.write() {
                    *res = paths;
                }
                if let Ok(mut g) = progress_arc.lock() {
                    *g = 100.0;
                }
                phase_arc.store(OnyxPointerScanPhase::Completed as u32, Ordering::SeqCst);
            }
            Err(_) => {
                if cancel_arc.load(Ordering::Relaxed) {
                    phase_arc.store(OnyxPointerScanPhase::Cancelled as u32, Ordering::SeqCst);
                } else {
                    phase_arc.store(OnyxPointerScanPhase::Failed as u32, Ordering::SeqCst);
                }
            }
        }
    }));

    1
}

#[no_mangle]
pub unsafe extern "C" fn onyx_pointer_scanner_intersect_file(
    session: *mut PointerScannerSession,
    other_results_file: *const c_char,
) -> i32 {
    if session.is_null() || other_results_file.is_null() {
        return 0;
    }
    let path_str = match CStr::from_ptr(other_results_file).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let other_paths = match PointerScanner::load_from_file(path_str) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let s = &*session;
    if let Ok(mut current) = s.results.write() {
        let intersected = PointerScanner::intersect_paths(&current, &other_paths);
        s.found_count.store(intersected.len(), Ordering::SeqCst);
        *current = intersected;
        1
    } else {
        0
    }
}

