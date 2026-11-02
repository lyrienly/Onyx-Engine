use std::ffi::c_char;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;

use onyx_core::pointer_scanner::{PointerPath, PointerScanner};
use onyx_core::process::ModuleEntry;

use crate::matrix::CompactPointerMatrix;

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
    pub matrix: Arc<RwLock<CompactPointerMatrix>>,
    pub results: Arc<RwLock<Vec<PointerPath>>>,
    pub loaded_modules: Arc<RwLock<Vec<ModuleEntry>>>,
    pub phase: Arc<AtomicU32>,
    pub progress_pct: Arc<Mutex<f32>>,
    pub found_count: Arc<AtomicUsize>,
    pub cancel_flag: Arc<AtomicBool>,
    pub worker_handle: Option<JoinHandle<()>>,
}

impl PointerScannerSession {
    pub fn cancel(&self) {
        use std::sync::atomic::Ordering;
        self.cancel_flag.store(true, Ordering::SeqCst);
    }

    pub fn new() -> Self {
        Self {
            scanner: Arc::new(Mutex::new(PointerScanner::new())),
            matrix: Arc::new(RwLock::new(CompactPointerMatrix::new())),
            results: Arc::new(RwLock::new(Vec::new())),
            loaded_modules: Arc::new(RwLock::new(Vec::new())),
            phase: Arc::new(AtomicU32::new(OnyxPointerScanPhase::Idle as u32)),
            progress_pct: Arc::new(Mutex::new(0.0)),
            found_count: Arc::new(AtomicUsize::new(0)),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            worker_handle: None,
        }
    }
}

impl Default for PointerScannerSession {
    fn default() -> Self {
        Self::new()
    }
}
