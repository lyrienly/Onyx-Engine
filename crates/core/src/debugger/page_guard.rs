use std::collections::HashMap;
use std::mem::zeroed;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::win32::*;

pub const EXCEPTION_GUARD_PAGE: DWORD = 0x80000001;
pub const PAGE_SIZE: usize = 0x1000;
pub const EFLAGS_TRAP_FLAG: u64 = 0x100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessType {
    Read,
    Write,
    ReadWrite,
}

impl AccessType {
    pub fn from_exception_info(code: ULONG_PTR) -> AccessType {
        match code {
            0 => AccessType::Read,
            1 => AccessType::Write,
            _ => AccessType::ReadWrite,
        }
    }

    pub fn matches(self, observed: AccessType) -> bool {
        match self {
            AccessType::ReadWrite => true,
            AccessType::Read => matches!(observed, AccessType::Read),
            AccessType::Write => matches!(observed, AccessType::Write),
        }
    }
}

pub type BpId = u64;

#[derive(Debug, Clone, Copy)]
pub struct PageGuardBreakpoint {
    pub id: BpId,
    pub address: u64,
    pub size: usize,
    pub access: AccessType,

    pub original_protect: DWORD,
}

#[derive(Debug, Clone, Copy)]
pub struct BpHit {
    pub id: BpId,
    pub address: u64,
    pub fault_address: u64,
    pub thread_id: u32,
    pub access_type: AccessType,
}

#[inline]
pub fn page_base(addr: u64) -> u64 {
    addr & !(PAGE_SIZE as u64 - 1)
}

pub fn match_bp(
    bps: &HashMap<BpId, PageGuardBreakpoint>,
    fault_address: u64,
    observed: AccessType,
) -> Option<BpId> {
    for bp in bps.values() {
        let start = bp.address;
        let end = bp.address.saturating_add(bp.size as u64);
        if fault_address >= start && fault_address < end && bp.access.matches(observed) {
            return Some(bp.id);
        }
    }
    None
}

pub fn pages_for(bps: &HashMap<BpId, PageGuardBreakpoint>) -> std::collections::HashSet<u64> {
    let mut s = std::collections::HashSet::new();
    for bp in bps.values() {
        s.insert(page_base(bp.address));
    }
    s
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageGuardError {
    AttachFailed,
    OpenProcessFailed,
    VirtualProtectFailed,
    UnknownBp,
    NotAttached,
}

impl std::fmt::Display for PageGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PageGuardError::AttachFailed => "DebugActiveProcess falhou",
            PageGuardError::OpenProcessFailed => "OpenProcess falhou",
            PageGuardError::VirtualProtectFailed => "VirtualProtectEx falhou ao aplicar PAGE_GUARD",
            PageGuardError::UnknownBp => "BpId desconhecido",
            PageGuardError::NotAttached => "manager nao esta attachado",
        })
    }
}

impl std::error::Error for PageGuardError {}

type HitCallback = Box<dyn FnMut(BpHit) + Send + 'static>;

struct Inner {
    bps: HashMap<BpId, PageGuardBreakpoint>,

    pending_rearm: HashMap<u32, Vec<u64>>,
    callback: Option<HitCallback>,
}

pub struct PageGuardManager {
    pub pid: u32,
    h_process: HANDLE,
    inner: Arc<Mutex<Inner>>,
    stop: Arc<AtomicBool>,
    next_id: AtomicU64,
    debugger_thread: Option<JoinHandle<()>>,
}

unsafe impl Send for PageGuardManager {}
unsafe impl Sync for PageGuardManager {}

impl PageGuardManager {
    pub fn attach(pid: u32) -> Result<Self, PageGuardError> {
        let h_process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
        if h_process.is_null() {
            return Err(PageGuardError::OpenProcessFailed);
        }

        let mut mgr = Self::new_internal(pid, h_process);
        mgr.spawn_worker_attaching()?;
        Ok(mgr)
    }

    fn new_internal(pid: u32, h_process: HANDLE) -> Self {
        PageGuardManager {
            pid,
            h_process,
            inner: Arc::new(Mutex::new(Inner {
                bps: HashMap::new(),
                pending_rearm: HashMap::new(),
                callback: None,
            })),
            stop: Arc::new(AtomicBool::new(false)),
            next_id: AtomicU64::new(1),
            debugger_thread: None,
        }
    }

    fn spawn_worker_attaching(&mut self) -> Result<(), PageGuardError> {
        let inner = Arc::clone(&self.inner);
        let stop = Arc::clone(&self.stop);
        let h_process = self.h_process as usize;
        let pid = self.pid;

        let (tx, rx) = std::sync::mpsc::channel::<Result<(), PageGuardError>>();

        let handle = std::thread::spawn(move || {
            let attached = unsafe { DebugActiveProcess(pid) };
            if attached != TRUE {
                let _ = tx.send(Err(PageGuardError::AttachFailed));
                return;
            }
            let _ = tx.send(Ok(()));
            run_event_loop(h_process as HANDLE, inner, stop);
            unsafe { DebugActiveProcessStop(pid) };
        });

        match rx.recv() {
            Ok(Ok(())) => {
                self.debugger_thread = Some(handle);
                Ok(())
            }
            Ok(Err(e)) => {
                let _ = handle.join();
                Err(e)
            }
            Err(_) => Err(PageGuardError::AttachFailed),
        }
    }

    pub fn on_hit<F>(&self, callback: F)
    where
        F: FnMut(BpHit) + Send + 'static,
    {
        let mut inner = self.inner.lock().unwrap();
        inner.callback = Some(Box::new(callback));
    }

    pub fn set(
        &self,
        address: u64,
        size: usize,
        access: AccessType,
    ) -> Result<BpId, PageGuardError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let page = page_base(address);

        let mut old_protect: DWORD = 0;
        let ok = unsafe {
            VirtualProtectEx(
                self.h_process,
                page as LPVOID,
                PAGE_SIZE,
                PAGE_READWRITE | PAGE_GUARD,
                &mut old_protect,
            )
        };
        if ok != TRUE {
            return Err(PageGuardError::VirtualProtectFailed);
        }

        let bp = PageGuardBreakpoint {
            id,
            address,
            size,
            access,
            original_protect: if old_protect == 0 {
                PAGE_READWRITE
            } else {
                old_protect & !PAGE_GUARD
            },
        };
        self.inner.lock().unwrap().bps.insert(id, bp);
        Ok(id)
    }

    pub fn remove(&self, id: BpId) -> Result<(), PageGuardError> {
        let mut inner = self.inner.lock().unwrap();
        let bp = inner.bps.remove(&id).ok_or(PageGuardError::UnknownBp)?;

        let page = page_base(bp.address);
        let still_covered = inner.bps.values().any(|b| page_base(b.address) == page);
        drop(inner);

        if !still_covered {
            let mut old: DWORD = 0;
            let ok = unsafe {
                VirtualProtectEx(
                    self.h_process,
                    page as LPVOID,
                    PAGE_SIZE,
                    bp.original_protect,
                    &mut old,
                )
            };
            if ok != TRUE {
                return Err(PageGuardError::VirtualProtectFailed);
            }
        }
        Ok(())
    }

    pub fn breakpoints(&self) -> Vec<PageGuardBreakpoint> {
        self.inner.lock().unwrap().bps.values().copied().collect()
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for PageGuardManager {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.debugger_thread.take() {
            let _ = h.join();
        }
        if !self.h_process.is_null() && self.h_process != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.h_process) };
        }
    }
}

fn rearm_page(h_process: HANDLE, page: u64, protect: DWORD) -> bool {
    let mut old: DWORD = 0;
    let ok = unsafe {
        VirtualProtectEx(
            h_process,
            page as LPVOID,
            PAGE_SIZE,
            protect | PAGE_GUARD,
            &mut old,
        )
    };
    ok == TRUE
}

fn run_event_loop(h_process: HANDLE, inner: Arc<Mutex<Inner>>, stop: Arc<AtomicBool>) {
    let mut event: DEBUG_EVENT = unsafe { zeroed() };
    let trace = std::env::var("ONYX_PAGE_GUARD_TRACE").is_ok();
    if trace {
        eprintln!(
            "[pg] worker iniciado (h_process=0x{:X})",
            h_process as usize
        );
    }

    while !stop.load(Ordering::Relaxed) {
        let got = unsafe { WaitForDebugEvent(&mut event, 50) };
        if got != TRUE {
            continue;
        }
        if trace {
            eprintln!(
                "[pg] evt code=0x{:X} pid={} tid={}",
                event.dwDebugEventCode, event.dwProcessId, event.dwThreadId
            );
        }

        let continue_status: DWORD;

        match event.dwDebugEventCode {
            EXCEPTION_DEBUG_EVENT => {
                let ex = unsafe { event.u.Exception };
                let code = ex.ExceptionRecord.ExceptionCode;

                if code == EXCEPTION_GUARD_PAGE {
                    let access =
                        AccessType::from_exception_info(ex.ExceptionRecord.ExceptionInformation[0]);
                    let fault_addr = ex.ExceptionRecord.ExceptionInformation[1] as u64;
                    let tid = event.dwThreadId;
                    if trace {
                        eprintln!(
                            "[pg] GUARD_PAGE fault_addr=0x{:X} access={:?} tid={}",
                            fault_addr, access, tid
                        );
                    }

                    let mut guard = inner.lock().unwrap();
                    let bps_snapshot = guard.bps.clone();
                    let matched = match_bp(&bps_snapshot, fault_addr, access);

                    if let Some(id) = matched {
                        let bp = bps_snapshot[&id];

                        if let Some(cb) = guard.callback.as_mut() {
                            cb(BpHit {
                                id,
                                address: bp.address,
                                fault_address: fault_addr,
                                thread_id: tid,
                                access_type: access,
                            });
                        }
                    }

                    let affected_pages: Vec<u64> = pages_for(&bps_snapshot)
                        .into_iter()
                        .filter(|p| *p == page_base(fault_addr))
                        .collect();

                    if !affected_pages.is_empty() {
                        guard.pending_rearm.insert(tid, affected_pages);
                    }
                    drop(guard);

                    let h_thread = unsafe { OpenThread(THREAD_ALL_ACCESS, FALSE, tid) };
                    if !h_thread.is_null() && h_thread != INVALID_HANDLE_VALUE {
                        let mut ctx: CONTEXT = unsafe { zeroed() };
                        ctx.ContextFlags = CONTEXT_ALL;
                        if unsafe { GetThreadContext(h_thread, &mut ctx) } == TRUE {
                            ctx.EFlags |= EFLAGS_TRAP_FLAG as u32;
                            unsafe { SetThreadContext(h_thread, &ctx) };
                        }
                        unsafe { CloseHandle(h_thread) };
                    }

                    continue_status = DBG_CONTINUE;
                } else if code == EXCEPTION_SINGLE_STEP {
                    let tid = event.dwThreadId;
                    let pages = {
                        let mut guard = inner.lock().unwrap();
                        guard.pending_rearm.remove(&tid).unwrap_or_default()
                    };

                    for page in pages {
                        let protect = {
                            let guard = inner.lock().unwrap();
                            guard
                                .bps
                                .values()
                                .find(|b| page_base(b.address) == page)
                                .map(|b| b.original_protect)
                                .unwrap_or(PAGE_READWRITE)
                        };
                        rearm_page(h_process, page, protect);
                    }

                    continue_status = DBG_CONTINUE;
                } else if code == EXCEPTION_BREAKPOINT {
                    continue_status = DBG_CONTINUE;
                } else {
                    continue_status = DBG_EXCEPTION_NOT_HANDLED;
                }
            }
            _ => {
                continue_status = DBG_CONTINUE;
            }
        }

        unsafe {
            ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continue_status);
        }

        if event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
            break;
        }
    }
}

const PROCESS_ALL_ACCESS: DWORD = 0x001F_0FFF;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_base_alinha_para_4k() {
        assert_eq!(page_base(0x1000), 0x1000);
        assert_eq!(page_base(0x1234), 0x1000);
        assert_eq!(page_base(0x1FFF), 0x1000);
        assert_eq!(page_base(0x2000), 0x2000);
        assert_eq!(page_base(0xDEAD_BEEF), 0xDEAD_B000);
    }

    #[test]
    fn access_type_from_exception_info_classifica() {
        assert_eq!(AccessType::from_exception_info(0), AccessType::Read);
        assert_eq!(AccessType::from_exception_info(1), AccessType::Write);
        assert_eq!(AccessType::from_exception_info(8), AccessType::ReadWrite);
    }

    #[test]
    fn access_type_matches_respeita_filtro() {
        assert!(AccessType::ReadWrite.matches(AccessType::Read));
        assert!(AccessType::ReadWrite.matches(AccessType::Write));
        assert!(AccessType::Write.matches(AccessType::Write));
        assert!(!AccessType::Write.matches(AccessType::Read));
        assert!(AccessType::Read.matches(AccessType::Read));
        assert!(!AccessType::Read.matches(AccessType::Write));
    }

    fn mk_bp(id: BpId, address: u64, size: usize, access: AccessType) -> PageGuardBreakpoint {
        PageGuardBreakpoint {
            id,
            address,
            size,
            access,
            original_protect: PAGE_READWRITE,
        }
    }

    #[test]
    fn match_bp_filtra_falso_positivo_na_mesma_pagina() {
        let mut bps = HashMap::new();
        bps.insert(1, mk_bp(1, 0x4000_1000, 4, AccessType::Write));
        bps.insert(2, mk_bp(2, 0x4000_1800, 8, AccessType::Write));

        assert_eq!(match_bp(&bps, 0x4000_1002, AccessType::Write), Some(1));

        assert_eq!(match_bp(&bps, 0x4000_1804, AccessType::Write), Some(2));

        assert_eq!(match_bp(&bps, 0x4000_1400, AccessType::Write), None);
    }

    #[test]
    fn match_bp_respeita_tipo_de_acesso() {
        let mut bps = HashMap::new();
        bps.insert(7, mk_bp(7, 0x5000_0000, 4, AccessType::Write));

        assert_eq!(match_bp(&bps, 0x5000_0000, AccessType::Write), Some(7));
        assert_eq!(match_bp(&bps, 0x5000_0000, AccessType::Read), None);
    }

    #[test]
    fn pages_for_agrupa_paginas_distintas() {
        let mut bps = HashMap::new();
        bps.insert(1, mk_bp(1, 0x4000_1000, 4, AccessType::Write));
        bps.insert(2, mk_bp(2, 0x4000_1800, 8, AccessType::Write));
        bps.insert(3, mk_bp(3, 0x4000_2000, 4, AccessType::Read));

        let pages = pages_for(&bps);
        assert_eq!(pages.len(), 2);
        assert!(pages.contains(&0x4000_1000));
        assert!(pages.contains(&0x4000_2000));
    }
}
