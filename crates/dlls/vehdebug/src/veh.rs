use crate::ffi::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VehDisposition {

    Search,

    Continue,
}

impl VehDisposition {
    pub fn as_ntstatus(self) -> LONG {
        match self {
            VehDisposition::Search => EXCEPTION_CONTINUE_SEARCH,
            VehDisposition::Continue => EXCEPTION_CONTINUE_EXECUTION,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct BreakpointId(pub u64);

pub trait VehHandler: Send + Sync {
    fn id(&self) -> BreakpointId;
    fn matches(&self, record: &EXCEPTION_RECORD, context: &CONTEXT) -> bool;
    fn handle(&self, record: &EXCEPTION_RECORD, context: &mut CONTEXT) -> VehDisposition;
}

type HandlerBox = Box<dyn VehHandler>;

struct Registry {
    next_id: AtomicU64,
    handlers: RwLock<Vec<HandlerBox>>,
}

impl Registry {
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            handlers: RwLock::new(Vec::new()),
        }
    }
    fn allocate_id(&self) -> BreakpointId {
        BreakpointId(self.next_id.fetch_add(1, Ordering::Relaxed))
    }
    fn insert(&self, handler: HandlerBox) {
        if let Ok(mut g) = self.handlers.write() {
            g.push(handler);
        }
    }
    fn remove(&self, id: BreakpointId) -> Option<HandlerBox> {
        let mut g = self.handlers.write().ok()?;
        let pos = g.iter().position(|h| h.id() == id)?;
        Some(g.swap_remove(pos))
    }
    fn with_handlers<R>(&self, f: impl FnOnce(&[HandlerBox]) -> R) -> R {
        let g = self.handlers.read().expect("veh registry poisoned");
        f(&g)
    }
}

static REGISTRY: OnceLock<Registry> = OnceLock::new();
fn registry() -> &'static Registry {
    REGISTRY.get_or_init(Registry::new)
}

pub struct VehRegistration {
    handle: PVOID,
}

unsafe impl Send for VehRegistration {}
unsafe impl Sync for VehRegistration {}

impl VehRegistration {

    pub fn install() -> Option<Self> {
        let handle = unsafe { AddVectoredExceptionHandler(1, dispatcher) };
        if handle.is_null() {
            None
        } else {
            Some(Self { handle })
        }
    }
    pub fn raw(&self) -> PVOID {
        self.handle
    }
}

impl Drop for VehRegistration {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                RemoveVectoredExceptionHandler(self.handle);
            }
            self.handle = std::ptr::null_mut();
        }
    }
}

pub fn register_handler(h: HandlerBox) {
    registry().insert(h);
}

pub fn unregister_handler(id: BreakpointId) -> Option<HandlerBox> {
    registry().remove(id)
}

pub fn allocate_id() -> BreakpointId {
    registry().allocate_id()
}

static DISPATCHER_ARMED: AtomicBool = AtomicBool::new(true);

pub fn arm_dispatcher() {
    DISPATCHER_ARMED.store(true, Ordering::SeqCst);
}
pub fn disarm_dispatcher() {
    DISPATCHER_ARMED.store(false, Ordering::SeqCst);
}

pub(crate) unsafe extern "system" fn dispatcher(ex: *mut EXCEPTION_POINTERS) -> LONG {
    if !DISPATCHER_ARMED.load(Ordering::Relaxed) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if ex.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let rec_ptr = (*ex).ExceptionRecord;
    let ctx_ptr = (*ex).ContextRecord;
    if rec_ptr.is_null() || ctx_ptr.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let rec: &EXCEPTION_RECORD = &*rec_ptr;
    let ctx: &mut CONTEXT = &mut *ctx_ptr;

    let ctx_snapshot: CONTEXT = *ctx;

    registry().with_handlers(|hs| {
        for h in hs.iter() {
            if h.matches(rec, &ctx_snapshot) {
                let d = h.handle(rec, ctx);
                if d == VehDisposition::Continue {

                    ctx.EFlags &= !EFLAGS_RF;

                    ctx.ContextFlags |= CONTEXT_CONTROL | CONTEXT_INTEGER
                        | CONTEXT_DEBUG_REGISTERS;
                }
                return d.as_ntstatus();
            }
        }
        EXCEPTION_CONTINUE_SEARCH
    })
}
