//! Dispatcher central e wrapper RAII em volta de AddVectoredExceptionHandler.
//!
//! Objetivos de estabilidade:
//! * Qualquer excecao que nao pertenca a um breakpoint registrado devolve
//!   `EXCEPTION_CONTINUE_SEARCH` para nao mascarar falhas do processo alvo.
//! * O handle devolvido por `AddVectoredExceptionHandler` e envolvido em um
//!   `VehRegistration` com `Drop` — evita vazamento quando a DLL e descarregada
//!   ou quando o `VehDebugger` sai de escopo.
//! * O dispatcher roteia por `ExceptionAddress` para o handler certo, mantido
//!   em um registry `RwLock` ordenado por `BreakpointId`.

use crate::ffi::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};

/// Resposta de um handler ao dispatcher. Mapeia 1:1 nos codigos NTSTATUS
/// esperados por `AddVectoredExceptionHandler`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VehDisposition {
    /// Deixa a excecao continuar o walk de SEH/debugger externo.
    Search,
    /// Reexecuta a instrucao no RIP corrente (bp tratado).
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

/// Identificador opaco de um breakpoint registrado no `VehDebugger`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct BreakpointId(pub u64);

/// Contrato que todo breakpoint implementa. O dispatcher chama `matches` para
/// decidir se a excecao e dele; se sim, chama `handle` e usa o retorno.
pub trait VehHandler: Send + Sync {
    fn id(&self) -> BreakpointId;
    fn matches(&self, record: &EXCEPTION_RECORD, context: &CONTEXT) -> bool;
    fn handle(&self, record: &EXCEPTION_RECORD, context: &mut CONTEXT) -> VehDisposition;
}

type HandlerBox = Box<dyn VehHandler>;

/// Registry global thread-safe. A api publica (`VehDebugger`) e quem
/// adiciona/remove — o dispatcher apenas itera com um `read()`.
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

/// Wrapper RAII em cima do handle de `AddVectoredExceptionHandler`.
pub struct VehRegistration {
    handle: PVOID,
}

// handle e um ponteiro opaco gerido pelo kernel; nao se dereferencia.
unsafe impl Send for VehRegistration {}
unsafe impl Sync for VehRegistration {}

impl VehRegistration {
    /// Registra o dispatcher central. Chama `AddVectoredExceptionHandler(1,...)`
    /// — First=1 insere no inicio da cadeia, que e o que queremos para
    /// interceptar antes de qualquer SEH do alvo.
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

/// Entrada global para registro — expoe o registry para `debugger.rs`.
pub fn register_handler(h: HandlerBox) {
    registry().insert(h);
}

pub fn unregister_handler(id: BreakpointId) -> Option<HandlerBox> {
    registry().remove(id)
}

pub fn allocate_id() -> BreakpointId {
    registry().allocate_id()
}

/// Flag que `UninitializeVEH` liga para desarmar o dispatcher sem desregistrar
/// a cadeia (evita race onde uma excecao em voo encontra registry parcialmente
/// destruido).
static DISPATCHER_ARMED: AtomicBool = AtomicBool::new(true);

pub fn arm_dispatcher() {
    DISPATCHER_ARMED.store(true, Ordering::SeqCst);
}
pub fn disarm_dispatcher() {
    DISPATCHER_ARMED.store(false, Ordering::SeqCst);
}

/// Dispatcher central. Mantem o contrato: se nenhum handler reclamar a
/// excecao, devolve `EXCEPTION_CONTINUE_SEARCH`.
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

    // Snapshot imutavel do contexto para o predicate `matches` — evita
    // UB caso um handler modifique campos antes do proximo matches ser
    // consultado.
    let ctx_snapshot: CONTEXT = *ctx;

    registry().with_handlers(|hs| {
        for h in hs.iter() {
            if h.matches(rec, &ctx_snapshot) {
                let d = h.handle(rec, ctx);
                if d == VehDisposition::Continue {
                    // Para single-step/hw bp: limpa a Resume Flag para o
                    // caller nao refirar o DR imediatamente no reexec.
                    ctx.EFlags &= !EFLAGS_RF;
                    // Garante que ContextFlags sinalize ao kernel que
                    // alteramos registros de depuracao e controle.
                    ctx.ContextFlags |= CONTEXT_CONTROL | CONTEXT_INTEGER
                        | CONTEXT_DEBUG_REGISTERS;
                }
                return d.as_ntstatus();
            }
        }
        EXCEPTION_CONTINUE_SEARCH
    })
}
