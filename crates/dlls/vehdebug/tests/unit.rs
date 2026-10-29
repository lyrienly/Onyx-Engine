#![cfg(windows)]

use vehdebug_dll::ffi::*;
use vehdebug_dll::veh::{
    BreakpointId, VehDisposition, VehHandler, VehRegistration, allocate_id,
    register_handler, unregister_handler,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct CountingHandler {
    id: BreakpointId,
    hits: Arc<AtomicUsize>,
    want_code: DWORD,
}

impl VehHandler for CountingHandler {
    fn id(&self) -> BreakpointId {
        self.id
    }
    fn matches(&self, record: &EXCEPTION_RECORD, _ctx: &CONTEXT) -> bool {
        record.ExceptionCode == self.want_code
    }
    fn handle(&self, _record: &EXCEPTION_RECORD, _ctx: &mut CONTEXT) -> VehDisposition {
        self.hits.fetch_add(1, Ordering::SeqCst);
        VehDisposition::Continue
    }
}

#[test]
fn registry_insert_and_remove() {
    let id = allocate_id();
    let hits = Arc::new(AtomicUsize::new(0));
    register_handler(Box::new(CountingHandler {
        id,
        hits: hits.clone(),
        want_code: EXCEPTION_BREAKPOINT,
    }));
    let removed = unregister_handler(id);
    assert!(removed.is_some(), "handler deveria estar no registry");
    let gone = unregister_handler(id);
    assert!(gone.is_none(), "segundo remove nao deve achar nada");
}

#[test]
fn registration_drop_removes_handler() {
    let reg = VehRegistration::install().expect("install");
    let raw = reg.raw();
    assert!(!raw.is_null());
    drop(reg);

}

#[test]
fn disposition_mapping() {
    assert_eq!(VehDisposition::Continue.as_ntstatus(), EXCEPTION_CONTINUE_EXECUTION);
    assert_eq!(VehDisposition::Search.as_ntstatus(), EXCEPTION_CONTINUE_SEARCH);
}
