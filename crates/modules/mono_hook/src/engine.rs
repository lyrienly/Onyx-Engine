use std::collections::HashMap;

use onyx_hook::{Hook, HookError};

use crate::gc_safe::GcGuard;
use crate::mono_jit::MonoApi;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MethodId(pub usize);

#[derive(Debug)]
pub enum JitHookError {
    NullPointer,
    AlreadyHooked,
    NotFound,
    Hook(HookError),
}

impl std::fmt::Display for JitHookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JitHookError::NullPointer => write!(f, "ponteiro JIT nulo"),
            JitHookError::AlreadyHooked => write!(f, "metodo ja possui hook"),
            JitHookError::NotFound => write!(f, "hook nao encontrado"),
            JitHookError::Hook(e) => write!(f, "falha no hook: {}", e),
        }
    }
}

impl std::error::Error for JitHookError {}

impl From<HookError> for JitHookError {
    fn from(e: HookError) -> Self {
        JitHookError::Hook(e)
    }
}

pub struct JitHookManager {
    pub api: MonoApi,
    hooks: HashMap<MethodId, Hook>,
}

impl JitHookManager {
    pub fn new(api: MonoApi) -> Self {
        Self {
            api,
            hooks: HashMap::new(),
        }
    }

    pub fn hook_method_by_ptr(
        &mut self,
        jit_ptr: *mut u8,
        hook_fn: *const u8,
    ) -> Result<MethodId, JitHookError> {
        if jit_ptr.is_null() || hook_fn.is_null() {
            return Err(JitHookError::NullPointer);
        }
        let id = MethodId(jit_ptr as usize);
        if self.hooks.contains_key(&id) {
            return Err(JitHookError::AlreadyHooked);
        }
        let _guard = GcGuard::new(&self.api);
        let hook = Hook::new(jit_ptr as *const u8, hook_fn)?;
        self.hooks.insert(id, hook);
        Ok(id)
    }

    pub fn original(&self, id: MethodId) -> Option<*const u8> {
        self.hooks.get(&id).map(|h| h.original())
    }

    pub fn remove(&mut self, id: MethodId) -> Result<(), JitHookError> {
        let hook = self.hooks.remove(&id).ok_or(JitHookError::NotFound)?;
        let _guard = GcGuard::new(&self.api);
        hook.remove()?;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }
}
