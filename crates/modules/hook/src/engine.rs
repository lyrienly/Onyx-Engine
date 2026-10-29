use std::collections::HashMap;

use crate::detour::{Hook, HookError};

pub struct HookEngine {
    hooks: HashMap<String, Hook>,
    targets: HashMap<usize, String>,
}

impl Default for HookEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl HookEngine {
    pub fn new() -> Self {
        Self {
            hooks: HashMap::new(),
            targets: HashMap::new(),
        }
    }

    pub fn install(
        &mut self,
        name: &str,
        target_fn: *const u8,
        hook_fn: *const u8,
    ) -> Result<*const u8, HookError> {
        let key = target_fn as usize;
        if self.targets.contains_key(&key) {
            return Err(HookError::Alloc);
        }
        let hook = Hook::new(target_fn, hook_fn)?;
        let original = hook.original();
        self.hooks.insert(name.to_string(), hook);
        self.targets.insert(key, name.to_string());
        Ok(original)
    }

    pub fn remove(&mut self, name: &str) -> Result<(), HookError> {
        if let Some(hook) = self.hooks.remove(name) {
            let key = hook_target_addr(&hook);
            self.targets.remove(&key);
            return hook.remove();
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }
}

fn hook_target_addr(hook: &Hook) -> usize {

    hook.original() as usize
}
