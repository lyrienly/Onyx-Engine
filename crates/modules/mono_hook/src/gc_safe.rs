use crate::mono_jit::MonoApi;

pub struct GcGuard<'a> {
    api: &'a MonoApi,
    engaged: bool,
}

impl<'a> GcGuard<'a> {
    pub fn new(api: &'a MonoApi) -> Self {
        let engaged = if let Some(f) = api.gc_disable {
            unsafe { f() };
            true
        } else {
            false
        };
        Self { api, engaged }
    }

    pub fn is_engaged(&self) -> bool {
        self.engaged
    }
}

impl<'a> Drop for GcGuard<'a> {
    fn drop(&mut self) {
        if self.engaged {
            if let Some(f) = self.api.gc_enable {
                unsafe { f() };
            }
        }
    }
}
