use std::ffi::c_void;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonoRuntime {
    MonoClassic,
    Il2Cpp,
}

pub type GcFn = unsafe extern "C" fn();
pub type CompileMethodFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

#[derive(Clone)]
pub struct MonoApi {
    pub runtime: MonoRuntime,
    pub gc_disable: Option<GcFn>,
    pub gc_enable: Option<GcFn>,
    pub compile_method: Option<CompileMethodFn>,
}

impl MonoApi {
    pub fn new(runtime: MonoRuntime) -> Self {
        Self {
            runtime,
            gc_disable: None,
            gc_enable: None,
            compile_method: None,
        }
    }

    #[cfg(windows)]
    pub fn resolve_from_module(runtime: MonoRuntime, module_base: *mut c_void) -> Self {
        use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
        let hmod = module_base as windows_sys::Win32::Foundation::HMODULE;
        let mut api = Self::new(runtime);
        let (dis_name, en_name, compile_name): (&[u8], &[u8], &[u8]) = match runtime {
            MonoRuntime::MonoClassic => (
                b"mono_gc_disable\0",
                b"mono_gc_enable\0",
                b"mono_compile_method\0",
            ),
            MonoRuntime::Il2Cpp => (
                b"il2cpp_gc_disable\0",
                b"il2cpp_gc_enable\0",
                b"\0",
            ),
        };
        unsafe {
            let p = GetProcAddress(hmod, dis_name.as_ptr());
            if let Some(f) = p {
                api.gc_disable = Some(std::mem::transmute::<_, GcFn>(f));
            }
            let p = GetProcAddress(hmod, en_name.as_ptr());
            if let Some(f) = p {
                api.gc_enable = Some(std::mem::transmute::<_, GcFn>(f));
            }
            if !compile_name.is_empty() && compile_name[0] != 0 {
                let p = GetProcAddress(hmod, compile_name.as_ptr());
                if let Some(f) = p {
                    api.compile_method = Some(std::mem::transmute::<_, CompileMethodFn>(f));
                }
            }
        }
        api
    }

    pub fn resolve_jit_ptr(&self, method_desc: *mut c_void) -> Option<*mut c_void> {
        match self.runtime {
            MonoRuntime::MonoClassic => {
                let f = self.compile_method?;
                let p = unsafe { f(method_desc) };
                if p.is_null() { None } else { Some(p) }
            }
            MonoRuntime::Il2Cpp => {
                if method_desc.is_null() {
                    return None;
                }
                unsafe {
                    let mp = *(method_desc as *const *mut c_void);
                    if mp.is_null() { None } else { Some(mp) }
                }
            }
        }
    }
}
