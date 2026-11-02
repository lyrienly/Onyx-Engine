pub mod engine;
pub mod gc_safe;
pub mod mono_jit;

pub use engine::{JitHookError, JitHookManager, MethodId};
pub use gc_safe::GcGuard;
pub use mono_jit::{MonoApi, MonoRuntime};

#[no_mangle]
pub unsafe extern "C" fn onyx_mono_hook_version() -> u32 {
    0x010000
}
