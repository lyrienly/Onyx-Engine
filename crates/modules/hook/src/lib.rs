pub mod detour;
pub mod engine;
pub mod trampoline;

pub use detour::{Hook, HookError};
pub use engine::HookEngine;
pub use trampoline::{build_trampoline, RelocationInfo, PATCH_SIZE};
