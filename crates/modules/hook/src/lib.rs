pub mod trampoline;
pub mod detour;
pub mod engine;

pub use detour::{Hook, HookError};
pub use engine::HookEngine;
pub use trampoline::{build_trampoline, RelocationInfo, PATCH_SIZE};
