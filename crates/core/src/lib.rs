// OnyxEngine Core Library (onyx_core)
// High-performance native memory, process inspection, debugging, and scripting subsystems

pub mod memory;
pub mod process;
pub mod debugger;
pub mod scripting;
pub mod mono;
pub mod injection;

// Top-level module re-exports for flat access
pub use memory::{scanner, pointer_scanner, freeze, structure};
pub use process::{win32, symbol, kernel};
pub use debugger::{disasm, veh, hook};
pub use scripting::{autoassembler, lua_api, ct_parser, table};
pub use injection::{speedhack, allochook};

// Flat re-exports of primary types
pub use memory::*;
pub use process::*;
pub use debugger::*;
pub use scripting::*;
pub use mono::*;
pub use injection::*;
