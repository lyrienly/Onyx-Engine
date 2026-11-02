pub mod protocol;
pub mod server;
pub mod target;

pub use protocol::{encode_packet, parse_packet, Packet, ParseError};
pub use server::{serve_connection, GdbServer};
pub use target::{GdbTarget, MockTarget, Registers, StopReason};

#[no_mangle]
pub unsafe extern "C" fn onyx_gdb_server_version() -> u32 {
    0x010000
}
