//! OnyxEngine Native MCP Server Module (DLL)
//! Model Context Protocol native interface for AI agents, LLMs, and external automation tools.

pub mod plugins;
pub mod protocol;
pub mod server;
pub mod session;
pub mod tools;

use server::McpServer;
use std::ffi::{c_char, CStr};
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};

static GLOBAL_SERVER: OnceLock<Arc<McpServer>> = OnceLock::new();
static RUNNING_FLAG: AtomicBool = AtomicBool::new(false);
static STDIO_THREAD: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

pub fn get_server() -> &'static Arc<McpServer> {
    GLOBAL_SERVER.get_or_init(|| Arc::new(McpServer::new()))
}

/// Initialize the MCP engine in-process. Returns 1 on success.
#[no_mangle]
pub extern "C" fn onyx_mcp_init() -> i32 {
    let _ = get_server();
    1
}

/// Check if the MCP server is actively running.
#[no_mangle]
pub extern "C" fn onyx_mcp_is_running() -> i32 {
    if RUNNING_FLAG.load(Ordering::SeqCst) {
        1
    } else {
        0
    }
}

/// Start the MCP server loop on standard I/O in a background thread.
#[no_mangle]
pub extern "C" fn onyx_mcp_start_stdio_thread() -> i32 {
    if RUNNING_FLAG.swap(true, Ordering::SeqCst) {
        return 1; // Already running
    }

    let server = get_server().clone();
    let handle = thread::spawn(move || {
        server.run_stdio();
        RUNNING_FLAG.store(false, Ordering::SeqCst);
    });

    *STDIO_THREAD.lock().unwrap() = Some(handle);
    1
}

/// Stop the MCP background thread.
#[no_mangle]
pub extern "C" fn onyx_mcp_stop() -> i32 {
    RUNNING_FLAG.store(false, Ordering::SeqCst);
    1
}

/// Dispatch a raw JSON-RPC string directly to the MCP server.
/// Returns the number of bytes written to `out_buf` (including null terminator).
#[no_mangle]
pub unsafe extern "C" fn onyx_mcp_dispatch_json(
    req_json: *const c_char,
    out_buf: *mut c_char,
    max_len: u32,
) -> u32 {
    if req_json.is_null() || out_buf.is_null() || max_len == 0 {
        return 0;
    }

    let req_str = match CStr::from_ptr(req_json).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let server = get_server();
    let resp = match server.handle_message(req_str) {
        Some(r) => r,
        None => return 0,
    };

    let bytes = resp.as_bytes();
    let write_len = bytes.len().min(max_len as usize - 1);
    let slice_out = slice::from_raw_parts_mut(out_buf as *mut u8, max_len as usize);
    slice_out[..write_len].copy_from_slice(&bytes[..write_len]);
    slice_out[write_len] = 0;

    (write_len + 1) as u32
}

/// Retrieve the full JSON tools manifest for AI client configuration.
#[no_mangle]
pub unsafe extern "C" fn onyx_mcp_get_manifest(
    out_buf: *mut c_char,
    max_len: u32,
) -> u32 {
    if out_buf.is_null() || max_len == 0 {
        return 0;
    }

    let registry = tools::ToolRegistry::new();
    let manifest = serde_json::to_string_pretty(&registry.list()).unwrap_or_else(|_| "[]".to_string());

    let bytes = manifest.as_bytes();
    let write_len = bytes.len().min(max_len as usize - 1);
    let slice_out = slice::from_raw_parts_mut(out_buf as *mut u8, max_len as usize);
    slice_out[..write_len].copy_from_slice(&bytes[..write_len]);
    slice_out[write_len] = 0;

    (write_len + 1) as u32
}
