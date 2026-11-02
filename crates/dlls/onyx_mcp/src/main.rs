//! OnyxEngine Native MCP Server Standalone Executable
//! Model Context Protocol runner for AI clients (Antigravity, Claude Desktop, Cursor, OpenAI).

use onyx_mcp::server::McpServer;
use onyx_mcp::tools::ToolRegistry;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && (args[1] == "--manifest" || args[1] == "-m") {
        let registry = ToolRegistry::new();
        println!("{}", serde_json::to_string_pretty(&registry.list()).unwrap());
        return;
    }

    if args.len() > 1 && (args[1] == "--version" || args[1] == "-v") {
        println!("OnyxEngine Native MCP Server v2.0.0");
        return;
    }

    // Default: run standard MCP JSON-RPC on stdio
    let server = McpServer::new();
    server.run_stdio();
}
