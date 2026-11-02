//! Model Context Protocol (MCP) Server Dispatcher & Transport

use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
use crate::session::McpSession;
use crate::tools::ToolRegistry;
use serde_json::json;
use std::io::{self, BufRead, Write};
use std::sync::Arc;

pub struct McpServer {
    session: Arc<McpSession>,
    registry: ToolRegistry,
}

impl McpServer {
    pub fn new() -> Self {
        Self {
            session: Arc::new(McpSession::new()),
            registry: ToolRegistry::new(),
        }
    }

    pub fn handle_message(&self, raw_line: &str) -> Option<String> {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            return None;
        }

        let req: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let err_resp = JsonRpcResponse::err(None, -32700, format!("Parse error: {}", e));
                return Some(serde_json::to_string(&err_resp).unwrap());
            }
        };

        let response = match req.method.as_str() {
            "initialize" => {
                let result = json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {
                            "listChanged": false
                        }
                    },
                    "serverInfo": {
                        "name": "OnyxEngine Native MCP Server",
                        "version": "2.0.0"
                    }
                });
                Some(JsonRpcResponse::ok(req.id, result))
            }

            "notifications/initialized" => {
                None
            }

            "ping" => {
                Some(JsonRpcResponse::ok(req.id, json!({})))
            }

            "tools/list" => {
                let tools_json = self.registry.list();
                let result = json!({
                    "tools": tools_json
                });
                Some(JsonRpcResponse::ok(req.id, result))
            }

            "tools/call" => {
                let default_args = json!({});
                let (tool_name, arguments) = match &req.params {
                    Some(params) => {
                        let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let args = params.get("arguments").unwrap_or(&default_args);
                        (name, args)
                    }
                    None => ("", &default_args),
                };

                let tool_res = self.registry.call(&self.session, tool_name, arguments);
                let result_value = serde_json::to_value(&tool_res).unwrap_or(json!({
                    "content": [{"type": "text", "text": "Erro ao serializar resultado."}],
                    "isError": true
                }));

                Some(JsonRpcResponse::ok(req.id, result_value))
            }

            _ => {
                if req.id.is_some() {
                    Some(JsonRpcResponse::err(req.id, -32601, format!("Method not found: {}", req.method)))
                } else {
                    None
                }
            }
        };

        response.map(|r| serde_json::to_string(&r).unwrap())
    }

    pub fn run_stdio(&self) {
        let stdin = io::stdin();
        let mut stdout = io::stdout();

        for line in stdin.lock().lines() {
            match line {
                Ok(content) => {
                    if let Some(resp) = self.handle_message(&content) {
                        let _ = stdout.write_all(resp.as_bytes());
                        let _ = stdout.write_all(b"\n");
                        let _ = stdout.flush();
                    }
                }
                Err(_) => break,
            }
        }
    }
}
