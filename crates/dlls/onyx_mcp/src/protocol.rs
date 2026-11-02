//! Model Context Protocol (MCP) JSON-RPC 2.0 Serialization Types

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    pub fn ok(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: Option<Value>, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpContentItem {
    #[serde(rename = "type")]
    pub item_type: String,
    pub text: String,
}

pub trait IntoMcpText {
    fn into_mcp_text(self) -> String;
}

impl IntoMcpText for String {
    fn into_mcp_text(self) -> String {
        self
    }
}

impl IntoMcpText for &str {
    fn into_mcp_text(self) -> String {
        self.to_string()
    }
}

impl IntoMcpText for Value {
    fn into_mcp_text(self) -> String {
        serde_json::to_string_pretty(&self).unwrap_or_else(|_| self.to_string())
    }
}

impl IntoMcpText for &Value {
    fn into_mcp_text(self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| self.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpCallToolResult {
    pub content: Vec<McpContentItem>,
    #[serde(rename = "isError", default)]
    pub is_error: bool,
}

impl McpCallToolResult {
    pub fn success(content: impl IntoMcpText) -> Self {
        Self {
            content: vec![McpContentItem {
                item_type: "text".to_string(),
                text: content.into_mcp_text(),
            }],
            is_error: false,
        }
    }

    pub fn error(text: impl Into<String>) -> Self {
        Self {
            content: vec![McpContentItem {
                item_type: "text".to_string(),
                text: text.into(),
            }],
            is_error: true,
        }
    }
}
