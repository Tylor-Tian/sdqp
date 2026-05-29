use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::registry::McpToolName;

/// Minimal JSON-RPC request shape used by MCP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpJsonRpcRequest {
    /// JSON-RPC version.
    pub jsonrpc: String,
    /// Request ID.
    pub id: Value,
    /// Method name.
    pub method: String,
    /// Method parameters.
    #[serde(default)]
    pub params: Value,
}

/// Minimal JSON-RPC response shape used by MCP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpJsonRpcResponse {
    /// JSON-RPC version.
    pub jsonrpc: String,
    /// Request ID.
    pub id: Value,
    /// Result payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

/// Server-Sent Events frame for MCP streaming transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SseEvent {
    /// SSE event name.
    pub event: String,
    /// Serialized event data.
    pub data: String,
}

impl SseEvent {
    /// Formats the event according to the SSE wire format.
    #[must_use]
    pub fn format(&self) -> String {
        format!("event: {}\ndata: {}\n\n", self.event, self.data)
    }
}

/// MCP server metadata and JSON-RPC/SSE helpers.
#[derive(Debug, Clone)]
pub struct McpServer {
    server_name: String,
    server_version: String,
}

impl McpServer {
    /// Creates an MCP server descriptor.
    pub fn new(server_name: impl Into<String>, server_version: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            server_version: server_version.into(),
        }
    }

    /// Returns the MCP tools manifest.
    #[must_use]
    pub fn tools_manifest(&self) -> Value {
        json!({
            "server": {
                "name": self.server_name,
                "version": self.server_version,
            },
            "tools": [
                tool_descriptor(McpToolName::SdqpQuery, "Run a permission-guarded SDQP query"),
                tool_descriptor(McpToolName::SdqpRequestPermission, "Request SDQP data access permission"),
                tool_descriptor(McpToolName::SdqpListGrants, "List active SDQP grants"),
                tool_descriptor(McpToolName::SdqpQueryAudit, "Query SDQP audit events"),
            ],
        })
    }

    /// Handles minimal MCP discovery methods.
    #[must_use]
    pub fn handle_discovery(&self, request: &McpJsonRpcRequest) -> McpJsonRpcResponse {
        let result = match request.method.as_str() {
            "initialize" => Some(json!({
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": self.server_name,
                    "version": self.server_version,
                },
                "capabilities": { "tools": {} },
            })),
            "tools/list" => Some(self.tools_manifest()),
            _ => None,
        };
        match result {
            Some(result) => McpJsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: request.id.clone(),
                result: Some(result),
                error: None,
            },
            None => McpJsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: request.id.clone(),
                result: None,
                error: Some(json!({ "code": -32601, "message": "method not found" })),
            },
        }
    }

    /// Wraps a JSON-RPC response as an SSE message event.
    pub fn response_event(response: &McpJsonRpcResponse) -> Result<SseEvent, serde_json::Error> {
        Ok(SseEvent {
            event: "message".into(),
            data: serde_json::to_string(response)?,
        })
    }
}

fn tool_descriptor(tool: McpToolName, description: &str) -> Value {
    json!({
        "name": tool.as_str(),
        "description": description,
    })
}
