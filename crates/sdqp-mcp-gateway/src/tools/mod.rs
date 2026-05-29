//! MCP tool implementations.

pub mod audit;
pub mod grants;
pub mod permission;
pub mod query;

use serde::{Deserialize, Serialize};

use crate::{McpGatewayError, McpPrincipal, McpResult, registry::McpToolName};

/// Shared context for a single MCP tool invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpToolContext {
    /// Tenant scope for the tool call.
    pub tenant_id: String,
    /// Authenticated MCP principal.
    pub principal: McpPrincipal,
}

impl McpToolContext {
    /// Ensures the principal is allowed to call the supplied tool.
    pub fn require_tool(&self, tool: McpToolName) -> McpResult<()> {
        if self.principal.can_call(tool) {
            Ok(())
        } else {
            Err(McpGatewayError::ForbiddenTool(tool.as_str().into()))
        }
    }
}
