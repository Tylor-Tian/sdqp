use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{
    McpGatewayError, McpResult,
    registry::{AgentRegistry, McpToolName},
};

/// Authentication configuration for MCP clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct McpAuthConfig {
    /// Requires an mTLS client subject to be supplied by the transport layer.
    pub require_mtls: bool,
}

/// Raw authentication material extracted from an MCP request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpAuthRequest {
    /// Registered agent ID.
    pub agent_id: String,
    /// Plain API key presented by the agent.
    pub api_key: String,
    /// SDQP user ID that the agent is acting for.
    pub delegated_user_id: String,
    /// MCP session ID assigned by the client or gateway.
    pub mcp_session_id: String,
    /// mTLS client certificate subject supplied by the ingress layer.
    pub client_certificate_subject: Option<String>,
}

/// Authenticated MCP caller principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpPrincipal {
    /// Registered agent ID.
    pub agent_id: String,
    /// SDQP user ID that the agent is acting for.
    pub delegated_user_id: String,
    /// MCP session ID.
    pub mcp_session_id: String,
    /// Allowed tools copied from the agent registration.
    pub allowed_tools: HashSet<McpToolName>,
    /// Roles copied from the agent registration.
    pub roles: HashSet<String>,
    /// Verified mTLS client certificate subject, when present.
    pub client_certificate_subject: Option<String>,
}

impl McpPrincipal {
    /// Returns true if the principal has the supplied role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }

    /// Returns true if the principal may call the supplied tool.
    pub fn can_call(&self, tool: McpToolName) -> bool {
        self.allowed_tools.contains(&tool)
    }
}

/// Authenticator for API key plus mTLS-gated MCP clients.
#[derive(Debug, Clone)]
pub struct McpAuthenticator {
    registry: AgentRegistry,
    config: McpAuthConfig,
}

impl McpAuthenticator {
    /// Creates a new MCP authenticator.
    pub fn new(registry: AgentRegistry, config: McpAuthConfig) -> Self {
        Self { registry, config }
    }

    /// Authenticates the request and returns an MCP principal.
    pub fn authenticate(&self, request: &McpAuthRequest) -> McpResult<McpPrincipal> {
        let agent = self
            .registry
            .authenticate_api_key(&request.agent_id, &request.api_key)?;
        if !agent.allows_user(&request.delegated_user_id) {
            return Err(McpGatewayError::ForbiddenUser(
                request.delegated_user_id.clone(),
            ));
        }

        if self.config.require_mtls || agent.mtls_subject.is_some() {
            let Some(subject) = request.client_certificate_subject.as_deref() else {
                return Err(McpGatewayError::Authentication(
                    "mTLS client certificate required".into(),
                ));
            };
            if let Some(expected) = agent.mtls_subject.as_deref()
                && expected != subject
            {
                return Err(McpGatewayError::Authentication(
                    "mTLS client subject mismatch".into(),
                ));
            }
        }

        Ok(McpPrincipal {
            agent_id: agent.agent_id,
            delegated_user_id: request.delegated_user_id.clone(),
            mcp_session_id: request.mcp_session_id.clone(),
            allowed_tools: agent.allowed_tools,
            roles: agent.roles,
            client_certificate_subject: request.client_certificate_subject.clone(),
        })
    }
}
