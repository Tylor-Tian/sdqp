use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{McpGatewayError, McpResult};

/// MCP tools exposed by the SDQP gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpToolName {
    /// Controlled data query tool.
    SdqpQuery,
    /// Permission request tool.
    SdqpRequestPermission,
    /// Grant listing tool.
    SdqpListGrants,
    /// Audit query tool.
    SdqpQueryAudit,
}

impl McpToolName {
    /// Returns the MCP protocol tool name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SdqpQuery => "sdqp_query",
            Self::SdqpRequestPermission => "sdqp_request_permission",
            Self::SdqpListGrants => "sdqp_list_grants",
            Self::SdqpQueryAudit => "sdqp_query_audit",
        }
    }

    /// Parses a tool name from the MCP protocol label.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "sdqp_query" => Some(Self::SdqpQuery),
            "sdqp_request_permission" => Some(Self::SdqpRequestPermission),
            "sdqp_list_grants" => Some(Self::SdqpListGrants),
            "sdqp_query_audit" => Some(Self::SdqpQueryAudit),
            _ => None,
        }
    }
}

/// User scope that an AI agent may impersonate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentUserScope {
    /// The agent may act for any authenticated SDQP user.
    Any,
    /// The agent may act only for the listed user IDs.
    Only(HashSet<String>),
}

impl AgentUserScope {
    /// Returns true when the delegated user is inside this scope.
    pub fn allows(&self, user_id: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Only(users) => users.contains(user_id),
        }
    }
}

/// Per-agent rate limit configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRateLimits {
    /// Maximum calls per minute.
    pub per_minute: u32,
    /// Maximum calls per hour.
    pub per_hour: u32,
}

impl Default for AgentRateLimits {
    fn default() -> Self {
        Self {
            per_minute: 60,
            per_hour: 1_000,
        }
    }
}

/// Whitelist registration for one MCP AI agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRegistration {
    /// Globally unique agent ID.
    pub agent_id: String,
    /// SHA-256 digest of the API key.
    pub api_key_sha256: String,
    /// Users the agent is allowed to act for.
    pub allowed_users: AgentUserScope,
    /// MCP tools the agent is allowed to call.
    pub allowed_tools: HashSet<McpToolName>,
    /// Rate limits applied to this agent.
    pub rate_limits: AgentRateLimits,
    /// Optional expected mTLS client certificate subject.
    pub mtls_subject: Option<String>,
    /// Gateway roles granted to the agent, such as `auditor`.
    pub roles: HashSet<String>,
}

impl AgentRegistration {
    /// Builds an agent registration from a plaintext API key.
    pub fn from_api_key(
        agent_id: impl Into<String>,
        api_key: &str,
        allowed_users: AgentUserScope,
        allowed_tools: impl IntoIterator<Item = McpToolName>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            api_key_sha256: hash_api_key(api_key),
            allowed_users,
            allowed_tools: allowed_tools.into_iter().collect(),
            rate_limits: AgentRateLimits::default(),
            mtls_subject: None,
            roles: HashSet::new(),
        }
    }

    /// Returns true when the supplied API key matches the stored digest.
    pub fn verify_api_key(&self, api_key: &str) -> bool {
        self.api_key_sha256 == hash_api_key(api_key)
    }

    /// Returns true when this agent can call the given tool.
    pub fn allows_tool(&self, tool: McpToolName) -> bool {
        self.allowed_tools.contains(&tool)
    }

    /// Returns true when this agent can act for the given user.
    pub fn allows_user(&self, user_id: &str) -> bool {
        self.allowed_users.allows(user_id)
    }

    /// Returns true when this agent has the supplied role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }
}

/// In-memory whitelist registry for MCP agents.
#[derive(Debug, Clone, Default)]
pub struct AgentRegistry {
    agents: Arc<RwLock<HashMap<String, AgentRegistration>>>,
}

impl AgentRegistry {
    /// Registers or replaces an agent record.
    pub fn register(&self, registration: AgentRegistration) -> McpResult<()> {
        let mut agents = self
            .agents
            .write()
            .map_err(|_| McpGatewayError::Backend("agent registry lock poisoned".into()))?;
        agents.insert(registration.agent_id.clone(), registration);
        Ok(())
    }

    /// Loads an agent record by ID.
    pub fn get(&self, agent_id: &str) -> McpResult<Option<AgentRegistration>> {
        let agents = self
            .agents
            .read()
            .map_err(|_| McpGatewayError::Backend("agent registry lock poisoned".into()))?;
        Ok(agents.get(agent_id).cloned())
    }

    /// Authenticates an agent API key and returns the registration.
    pub fn authenticate_api_key(
        &self,
        agent_id: &str,
        api_key: &str,
    ) -> McpResult<AgentRegistration> {
        let Some(agent) = self.get(agent_id)? else {
            return Err(McpGatewayError::Authentication("unknown agent".into()));
        };
        if !agent.verify_api_key(api_key) {
            return Err(McpGatewayError::Authentication("invalid api key".into()));
        }
        Ok(agent)
    }
}

/// Computes a SHA-256 API key digest.
#[must_use]
pub fn hash_api_key(api_key: &str) -> String {
    hex_string(Sha256::digest(api_key.as_bytes()).as_slice())
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
