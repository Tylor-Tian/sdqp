//! MCP Gateway for controlled SDQP access by AI agents.

#![forbid(unsafe_code)]

pub mod auth;
pub mod rate_limit;
pub mod registry;
pub mod server;
pub mod tools;
pub mod watermark;

use thiserror::Error;

pub use auth::{McpAuthConfig, McpAuthRequest, McpAuthenticator, McpPrincipal};
pub use rate_limit::{InMemoryRateLimiter, RateLimitDecision, TokenBucketConfig};
pub use registry::{
    AgentRateLimits, AgentRegistration, AgentRegistry, AgentUserScope, McpToolName,
};
pub use server::{McpJsonRpcRequest, McpJsonRpcResponse, McpServer, SseEvent};
pub use tools::McpToolContext;
pub use watermark::{McpWatermarkEnvelope, McpWatermarkPayload};

/// Result type used by the MCP Gateway crate.
pub type McpResult<T> = Result<T, McpGatewayError>;

/// Error type for MCP Gateway authentication, authorization, protocol, and backend failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum McpGatewayError {
    /// The request did not contain valid agent credentials.
    #[error("authentication failed: {0}")]
    Authentication(String),
    /// The authenticated agent is not allowed to impersonate the requested user.
    #[error("agent is not allowed to act for user: {0}")]
    ForbiddenUser(String),
    /// The authenticated agent is not allowed to call the requested MCP tool.
    #[error("agent is not allowed to call tool: {0}")]
    ForbiddenTool(String),
    /// The request exceeded the configured rate limit.
    #[error("rate limit exceeded")]
    RateLimited,
    /// The request payload is invalid.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// The permission engine denied the requested operation.
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    /// The caller lacks the auditor role required for audit queries.
    #[error("auditor role required")]
    AuditorRoleRequired,
    /// A backend dependency returned an error.
    #[error("backend error: {0}")]
    Backend(String),
    /// Serialization or deserialization failed.
    #[error("serialization failed: {0}")]
    Serialization(String),
}
