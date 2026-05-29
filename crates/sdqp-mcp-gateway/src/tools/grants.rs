use sdqp_permission_engine::{GrantStatus, PermissionGrant, PermissionRegistry};
use serde::{Deserialize, Serialize};

use crate::{McpResult, registry::McpToolName, tools::McpToolContext};

/// Input for `sdqp_list_grants`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GrantListInput {
    /// Optional project filter.
    pub project_id: Option<String>,
    /// Optional data-source filter.
    pub data_source_id: Option<String>,
    /// When true, includes inactive grants.
    #[serde(default)]
    pub include_inactive: bool,
}

/// Response from `sdqp_list_grants`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantListResponse {
    /// Grants visible for the delegated user.
    pub grants: Vec<PermissionGrant>,
}

/// Implements `sdqp_list_grants` against the Module 2 permission registry.
pub fn sdqp_list_grants(
    context: &McpToolContext,
    registry: &PermissionRegistry,
    input: GrantListInput,
) -> McpResult<GrantListResponse> {
    context.require_tool(McpToolName::SdqpListGrants)?;
    let mut grants = registry.list_grants(
        &context.principal.delegated_user_id,
        input.project_id.as_deref(),
        input.data_source_id.as_deref(),
    );
    if !input.include_inactive {
        grants.retain(|grant| grant.status == GrantStatus::Active);
    }
    Ok(GrantListResponse { grants })
}
