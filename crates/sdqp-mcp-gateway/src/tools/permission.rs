use chrono::{Duration, Utc};
use sdqp_core::FilterCondition;
use sdqp_permission_engine::{
    GrantLifecycle, GrantStatus, OrgBinding, PermissionApplication, PermissionRegistry,
};
use serde::{Deserialize, Serialize};

use crate::{McpGatewayError, McpResult, registry::McpToolName, tools::McpToolContext};

/// Input for `sdqp_request_permission`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRequestInput {
    /// Project ID for the requested access.
    pub project_id: String,
    /// Data source ID for the requested access.
    pub data_source_id: String,
    /// Requested field names.
    pub fields: Vec<String>,
    /// Optional row-level conditions requested by the agent.
    #[serde(default)]
    pub conditions: Vec<FilterCondition>,
    /// Requested grant duration in days.
    pub valid_days: i64,
    /// Business reason written to audit context by the caller.
    pub reason: String,
}

/// Response from `sdqp_request_permission`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRequestResponse {
    /// Permission application created in Module 2.
    pub application: PermissionApplication,
    /// Lifecycle requested for the eventual grant.
    pub requested_lifecycle: GrantLifecycle,
    /// Count of requested conditions.
    pub requested_condition_count: usize,
    /// Business reason echoed for audit linkage.
    pub reason: String,
}

/// Implements `sdqp_request_permission` against the Module 2 permission registry.
pub fn sdqp_request_permission(
    context: &McpToolContext,
    registry: &mut PermissionRegistry,
    input: PermissionRequestInput,
) -> McpResult<PermissionRequestResponse> {
    context.require_tool(McpToolName::SdqpRequestPermission)?;
    if input.fields.is_empty() {
        return Err(McpGatewayError::InvalidRequest(
            "permission request requires at least one field".into(),
        ));
    }
    if input.reason.trim().is_empty() {
        return Err(McpGatewayError::InvalidRequest(
            "permission request reason is required".into(),
        ));
    }
    if input.valid_days <= 0 {
        return Err(McpGatewayError::InvalidRequest(
            "valid_days must be positive".into(),
        ));
    }

    let application = registry.submit_application(
        context.principal.delegated_user_id.clone(),
        input.project_id,
        input.data_source_id,
        input.fields,
    );
    let requested_lifecycle = GrantLifecycle {
        valid_from: Utc::now(),
        valid_until: Utc::now() + Duration::days(input.valid_days),
        org_binding: OrgBinding {
            department_id: "mcp-requested".into(),
            manager_id: None,
        },
        status: GrantStatus::Pending,
    };
    Ok(PermissionRequestResponse {
        application,
        requested_lifecycle,
        requested_condition_count: input.conditions.len(),
        reason: input.reason,
    })
}
