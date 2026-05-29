use chrono::{DateTime, Utc};
use sdqp_audit::{ActionType, AuditEvent};
use serde::{Deserialize, Serialize};

use crate::{McpGatewayError, McpResult, registry::McpToolName, tools::McpToolContext};

/// Time range for MCP audit queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditTimeRange {
    /// Inclusive start timestamp.
    pub from: DateTime<Utc>,
    /// Inclusive end timestamp.
    pub to: DateTime<Utc>,
}

/// Input for `sdqp_query_audit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditQueryInput {
    /// Optional project filter.
    pub project_id: Option<String>,
    /// Optional actor/user filter.
    pub actor_id: Option<String>,
    /// Optional action type filters.
    #[serde(default)]
    pub action_types: Vec<String>,
    /// Required time range.
    pub time_range: AuditTimeRange,
    /// Result limit; defaults to 100 and is capped at 1,000.
    pub limit: Option<usize>,
}

/// Response from `sdqp_query_audit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditQueryResponse {
    /// Matching audit events.
    pub events: Vec<AuditEvent>,
}

/// Implements `sdqp_query_audit` for auditor-role agents.
pub fn sdqp_query_audit(
    context: &McpToolContext,
    events: &[AuditEvent],
    input: AuditQueryInput,
) -> McpResult<AuditQueryResponse> {
    context.require_tool(McpToolName::SdqpQueryAudit)?;
    if !context.principal.has_role("auditor") {
        return Err(McpGatewayError::AuditorRoleRequired);
    }

    let action_filters = input
        .action_types
        .iter()
        .map(|label| {
            ActionType::parse_label(label).ok_or_else(|| {
                McpGatewayError::InvalidRequest(format!("unknown action type: {label}"))
            })
        })
        .collect::<McpResult<Vec<_>>>()?;
    let limit = input.limit.unwrap_or(100).clamp(1, 1_000);
    let mut matches = events
        .iter()
        .filter(|event| event.timestamp >= input.time_range.from)
        .filter(|event| event.timestamp <= input.time_range.to)
        .filter(|event| {
            input
                .project_id
                .as_ref()
                .is_none_or(|project_id| event.target.project_id.as_ref() == Some(project_id))
        })
        .filter(|event| {
            input
                .actor_id
                .as_ref()
                .is_none_or(|actor_id| event.actor.user_id == *actor_id)
        })
        .filter(|event| action_filters.is_empty() || action_filters.contains(&event.action))
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    matches.sort_by_key(|event| event.timestamp);
    Ok(AuditQueryResponse { events: matches })
}
