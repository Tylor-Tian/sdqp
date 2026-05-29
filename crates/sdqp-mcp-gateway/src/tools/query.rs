use async_trait::async_trait;
use sdqp_core::{FieldSelector, FilterCondition, Pagination};
use sdqp_datasource_adapter::{QueryResult, UnifiedQuery};
use sdqp_permission_engine::{GrantStatus, PermissionGrant, apply_grant_to_query};
use serde::{Deserialize, Serialize};

use crate::{
    McpGatewayError, McpResult,
    registry::McpToolName,
    tools::McpToolContext,
    watermark::{McpWatermarkEnvelope, build_mcp_watermark},
};

/// Pagination input accepted by `sdqp_query`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpPaginationInput {
    /// Requested page size.
    pub page_size: usize,
    /// Optional cursor.
    pub cursor: Option<String>,
}

/// Input for `sdqp_query`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryToolInput {
    /// Project ID.
    pub project_id: String,
    /// Data source ID.
    pub data_source_id: String,
    /// Requested field names.
    pub fields: Vec<String>,
    /// Optional caller-supplied filters.
    #[serde(default)]
    pub conditions: Vec<FilterCondition>,
    /// Optional pagination.
    pub pagination: Option<McpPaginationInput>,
    /// Business reason written to audit context by the caller.
    pub reason: String,
    /// Optional watermark sequence number.
    pub sequence_number: Option<u64>,
}

/// Response from `sdqp_query`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryToolResponse {
    /// Query result returned by Module 1.
    pub result: QueryResult,
    /// MCP-specific watermark envelope.
    pub watermark: McpWatermarkEnvelope,
}

/// Query execution backend used by `sdqp_query`.
#[async_trait]
pub trait McpQueryExecutor: Send + Sync {
    /// Executes the guarded query against the named data source.
    async fn execute_query(
        &self,
        data_source_id: &str,
        query: UnifiedQuery,
    ) -> McpResult<QueryResult>;
}

/// Implements `sdqp_query` using Module 2 QueryGuard semantics.
pub async fn sdqp_query(
    context: &McpToolContext,
    executor: &dyn McpQueryExecutor,
    grant: &PermissionGrant,
    input: QueryToolInput,
) -> McpResult<QueryToolResponse> {
    context.require_tool(McpToolName::SdqpQuery)?;
    if input.reason.trim().is_empty() {
        return Err(McpGatewayError::InvalidRequest(
            "query reason is required".into(),
        ));
    }
    if grant.status != GrantStatus::Active {
        return Err(McpGatewayError::PermissionDenied(
            "active grant required".into(),
        ));
    }
    if grant.applicant_user_id != context.principal.delegated_user_id {
        return Err(McpGatewayError::PermissionDenied(
            "grant does not belong to delegated user".into(),
        ));
    }
    if grant.project_id != input.project_id || grant.data_source_id != input.data_source_id {
        return Err(McpGatewayError::PermissionDenied(
            "grant scope does not match query".into(),
        ));
    }

    let fields = input
        .fields
        .iter()
        .map(FieldSelector::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| McpGatewayError::InvalidRequest(error.to_string()))?;
    let mut query = apply_grant_to_query(grant, &fields)
        .map_err(|error| McpGatewayError::PermissionDenied(error.to_string()))?;
    query.conditions.extend(input.conditions);
    if let Some(pagination) = input.pagination {
        query.pagination = Some(
            Pagination::bounded(pagination.page_size, pagination.cursor)
                .map_err(|error| McpGatewayError::InvalidRequest(error.to_string()))?,
        );
    }

    let result = executor.execute_query(&input.data_source_id, query).await?;
    let watermark = build_mcp_watermark(
        &context.tenant_id,
        &input.project_id,
        &context.principal.delegated_user_id,
        input.sequence_number.unwrap_or(1),
        Some(result.task_id.clone()),
        &context.principal.agent_id,
        McpToolName::SdqpQuery,
        &context.principal.mcp_session_id,
    )?;
    Ok(QueryToolResponse { result, watermark })
}
