use chrono::{Duration, Utc};
use sdqp_audit::{ActionResult, ActionType, ActorInfo, AuditEvent, TargetRef};
use sdqp_core::FilterOperator;
use sdqp_datasource_adapter::{FieldQueryResult, QueryResult, QueryStatus, UnifiedQuery};
use sdqp_mcp_gateway::{
    AgentRegistration, AgentRegistry, AgentUserScope, InMemoryRateLimiter, McpAuthConfig,
    McpAuthRequest, McpAuthenticator, McpResult, McpServer, McpToolContext, McpToolName,
    registry::AgentRateLimits,
    tools::{
        audit::{AuditQueryInput, AuditTimeRange, sdqp_query_audit},
        grants::{GrantListInput, sdqp_list_grants},
        permission::{PermissionRequestInput, sdqp_request_permission},
        query::{McpPaginationInput, McpQueryExecutor, QueryToolInput, sdqp_query},
    },
    watermark::decode_mcp_payload,
};
use sdqp_permission_engine::{FieldPermission, PermissionGrant, PermissionRegistry};

struct MockExecutor;

#[async_trait::async_trait]
impl McpQueryExecutor for MockExecutor {
    async fn execute_query(
        &self,
        _data_source_id: &str,
        query: UnifiedQuery,
    ) -> McpResult<QueryResult> {
        Ok(QueryResult {
            task_id: "task-mcp-1".into(),
            rows: vec![
                query
                    .fields
                    .iter()
                    .map(|field| FieldQueryResult {
                        field: field.as_str().into(),
                        value: "masked-value".into(),
                    })
                    .collect(),
            ],
            status: QueryStatus::Completed,
        })
    }
}

fn context_with_registry() -> (AgentRegistry, McpToolContext) {
    let registry = AgentRegistry::default();
    let mut agent = AgentRegistration::from_api_key(
        "agent-a",
        "secret",
        AgentUserScope::Only(["user-a".to_string()].into_iter().collect()),
        [
            McpToolName::SdqpQuery,
            McpToolName::SdqpRequestPermission,
            McpToolName::SdqpListGrants,
            McpToolName::SdqpQueryAudit,
        ],
    );
    agent.roles.insert("auditor".into());
    registry.register(agent).expect("agent registered");
    let authenticator =
        McpAuthenticator::new(registry.clone(), McpAuthConfig { require_mtls: true });
    let principal = authenticator
        .authenticate(&McpAuthRequest {
            agent_id: "agent-a".into(),
            api_key: "secret".into(),
            delegated_user_id: "user-a".into(),
            mcp_session_id: "mcp-session-a".into(),
            client_certificate_subject: Some("CN=agent-a".into()),
        })
        .expect("authenticated");
    (
        registry,
        McpToolContext {
            tenant_id: "tenant-a".into(),
            principal,
        },
    )
}

#[tokio::test]
async fn mock_agent_query_permission_grants_audit_and_sse_flow() {
    let (registry, context) = context_with_registry();
    let agent = registry.get("agent-a").expect("registry").expect("agent");
    let limiter = InMemoryRateLimiter::default();
    let decision = limiter
        .check(
            &agent.agent_id,
            McpToolName::SdqpQuery.as_str(),
            AgentRateLimits {
                per_minute: 1,
                per_hour: 10,
            },
        )
        .expect("rate limit");
    assert!(decision.allowed);

    let mut permissions = PermissionRegistry::default();
    let grant = PermissionGrant::active(
        "user-a",
        "project-a",
        "datasource-a",
        vec![FieldPermission {
            field_name: "employee_id".into(),
            denied: false,
        }],
        Vec::new(),
    );
    permissions.register_grant(grant.clone());

    let query = sdqp_query(
        &context,
        &MockExecutor,
        &grant,
        QueryToolInput {
            project_id: "project-a".into(),
            data_source_id: "datasource-a".into(),
            fields: vec!["employee_id".into()],
            conditions: vec![sdqp_core::FilterCondition {
                field: "region".into(),
                operator: FilterOperator::Eq,
                value: "apac".into(),
            }],
            pagination: Some(McpPaginationInput {
                page_size: 50,
                cursor: None,
            }),
            reason: "mcp investigation".into(),
            sequence_number: Some(7),
        },
    )
    .await
    .expect("query");
    assert_eq!(query.result.rows[0][0].field, "employee_id");
    let watermark = decode_mcp_payload(&query.watermark.token).expect("watermark");
    assert_eq!(watermark.agent_id, "agent-a");
    assert_eq!(watermark.tool_name, "sdqp_query");

    let grants =
        sdqp_list_grants(&context, &permissions, GrantListInput::default()).expect("grants");
    assert_eq!(grants.grants.len(), 1);

    let request = sdqp_request_permission(
        &context,
        &mut permissions,
        PermissionRequestInput {
            project_id: "project-a".into(),
            data_source_id: "datasource-a".into(),
            fields: vec!["employee_email".into()],
            conditions: Vec::new(),
            valid_days: 3,
            reason: "need email for fraud review".into(),
        },
    )
    .expect("permission request");
    assert_eq!(
        request.application.status,
        sdqp_permission_engine::GrantStatus::Pending
    );

    let event = AuditEvent::new(
        ActorInfo {
            user_id: "user-a".into(),
            session_id: "mcp-session-a".into(),
            ip_address: "127.0.0.1".into(),
        },
        ActionType::Query,
        TargetRef {
            tenant_id: "tenant-a".into(),
            project_id: Some("project-a".into()),
            resource_id: "task-mcp-1".into(),
        },
        "mcp query",
        ActionResult::Success,
        Some(query.watermark.token),
        None,
    );
    let audit = sdqp_query_audit(
        &context,
        &[event],
        AuditQueryInput {
            project_id: Some("project-a".into()),
            actor_id: Some("user-a".into()),
            action_types: vec!["query".into()],
            time_range: AuditTimeRange {
                from: Utc::now() - Duration::minutes(1),
                to: Utc::now() + Duration::minutes(1),
            },
            limit: Some(10),
        },
    )
    .expect("audit");
    assert_eq!(audit.events.len(), 1);

    let server = McpServer::new("sdqp-mcp-gateway", "0.1.0");
    let response = server.handle_discovery(&sdqp_mcp_gateway::McpJsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::json!(1),
        method: "tools/list".into(),
        params: serde_json::Value::Null,
    });
    let event = McpServer::response_event(&response).expect("sse");
    assert!(event.format().contains("event: message"));
    assert!(event.data.contains("sdqp_query"));
}
