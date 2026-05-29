use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::{Duration, Utc};
use sdqp_approval_engine::{
    ApprovalEngine, ApprovalFlowDefinition, ApprovalMode, ApprovalRequest, ApprovalStatus,
    ApprovalStepDefinition, ApproverSelector, MockNotificationSink,
};
use sdqp_audit::{
    ActionResult, ActionType, ActorInfo, AuditContextFields, AuditEvent, AuditTrail, TargetRef,
};
use sdqp_core::{FilterCondition, FilterOperator, RequestContext, TenantId, UserId};
use sdqp_data_classification::{
    MaskingStrategy, SensitivityLevel, classify_fields, default_rule_version,
};
use sdqp_data_view::{EncryptedSnapshotProvider, SnapshotAccessProfile};
use sdqp_datasource_adapter::{FieldQueryResult, QueryResult, QueryStatus, UnifiedQuery};
use sdqp_encryption::{
    EnvelopeCipher, InMemorySnapshotStore, KmsEnvelopeCipher, MockKmsService,
    SnapshotPayloadFormat, SnapshotStore, SnapshotWriteRequest,
};
use sdqp_hr_integration::{
    EmploymentStatus, HrEvent, HrEventType, OrgDirectory, OrgUser, RevocationReason, SyncSource,
};
use sdqp_mcp_gateway::{
    AgentRegistration, AgentRegistry, AgentUserScope, InMemoryRateLimiter, McpAuthConfig,
    McpAuthRequest, McpAuthenticator, McpGatewayError, McpResult, McpServer, McpToolContext,
    McpToolName,
    registry::AgentRateLimits,
    tools::{
        audit::{AuditQueryInput, AuditTimeRange, sdqp_query_audit},
        query::{McpPaginationInput, McpQueryExecutor, QueryToolInput, sdqp_query},
    },
    watermark::decode_mcp_payload,
};
use sdqp_permission_engine::{
    FieldPermission, GrantLifecycle, GrantStatus, OrgBinding, PermissionGrant, PermissionRegistry,
};
use sdqp_system_security::{SessionBinding, SessionPolicy, issue_access_token, parse_access_token};
use sdqp_watermark::{embed_marker, encode_payload, verify_content};

#[derive(Debug, Clone)]
struct CapturingExecutor {
    rows: Vec<HashMap<String, String>>,
    last_query: Arc<Mutex<Option<UnifiedQuery>>>,
}

impl CapturingExecutor {
    fn new(rows: Vec<HashMap<String, String>>) -> Self {
        Self {
            rows,
            last_query: Arc::new(Mutex::new(None)),
        }
    }

    fn last_query(&self) -> UnifiedQuery {
        self.last_query
            .lock()
            .expect("query capture lock")
            .clone()
            .expect("captured query")
    }
}

#[async_trait]
impl McpQueryExecutor for CapturingExecutor {
    async fn execute_query(
        &self,
        data_source_id: &str,
        query: UnifiedQuery,
    ) -> McpResult<QueryResult> {
        if data_source_id != "datasource-rest" {
            return Err(McpGatewayError::Backend("unexpected data source".into()));
        }
        *self.last_query.lock().expect("query capture lock") = Some(query.clone());
        let rows = self
            .rows
            .iter()
            .map(|row| {
                query
                    .fields
                    .iter()
                    .map(|field| FieldQueryResult {
                        field: field.as_str().to_string(),
                        value: row.get(field.as_str()).cloned().unwrap_or_default(),
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        Ok(QueryResult {
            task_id: "task-cross-module-1".into(),
            rows,
            status: QueryStatus::Completed,
        })
    }
}

fn mcp_context(agent_id: &str, user_id: &str, roles: HashSet<String>) -> McpToolContext {
    let registry = AgentRegistry::default();
    let mut registration = AgentRegistration::from_api_key(
        agent_id,
        "secret",
        AgentUserScope::Only([user_id.to_string()].into_iter().collect()),
        [
            McpToolName::SdqpQuery,
            McpToolName::SdqpRequestPermission,
            McpToolName::SdqpListGrants,
            McpToolName::SdqpQueryAudit,
        ],
    );
    registration.mtls_subject = Some(format!("CN={agent_id}"));
    registration.roles = roles;
    registry.register(registration).expect("agent registered");

    let principal = McpAuthenticator::new(registry, McpAuthConfig { require_mtls: true })
        .authenticate(&McpAuthRequest {
            agent_id: agent_id.into(),
            api_key: "secret".into(),
            delegated_user_id: user_id.into(),
            mcp_session_id: format!("session-{agent_id}"),
            client_certificate_subject: Some(format!("CN={agent_id}")),
        })
        .expect("authenticated");

    McpToolContext {
        tenant_id: "tenant-alpha".into(),
        principal,
    }
}

fn directory() -> OrgDirectory {
    let mut directory = OrgDirectory::default();
    directory.sync_snapshot(
        SyncSource::FeishuMock,
        vec![
            OrgUser {
                user_id: "manager-a".into(),
                department_id: "dept-risk".into(),
                manager_id: None,
                status: EmploymentStatus::Active,
                approver_profile: None,
            },
            OrgUser {
                user_id: "security-a".into(),
                department_id: "dept-security".into(),
                manager_id: None,
                status: EmploymentStatus::Active,
                approver_profile: None,
            },
            OrgUser {
                user_id: "user-a".into(),
                department_id: "dept-risk".into(),
                manager_id: Some("manager-a".into()),
                status: EmploymentStatus::Active,
                approver_profile: None,
            },
        ],
    );
    directory
}

fn append_audit(
    trail: &mut AuditTrail,
    action: ActionType,
    context: &str,
    result: ActionResult,
    data_fingerprint: Option<String>,
) -> AuditEvent {
    let event = AuditEvent::new_with_fields(
        ActorInfo {
            user_id: "user-a".into(),
            session_id: "session-cross-module".into(),
            ip_address: "127.0.0.1".into(),
        },
        action,
        TargetRef {
            tenant_id: "tenant-alpha".into(),
            project_id: Some("project-alpha".into()),
            resource_id: "resource-cross-module".into(),
        },
        context,
        AuditContextFields::builder()
            .field("agent_id", "agent-cross")
            .field("data_source_id", "datasource-rest")
            .build(),
        result,
        data_fingerprint,
        trail.latest_event_hash(),
    );
    trail.append(event.clone());
    event
}

fn approved_grant() -> PermissionGrant {
    let now = Utc::now();
    PermissionGrant::new(
        "user-a",
        "project-alpha",
        "datasource-rest",
        vec![FieldPermission {
            field_name: "employee_email".into(),
            denied: false,
        }],
        vec![FilterCondition {
            field: "department".into(),
            operator: FilterOperator::Eq,
            value: "fraud".into(),
        }],
        GrantLifecycle {
            valid_from: now - Duration::minutes(1),
            valid_until: now + Duration::hours(2),
            org_binding: OrgBinding {
                department_id: "dept-risk".into(),
                manager_id: Some("manager-a".into()),
            },
            status: GrantStatus::Active,
        },
    )
}

#[tokio::test]
async fn core_request_path_auth_guard_snapshot_mask_watermark_and_audit_chain() {
    let request = RequestContext::new(
        TenantId::new("tenant-alpha").expect("tenant"),
        UserId::new("user-a").expect("user"),
    );
    let claims = SessionPolicy { ttl_minutes: 15 }.issue(
        &request,
        SessionBinding {
            ip_address: "127.0.0.1".into(),
            device_fingerprint: "device-a".into(),
        },
    );
    let access_token = issue_access_token(&claims, "test-secret").expect("token");
    let parsed_claims = parse_access_token(&access_token, "test-secret").expect("claims");
    assert_eq!(parsed_claims.user_id, "user-a");
    assert!(parsed_claims.is_bound_to("127.0.0.1", "device-a"));

    let context = mcp_context("agent-cross", "user-a", HashSet::from(["auditor".into()]));
    let grant = approved_grant();
    let executor = CapturingExecutor::new(vec![HashMap::from([(
        "employee_email".into(),
        "alice@example.com".into(),
    )])]);

    let denied = sdqp_query(
        &context,
        &executor,
        &grant,
        QueryToolInput {
            project_id: "project-alpha".into(),
            data_source_id: "datasource-rest".into(),
            fields: vec!["employee_email".into(), "bank_card".into()],
            conditions: Vec::new(),
            pagination: None,
            reason: "negative field authorization check".into(),
            sequence_number: Some(1),
        },
    )
    .await
    .expect_err("unauthorized field denied");
    assert!(matches!(denied, McpGatewayError::PermissionDenied(_)));

    let response = sdqp_query(
        &context,
        &executor,
        &grant,
        QueryToolInput {
            project_id: "project-alpha".into(),
            data_source_id: "datasource-rest".into(),
            fields: vec!["employee_email".into()],
            conditions: vec![FilterCondition {
                field: "region".into(),
                operator: FilterOperator::Eq,
                value: "apac".into(),
            }],
            pagination: Some(McpPaginationInput {
                page_size: 50,
                cursor: None,
            }),
            reason: "core request path".into(),
            sequence_number: Some(42),
        },
    )
    .await
    .expect("query response");
    assert_eq!(response.result.rows.len(), 1);
    assert_eq!(response.result.rows[0].len(), 1);

    let guarded_query = executor.last_query();
    assert_eq!(guarded_query.conditions.len(), 2);
    assert!(guarded_query.conditions.iter().any(|condition| {
        condition.field == "department" && condition.operator == FilterOperator::Eq
    }));

    let policies = classify_fields(
        &default_rule_version("project-alpha", "datasource-rest"),
        &[HashMap::from([(
            "employee_email".into(),
            "alice@example.com".into(),
        )])],
        &["employee_email".into()],
        Some("run-core"),
    );
    assert_eq!(policies[0].level, SensitivityLevel::L4Sensitive);
    assert_eq!(policies[0].masking_strategy, MaskingStrategy::PartialEmail);

    let cipher = KmsEnvelopeCipher::new(MockKmsService::new("master-key", "ring-a", 1));
    let encrypted = cipher
        .encrypt(&serde_json::to_vec(&response.result.rows).expect("rows json"))
        .expect("encrypted snapshot");
    let mut snapshot_store = InMemorySnapshotStore::default();
    let snapshot = snapshot_store.put(
        SnapshotWriteRequest {
            tenant_id: "tenant-alpha".into(),
            project_id: "project-alpha".into(),
            owner_user_id: "user-a".into(),
            grant_id: grant.grant_id.clone(),
            grant_expires_at: grant.valid_until,
            retention_until: Utc::now() + Duration::days(30),
            data_source_id: "datasource-rest".into(),
            object_bucket: "sdqp-snapshots".into(),
            data_fingerprint: "sha256:query-result".into(),
            columns: vec!["employee_email".into()],
            payload_format: SnapshotPayloadFormat::JsonRows,
        },
        encrypted,
        response.result.rows.len(),
    );
    let provider = EncryptedSnapshotProvider::new(cipher);
    let page = provider
        .read_page(
            &snapshot,
            &SnapshotAccessProfile::new(vec!["employee_email".into()])
                .with_masking_rule("employee_email", MaskingStrategy::PartialEmail),
            &[],
            10,
            None,
        )
        .await
        .expect("data view page");
    assert_eq!(page.rows[0]["employee_email"], "a***@example.com");

    let mcp_payload = decode_mcp_payload(&response.watermark.token).expect("mcp watermark");
    assert_eq!(mcp_payload.agent_id, "agent-cross");
    let standard_payload = mcp_payload.standard_payload();
    assert_eq!(standard_payload.user_id, "user-a");
    assert_eq!(standard_payload.project_id, "project-alpha");
    let standard_token = encode_payload(&standard_payload).expect("standard watermark");
    let marked_content = embed_marker("masked export", &standard_token);
    assert!(verify_content(&marked_content, Some(&standard_token)).verified);

    let mut audit = AuditTrail::default();
    append_audit(
        &mut audit,
        ActionType::Login,
        "module12 auth",
        ActionResult::Success,
        None,
    );
    append_audit(
        &mut audit,
        ActionType::PermissionApply,
        "module2 permission guard",
        ActionResult::Success,
        None,
    );
    append_audit(
        &mut audit,
        ActionType::Query,
        "module1 query and module8 data view",
        ActionResult::Success,
        Some(response.watermark.token),
    );
    append_audit(
        &mut audit,
        ActionType::Export,
        "module10 watermark injection",
        ActionResult::Success,
        Some(standard_token),
    );
    assert!(audit.chain_valid());
    assert_eq!(audit.event_count(), 4);
}

#[tokio::test]
async fn permission_lifecycle_approval_hr_revocation_and_denied_query_are_audited() {
    let mut permission_registry = PermissionRegistry::default();
    let application = permission_registry.submit_application(
        "user-a",
        "project-alpha",
        "datasource-rest",
        vec!["employee_email".into()],
    );
    let flow = ApprovalFlowDefinition {
        flow_id: "flow-lifecycle".into(),
        version: 1,
        steps: vec![ApprovalStepDefinition {
            step_id: "manager-approval".into(),
            mode: ApprovalMode::Serial,
            approvers: vec![ApproverSelector::Manager],
            timeout_minutes: 30,
            escalation: Some(ApproverSelector::User("security-a".into())),
        }],
    };
    let approval_request = ApprovalRequest {
        request_id: application.application_id.clone(),
        applicant_user_id: application.applicant_user_id.clone(),
        project_id: application.project_id.clone(),
        data_source_id: application.data_source_id.clone(),
    };
    let mut directory = directory();
    let mut notifier = MockNotificationSink::default();
    let mut instance = ApprovalEngine::start_instance(
        &flow,
        &approval_request,
        &directory,
        Utc::now(),
        &mut notifier,
    )
    .expect("approval instance");
    ApprovalEngine::approve(
        &mut instance,
        &flow,
        &approval_request,
        &directory,
        "manager-a",
        Utc::now(),
        &mut notifier,
    )
    .expect("approval");
    assert_eq!(instance.status, ApprovalStatus::Approved);

    let grant = approved_grant();
    let grant_id = grant.grant_id.clone();
    let active_grant = permission_registry
        .activate_application_with_grant(
            &application.application_id,
            grant,
            Some(instance.instance_id.clone()),
        )
        .expect("grant activated");
    assert_eq!(
        permission_registry.active_grant_count("user-a", Some("project-alpha")),
        1
    );

    let context = mcp_context("agent-lifecycle", "user-a", HashSet::new());
    let executor = CapturingExecutor::new(vec![HashMap::from([(
        "employee_email".into(),
        "alice@example.com".into(),
    )])]);
    sdqp_query(
        &context,
        &executor,
        &active_grant,
        QueryToolInput {
            project_id: "project-alpha".into(),
            data_source_id: "datasource-rest".into(),
            fields: vec!["employee_email".into()],
            conditions: Vec::new(),
            pagination: None,
            reason: "pre-revocation query".into(),
            sequence_number: Some(2),
        },
    )
    .await
    .expect("query before revocation");

    let revocations = directory
        .apply_event(HrEvent::new(
            "user-a",
            HrEventType::Transfer,
            Some("dept-fraud".into()),
            Some("manager-a".into()),
        ))
        .expect("hr transfer");
    assert_eq!(revocations[0].reason, RevocationReason::Transfer);
    for command in revocations {
        permission_registry.revoke_grants_for_user(&command.user_id, command.project_id.as_deref());
    }
    let revoked = permission_registry
        .get_grant(&grant_id)
        .expect("revoked grant");
    assert_eq!(revoked.status, GrantStatus::Revoked);

    let denied = sdqp_query(
        &context,
        &executor,
        &revoked,
        QueryToolInput {
            project_id: "project-alpha".into(),
            data_source_id: "datasource-rest".into(),
            fields: vec!["employee_email".into()],
            conditions: Vec::new(),
            pagination: None,
            reason: "post-revocation query".into(),
            sequence_number: Some(3),
        },
    )
    .await
    .expect_err("revoked grant denied");
    assert!(matches!(denied, McpGatewayError::PermissionDenied(_)));

    let mut audit = AuditTrail::default();
    append_audit(
        &mut audit,
        ActionType::PermissionApply,
        "application approved and grant activated",
        ActionResult::Success,
        Some(instance.instance_id),
    );
    append_audit(
        &mut audit,
        ActionType::ConfigChange,
        "hr transfer revoked grant",
        ActionResult::Success,
        Some(grant_id),
    );
    append_audit(
        &mut audit,
        ActionType::Query,
        "query denied after revocation",
        ActionResult::Denied,
        None,
    );
    assert!(audit.chain_valid());
    assert!(
        audit
            .events()
            .iter()
            .any(|event| event.result == ActionResult::Denied)
    );
}

#[test]
fn mcp_gateway_end_to_end_rejects_unknown_agent_and_rate_limited_calls() {
    let registry = AgentRegistry::default();
    let mut registration = AgentRegistration::from_api_key(
        "agent-e2e",
        "secret",
        AgentUserScope::Only(["user-a".to_string()].into_iter().collect()),
        [McpToolName::SdqpQuery, McpToolName::SdqpQueryAudit],
    );
    registration.roles.insert("auditor".into());
    registry.register(registration).expect("agent registered");
    let authenticator =
        McpAuthenticator::new(registry.clone(), McpAuthConfig { require_mtls: true });

    let unknown = authenticator
        .authenticate(&McpAuthRequest {
            agent_id: "missing-agent".into(),
            api_key: "secret".into(),
            delegated_user_id: "user-a".into(),
            mcp_session_id: "session-e2e".into(),
            client_certificate_subject: Some("CN=missing-agent".into()),
        })
        .expect_err("unknown agent rejected");
    assert!(matches!(unknown, McpGatewayError::Authentication(_)));

    let principal = authenticator
        .authenticate(&McpAuthRequest {
            agent_id: "agent-e2e".into(),
            api_key: "secret".into(),
            delegated_user_id: "user-a".into(),
            mcp_session_id: "session-e2e".into(),
            client_certificate_subject: Some("CN=agent-e2e".into()),
        })
        .expect("authenticated");
    let limiter = InMemoryRateLimiter::default();
    let first = limiter
        .check(
            &principal.agent_id,
            McpToolName::SdqpQuery.as_str(),
            AgentRateLimits {
                per_minute: 1,
                per_hour: 10,
            },
        )
        .expect("first rate limit check");
    let second = limiter
        .check(
            &principal.agent_id,
            McpToolName::SdqpQuery.as_str(),
            AgentRateLimits {
                per_minute: 1,
                per_hour: 10,
            },
        )
        .expect("second rate limit check");
    assert!(first.allowed);
    assert!(!second.allowed);
    assert!(second.retry_after.is_some());

    let context = McpToolContext {
        tenant_id: "tenant-alpha".into(),
        principal,
    };
    let query_event = AuditEvent::new_with_fields(
        ActorInfo {
            user_id: "user-a".into(),
            session_id: "session-e2e".into(),
            ip_address: "127.0.0.1".into(),
        },
        ActionType::Query,
        TargetRef {
            tenant_id: "tenant-alpha".into(),
            project_id: Some("project-alpha".into()),
            resource_id: "task-e2e".into(),
        },
        "mcp query",
        AuditContextFields::builder()
            .field("agent_id", "agent-e2e")
            .build(),
        ActionResult::Success,
        None,
        None,
    );
    let audit = sdqp_query_audit(
        &context,
        &[query_event],
        AuditQueryInput {
            project_id: Some("project-alpha".into()),
            actor_id: Some("user-a".into()),
            action_types: vec!["query".into()],
            time_range: AuditTimeRange {
                from: Utc::now() - Duration::minutes(1),
                to: Utc::now() + Duration::minutes(1),
            },
            limit: Some(10),
        },
    )
    .expect("audit query");
    let agent_id = audit.events[0]
        .context_fields
        .iter()
        .find(|(key, _)| key.as_str() == "agent_id")
        .map(|(_, value)| value);
    assert!(agent_id.is_some());

    let server = McpServer::new("sdqp-mcp-gateway", "0.1.0");
    let manifest = server.tools_manifest();
    assert!(manifest.to_string().contains("sdqp_query"));
}
