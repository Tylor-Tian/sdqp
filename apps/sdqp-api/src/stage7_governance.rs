use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Extension, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use sdqp_approval_engine::{
    ApprovalEngine, ApprovalFlowDefinition, ApprovalInstance, ApprovalRequest, ApprovalRouteTrace,
    ApprovalStatus, Notification, NotificationAction, NotificationCallback, NotificationKind,
    NotificationSink, StepState,
};
use sdqp_audit::{ActionResult, ActionType, ActorInfo, AuditContextFields, TargetRef};
use sdqp_config::settings::{
    FeishuIntegrationSettings, LdapIntegrationSettings, SapSuccessFactorsIntegrationSettings,
    WorkdayIntegrationSettings,
};
use sdqp_core::RequestContext;
use sdqp_hr_integration::{
    ApproverAvailability, ApproverProfile, ApproverResolutionPolicy, ApproverRoute,
    ApproverRouteKind, EmploymentStatus, FeishuEventPage, FeishuEventPayload, FeishuProviderAuth,
    FeishuProviderConfig, FeishuSnapshotPayload, FeishuWebhookEnvelope, HrEvent, HrEventType,
    LdapAttributeMapping, LdapDirectorySearchResult, LdapProviderAuth, LdapProviderConfig,
    LdapTlsMode, OrgDirectory, OrgUser, SapSuccessFactorsEventPage, SapSuccessFactorsEventPayload,
    SapSuccessFactorsProviderAuth, SapSuccessFactorsProviderConfig,
    SapSuccessFactorsSnapshotPayload, SapSuccessFactorsWebhookEnvelope, SyncSource,
    WorkdayEventPage, WorkdayProviderAuth, WorkdayProviderConfig, WorkdaySnapshotPage,
    WorkdayWebhookEnvelope,
};
use sdqp_permission_engine::{
    ApplicantEligibilityRule, ApplicantRuntimeProfile, EmploymentState, FieldPermission,
    GrantLifecycle, GrantLifecycleScheduler, GrantLifecycleTransition, GrantLifecycleTrigger,
    GrantStatus, OrgBinding, PermissionApplication, PermissionGrant, PermissionRegistry,
};
use sdqp_system_security::Role;
use sdqp_tenant_isolation::ProjectState;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, types::Json as SqlJson};
use sqlx_postgres::PgRow;
use tokio::time::sleep;
use tracing::warn;
use ulid::Ulid;

use crate::{
    ApiState, AuthenticatedSession, json_error,
    persistence::{ApiPersistence, PersistenceError},
};

const GOVERNANCE_LOOP_INTERVAL_MS: u64 = 50;
const NOTIFICATION_MAX_ATTEMPTS: i32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionGrantRecordResponse {
    pub grant_id: String,
    pub data_source_id: String,
    pub status: String,
    pub fields: Vec<String>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionGrantsResponse {
    pub grants: Vec<PermissionGrantRecordResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalTaskResponse {
    pub instance_id: String,
    pub application_id: String,
    pub applicant_user_id: String,
    pub data_source_id: String,
    pub step_id: String,
    pub status: String,
    pub pending_approvers: Vec<String>,
    pub requested_fields: Vec<String>,
    pub due_at: DateTime<Utc>,
    pub escalation_target: Option<String>,
    pub delegated_to: Option<String>,
    pub routing: Vec<ApprovalRouteTrace>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalTasksResponse {
    pub tasks: Vec<ApprovalTaskResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalCallbackRequest {
    pub instance_id: String,
    pub action: String,
    pub delegate_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalCallbackResponse {
    pub instance_id: String,
    pub status: String,
    pub application_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverResolutionRequest {
    pub requested_user_id: String,
    #[serde(default)]
    pub reroute_unavailable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverResolutionResponse {
    pub requested_user_id: String,
    pub resolved_user_id: String,
    pub route_kind: String,
    pub delegated_from: Option<String>,
    pub escalation_target: Option<String>,
    pub used_system_fallback: bool,
    pub traversed_user_ids: Vec<String>,
    pub unavailable_user_ids: Vec<String>,
    pub policy_system_fallback_user_id: String,
    pub policy_escalation_user_ids: Vec<String>,
    pub policy_max_manager_hops: usize,
    pub policy_allow_delegation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HrEventRequest {
    pub source: String,
    pub event_id: Option<String>,
    pub user_id: String,
    pub event_type: String,
    pub department_id: Option<String>,
    pub manager_id: Option<String>,
    pub approver_availability: Option<String>,
    pub delegate_user_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionLifecycleTransitionResponse {
    pub transition_id: String,
    pub grant_id: String,
    pub applicant_user_id: String,
    pub project_id: String,
    pub data_source_id: String,
    pub from_status: String,
    pub to_status: String,
    pub trigger: String,
    pub reason: String,
    pub effective_at: DateTime<Utc>,
    pub source_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPermissionTransitionRequest {
    pub user_id: String,
    pub project_id: Option<String>,
    pub action: String,
    pub source_event_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPermissionTransitionResponse {
    pub applied: usize,
    pub revoked_grants: usize,
    pub suspended_grants: usize,
    pub resumed_grants: usize,
    pub expired_grants: usize,
    pub lifecycle_transitions: Vec<PermissionLifecycleTransitionResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HrEventResponse {
    pub processed: bool,
    pub revoked_grants: usize,
    pub suspended_grants: usize,
    pub resumed_grants: usize,
    pub expired_grants: usize,
    pub lifecycle_transitions: Vec<PermissionLifecycleTransitionResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeishuHrRuntimeResponse {
    pub provider_id: String,
    pub runtime_mode: String,
    pub auth_mode: String,
    pub operation: String,
    pub checkpoint_before: Option<String>,
    pub checkpoint_after: Option<String>,
    pub snapshot_cursor_after: Option<String>,
    pub synced_user_count: usize,
    pub received_event_count: usize,
    pub applied_event_count: usize,
    pub skipped_event_count: usize,
    pub revoked_grants: usize,
    pub suspended_grants: usize,
    pub resumed_grants: usize,
    pub expired_grants: usize,
    pub lifecycle_transitions: Vec<PermissionLifecycleTransitionResponse>,
    pub audit_checkpoint_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkdayHrRuntimeResponse {
    pub provider_id: String,
    pub runtime_mode: String,
    pub auth_mode: String,
    pub operation: String,
    pub checkpoint_before: Option<String>,
    pub checkpoint_after: Option<String>,
    pub snapshot_cursor_after: Option<String>,
    pub synced_user_count: usize,
    pub received_event_count: usize,
    pub applied_event_count: usize,
    pub skipped_event_count: usize,
    pub revoked_grants: usize,
    pub suspended_grants: usize,
    pub resumed_grants: usize,
    pub expired_grants: usize,
    pub lifecycle_transitions: Vec<PermissionLifecycleTransitionResponse>,
    pub audit_checkpoint_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SapSuccessFactorsHrRuntimeResponse {
    pub provider_id: String,
    pub runtime_mode: String,
    pub auth_mode: String,
    pub operation: String,
    pub checkpoint_before: Option<String>,
    pub checkpoint_after: Option<String>,
    pub snapshot_cursor_after: Option<String>,
    pub synced_user_count: usize,
    pub received_event_count: usize,
    pub applied_event_count: usize,
    pub skipped_event_count: usize,
    pub revoked_grants: usize,
    pub suspended_grants: usize,
    pub resumed_grants: usize,
    pub expired_grants: usize,
    pub lifecycle_transitions: Vec<PermissionLifecycleTransitionResponse>,
    pub audit_checkpoint_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapHrRuntimeResponse {
    pub provider_id: String,
    pub runtime_mode: String,
    pub auth_mode: String,
    pub tls_mode: String,
    pub operation: String,
    pub checkpoint_before: Option<String>,
    pub checkpoint_after: Option<String>,
    pub snapshot_cursor_after: Option<String>,
    pub page_size: usize,
    pub estimated_page_count: usize,
    pub synced_user_count: usize,
    pub received_event_count: usize,
    pub applied_event_count: usize,
    pub skipped_event_count: usize,
    pub revoked_grants: usize,
    pub suspended_grants: usize,
    pub resumed_grants: usize,
    pub expired_grants: usize,
    pub lifecycle_transitions: Vec<PermissionLifecycleTransitionResponse>,
    pub audit_checkpoint_id: String,
}

#[derive(Debug, Clone)]
struct ApprovalBundle {
    application: PermissionApplication,
    flow: ApprovalFlowDefinition,
    request: ApprovalRequest,
    instance: ApprovalInstance,
}

#[derive(Debug, Clone)]
struct NotificationDeliveryRow {
    delivery_id: String,
    instance_id: Option<String>,
    project_id: Option<String>,
    channel: String,
    notification: Notification,
    attempt_count: i32,
}

#[derive(Debug, Clone, Default)]
struct HrProviderCheckpoint {
    event_cursor: Option<String>,
    snapshot_cursor: Option<String>,
}

#[derive(Debug, Clone)]
struct HrEventProcessingReport {
    received_event_count: usize,
    applied_event_count: usize,
    skipped_event_count: usize,
    last_event_id: Option<String>,
    lifecycle_transitions: Vec<GrantLifecycleTransition>,
}

#[derive(Debug, Clone)]
pub(crate) enum PermissionApplicationSubmissionError {
    Forbidden(&'static str),
    Internal(&'static str),
}

impl PermissionApplicationSubmissionError {
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub(crate) fn audit_result(&self) -> ActionResult {
        match self {
            Self::Forbidden(_) => ActionResult::Denied,
            Self::Internal(_) => ActionResult::Failure,
        }
    }

    pub(crate) fn message(&self) -> &'static str {
        match self {
            Self::Forbidden(message) | Self::Internal(message) => message,
        }
    }
}

#[derive(Debug, Default)]
struct QueueingNotificationSink {
    notifications: Vec<Notification>,
}

impl NotificationSink for QueueingNotificationSink {
    fn push_notification(&mut self, notification: Notification) {
        self.notifications.push(notification);
    }
}

pub(crate) async fn load_permission_registry(
    persistence: &ApiPersistence,
) -> Result<PermissionRegistry, PersistenceError> {
    let mut registry = PermissionRegistry::default();

    let application_rows = sqlx::query(
        r#"
        SELECT
            application_id,
            applicant_user_id,
            project_id,
            data_source_id,
            requested_fields_json,
            status,
            approval_instance_id,
            merged_into_application_id
        FROM permission_applications
        ORDER BY created_at, application_id
        "#,
    )
    .fetch_all(persistence.pool())
    .await?;
    for row in application_rows {
        registry.restore_application(parse_permission_application_row(&row)?);
    }

    let grant_rows = sqlx::query(
        r#"
        SELECT
            grant_id,
            applicant_user_id,
            project_id,
            data_source_id,
            fields_json,
            conditions_json,
            valid_from,
            valid_until,
            org_binding_json,
            status
        FROM permission_grants
        ORDER BY created_at, grant_id
        "#,
    )
    .fetch_all(persistence.pool())
    .await?;
    for row in grant_rows {
        registry.register_grant(parse_permission_grant_row(&row)?);
    }

    Ok(registry)
}

pub(crate) async fn submit_persistent_permission_application(
    state: Arc<ApiState>,
    session: &AuthenticatedSession,
    project_id: &str,
    data_source_id: String,
    requested_fields: Vec<String>,
) -> Result<PermissionApplication, PermissionApplicationSubmissionError> {
    let Some(persistence) = state.persistence.as_ref() else {
        return Err(PermissionApplicationSubmissionError::Internal(
            "persistent governance runtime is unavailable",
        ));
    };

    let mut application = PermissionApplication {
        application_id: Ulid::new().to_string(),
        applicant_user_id: session.claims.user_id.clone(),
        project_id: project_id.to_string(),
        data_source_id,
        requested_fields,
        status: GrantStatus::Pending,
        approval_instance_id: None,
        merged_into_application_id: None,
    };
    let merge_key = application.merge_key();
    let directory = load_org_directory(persistence).await.map_err(|_| {
        PermissionApplicationSubmissionError::Internal("failed to load organization directory")
    })?;
    let rule = load_eligibility_rule_for_project(persistence, project_id)
        .await
        .map_err(|_| {
            PermissionApplicationSubmissionError::Internal("failed to load eligibility rule")
        })?;
    let profile = applicant_profile_from_roles(
        &directory,
        &session.claims.user_id,
        session.roles.iter().map(role_label).collect(),
    );
    let decision = GrantLifecycleScheduler.evaluate_activation(&profile, &rule);
    if !decision.eligible {
        return Err(PermissionApplicationSubmissionError::Forbidden(
            "applicant is not eligible for this project permission request",
        ));
    }

    if let Some(existing) = load_pending_application_by_merge_key(persistence, &merge_key)
        .await
        .map_err(|_| {
            PermissionApplicationSubmissionError::Internal(
                "failed to inspect pending permission applications",
            )
        })?
    {
        state
            .permissions
            .lock()
            .expect("permission registry")
            .restore_application(existing.clone());
        return Ok(existing);
    }

    let flow = load_approval_flow(persistence, project_id)
        .await
        .map_err(|_| {
            PermissionApplicationSubmissionError::Internal("failed to load approval flow")
        })?;
    let request = ApprovalRequest {
        request_id: application.application_id.clone(),
        applicant_user_id: application.applicant_user_id.clone(),
        project_id: application.project_id.clone(),
        data_source_id: application.data_source_id.clone(),
    };
    let mut notifier = QueueingNotificationSink::default();
    let approver_policy = approver_resolution_policy_from_state(&state);
    let instance = ApprovalEngine::start_instance_with_policy(
        &flow,
        &request,
        &directory,
        &approver_policy,
        Utc::now(),
        &mut notifier,
    )
    .map_err(|_| {
        PermissionApplicationSubmissionError::Internal("failed to start approval workflow")
    })?;
    application.approval_instance_id = Some(instance.instance_id.clone());

    save_approval_instance(persistence, &application, &flow, &request, &instance)
        .await
        .map_err(|_| {
            PermissionApplicationSubmissionError::Internal("failed to persist approval instance")
        })?;
    save_permission_application(persistence, &application, &merge_key)
        .await
        .map_err(|_| {
            PermissionApplicationSubmissionError::Internal(
                "failed to persist permission application",
            )
        })?;
    queue_notifications(
        persistence,
        Some(&instance.instance_id),
        &notifier.notifications,
    )
    .await
    .map_err(|_| {
        PermissionApplicationSubmissionError::Internal("failed to queue approval notifications")
    })?;

    state
        .permissions
        .lock()
        .expect("permission registry")
        .restore_application(application.clone());

    Ok(application)
}

pub(crate) fn spawn_governance_runtime(state: Arc<ApiState>) {
    tokio::spawn(async move {
        loop {
            if let Err(error) = run_governance_tick(state.clone()).await {
                warn!(error = %error, "stage7 governance tick failed");
            }
            sleep(Duration::from_millis(GOVERNANCE_LOOP_INTERVAL_MS)).await;
        }
    });
}

pub(crate) async fn persist_project_grant_state(
    state: Arc<ApiState>,
    project_id: &str,
    next_state: ProjectState,
) -> Result<(), PersistenceError> {
    let Some(persistence) = state.persistence.as_ref() else {
        return Ok(());
    };

    match next_state {
        ProjectState::Frozen => {
            update_grants_for_project_status(persistence, project_id, "active", "suspended")
                .await?;
        }
        ProjectState::Active => {
            update_grants_for_project_status(persistence, project_id, "suspended", "active")
                .await?;
        }
        ProjectState::Archived | ProjectState::Deleted => {
            update_grants_for_project_status(persistence, project_id, "active", "revoked").await?;
            update_grants_for_project_status(persistence, project_id, "suspended", "revoked")
                .await?;
        }
        ProjectState::Created => {}
    }

    Ok(())
}

#[derive(Debug, Default)]
struct LifecycleTransitionStats {
    revoked: usize,
    suspended: usize,
    resumed: usize,
    expired: usize,
}

async fn run_permission_lifecycle_scheduler(
    state: Arc<ApiState>,
    now: DateTime<Utc>,
) -> Result<Vec<GrantLifecycleTransition>, PersistenceError> {
    let Some(persistence) = state.persistence.as_ref() else {
        return Ok(Vec::new());
    };
    let directory = load_org_directory(persistence).await?;
    let rules = load_eligibility_rules(persistence).await?;
    let grants = load_lifecycle_grants(persistence).await?;
    let scheduler = GrantLifecycleScheduler;
    let mut transitions = Vec::new();

    for grant in grants {
        let profile = applicant_profile_from_state(&state, &directory, &grant.applicant_user_id);
        let rule = rules
            .get(&grant.project_id)
            .cloned()
            .unwrap_or_else(|| ApplicantEligibilityRule::active_hr_only(&grant.project_id));
        let trigger = project_lifecycle_trigger(&state, &grant)
            .unwrap_or(GrantLifecycleTrigger::SchedulerTick);
        if let Some(transition) = scheduler.evaluate_grant(&grant, &profile, &rule, now, trigger) {
            transitions.push(transition);
        }
    }

    apply_lifecycle_transitions(state, transitions).await
}

async fn apply_hr_lifecycle_for_user(
    state: Arc<ApiState>,
    directory: &OrgDirectory,
    user_id: &str,
    project_id: Option<&str>,
    source_event_id: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Vec<GrantLifecycleTransition>, PersistenceError> {
    let Some(persistence) = state.persistence.as_ref() else {
        return Ok(Vec::new());
    };
    let rules = load_eligibility_rules(persistence).await?;
    let grants = load_lifecycle_grants_for_user(persistence, user_id, project_id).await?;
    let scheduler = GrantLifecycleScheduler;
    let mut transitions = Vec::new();

    for grant in grants {
        let profile = applicant_profile_from_state(&state, directory, &grant.applicant_user_id);
        let rule = rules
            .get(&grant.project_id)
            .cloned()
            .unwrap_or_else(|| ApplicantEligibilityRule::active_hr_only(&grant.project_id));
        if let Some(mut transition) =
            scheduler.evaluate_grant(&grant, &profile, &rule, now, GrantLifecycleTrigger::HrSync)
        {
            if let Some(source_event_id) = source_event_id {
                transition.source_event_id = Some(source_event_id.to_string());
            }
            transitions.push(transition);
        }
    }

    apply_lifecycle_transitions(state, transitions).await
}

pub(crate) async fn apply_audit_permission_signal_for_user(
    state: Arc<ApiState>,
    user_id: &str,
    project_id: Option<&str>,
    trigger: GrantLifecycleTrigger,
    source_event_id: Option<&str>,
    reason: &str,
) -> Result<Vec<GrantLifecycleTransition>, PersistenceError> {
    let Some(persistence) = state.persistence.as_ref() else {
        return Ok(Vec::new());
    };
    let directory = load_org_directory(persistence).await?;
    let rules = load_eligibility_rules(persistence).await?;
    let grants = load_lifecycle_grants_for_user(persistence, user_id, project_id).await?;
    let scheduler = GrantLifecycleScheduler;
    let now = Utc::now();
    let mut transitions = Vec::new();

    for grant in grants {
        let profile = applicant_profile_from_state(&state, &directory, &grant.applicant_user_id);
        let rule = rules
            .get(&grant.project_id)
            .cloned()
            .unwrap_or_else(|| ApplicantEligibilityRule::active_hr_only(&grant.project_id));
        if let Some(mut transition) =
            scheduler.evaluate_grant(&grant, &profile, &rule, now, trigger)
        {
            if !reason.trim().is_empty() {
                transition.reason = reason.to_string();
            }
            if let Some(source_event_id) = source_event_id {
                transition.source_event_id = Some(source_event_id.to_string());
            }
            transitions.push(transition);
        }
    }

    apply_lifecycle_transitions(state, transitions).await
}

async fn apply_lifecycle_transitions(
    state: Arc<ApiState>,
    transitions: Vec<GrantLifecycleTransition>,
) -> Result<Vec<GrantLifecycleTransition>, PersistenceError> {
    let Some(persistence) = state.persistence.as_ref() else {
        return Ok(Vec::new());
    };
    let mut applied = Vec::new();

    for transition in transitions {
        let in_memory_applied = {
            state
                .permissions
                .lock()
                .expect("permission registry")
                .apply_lifecycle_transition(&transition)
        };
        update_permission_grant_lifecycle_status(persistence, &transition).await?;
        let checkpoint = append_transition_audit(state.clone(), &transition).await;
        save_permission_lifecycle_event(persistence, &transition, &checkpoint.checkpoint_id)
            .await?;
        if in_memory_applied || state.persistence.is_some() {
            applied.push(transition);
        }
    }

    Ok(applied)
}

async fn append_transition_audit(
    state: Arc<ApiState>,
    transition: &GrantLifecycleTransition,
) -> sdqp_audit::AuditCheckpoint {
    let context_fields = AuditContextFields::builder()
        .field("transition_id", transition.transition_id.clone())
        .field("grant_id", transition.grant_id.clone())
        .field("applicant_user_id", transition.applicant_user_id.clone())
        .field("from_status", grant_status_label(&transition.from_status))
        .field("to_status", grant_status_label(&transition.to_status))
        .field("trigger", transition.trigger.as_str())
        .field("reason", transition.reason.clone())
        .field(
            "source_event_id",
            transition.source_event_id.clone().unwrap_or_default(),
        )
        .build();
    crate::record_audit_event_from_parts_with_fields(
        &state,
        ActorInfo {
            user_id: lifecycle_actor_for_trigger(transition.trigger).into(),
            session_id: transition
                .source_event_id
                .clone()
                .unwrap_or_else(|| "runtime-job".into()),
            ip_address: "127.0.0.1".into(),
        },
        ActionType::PermissionApply,
        TargetRef {
            tenant_id: tenant_id_for_project(&state, &transition.project_id),
            project_id: Some(transition.project_id.clone()),
            resource_id: transition.grant_id.clone(),
        },
        format!(
            "permission lifecycle transition {} -> {}",
            grant_status_label(&transition.from_status),
            grant_status_label(&transition.to_status)
        ),
        context_fields,
        ActionResult::Success,
        None,
    )
    .await
}

async fn append_permission_lifecycle_audit(
    state: Arc<ApiState>,
    project_id: &str,
    resource_id: &str,
    context: &str,
    context_fields: AuditContextFields,
) -> sdqp_audit::AuditCheckpoint {
    crate::record_audit_event_from_parts_with_fields(
        &state,
        ActorInfo {
            user_id: "permission-lifecycle-scheduler".into(),
            session_id: "runtime-job".into(),
            ip_address: "127.0.0.1".into(),
        },
        ActionType::PermissionApply,
        TargetRef {
            tenant_id: tenant_id_for_project(&state, project_id),
            project_id: Some(project_id.to_string()),
            resource_id: resource_id.to_string(),
        },
        context,
        context_fields,
        ActionResult::Denied,
        None,
    )
    .await
}

async fn append_approver_resolution_audit(
    state: Arc<ApiState>,
    session: &AuthenticatedSession,
    project_id: &str,
    route: &ApproverRoute,
    policy: &ApproverResolutionPolicy,
    reroute_unavailable: bool,
) -> sdqp_audit::AuditCheckpoint {
    crate::record_audit_event_from_parts_with_fields(
        &state,
        ActorInfo {
            user_id: session.claims.user_id.clone(),
            session_id: session.claims.session_id.clone(),
            ip_address: session.claims.binding.ip_address.clone(),
        },
        ActionType::PermissionApply,
        TargetRef {
            tenant_id: tenant_id_for_project(&state, project_id),
            project_id: Some(project_id.to_string()),
            resource_id: route.requested_user_id.clone(),
        },
        "approver resolution evaluated",
        AuditContextFields::builder()
            .field("requested_user_id", route.requested_user_id.clone())
            .field("resolved_user_id", route.resolved_user_id.clone())
            .field("route_kind", approver_route_kind_label(&route.route_kind))
            .field(
                "delegated_from",
                route.delegated_from.clone().unwrap_or_default(),
            )
            .field(
                "escalation_target",
                route.escalation_target.clone().unwrap_or_default(),
            )
            .field(
                "used_system_fallback",
                route.used_system_fallback.to_string(),
            )
            .field("reroute_unavailable", reroute_unavailable.to_string())
            .field("traversed_user_ids", route.traversed_user_ids.join(","))
            .field("unavailable_user_ids", route.unavailable_user_ids.join(","))
            .field(
                "policy_system_fallback_user_id",
                policy.system_fallback_user_id.clone(),
            )
            .field(
                "policy_escalation_user_ids",
                policy.escalation_user_ids.join(","),
            )
            .field(
                "policy_max_manager_hops",
                policy.max_manager_hops.to_string(),
            )
            .field(
                "policy_allow_delegation",
                policy.allow_delegation.to_string(),
            )
            .build(),
        ActionResult::Success,
        None,
    )
    .await
}

async fn append_notification_delivery_audit(
    state: Arc<ApiState>,
    delivery: &NotificationDeliveryRow,
    status: &str,
    attempt_count: i32,
    next_attempt_at: Option<DateTime<Utc>>,
    last_error: Option<&str>,
) -> sdqp_audit::AuditCheckpoint {
    let project_id = delivery.project_id.clone();
    let tenant_id = project_id
        .as_deref()
        .map(|project_id| tenant_id_for_project(&state, project_id))
        .unwrap_or_else(|| "tenant-alpha".into());
    let result = if status == "sent" {
        ActionResult::Success
    } else {
        ActionResult::Failure
    };
    crate::record_audit_event_from_parts_with_fields(
        &state,
        ActorInfo {
            user_id: "approval-notification-runtime".into(),
            session_id: delivery
                .instance_id
                .clone()
                .unwrap_or_else(|| "runtime-job".into()),
            ip_address: "127.0.0.1".into(),
        },
        ActionType::PermissionApply,
        TargetRef {
            tenant_id,
            project_id,
            resource_id: delivery.delivery_id.clone(),
        },
        "approval notification delivery attempt",
        AuditContextFields::builder()
            .field("delivery_id", delivery.delivery_id.clone())
            .field(
                "instance_id",
                delivery.instance_id.clone().unwrap_or_default(),
            )
            .field("channel", delivery.channel.clone())
            .field("recipient", delivery.notification.recipient.clone())
            .field("status", status.to_string())
            .field("attempt_count", attempt_count.to_string())
            .field("terminal_failure", (status == "failed").to_string())
            .field(
                "next_attempt_at",
                next_attempt_at
                    .map(|value| value.to_rfc3339())
                    .unwrap_or_default(),
            )
            .field("last_error", last_error.unwrap_or_default().to_string())
            .field(
                "notification_kind",
                notification_kind_label(&delivery.notification.kind),
            )
            .field(
                "step_id",
                delivery.notification.step_id.clone().unwrap_or_default(),
            )
            .build(),
        result,
        None,
    )
    .await
}

fn lifecycle_actor_for_trigger(trigger: GrantLifecycleTrigger) -> &'static str {
    match trigger {
        GrantLifecycleTrigger::HrSync => "hr-integration",
        GrantLifecycleTrigger::AuditAnomaly
        | GrantLifecycleTrigger::AuditCleared
        | GrantLifecycleTrigger::AuditConfirmedCompromise => "audit-runtime",
        _ => "permission-lifecycle-scheduler",
    }
}

fn parse_audit_lifecycle_trigger(action: &str) -> Option<GrantLifecycleTrigger> {
    match action.trim().to_ascii_lowercase().as_str() {
        "suspend" | "audit_anomaly" => Some(GrantLifecycleTrigger::AuditAnomaly),
        "resume" | "audit_cleared" => Some(GrantLifecycleTrigger::AuditCleared),
        "revoke" | "audit_confirmed_compromise" => {
            Some(GrantLifecycleTrigger::AuditConfirmedCompromise)
        }
        "expire" | "expiration_check" => Some(GrantLifecycleTrigger::SchedulerTick),
        _ => None,
    }
}

fn project_lifecycle_trigger(
    state: &Arc<ApiState>,
    grant: &PermissionGrant,
) -> Option<GrantLifecycleTrigger> {
    let projects = state.projects.lock().expect("projects");
    match projects.get(&grant.project_id).map(|project| project.state) {
        Some(ProjectState::Frozen) => Some(GrantLifecycleTrigger::ProjectFrozen),
        Some(ProjectState::Archived | ProjectState::Deleted) => {
            Some(GrantLifecycleTrigger::ProjectClosed)
        }
        _ => None,
    }
}

fn applicant_profile_from_state(
    state: &Arc<ApiState>,
    directory: &OrgDirectory,
    user_id: &str,
) -> ApplicantRuntimeProfile {
    applicant_profile_from_roles(directory, user_id, roles_for_user_id(state, user_id))
}

fn applicant_profile_from_roles(
    directory: &OrgDirectory,
    user_id: &str,
    roles: Vec<String>,
) -> ApplicantRuntimeProfile {
    let Some(user) = directory.get_user(user_id) else {
        return ApplicantRuntimeProfile::missing(user_id, roles);
    };
    ApplicantRuntimeProfile {
        user_id: user.user_id.clone(),
        department_id: Some(user.department_id.clone()),
        manager_id: user.manager_id.clone(),
        roles,
        employment: match user.status {
            EmploymentStatus::Active => EmploymentState::Active,
            EmploymentStatus::Departed => EmploymentState::Departed,
        },
    }
}

fn roles_for_user_id(state: &Arc<ApiState>, user_id: &str) -> Vec<String> {
    state
        .users
        .lock()
        .expect("users")
        .values()
        .find(|account| account.user_id == user_id)
        .map(|account| account.roles.iter().map(role_label).collect())
        .unwrap_or_default()
}

fn role_label(role: &Role) -> String {
    match role {
        Role::SystemAdmin => "system_admin",
        Role::ProjectAdmin => "project_admin",
        Role::DataOwner => "data_owner",
        Role::Analyst => "analyst",
        Role::Auditor => "auditor",
        Role::Approver => "approver",
    }
    .to_string()
}

fn tenant_id_for_project(state: &Arc<ApiState>, project_id: &str) -> String {
    state
        .projects
        .lock()
        .expect("projects")
        .get(project_id)
        .map(|project| project.tenant_id.as_str().to_string())
        .unwrap_or_else(|| "tenant-alpha".into())
}

fn lifecycle_transition_stats(
    transitions: &[GrantLifecycleTransition],
) -> LifecycleTransitionStats {
    let mut stats = LifecycleTransitionStats::default();
    for transition in transitions {
        match transition.to_status {
            GrantStatus::Revoked => stats.revoked += 1,
            GrantStatus::Suspended => stats.suspended += 1,
            GrantStatus::Active => stats.resumed += 1,
            GrantStatus::Expired => stats.expired += 1,
            _ => {}
        }
    }
    stats
}

fn lifecycle_transition_response(
    transition: &GrantLifecycleTransition,
) -> PermissionLifecycleTransitionResponse {
    PermissionLifecycleTransitionResponse {
        transition_id: transition.transition_id.clone(),
        grant_id: transition.grant_id.clone(),
        applicant_user_id: transition.applicant_user_id.clone(),
        project_id: transition.project_id.clone(),
        data_source_id: transition.data_source_id.clone(),
        from_status: grant_status_label(&transition.from_status).into(),
        to_status: grant_status_label(&transition.to_status).into(),
        trigger: transition.trigger.as_str().into(),
        reason: transition.reason.clone(),
        effective_at: transition.effective_at,
        source_event_id: transition.source_event_id.clone(),
    }
}

pub async fn permission_grants_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let Some(project_id) = request_context
        .project_id
        .as_ref()
        .map(|value| value.as_str())
    else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "missing project scope");
    };

    let grants = if let Some(persistence) = state.persistence.as_ref() {
        match load_grants_for_user(persistence, &session.claims.user_id, project_id).await {
            Ok(grants) => grants,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load permission grants",
                );
            }
        }
    } else {
        state
            .permissions
            .lock()
            .expect("permission registry")
            .list_grants(&session.claims.user_id, Some(project_id), None)
    };

    Json(PermissionGrantsResponse {
        grants: grants
            .into_iter()
            .map(|grant| PermissionGrantRecordResponse {
                grant_id: grant.grant_id,
                data_source_id: grant.data_source_id,
                status: grant_status_label(&grant.status).to_string(),
                fields: grant
                    .fields
                    .into_iter()
                    .filter(|field| !field.denied)
                    .map(|field| field.field_name)
                    .collect(),
                valid_until: grant.valid_until,
            })
            .collect(),
    })
    .into_response()
}

pub async fn approval_tasks_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    if !can_approve(&session.roles) {
        return json_error(StatusCode::FORBIDDEN, "approver role required");
    }

    let Some(project_id) = request_context
        .project_id
        .as_ref()
        .map(|value| value.as_str())
    else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "missing project scope");
    };
    let Some(persistence) = state.persistence.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "approval tasks require persistent runtime",
        );
    };

    match list_pending_tasks_for_approver(persistence, project_id, &session.claims.user_id).await {
        Ok(tasks) => Json(ApprovalTasksResponse { tasks }).into_response(),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to load approval tasks",
        ),
    }
}

pub async fn approval_callback_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<ApprovalCallbackRequest>,
) -> Response {
    if !can_approve(&session.roles) {
        return json_error(StatusCode::FORBIDDEN, "approver role required");
    }

    let Some(project_id) = request_context
        .project_id
        .as_ref()
        .map(|value| value.as_str())
    else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "missing project scope");
    };
    let Some(persistence) = state.persistence.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "approval callbacks require persistent runtime",
        );
    };

    let bundle = match load_approval_bundle(persistence, &payload.instance_id).await {
        Ok(Some(bundle)) => bundle,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "approval instance not found"),
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to load approval instance",
            );
        }
    };
    if bundle.application.project_id != project_id {
        return json_error(StatusCode::FORBIDDEN, "approval instance project mismatch");
    }

    let directory = match load_org_directory(persistence).await {
        Ok(directory) => directory,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to load org data"),
    };
    let mut notifier = QueueingNotificationSink::default();
    let mut instance = bundle.instance.clone();
    let approver_policy = approver_resolution_policy_from_state(&state);

    let action = payload.action.trim().to_ascii_lowercase();
    let operation = match action.as_str() {
        "approve" => ApprovalEngine::approve_with_policy(
            &mut instance,
            &bundle.flow,
            &bundle.request,
            &directory,
            &approver_policy,
            &session.claims.user_id,
            Utc::now(),
            &mut notifier,
        ),
        "reject" => ApprovalEngine::reject(&mut instance, &session.claims.user_id),
        "delegate" => ApprovalEngine::delegate_with_directory_and_policy(
            &mut instance,
            &bundle.request,
            &session.claims.user_id,
            payload.delegate_to.as_deref().unwrap_or_default(),
            &directory,
            &approver_policy,
            &mut notifier,
        ),
        _ => return json_error(StatusCode::BAD_REQUEST, "unsupported approval action"),
    };
    if operation.is_err() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "approval action could not be applied",
        );
    }

    let application_status = if instance.status == ApprovalStatus::Approved {
        let rule = match load_eligibility_rule_for_project(persistence, project_id).await {
            Ok(rule) => rule,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load eligibility rule",
                );
            }
        };
        let profile =
            applicant_profile_from_state(&state, &directory, &bundle.application.applicant_user_id);
        let decision = GrantLifecycleScheduler.evaluate_activation(&profile, &rule);
        if !decision.eligible {
            let updated_application = PermissionApplication {
                status: GrantStatus::Denied,
                ..bundle.application.clone()
            };
            if save_permission_application(
                persistence,
                &updated_application,
                &updated_application.merge_key(),
            )
            .await
            .is_err()
            {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to update permission application eligibility",
                );
            }
            state
                .permissions
                .lock()
                .expect("permission registry")
                .restore_application(updated_application.clone());
            append_permission_lifecycle_audit(
                state.clone(),
                &updated_application.project_id,
                &updated_application.application_id,
                "permission activation denied by HR-linked eligibility",
                AuditContextFields::builder()
                    .field(
                        "applicant_user_id",
                        updated_application.applicant_user_id.clone(),
                    )
                    .field("eligibility_reason", decision.reason)
                    .field("eligibility_rule_id", rule.rule_id)
                    .build(),
            )
            .await;
            notifier.push_notification(Notification::request_rejected(
                updated_application.applicant_user_id.clone(),
                updated_application.application_id.as_str(),
            ));
            GrantStatus::Denied
        } else {
            let org_binding = directory
                .get_user(&bundle.application.applicant_user_id)
                .map(|user| OrgBinding {
                    department_id: user.department_id.clone(),
                    manager_id: user.manager_id.clone(),
                })
                .unwrap_or(OrgBinding {
                    department_id: "dept-default".into(),
                    manager_id: None,
                });
            let grant = PermissionGrant::new(
                bundle.application.applicant_user_id.clone(),
                bundle.application.project_id.clone(),
                bundle.application.data_source_id.clone(),
                bundle
                    .application
                    .requested_fields
                    .iter()
                    .cloned()
                    .map(|field_name| FieldPermission {
                        field_name,
                        denied: false,
                    })
                    .collect(),
                Vec::new(),
                GrantLifecycle {
                    valid_from: Utc::now(),
                    valid_until: Utc::now() + chrono::Duration::hours(8),
                    org_binding,
                    status: GrantStatus::Active,
                },
            );
            let updated_application = PermissionApplication {
                status: GrantStatus::Active,
                ..bundle.application.clone()
            };
            if save_permission_grant(persistence, &grant, instance.instance_id.as_str())
                .await
                .is_err()
                || save_permission_application(
                    persistence,
                    &updated_application,
                    &updated_application.merge_key(),
                )
                .await
                .is_err()
            {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to activate permission grant",
                );
            }
            state
                .permissions
                .lock()
                .expect("permission registry")
                .activate_application_with_grant(
                    &updated_application.application_id,
                    grant,
                    Some(instance.instance_id.clone()),
                );
            notifier.push_notification(Notification::request_approved(
                updated_application.applicant_user_id.clone(),
                updated_application.application_id.as_str(),
            ));
            GrantStatus::Active
        }
    } else if instance.status == ApprovalStatus::Rejected {
        let updated_application = PermissionApplication {
            status: GrantStatus::Denied,
            ..bundle.application.clone()
        };
        if save_permission_application(
            persistence,
            &updated_application,
            &updated_application.merge_key(),
        )
        .await
        .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to update permission application",
            );
        }
        state
            .permissions
            .lock()
            .expect("permission registry")
            .restore_application(updated_application.clone());
        notifier.push_notification(Notification::request_rejected(
            updated_application.applicant_user_id.clone(),
            updated_application.application_id.as_str(),
        ));
        GrantStatus::Denied
    } else {
        bundle.application.status.clone()
    };

    if save_approval_action(
        persistence,
        &instance.instance_id,
        &session.claims.user_id,
        &action,
        payload.delegate_to.as_deref(),
    )
    .await
    .is_err()
        || save_approval_instance(
            persistence,
            &bundle.application,
            &bundle.flow,
            &bundle.request,
            &instance,
        )
        .await
        .is_err()
        || queue_notifications(
            persistence,
            Some(&instance.instance_id),
            &notifier.notifications,
        )
        .await
        .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist approval state",
        );
    }

    Json(ApprovalCallbackResponse {
        instance_id: instance.instance_id,
        status: approval_status_label(&instance.status).to_string(),
        application_status: grant_status_label(&application_status).to_string(),
    })
    .into_response()
}

pub async fn approver_resolution_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<ApproverResolutionRequest>,
) -> Response {
    if !can_approve(&session.roles) {
        return json_error(StatusCode::FORBIDDEN, "approver role required");
    }

    let Some(project_id) = request_context
        .project_id
        .as_ref()
        .map(|value| value.as_str())
    else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "missing project scope");
    };
    let Some(persistence) = state.persistence.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "approver resolution requires persistent runtime",
        );
    };
    let requested_user_id = payload.requested_user_id.trim();
    if requested_user_id.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "requested_user_id is required");
    }

    let directory = match load_org_directory(persistence).await {
        Ok(directory) => directory,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to load org data"),
    };
    let policy = approver_resolution_policy_from_state(&state);
    let route = if payload.reroute_unavailable {
        directory.reroute_unavailable_approver_with_policy(requested_user_id, &policy)
    } else {
        directory.resolve_effective_approver_with_policy(requested_user_id, &policy)
    };
    let route = match route {
        Ok(route) => route,
        Err(_) => return json_error(StatusCode::NOT_FOUND, "approver candidate not found"),
    };

    append_approver_resolution_audit(
        state.clone(),
        &session,
        project_id,
        &route,
        &policy,
        payload.reroute_unavailable,
    )
    .await;

    Json(approver_resolution_response(&route, &policy)).into_response()
}

pub async fn hr_event_handler(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(payload): Json<HrEventRequest>,
) -> Response {
    let token = headers
        .get("x-sdqp-hr-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if token != state.integrations.hr.token {
        return json_error(StatusCode::UNAUTHORIZED, "invalid hr integration token");
    }

    let Some(persistence) = state.persistence.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "hr events require persistent runtime",
        );
    };

    let source = match parse_sync_source(payload.source.as_str()) {
        Ok(source) => source,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "unsupported hr source"),
    };
    let event_type = match parse_hr_event_type(payload.event_type.as_str()) {
        Ok(event_type) => event_type,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "unsupported hr event type"),
    };
    let mut directory = match load_org_directory(persistence).await {
        Ok(directory) => directory,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to load org data"),
    };
    let approver_profile = match requested_approver_profile(&payload, &directory) {
        Ok(profile) => profile,
        Err(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid approver profile in hr event",
            );
        }
    };
    let event = HrEvent {
        event_id: payload.event_id.unwrap_or_else(|| Ulid::new().to_string()),
        user_id: payload.user_id,
        event_type,
        department_id: payload.department_id,
        manager_id: payload.manager_id,
        approver_profile,
        occurred_at: Utc::now(),
    };

    match insert_hr_event_if_new(persistence, &source, &event, None, None).await {
        Ok(false) => {
            return Json(HrEventResponse {
                processed: false,
                revoked_grants: 0,
                suspended_grants: 0,
                resumed_grants: 0,
                expired_grants: 0,
                lifecycle_transitions: Vec::new(),
            })
            .into_response();
        }
        Ok(true) => {}
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist hr event",
            );
        }
    }

    let commands = match directory.apply_event(event.clone()) {
        Ok(commands) => commands,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "hr event could not be applied"),
    };
    if let Some(user) = directory.get_user(&event.user_id)
        && upsert_org_user(persistence, &source, None, user)
            .await
            .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist org directory update",
        );
    }

    let mut transitions = match apply_hr_lifecycle_for_user(
        state.clone(),
        &directory,
        &event.user_id,
        None,
        Some(&event.event_id),
        Utc::now(),
    )
    .await
    {
        Ok(transitions) => transitions,
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist HR-linked permission lifecycle",
            );
        }
    };
    for command in commands {
        if command.user_id == event.user_id {
            continue;
        }
        match apply_hr_lifecycle_for_user(
            state.clone(),
            &directory,
            &command.user_id,
            command.project_id.as_deref(),
            Some(&event.event_id),
            Utc::now(),
        )
        .await
        {
            Ok(mut extra) => transitions.append(&mut extra),
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to persist HR-linked permission lifecycle",
                );
            }
        }
    }
    let stats = lifecycle_transition_stats(&transitions);

    Json(HrEventResponse {
        processed: true,
        revoked_grants: stats.revoked,
        suspended_grants: stats.suspended,
        resumed_grants: stats.resumed,
        expired_grants: stats.expired,
        lifecycle_transitions: transitions
            .iter()
            .map(lifecycle_transition_response)
            .collect(),
    })
    .into_response()
}

pub async fn feishu_snapshot_sync_handler(
    State(state): State<Arc<ApiState>>,
    _headers: HeaderMap,
) -> Response {
    let Some(persistence) = state.persistence.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "Feishu snapshot sync requires persistent runtime",
        );
    };
    let config = match feishu_provider_config(&state.integrations.hr.feishu) {
        Ok(config) => config,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, &message),
    };
    let checkpoint_before =
        match load_hr_provider_checkpoint(persistence, &config.provider_id).await {
            Ok(checkpoint) => checkpoint,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load Feishu checkpoint",
                );
            }
        };

    let page = match fetch_feishu_snapshot(&config).await {
        Ok(page) => page,
        Err(message) => {
            let checkpoint = append_feishu_runtime_audit(
                state.clone(),
                &config,
                ProviderRuntimeAudit {
                    operation: "snapshot",
                    checkpoint_before: checkpoint_before.event_cursor.as_deref(),
                    checkpoint_after: checkpoint_before.event_cursor.as_deref(),
                    snapshot_watermark: None,
                    synced_user_count: 0,
                    received_event_count: 0,
                    applied_event_count: 0,
                    result: ActionResult::Failure,
                    error: Some(&message),
                },
            )
            .await;
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": message,
                    "audit_checkpoint_id": checkpoint.checkpoint_id
                })),
            )
                .into_response();
        }
    };
    let snapshot_cursor_after = page
        .next_cursor
        .clone()
        .or(checkpoint_before.snapshot_cursor.clone());
    let users = page.into_org_users();
    for user in &users {
        if upsert_org_user(
            persistence,
            &SyncSource::Feishu,
            Some(&config.provider_id),
            user,
        )
        .await
        .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist Feishu snapshot user",
            );
        }
    }
    if save_feishu_provider_checkpoint(
        persistence,
        &config,
        checkpoint_before.event_cursor.as_deref(),
        snapshot_cursor_after.as_deref(),
        FeishuCheckpointOperation::Snapshot,
    )
    .await
    .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist Feishu snapshot checkpoint",
        );
    }

    let checkpoint = append_feishu_runtime_audit(
        state.clone(),
        &config,
        ProviderRuntimeAudit {
            operation: "snapshot",
            checkpoint_before: checkpoint_before.event_cursor.as_deref(),
            checkpoint_after: checkpoint_before.event_cursor.as_deref(),
            snapshot_watermark: None,
            synced_user_count: users.len(),
            received_event_count: 0,
            applied_event_count: 0,
            result: ActionResult::Success,
            error: None,
        },
    )
    .await;
    let provider_id = config.provider_id.clone();
    let auth_mode = config.auth.mode().to_string();

    Json(FeishuHrRuntimeResponse {
        provider_id,
        runtime_mode: "real_http_openapi".into(),
        auth_mode,
        operation: "snapshot".into(),
        checkpoint_before: checkpoint_before.event_cursor,
        checkpoint_after: None,
        snapshot_cursor_after,
        synced_user_count: users.len(),
        received_event_count: 0,
        applied_event_count: 0,
        skipped_event_count: 0,
        revoked_grants: 0,
        suspended_grants: 0,
        resumed_grants: 0,
        expired_grants: 0,
        lifecycle_transitions: Vec::new(),
        audit_checkpoint_id: checkpoint.checkpoint_id,
    })
    .into_response()
}

pub async fn feishu_event_poll_handler(State(state): State<Arc<ApiState>>) -> Response {
    let Some(persistence) = state.persistence.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "Feishu event polling requires persistent runtime",
        );
    };
    let config = match feishu_provider_config(&state.integrations.hr.feishu) {
        Ok(config) => config,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, &message),
    };
    let checkpoint_before =
        match load_hr_provider_checkpoint(persistence, &config.provider_id).await {
            Ok(checkpoint) => checkpoint,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load Feishu checkpoint",
                );
            }
        };
    let page = match fetch_feishu_events(&config, checkpoint_before.event_cursor.as_deref()).await {
        Ok(page) => page,
        Err(message) => {
            let checkpoint = append_feishu_runtime_audit(
                state.clone(),
                &config,
                ProviderRuntimeAudit {
                    operation: "event_poll",
                    checkpoint_before: checkpoint_before.event_cursor.as_deref(),
                    checkpoint_after: checkpoint_before.event_cursor.as_deref(),
                    snapshot_watermark: None,
                    synced_user_count: 0,
                    received_event_count: 0,
                    applied_event_count: 0,
                    result: ActionResult::Failure,
                    error: Some(&message),
                },
            )
            .await;
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": message,
                    "audit_checkpoint_id": checkpoint.checkpoint_id
                })),
            )
                .into_response();
        }
    };
    apply_feishu_event_page(
        state.clone(),
        persistence,
        config,
        checkpoint_before,
        page,
        FeishuCheckpointOperation::EventPoll,
        "event_poll",
    )
    .await
}

pub async fn feishu_webhook_handler(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(envelope): Json<FeishuWebhookEnvelope>,
) -> Response {
    let Some(persistence) = state.persistence.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "Feishu webhook ingestion requires persistent runtime",
        );
    };
    let config = match feishu_provider_config(&state.integrations.hr.feishu) {
        Ok(config) => config,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, &message),
    };
    if let Some(expected) = config.webhook_verification_token.as_deref()
        && !expected.trim().is_empty()
    {
        let received = headers
            .get("x-feishu-webhook-token")
            .or_else(|| headers.get("x-lark-webhook-token"))
            .and_then(|value| value.to_str().ok())
            .or(envelope.token.as_deref())
            .unwrap_or_default();
        if received != expected {
            return json_error(StatusCode::UNAUTHORIZED, "invalid Feishu webhook token");
        }
    }
    if let Some(challenge) = envelope.challenge.as_deref()
        && envelope.events.is_empty()
        && envelope.event.is_none()
    {
        return Json(json!({ "challenge": challenge })).into_response();
    }
    let checkpoint_before =
        match load_hr_provider_checkpoint(persistence, &config.provider_id).await {
            Ok(checkpoint) => checkpoint,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load Feishu checkpoint",
                );
            }
        };

    apply_feishu_event_page(
        state.clone(),
        persistence,
        config,
        checkpoint_before,
        envelope.into_event_page(),
        FeishuCheckpointOperation::Webhook,
        "webhook",
    )
    .await
}

#[derive(Debug, Clone, Copy)]
enum FeishuCheckpointOperation {
    Snapshot,
    EventPoll,
    Webhook,
}

impl FeishuCheckpointOperation {
    fn marks_snapshot(self) -> bool {
        matches!(self, Self::Snapshot)
    }

    fn marks_event_poll(self) -> bool {
        matches!(self, Self::EventPoll)
    }

    fn marks_webhook(self) -> bool {
        matches!(self, Self::Webhook)
    }
}

async fn apply_feishu_event_page(
    state: Arc<ApiState>,
    persistence: &ApiPersistence,
    config: FeishuProviderConfig,
    checkpoint_before: HrProviderCheckpoint,
    page: FeishuEventPage,
    operation: FeishuCheckpointOperation,
    operation_label: &'static str,
) -> Response {
    let provider_next_cursor = page.next_cursor.clone();
    let events = page.into_hr_events();
    let report = match process_feishu_events(
        state.clone(),
        persistence,
        &config.provider_id,
        events,
        provider_next_cursor.as_deref(),
    )
    .await
    {
        Ok(report) => report,
        Err(message) => {
            return json_error(StatusCode::BAD_REQUEST, &message);
        }
    };
    let checkpoint_after = provider_next_cursor
        .or(report.last_event_id.clone())
        .or(checkpoint_before.event_cursor.clone());

    if save_feishu_provider_checkpoint(
        persistence,
        &config,
        checkpoint_after.as_deref(),
        checkpoint_before.snapshot_cursor.as_deref(),
        operation,
    )
    .await
    .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist Feishu event checkpoint",
        );
    }

    let stats = lifecycle_transition_stats(&report.lifecycle_transitions);
    let checkpoint = append_feishu_runtime_audit(
        state,
        &config,
        ProviderRuntimeAudit {
            operation: operation_label,
            checkpoint_before: checkpoint_before.event_cursor.as_deref(),
            checkpoint_after: checkpoint_after.as_deref(),
            snapshot_watermark: None,
            synced_user_count: 0,
            received_event_count: report.received_event_count,
            applied_event_count: report.applied_event_count,
            result: ActionResult::Success,
            error: None,
        },
    )
    .await;
    let provider_id = config.provider_id.clone();
    let auth_mode = config.auth.mode().to_string();
    Json(FeishuHrRuntimeResponse {
        provider_id,
        runtime_mode: "real_http_openapi".into(),
        auth_mode,
        operation: operation_label.into(),
        checkpoint_before: checkpoint_before.event_cursor,
        checkpoint_after,
        snapshot_cursor_after: checkpoint_before.snapshot_cursor,
        synced_user_count: 0,
        received_event_count: report.received_event_count,
        applied_event_count: report.applied_event_count,
        skipped_event_count: report.skipped_event_count,
        revoked_grants: stats.revoked,
        suspended_grants: stats.suspended,
        resumed_grants: stats.resumed,
        expired_grants: stats.expired,
        lifecycle_transitions: report
            .lifecycle_transitions
            .iter()
            .map(lifecycle_transition_response)
            .collect(),
        audit_checkpoint_id: checkpoint.checkpoint_id,
    })
    .into_response()
}

async fn process_feishu_events(
    state: Arc<ApiState>,
    persistence: &ApiPersistence,
    provider_id: &str,
    events: Vec<HrEvent>,
    provider_cursor: Option<&str>,
) -> Result<HrEventProcessingReport, String> {
    let mut directory = load_org_directory(persistence)
        .await
        .map_err(|_| "failed to load org data".to_string())?;
    let received_event_count = events.len();
    let mut applied_event_count = 0;
    let mut skipped_event_count = 0;
    let mut last_event_id = None;
    let mut lifecycle_transitions = Vec::new();

    for event in events {
        last_event_id = Some(event.event_id.clone());
        let inserted = insert_hr_event_if_new(
            persistence,
            &SyncSource::Feishu,
            &event,
            Some(provider_id),
            provider_cursor,
        )
        .await
        .map_err(|_| "failed to persist Feishu event".to_string())?;
        if !inserted {
            skipped_event_count += 1;
            continue;
        }

        let commands = directory
            .apply_event(event.clone())
            .map_err(|_| "Feishu event could not be applied".to_string())?;
        if let Some(user) = directory.get_user(&event.user_id) {
            upsert_org_user(persistence, &SyncSource::Feishu, Some(provider_id), user)
                .await
                .map_err(|_| "failed to persist Feishu org directory update".to_string())?;
        }
        let mut transitions = apply_hr_lifecycle_for_user(
            state.clone(),
            &directory,
            &event.user_id,
            None,
            Some(&event.event_id),
            Utc::now(),
        )
        .await
        .map_err(|_| "failed to persist HR-linked permission lifecycle".to_string())?;
        for command in commands {
            if command.user_id == event.user_id {
                continue;
            }
            let mut extra = apply_hr_lifecycle_for_user(
                state.clone(),
                &directory,
                &command.user_id,
                command.project_id.as_deref(),
                Some(&event.event_id),
                Utc::now(),
            )
            .await
            .map_err(|_| "failed to persist HR-linked permission lifecycle".to_string())?;
            transitions.append(&mut extra);
        }
        lifecycle_transitions.append(&mut transitions);
        applied_event_count += 1;
    }

    Ok(HrEventProcessingReport {
        received_event_count,
        applied_event_count,
        skipped_event_count,
        last_event_id,
        lifecycle_transitions,
    })
}

fn feishu_provider_config(
    settings: &FeishuIntegrationSettings,
) -> Result<FeishuProviderConfig, String> {
    let auth = match settings.auth_mode.trim().to_ascii_lowercase().as_str() {
        "app_credentials" | "app_access" | "tenant_access_token_internal" => {
            FeishuProviderAuth::AppCredentials {
                token_url: settings.token_url.clone(),
                app_id: settings.app_id.clone(),
                app_secret: settings.app_secret.clone(),
            }
        }
        "tenant_access_token" | "bearer" | "bearer_token" => {
            FeishuProviderAuth::TenantAccessToken {
                token: settings.tenant_access_token.clone(),
            }
        }
        other => {
            return Err(format!("unsupported Feishu auth mode: {other}"));
        }
    };
    let config = FeishuProviderConfig {
        provider_id: settings.provider_id.clone(),
        tenant_key: settings.tenant_key.clone(),
        base_url: settings.base_url.clone(),
        auth,
        users_path: settings.users_path.clone(),
        events_path: settings.events_path.clone(),
        webhook_verification_token: (!settings.webhook_verification_token.trim().is_empty())
            .then(|| settings.webhook_verification_token.clone()),
        page_size: settings.page_size as usize,
        timeout_ms: settings.timeout_ms,
    };
    config
        .validate_real_runtime()
        .map_err(|error| error.to_string())?;
    Ok(config)
}

#[derive(Debug, Deserialize)]
struct FeishuTenantAccessTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    tenant_access_token: Option<String>,
}

async fn fetch_feishu_snapshot(
    config: &FeishuProviderConfig,
) -> Result<sdqp_hr_integration::FeishuSnapshotPage, String> {
    let client = feishu_http_client(config)?;
    let token = feishu_access_token(&client, config).await?;
    let mut url = feishu_endpoint_url(&config.base_url, &config.users_path)?;
    url.query_pairs_mut()
        .append_pair("tenant_key", &config.tenant_key)
        .append_pair("page_size", &config.page_size.to_string());
    let response = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|error| format!("Feishu snapshot request failed: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("Feishu snapshot request returned {status}"));
    }
    response
        .json::<FeishuSnapshotPayload>()
        .await
        .map(FeishuSnapshotPayload::into_page)
        .map_err(|error| format!("Feishu snapshot response was invalid: {error}"))
}

async fn fetch_feishu_events(
    config: &FeishuProviderConfig,
    cursor: Option<&str>,
) -> Result<FeishuEventPage, String> {
    let client = feishu_http_client(config)?;
    let token = feishu_access_token(&client, config).await?;
    let mut url = feishu_endpoint_url(&config.base_url, &config.events_path)?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("tenant_key", &config.tenant_key)
            .append_pair("page_size", &config.page_size.to_string());
        if let Some(cursor) = cursor.filter(|cursor| !cursor.trim().is_empty()) {
            query.append_pair("cursor", cursor);
        }
    }
    let response = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|error| format!("Feishu event poll request failed: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("Feishu event poll request returned {status}"));
    }
    response
        .json::<FeishuEventPayload>()
        .await
        .map(FeishuEventPayload::into_page)
        .map_err(|error| format!("Feishu event poll response was invalid: {error}"))
}

fn feishu_http_client(config: &FeishuProviderConfig) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .build()
        .map_err(|error| format!("failed to build Feishu HTTP client: {error}"))
}

async fn feishu_access_token(
    client: &reqwest::Client,
    config: &FeishuProviderConfig,
) -> Result<String, String> {
    match &config.auth {
        FeishuProviderAuth::TenantAccessToken { token } => Ok(token.clone()),
        FeishuProviderAuth::AppCredentials {
            token_url,
            app_id,
            app_secret,
        } => {
            let response = client
                .post(token_url)
                .json(&json!({
                    "app_id": app_id,
                    "app_secret": app_secret,
                }))
                .send()
                .await
                .map_err(|error| format!("Feishu tenant token request failed: {error}"))?;
            let status = response.status();
            if !status.is_success() {
                return Err(format!("Feishu tenant token request returned {status}"));
            }
            let token = response
                .json::<FeishuTenantAccessTokenResponse>()
                .await
                .map_err(|error| format!("Feishu tenant token response was invalid: {error}"))?;
            token
                .tenant_access_token
                .or(token.access_token)
                .filter(|token| !token.trim().is_empty())
                .ok_or_else(|| "Feishu token response did not include tenant_access_token".into())
        }
    }
}

fn feishu_endpoint_url(base_url: &str, path: &str) -> Result<reqwest::Url, String> {
    let raw = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    };
    reqwest::Url::parse(&raw).map_err(|error| format!("invalid Feishu endpoint URL: {error}"))
}

async fn save_feishu_provider_checkpoint(
    persistence: &ApiPersistence,
    config: &FeishuProviderConfig,
    event_cursor: Option<&str>,
    snapshot_cursor: Option<&str>,
    operation: FeishuCheckpointOperation,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO hr_sync_checkpoints (
            provider_id,
            source,
            event_cursor,
            snapshot_cursor,
            last_snapshot_at,
            last_event_poll_at,
            last_webhook_at,
            auth_mode,
            provider_base_url,
            updated_at
        )
        VALUES (
            $1,
            $2,
            $3,
            $4,
            CASE WHEN $5 THEN NOW() ELSE NULL END,
            CASE WHEN $6 THEN NOW() ELSE NULL END,
            CASE WHEN $7 THEN NOW() ELSE NULL END,
            $8,
            $9,
            NOW()
        )
        ON CONFLICT (provider_id) DO UPDATE SET
            source = EXCLUDED.source,
            event_cursor = EXCLUDED.event_cursor,
            snapshot_cursor = EXCLUDED.snapshot_cursor,
            last_snapshot_at = CASE
                WHEN $5 THEN NOW()
                ELSE hr_sync_checkpoints.last_snapshot_at
            END,
            last_event_poll_at = CASE
                WHEN $6 THEN NOW()
                ELSE hr_sync_checkpoints.last_event_poll_at
            END,
            last_webhook_at = CASE
                WHEN $7 THEN NOW()
                ELSE hr_sync_checkpoints.last_webhook_at
            END,
            auth_mode = EXCLUDED.auth_mode,
            provider_base_url = EXCLUDED.provider_base_url,
            updated_at = NOW()
        "#,
    )
    .bind(&config.provider_id)
    .bind(sync_source_label(&SyncSource::Feishu))
    .bind(event_cursor)
    .bind(snapshot_cursor)
    .bind(operation.marks_snapshot())
    .bind(operation.marks_event_poll())
    .bind(operation.marks_webhook())
    .bind(config.auth.mode())
    .bind(&config.base_url)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

struct ProviderRuntimeAudit<'a> {
    operation: &'a str,
    checkpoint_before: Option<&'a str>,
    checkpoint_after: Option<&'a str>,
    snapshot_watermark: Option<&'a str>,
    synced_user_count: usize,
    received_event_count: usize,
    applied_event_count: usize,
    result: ActionResult,
    error: Option<&'a str>,
}

async fn append_feishu_runtime_audit(
    state: Arc<ApiState>,
    config: &FeishuProviderConfig,
    audit: ProviderRuntimeAudit<'_>,
) -> sdqp_audit::AuditCheckpoint {
    let ProviderRuntimeAudit {
        operation,
        checkpoint_before,
        checkpoint_after,
        synced_user_count,
        received_event_count,
        applied_event_count,
        result,
        error,
        ..
    } = audit;
    let mut builder = AuditContextFields::builder()
        .field("provider", "feishu")
        .field("provider_id", config.provider_id.clone())
        .field("tenant_key", config.tenant_key.clone())
        .field("runtime_mode", "real_http_openapi")
        .field("auth_mode", config.auth.mode())
        .field("operation", operation)
        .field(
            "checkpoint_before",
            checkpoint_before.unwrap_or_default().to_string(),
        )
        .field(
            "checkpoint_after",
            checkpoint_after.unwrap_or_default().to_string(),
        )
        .field("synced_user_count", synced_user_count.to_string())
        .field("received_event_count", received_event_count.to_string())
        .field("applied_event_count", applied_event_count.to_string());
    if let Some(error) = error {
        builder = builder.field("error", error.to_string());
    }
    crate::record_audit_event_from_parts_with_fields(
        &state,
        ActorInfo {
            user_id: "feishu-hr-provider".into(),
            session_id: format!("feishu-{operation}"),
            ip_address: "127.0.0.1".into(),
        },
        ActionType::PermissionApply,
        TargetRef {
            tenant_id: "tenant-alpha".into(),
            project_id: None,
            resource_id: config.provider_id.clone(),
        },
        format!("feishu hr provider {operation}"),
        builder.build(),
        result,
        None,
    )
    .await
}

pub async fn ldap_snapshot_sync_handler(State(state): State<Arc<ApiState>>) -> Response {
    let Some(persistence) = state.persistence.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "LDAP snapshot sync requires persistent runtime",
        );
    };
    let config = match ldap_provider_config(&state.integrations.hr.ldap) {
        Ok(config) => config,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, &message),
    };
    let checkpoint_before =
        match load_hr_provider_checkpoint(persistence, &config.provider_id).await {
            Ok(checkpoint) => checkpoint,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load LDAP checkpoint",
                );
            }
        };

    let search_filter = config.snapshot_search_filter();
    let result = match run_ldap_directory_search(&config, search_filter).await {
        Ok(result) => result,
        Err(message) => {
            let checkpoint = append_ldap_runtime_audit(
                state.clone(),
                &config,
                ProviderRuntimeAudit {
                    operation: "snapshot",
                    checkpoint_before: checkpoint_before.event_cursor.as_deref(),
                    checkpoint_after: checkpoint_before.event_cursor.as_deref(),
                    snapshot_watermark: checkpoint_before.snapshot_cursor.as_deref(),
                    synced_user_count: 0,
                    received_event_count: 0,
                    applied_event_count: 0,
                    result: ActionResult::Failure,
                    error: Some(&message),
                },
            )
            .await;
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": message,
                    "audit_checkpoint_id": checkpoint.checkpoint_id
                })),
            )
                .into_response();
        }
    };
    let snapshot_cursor_after = result
        .next_watermark
        .clone()
        .or(checkpoint_before.snapshot_cursor.clone());
    let users = match result.into_org_users(&config.attribute_mapping) {
        Ok(users) => users,
        Err(error) => {
            return json_error(
                StatusCode::BAD_GATEWAY,
                &format!("LDAP snapshot mapping failed: {error}"),
            );
        }
    };
    for user in &users {
        if upsert_org_user(
            persistence,
            &SyncSource::Ldap,
            Some(&config.provider_id),
            user,
        )
        .await
        .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist LDAP snapshot user",
            );
        }
    }
    if save_ldap_provider_checkpoint(
        persistence,
        &config,
        checkpoint_before.event_cursor.as_deref(),
        snapshot_cursor_after.as_deref(),
        LdapCheckpointOperation::Snapshot,
    )
    .await
    .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist LDAP snapshot checkpoint",
        );
    }

    let checkpoint = append_ldap_runtime_audit(
        state.clone(),
        &config,
        ProviderRuntimeAudit {
            operation: "snapshot",
            checkpoint_before: checkpoint_before.event_cursor.as_deref(),
            checkpoint_after: checkpoint_before.event_cursor.as_deref(),
            snapshot_watermark: snapshot_cursor_after.as_deref(),
            synced_user_count: users.len(),
            received_event_count: 0,
            applied_event_count: 0,
            result: ActionResult::Success,
            error: None,
        },
    )
    .await;
    let estimated_page_count = estimated_page_count(users.len(), config.page_size);

    Json(LdapHrRuntimeResponse {
        provider_id: config.provider_id.clone(),
        runtime_mode: "real_ldap_directory_sync".into(),
        auth_mode: config.auth.mode().into(),
        tls_mode: config.tls_mode.as_str().into(),
        operation: "snapshot".into(),
        checkpoint_before: checkpoint_before.event_cursor,
        checkpoint_after: None,
        snapshot_cursor_after,
        page_size: config.page_size,
        estimated_page_count,
        synced_user_count: users.len(),
        received_event_count: 0,
        applied_event_count: 0,
        skipped_event_count: 0,
        revoked_grants: 0,
        suspended_grants: 0,
        resumed_grants: 0,
        expired_grants: 0,
        lifecycle_transitions: Vec::new(),
        audit_checkpoint_id: checkpoint.checkpoint_id,
    })
    .into_response()
}

pub async fn ldap_incremental_poll_handler(State(state): State<Arc<ApiState>>) -> Response {
    let Some(persistence) = state.persistence.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "LDAP incremental polling requires persistent runtime",
        );
    };
    let config = match ldap_provider_config(&state.integrations.hr.ldap) {
        Ok(config) => config,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, &message),
    };
    let checkpoint_before =
        match load_hr_provider_checkpoint(persistence, &config.provider_id).await {
            Ok(checkpoint) => checkpoint,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load LDAP checkpoint",
                );
            }
        };
    let search_filter = config.incremental_search_filter(
        checkpoint_before
            .event_cursor
            .as_deref()
            .or(checkpoint_before.snapshot_cursor.as_deref()),
    );
    let result = match run_ldap_directory_search(&config, search_filter).await {
        Ok(result) => result,
        Err(message) => {
            let checkpoint = append_ldap_runtime_audit(
                state.clone(),
                &config,
                ProviderRuntimeAudit {
                    operation: "incremental_poll",
                    checkpoint_before: checkpoint_before.event_cursor.as_deref(),
                    checkpoint_after: checkpoint_before.event_cursor.as_deref(),
                    snapshot_watermark: checkpoint_before.snapshot_cursor.as_deref(),
                    synced_user_count: 0,
                    received_event_count: 0,
                    applied_event_count: 0,
                    result: ActionResult::Failure,
                    error: Some(&message),
                },
            )
            .await;
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": message,
                    "audit_checkpoint_id": checkpoint.checkpoint_id
                })),
            )
                .into_response();
        }
    };
    let next_watermark = result
        .next_watermark
        .clone()
        .or(checkpoint_before.event_cursor.clone())
        .or(checkpoint_before.snapshot_cursor.clone());
    let users = match result.into_org_users(&config.attribute_mapping) {
        Ok(users) => users,
        Err(error) => {
            return json_error(
                StatusCode::BAD_GATEWAY,
                &format!("LDAP incremental mapping failed: {error}"),
            );
        }
    };
    let report = match process_ldap_directory_delta(
        state.clone(),
        persistence,
        &config.provider_id,
        users,
        next_watermark.as_deref(),
    )
    .await
    {
        Ok(report) => report,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, &message),
    };
    let checkpoint_after = next_watermark
        .or(report.last_event_id.clone())
        .or(checkpoint_before.event_cursor.clone());

    if save_ldap_provider_checkpoint(
        persistence,
        &config,
        checkpoint_after.as_deref(),
        checkpoint_before.snapshot_cursor.as_deref(),
        LdapCheckpointOperation::IncrementalPoll,
    )
    .await
    .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist LDAP incremental checkpoint",
        );
    }

    let stats = lifecycle_transition_stats(&report.lifecycle_transitions);
    let checkpoint = append_ldap_runtime_audit(
        state,
        &config,
        ProviderRuntimeAudit {
            operation: "incremental_poll",
            checkpoint_before: checkpoint_before.event_cursor.as_deref(),
            checkpoint_after: checkpoint_after.as_deref(),
            snapshot_watermark: checkpoint_before.snapshot_cursor.as_deref(),
            synced_user_count: 0,
            received_event_count: report.received_event_count,
            applied_event_count: report.applied_event_count,
            result: ActionResult::Success,
            error: None,
        },
    )
    .await;
    Json(LdapHrRuntimeResponse {
        provider_id: config.provider_id.clone(),
        runtime_mode: "real_ldap_directory_sync".into(),
        auth_mode: config.auth.mode().into(),
        tls_mode: config.tls_mode.as_str().into(),
        operation: "incremental_poll".into(),
        checkpoint_before: checkpoint_before.event_cursor,
        checkpoint_after,
        snapshot_cursor_after: checkpoint_before.snapshot_cursor,
        page_size: config.page_size,
        estimated_page_count: estimated_page_count(report.received_event_count, config.page_size),
        synced_user_count: 0,
        received_event_count: report.received_event_count,
        applied_event_count: report.applied_event_count,
        skipped_event_count: report.skipped_event_count,
        revoked_grants: stats.revoked,
        suspended_grants: stats.suspended,
        resumed_grants: stats.resumed,
        expired_grants: stats.expired,
        lifecycle_transitions: report
            .lifecycle_transitions
            .iter()
            .map(lifecycle_transition_response)
            .collect(),
        audit_checkpoint_id: checkpoint.checkpoint_id,
    })
    .into_response()
}

#[derive(Debug, Clone, Copy)]
enum LdapCheckpointOperation {
    Snapshot,
    IncrementalPoll,
}

impl LdapCheckpointOperation {
    fn marks_snapshot(self) -> bool {
        matches!(self, Self::Snapshot)
    }

    fn marks_event_poll(self) -> bool {
        matches!(self, Self::IncrementalPoll)
    }
}

async fn process_ldap_directory_delta(
    state: Arc<ApiState>,
    persistence: &ApiPersistence,
    provider_id: &str,
    users: Vec<OrgUser>,
    provider_cursor: Option<&str>,
) -> Result<HrEventProcessingReport, String> {
    let mut directory = load_org_directory(persistence)
        .await
        .map_err(|_| "failed to load org data".to_string())?;
    let received_event_count = users.len();
    let mut applied_event_count = 0;
    let mut skipped_event_count = 0;
    let mut last_event_id = None;
    let mut lifecycle_transitions = Vec::new();

    for user in users {
        let event = ldap_delta_event(&directory, &user);
        upsert_org_user(persistence, &SyncSource::Ldap, Some(provider_id), &user)
            .await
            .map_err(|_| "failed to persist LDAP org directory update".to_string())?;
        let Some(event) = event else {
            skipped_event_count += 1;
            directory.sync_snapshot(SyncSource::Ldap, vec![user]);
            continue;
        };
        last_event_id = Some(event.event_id.clone());
        let inserted = insert_hr_event_if_new(
            persistence,
            &SyncSource::Ldap,
            &event,
            Some(provider_id),
            provider_cursor,
        )
        .await
        .map_err(|_| "failed to persist LDAP directory event".to_string())?;
        if !inserted {
            skipped_event_count += 1;
            continue;
        }

        let commands = directory
            .apply_event(event.clone())
            .map_err(|_| "LDAP directory event could not be applied".to_string())?;
        if let Some(updated) = directory.get_user(&event.user_id) {
            upsert_org_user(persistence, &SyncSource::Ldap, Some(provider_id), updated)
                .await
                .map_err(|_| "failed to persist LDAP applied directory update".to_string())?;
        }
        let mut transitions = apply_hr_lifecycle_for_user(
            state.clone(),
            &directory,
            &event.user_id,
            None,
            Some(&event.event_id),
            Utc::now(),
        )
        .await
        .map_err(|_| "failed to persist HR-linked permission lifecycle".to_string())?;
        for command in commands {
            if command.user_id == event.user_id {
                continue;
            }
            let mut extra = apply_hr_lifecycle_for_user(
                state.clone(),
                &directory,
                &command.user_id,
                command.project_id.as_deref(),
                Some(&event.event_id),
                Utc::now(),
            )
            .await
            .map_err(|_| "failed to persist HR-linked permission lifecycle".to_string())?;
            transitions.append(&mut extra);
        }
        lifecycle_transitions.append(&mut transitions);
        applied_event_count += 1;
    }

    Ok(HrEventProcessingReport {
        received_event_count,
        applied_event_count,
        skipped_event_count,
        last_event_id,
        lifecycle_transitions,
    })
}

fn ldap_delta_event(directory: &OrgDirectory, user: &OrgUser) -> Option<HrEvent> {
    let existing = directory.get_user(&user.user_id);
    let event_type = match existing {
        None => HrEventType::Onboard,
        Some(existing)
            if existing.status != user.status && user.status == EmploymentStatus::Departed =>
        {
            HrEventType::Departure
        }
        Some(existing) if existing.department_id != user.department_id => HrEventType::Transfer,
        Some(existing) if existing.manager_id != user.manager_id => HrEventType::ManagerChange,
        Some(existing) if existing.status != user.status => HrEventType::Transfer,
        Some(_) => return None,
    };
    Some(HrEvent {
        event_id: format!("ldap-{}-{}", user.user_id, Ulid::new()),
        user_id: user.user_id.clone(),
        event_type,
        department_id: Some(user.department_id.clone()),
        manager_id: user.manager_id.clone(),
        approver_profile: user.approver_profile.clone(),
        occurred_at: Utc::now(),
    })
}

fn ldap_provider_config(settings: &LdapIntegrationSettings) -> Result<LdapProviderConfig, String> {
    let auth = match settings.auth_mode.trim().to_ascii_lowercase().as_str() {
        "anonymous" | "none" => LdapProviderAuth::Anonymous,
        "simple" | "simple_bind" | "service_account" => LdapProviderAuth::SimpleBind {
            bind_dn: settings.bind_dn.clone(),
            bind_password: settings.bind_password.clone(),
        },
        other => return Err(format!("unsupported LDAP auth mode: {other}")),
    };
    let tls_mode = match settings.tls_mode.trim().to_ascii_lowercase().as_str() {
        "plain" | "none" => LdapTlsMode::Plain,
        "starttls" | "start_tls" => LdapTlsMode::StartTls,
        "ldaps" | "tls" => LdapTlsMode::Ldaps,
        other => return Err(format!("unsupported LDAP TLS mode: {other}")),
    };
    let config = LdapProviderConfig {
        provider_id: settings.provider_id.clone(),
        url: settings.url.clone(),
        auth,
        tls_mode,
        base_dn: settings.base_dn.clone(),
        search_filter: settings.search_filter.clone(),
        search_scope: settings.search_scope.clone(),
        page_size: settings.page_size as usize,
        timeout_ms: settings.timeout_ms,
        ldapsearch_binary: settings.ldapsearch_binary.clone(),
        ca_cert_path: (!settings.ca_cert_path.trim().is_empty())
            .then(|| settings.ca_cert_path.clone()),
        tls_require_valid_cert: settings.tls_require_valid_cert,
        attribute_mapping: LdapAttributeMapping {
            user_id: settings.user_id_attribute.clone(),
            department_id: settings.department_attribute.clone(),
            manager_id: settings.manager_attribute.clone(),
            status: settings.status_attribute.clone(),
            changed_since: settings.changed_since_attribute.clone(),
            active_status_values: settings.active_status_values.clone(),
            departed_status_values: settings.departed_status_values.clone(),
        },
    };
    config
        .validate_real_runtime()
        .map_err(|error| error.to_string())?;
    Ok(config)
}

async fn run_ldap_directory_search(
    config: &LdapProviderConfig,
    search_filter: String,
) -> Result<LdapDirectorySearchResult, String> {
    let config = config.clone();
    tokio::task::spawn_blocking(move || run_ldap_directory_search_blocking(&config, &search_filter))
        .await
        .map_err(|error| format!("LDAP search task failed: {error}"))?
}

fn run_ldap_directory_search_blocking(
    config: &LdapProviderConfig,
    search_filter: &str,
) -> Result<LdapDirectorySearchResult, String> {
    let mut command = Command::new(&config.ldapsearch_binary);
    command
        .arg("-LLL")
        .arg("-x")
        .arg("-H")
        .arg(&config.url)
        .arg("-b")
        .arg(&config.base_dn)
        .arg("-s")
        .arg(&config.search_scope)
        .arg("-E")
        .arg(format!("pr={}/noprompt", config.page_size))
        .arg("-o")
        .arg(format!("nettimeout={}", (config.timeout_ms / 1_000).max(1)));
    match config.tls_mode {
        LdapTlsMode::Plain | LdapTlsMode::Ldaps => {}
        LdapTlsMode::StartTls => {
            command.arg("-ZZ");
        }
    }
    if let Some(ca_cert_path) = config.ca_cert_path.as_deref() {
        command.env("LDAPTLS_CACERT", ca_cert_path);
    }
    command.env(
        "LDAPTLS_REQCERT",
        if config.tls_require_valid_cert {
            "demand"
        } else {
            "never"
        },
    );
    let password_file = match &config.auth {
        LdapProviderAuth::Anonymous => None,
        LdapProviderAuth::SimpleBind {
            bind_dn,
            bind_password,
        } => {
            let path = std::env::temp_dir().join(format!("sdqp-ldap-bind-{}.secret", Ulid::new()));
            let mut file = fs::File::create(&path)
                .map_err(|error| format!("failed to create LDAP bind password file: {error}"))?;
            file.write_all(bind_password.as_bytes())
                .map_err(|error| format!("failed to write LDAP bind password file: {error}"))?;
            command.arg("-D").arg(bind_dn).arg("-y").arg(&path);
            Some(path)
        }
    };
    command.arg(search_filter);
    for attribute in config.requested_attributes() {
        command.arg(attribute);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to start ldapsearch runtime: {error}"))?;
    let started = Instant::now();
    let timeout = Duration::from_millis(config.timeout_ms);
    let output = loop {
        if child
            .try_wait()
            .map_err(|error| format!("failed to poll ldapsearch runtime: {error}"))?
            .is_some()
        {
            break child
                .wait_with_output()
                .map_err(|error| format!("failed to collect ldapsearch output: {error}"))?;
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            let output = child.wait_with_output().map_err(|error| {
                format!("failed to collect timed out ldapsearch output: {error}")
            })?;
            if let Some(path) = password_file.as_ref() {
                let _ = fs::remove_file(path);
            }
            return Err(format!(
                "ldapsearch runtime timed out after {} ms",
                config.timeout_ms
            )
            .tap_output(output));
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    if let Some(path) = password_file.as_ref() {
        let _ = fs::remove_file(path);
    }
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "ldapsearch runtime returned {}: {}",
            output.status,
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    LdapDirectorySearchResult::from_ldif(&stdout, &config.attribute_mapping)
        .map_err(|error| error.to_string())
}

trait LdapTimeoutOutput {
    fn tap_output(self, output: std::process::Output) -> String;
}

impl LdapTimeoutOutput for String {
    fn tap_output(self, output: std::process::Output) -> String {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.trim().is_empty() {
            self
        } else {
            format!("{self}: {}", stderr.trim())
        }
    }
}

async fn save_ldap_provider_checkpoint(
    persistence: &ApiPersistence,
    config: &LdapProviderConfig,
    event_cursor: Option<&str>,
    snapshot_cursor: Option<&str>,
    operation: LdapCheckpointOperation,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO hr_sync_checkpoints (
            provider_id,
            source,
            event_cursor,
            snapshot_cursor,
            last_snapshot_at,
            last_event_poll_at,
            last_webhook_at,
            auth_mode,
            provider_base_url,
            updated_at
        )
        VALUES (
            $1,
            $2,
            $3,
            $4,
            CASE WHEN $5 THEN NOW() ELSE NULL END,
            CASE WHEN $6 THEN NOW() ELSE NULL END,
            NULL,
            $7,
            $8,
            NOW()
        )
        ON CONFLICT (provider_id) DO UPDATE SET
            source = EXCLUDED.source,
            event_cursor = EXCLUDED.event_cursor,
            snapshot_cursor = EXCLUDED.snapshot_cursor,
            last_snapshot_at = CASE
                WHEN $5 THEN NOW()
                ELSE hr_sync_checkpoints.last_snapshot_at
            END,
            last_event_poll_at = CASE
                WHEN $6 THEN NOW()
                ELSE hr_sync_checkpoints.last_event_poll_at
            END,
            auth_mode = EXCLUDED.auth_mode,
            provider_base_url = EXCLUDED.provider_base_url,
            updated_at = NOW()
        "#,
    )
    .bind(&config.provider_id)
    .bind(sync_source_label(&SyncSource::Ldap))
    .bind(event_cursor)
    .bind(snapshot_cursor)
    .bind(operation.marks_snapshot())
    .bind(operation.marks_event_poll())
    .bind(config.auth.mode())
    .bind(&config.url)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

async fn append_ldap_runtime_audit(
    state: Arc<ApiState>,
    config: &LdapProviderConfig,
    audit: ProviderRuntimeAudit<'_>,
) -> sdqp_audit::AuditCheckpoint {
    let ProviderRuntimeAudit {
        operation,
        checkpoint_before,
        checkpoint_after,
        snapshot_watermark,
        synced_user_count,
        received_event_count,
        applied_event_count,
        result,
        error,
    } = audit;
    let mut builder = AuditContextFields::builder()
        .field("provider", "ldap")
        .field("provider_id", config.provider_id.clone())
        .field("runtime_mode", "real_ldap_directory_sync")
        .field("auth_mode", config.auth.mode())
        .field("tls_mode", config.tls_mode.as_str())
        .field("base_dn", config.base_dn.clone())
        .field("search_scope", config.search_scope.clone())
        .field("search_filter", config.search_filter.clone())
        .field("page_size", config.page_size.to_string())
        .field(
            "changed_since_attribute",
            config.attribute_mapping.changed_since.clone(),
        )
        .field("operation", operation)
        .field(
            "checkpoint_before",
            checkpoint_before.unwrap_or_default().to_string(),
        )
        .field(
            "checkpoint_after",
            checkpoint_after.unwrap_or_default().to_string(),
        )
        .field(
            "snapshot_watermark",
            snapshot_watermark.unwrap_or_default().to_string(),
        )
        .field("synced_user_count", synced_user_count.to_string())
        .field("received_event_count", received_event_count.to_string())
        .field("applied_event_count", applied_event_count.to_string())
        .field("webhook_supported", "false");
    if let Some(error) = error {
        builder = builder.field("error", error.to_string());
    }
    crate::record_audit_event_from_parts_with_fields(
        &state,
        ActorInfo {
            user_id: "ldap-hr-provider".into(),
            session_id: format!("ldap-{operation}"),
            ip_address: "127.0.0.1".into(),
        },
        ActionType::PermissionApply,
        TargetRef {
            tenant_id: "tenant-alpha".into(),
            project_id: None,
            resource_id: config.provider_id.clone(),
        },
        format!("ldap hr provider {operation}"),
        builder.build(),
        result,
        None,
    )
    .await
}

fn estimated_page_count(total: usize, page_size: usize) -> usize {
    if total == 0 {
        0
    } else {
        let page_size = page_size.max(1);
        total.div_ceil(page_size)
    }
}

pub async fn workday_snapshot_sync_handler(
    State(state): State<Arc<ApiState>>,
    _headers: HeaderMap,
) -> Response {
    let Some(persistence) = state.persistence.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "workday snapshot sync requires persistent runtime",
        );
    };
    let config = match workday_provider_config(&state.integrations.hr.workday) {
        Ok(config) => config,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, &message),
    };
    let checkpoint_before =
        match load_hr_provider_checkpoint(persistence, &config.provider_id).await {
            Ok(checkpoint) => checkpoint,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load Workday checkpoint",
                );
            }
        };

    let page = match fetch_workday_snapshot(&config).await {
        Ok(page) => page,
        Err(message) => {
            let checkpoint = append_workday_runtime_audit(
                state.clone(),
                &config,
                ProviderRuntimeAudit {
                    operation: "snapshot",
                    checkpoint_before: checkpoint_before.event_cursor.as_deref(),
                    checkpoint_after: checkpoint_before.event_cursor.as_deref(),
                    snapshot_watermark: None,
                    synced_user_count: 0,
                    received_event_count: 0,
                    applied_event_count: 0,
                    result: ActionResult::Failure,
                    error: Some(&message),
                },
            )
            .await;
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": message,
                    "audit_checkpoint_id": checkpoint.checkpoint_id
                })),
            )
                .into_response();
        }
    };
    let snapshot_cursor_after = page
        .next_cursor
        .clone()
        .or(checkpoint_before.snapshot_cursor.clone());
    let users = page.into_org_users();
    for user in &users {
        if upsert_org_user(
            persistence,
            &SyncSource::Workday,
            Some(&config.provider_id),
            user,
        )
        .await
        .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist Workday snapshot user",
            );
        }
    }
    if save_hr_provider_checkpoint(
        persistence,
        &config,
        checkpoint_before.event_cursor.as_deref(),
        snapshot_cursor_after.as_deref(),
        WorkdayCheckpointOperation::Snapshot,
    )
    .await
    .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist Workday snapshot checkpoint",
        );
    }

    let checkpoint = append_workday_runtime_audit(
        state.clone(),
        &config,
        ProviderRuntimeAudit {
            operation: "snapshot",
            checkpoint_before: checkpoint_before.event_cursor.as_deref(),
            checkpoint_after: checkpoint_before.event_cursor.as_deref(),
            snapshot_watermark: None,
            synced_user_count: users.len(),
            received_event_count: 0,
            applied_event_count: 0,
            result: ActionResult::Success,
            error: None,
        },
    )
    .await;
    let provider_id = config.provider_id.clone();
    let auth_mode = config.auth.mode().to_string();

    Json(WorkdayHrRuntimeResponse {
        provider_id,
        runtime_mode: "real_http".into(),
        auth_mode,
        operation: "snapshot".into(),
        checkpoint_before: checkpoint_before.event_cursor,
        checkpoint_after: None,
        snapshot_cursor_after,
        synced_user_count: users.len(),
        received_event_count: 0,
        applied_event_count: 0,
        skipped_event_count: 0,
        revoked_grants: 0,
        suspended_grants: 0,
        resumed_grants: 0,
        expired_grants: 0,
        lifecycle_transitions: Vec::new(),
        audit_checkpoint_id: checkpoint.checkpoint_id,
    })
    .into_response()
}

pub async fn workday_event_poll_handler(State(state): State<Arc<ApiState>>) -> Response {
    let Some(persistence) = state.persistence.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "workday event polling requires persistent runtime",
        );
    };
    let config = match workday_provider_config(&state.integrations.hr.workday) {
        Ok(config) => config,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, &message),
    };
    let checkpoint_before =
        match load_hr_provider_checkpoint(persistence, &config.provider_id).await {
            Ok(checkpoint) => checkpoint,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load Workday checkpoint",
                );
            }
        };
    let page = match fetch_workday_events(&config, checkpoint_before.event_cursor.as_deref()).await
    {
        Ok(page) => page,
        Err(message) => {
            let checkpoint = append_workday_runtime_audit(
                state.clone(),
                &config,
                ProviderRuntimeAudit {
                    operation: "event_poll",
                    checkpoint_before: checkpoint_before.event_cursor.as_deref(),
                    checkpoint_after: checkpoint_before.event_cursor.as_deref(),
                    snapshot_watermark: None,
                    synced_user_count: 0,
                    received_event_count: 0,
                    applied_event_count: 0,
                    result: ActionResult::Failure,
                    error: Some(&message),
                },
            )
            .await;
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": message,
                    "audit_checkpoint_id": checkpoint.checkpoint_id
                })),
            )
                .into_response();
        }
    };
    apply_workday_event_page(
        state.clone(),
        persistence,
        config,
        checkpoint_before,
        page,
        WorkdayCheckpointOperation::EventPoll,
        "event_poll",
    )
    .await
}

pub async fn workday_webhook_handler(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(envelope): Json<WorkdayWebhookEnvelope>,
) -> Response {
    let Some(persistence) = state.persistence.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "workday webhook ingestion requires persistent runtime",
        );
    };
    let config = match workday_provider_config(&state.integrations.hr.workday) {
        Ok(config) => config,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, &message),
    };
    if let Some(expected) = config.webhook_secret.as_deref()
        && !expected.trim().is_empty()
    {
        let received = headers
            .get("x-workday-webhook-secret")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if received != expected {
            return json_error(StatusCode::UNAUTHORIZED, "invalid Workday webhook secret");
        }
    }
    let checkpoint_before =
        match load_hr_provider_checkpoint(persistence, &config.provider_id).await {
            Ok(checkpoint) => checkpoint,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load Workday checkpoint",
                );
            }
        };

    apply_workday_event_page(
        state.clone(),
        persistence,
        config,
        checkpoint_before,
        envelope.into_event_page(),
        WorkdayCheckpointOperation::Webhook,
        "webhook",
    )
    .await
}

#[derive(Debug, Clone, Copy)]
enum WorkdayCheckpointOperation {
    Snapshot,
    EventPoll,
    Webhook,
}

impl WorkdayCheckpointOperation {
    fn marks_snapshot(self) -> bool {
        matches!(self, Self::Snapshot)
    }

    fn marks_event_poll(self) -> bool {
        matches!(self, Self::EventPoll)
    }

    fn marks_webhook(self) -> bool {
        matches!(self, Self::Webhook)
    }
}

async fn apply_workday_event_page(
    state: Arc<ApiState>,
    persistence: &ApiPersistence,
    config: WorkdayProviderConfig,
    checkpoint_before: HrProviderCheckpoint,
    page: WorkdayEventPage,
    operation: WorkdayCheckpointOperation,
    operation_label: &'static str,
) -> Response {
    let provider_next_cursor = page.next_cursor.clone();
    let events = page.into_hr_events();
    let report = match process_workday_events(
        state.clone(),
        persistence,
        &config.provider_id,
        events,
        provider_next_cursor.as_deref(),
    )
    .await
    {
        Ok(report) => report,
        Err(message) => {
            return json_error(StatusCode::BAD_REQUEST, &message);
        }
    };
    let checkpoint_after = provider_next_cursor
        .or(report.last_event_id.clone())
        .or(checkpoint_before.event_cursor.clone());

    if save_hr_provider_checkpoint(
        persistence,
        &config,
        checkpoint_after.as_deref(),
        checkpoint_before.snapshot_cursor.as_deref(),
        operation,
    )
    .await
    .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist Workday event checkpoint",
        );
    }

    let stats = lifecycle_transition_stats(&report.lifecycle_transitions);
    let checkpoint = append_workday_runtime_audit(
        state,
        &config,
        ProviderRuntimeAudit {
            operation: operation_label,
            checkpoint_before: checkpoint_before.event_cursor.as_deref(),
            checkpoint_after: checkpoint_after.as_deref(),
            snapshot_watermark: None,
            synced_user_count: 0,
            received_event_count: report.received_event_count,
            applied_event_count: report.applied_event_count,
            result: ActionResult::Success,
            error: None,
        },
    )
    .await;
    let provider_id = config.provider_id.clone();
    let auth_mode = config.auth.mode().to_string();
    Json(WorkdayHrRuntimeResponse {
        provider_id,
        runtime_mode: "real_http".into(),
        auth_mode,
        operation: operation_label.into(),
        checkpoint_before: checkpoint_before.event_cursor,
        checkpoint_after,
        snapshot_cursor_after: checkpoint_before.snapshot_cursor,
        synced_user_count: 0,
        received_event_count: report.received_event_count,
        applied_event_count: report.applied_event_count,
        skipped_event_count: report.skipped_event_count,
        revoked_grants: stats.revoked,
        suspended_grants: stats.suspended,
        resumed_grants: stats.resumed,
        expired_grants: stats.expired,
        lifecycle_transitions: report
            .lifecycle_transitions
            .iter()
            .map(lifecycle_transition_response)
            .collect(),
        audit_checkpoint_id: checkpoint.checkpoint_id,
    })
    .into_response()
}

async fn process_workday_events(
    state: Arc<ApiState>,
    persistence: &ApiPersistence,
    provider_id: &str,
    events: Vec<HrEvent>,
    provider_cursor: Option<&str>,
) -> Result<HrEventProcessingReport, String> {
    let mut directory = load_org_directory(persistence)
        .await
        .map_err(|_| "failed to load org data".to_string())?;
    let received_event_count = events.len();
    let mut applied_event_count = 0;
    let mut skipped_event_count = 0;
    let mut last_event_id = None;
    let mut lifecycle_transitions = Vec::new();

    for event in events {
        last_event_id = Some(event.event_id.clone());
        let inserted = insert_hr_event_if_new(
            persistence,
            &SyncSource::Workday,
            &event,
            Some(provider_id),
            provider_cursor,
        )
        .await
        .map_err(|_| "failed to persist Workday event".to_string())?;
        if !inserted {
            skipped_event_count += 1;
            continue;
        }

        let commands = directory
            .apply_event(event.clone())
            .map_err(|_| "Workday event could not be applied".to_string())?;
        if let Some(user) = directory.get_user(&event.user_id) {
            upsert_org_user(persistence, &SyncSource::Workday, Some(provider_id), user)
                .await
                .map_err(|_| "failed to persist Workday org directory update".to_string())?;
        }
        let mut transitions = apply_hr_lifecycle_for_user(
            state.clone(),
            &directory,
            &event.user_id,
            None,
            Some(&event.event_id),
            Utc::now(),
        )
        .await
        .map_err(|_| "failed to persist HR-linked permission lifecycle".to_string())?;
        for command in commands {
            if command.user_id == event.user_id {
                continue;
            }
            let mut extra = apply_hr_lifecycle_for_user(
                state.clone(),
                &directory,
                &command.user_id,
                command.project_id.as_deref(),
                Some(&event.event_id),
                Utc::now(),
            )
            .await
            .map_err(|_| "failed to persist HR-linked permission lifecycle".to_string())?;
            transitions.append(&mut extra);
        }
        lifecycle_transitions.append(&mut transitions);
        applied_event_count += 1;
    }

    Ok(HrEventProcessingReport {
        received_event_count,
        applied_event_count,
        skipped_event_count,
        last_event_id,
        lifecycle_transitions,
    })
}

fn workday_provider_config(
    settings: &WorkdayIntegrationSettings,
) -> Result<WorkdayProviderConfig, String> {
    let auth = match settings.auth_mode.trim().to_ascii_lowercase().as_str() {
        "oauth" | "oauth_client_credentials" | "client_credentials" => {
            WorkdayProviderAuth::OAuthClientCredentials {
                token_url: settings.token_url.clone(),
                client_id: settings.client_id.clone(),
                client_secret: settings.client_secret.clone(),
                scope: (!settings.scope.trim().is_empty()).then(|| settings.scope.clone()),
            }
        }
        "bearer" | "bearer_token" => WorkdayProviderAuth::BearerToken {
            token: settings.bearer_token.clone(),
        },
        other => {
            return Err(format!("unsupported Workday auth mode: {other}"));
        }
    };
    let config = WorkdayProviderConfig {
        provider_id: settings.provider_id.clone(),
        tenant: settings.tenant.clone(),
        base_url: settings.base_url.clone(),
        auth,
        workers_path: settings.snapshot_path.clone(),
        events_path: settings.events_path.clone(),
        webhook_secret: (!settings.webhook_secret.trim().is_empty())
            .then(|| settings.webhook_secret.clone()),
        page_size: settings.page_size as usize,
        timeout_ms: settings.timeout_ms,
    };
    config
        .validate_real_runtime()
        .map_err(|error| error.to_string())?;
    Ok(config)
}

#[derive(Debug, Deserialize)]
struct WorkdayOAuthTokenResponse {
    access_token: String,
}

async fn fetch_workday_snapshot(
    config: &WorkdayProviderConfig,
) -> Result<WorkdaySnapshotPage, String> {
    let client = workday_http_client(config)?;
    let token = workday_access_token(&client, config).await?;
    let mut url = workday_endpoint_url(&config.base_url, &config.workers_path)?;
    url.query_pairs_mut()
        .append_pair("tenant", &config.tenant)
        .append_pair("count", &config.page_size.to_string());
    let response = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|error| format!("Workday snapshot request failed: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("Workday snapshot request returned {status}"));
    }
    response
        .json::<WorkdaySnapshotPage>()
        .await
        .map_err(|error| format!("Workday snapshot response was invalid: {error}"))
}

async fn fetch_workday_events(
    config: &WorkdayProviderConfig,
    cursor: Option<&str>,
) -> Result<WorkdayEventPage, String> {
    let client = workday_http_client(config)?;
    let token = workday_access_token(&client, config).await?;
    let mut url = workday_endpoint_url(&config.base_url, &config.events_path)?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("tenant", &config.tenant)
            .append_pair("limit", &config.page_size.to_string());
        if let Some(cursor) = cursor.filter(|cursor| !cursor.trim().is_empty()) {
            query.append_pair("cursor", cursor);
        }
    }
    let response = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|error| format!("Workday event poll request failed: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("Workday event poll request returned {status}"));
    }
    response
        .json::<WorkdayEventPage>()
        .await
        .map_err(|error| format!("Workday event poll response was invalid: {error}"))
}

fn workday_http_client(config: &WorkdayProviderConfig) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .build()
        .map_err(|error| format!("failed to build Workday HTTP client: {error}"))
}

async fn workday_access_token(
    client: &reqwest::Client,
    config: &WorkdayProviderConfig,
) -> Result<String, String> {
    match &config.auth {
        WorkdayProviderAuth::BearerToken { token } => Ok(token.clone()),
        WorkdayProviderAuth::OAuthClientCredentials {
            token_url,
            client_id,
            client_secret,
            scope,
        } => {
            let mut form = vec![
                ("grant_type", "client_credentials".to_string()),
                ("client_id", client_id.clone()),
                ("client_secret", client_secret.clone()),
            ];
            if let Some(scope) = scope {
                form.push(("scope", scope.clone()));
            }
            let response = client
                .post(token_url)
                .form(&form)
                .send()
                .await
                .map_err(|error| format!("Workday OAuth token request failed: {error}"))?;
            let status = response.status();
            if !status.is_success() {
                return Err(format!("Workday OAuth token request returned {status}"));
            }
            let token = response
                .json::<WorkdayOAuthTokenResponse>()
                .await
                .map_err(|error| format!("Workday OAuth token response was invalid: {error}"))?;
            if token.access_token.trim().is_empty() {
                return Err("Workday OAuth token response did not include access_token".into());
            }
            Ok(token.access_token)
        }
    }
}

fn workday_endpoint_url(base_url: &str, path: &str) -> Result<reqwest::Url, String> {
    let raw = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    };
    reqwest::Url::parse(&raw).map_err(|error| format!("invalid Workday endpoint URL: {error}"))
}

async fn load_hr_provider_checkpoint(
    persistence: &ApiPersistence,
    provider_id: &str,
) -> Result<HrProviderCheckpoint, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT event_cursor, snapshot_cursor
        FROM hr_sync_checkpoints
        WHERE provider_id = $1
        "#,
    )
    .bind(provider_id)
    .fetch_optional(persistence.pool())
    .await?;
    Ok(row
        .map(|row| HrProviderCheckpoint {
            event_cursor: row
                .try_get::<Option<String>, _>("event_cursor")
                .ok()
                .flatten(),
            snapshot_cursor: row
                .try_get::<Option<String>, _>("snapshot_cursor")
                .ok()
                .flatten(),
        })
        .unwrap_or_default())
}

async fn save_hr_provider_checkpoint(
    persistence: &ApiPersistence,
    config: &WorkdayProviderConfig,
    event_cursor: Option<&str>,
    snapshot_cursor: Option<&str>,
    operation: WorkdayCheckpointOperation,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO hr_sync_checkpoints (
            provider_id,
            source,
            event_cursor,
            snapshot_cursor,
            last_snapshot_at,
            last_event_poll_at,
            last_webhook_at,
            auth_mode,
            provider_base_url,
            updated_at
        )
        VALUES (
            $1,
            $2,
            $3,
            $4,
            CASE WHEN $5 THEN NOW() ELSE NULL END,
            CASE WHEN $6 THEN NOW() ELSE NULL END,
            CASE WHEN $7 THEN NOW() ELSE NULL END,
            $8,
            $9,
            NOW()
        )
        ON CONFLICT (provider_id) DO UPDATE SET
            source = EXCLUDED.source,
            event_cursor = EXCLUDED.event_cursor,
            snapshot_cursor = EXCLUDED.snapshot_cursor,
            last_snapshot_at = CASE
                WHEN $5 THEN NOW()
                ELSE hr_sync_checkpoints.last_snapshot_at
            END,
            last_event_poll_at = CASE
                WHEN $6 THEN NOW()
                ELSE hr_sync_checkpoints.last_event_poll_at
            END,
            last_webhook_at = CASE
                WHEN $7 THEN NOW()
                ELSE hr_sync_checkpoints.last_webhook_at
            END,
            auth_mode = EXCLUDED.auth_mode,
            provider_base_url = EXCLUDED.provider_base_url,
            updated_at = NOW()
        "#,
    )
    .bind(&config.provider_id)
    .bind(sync_source_label(&SyncSource::Workday))
    .bind(event_cursor)
    .bind(snapshot_cursor)
    .bind(operation.marks_snapshot())
    .bind(operation.marks_event_poll())
    .bind(operation.marks_webhook())
    .bind(config.auth.mode())
    .bind(&config.base_url)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

async fn append_workday_runtime_audit(
    state: Arc<ApiState>,
    config: &WorkdayProviderConfig,
    audit: ProviderRuntimeAudit<'_>,
) -> sdqp_audit::AuditCheckpoint {
    let ProviderRuntimeAudit {
        operation,
        checkpoint_before,
        checkpoint_after,
        synced_user_count,
        received_event_count,
        applied_event_count,
        result,
        error,
        ..
    } = audit;
    let mut builder = AuditContextFields::builder()
        .field("provider", "workday")
        .field("provider_id", config.provider_id.clone())
        .field("runtime_mode", "real_http")
        .field("auth_mode", config.auth.mode())
        .field("operation", operation)
        .field(
            "checkpoint_before",
            checkpoint_before.unwrap_or_default().to_string(),
        )
        .field(
            "checkpoint_after",
            checkpoint_after.unwrap_or_default().to_string(),
        )
        .field("synced_user_count", synced_user_count.to_string())
        .field("received_event_count", received_event_count.to_string())
        .field("applied_event_count", applied_event_count.to_string());
    if let Some(error) = error {
        builder = builder.field("error", error.to_string());
    }
    crate::record_audit_event_from_parts_with_fields(
        &state,
        ActorInfo {
            user_id: "workday-hr-provider".into(),
            session_id: format!("workday-{operation}"),
            ip_address: "127.0.0.1".into(),
        },
        ActionType::PermissionApply,
        TargetRef {
            tenant_id: "tenant-alpha".into(),
            project_id: None,
            resource_id: config.provider_id.clone(),
        },
        format!("workday hr provider {operation}"),
        builder.build(),
        result,
        None,
    )
    .await
}

pub async fn sap_successfactors_snapshot_sync_handler(
    State(state): State<Arc<ApiState>>,
    _headers: HeaderMap,
) -> Response {
    let Some(persistence) = state.persistence.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "SAP SuccessFactors snapshot sync requires persistent runtime",
        );
    };
    let config = match sap_successfactors_provider_config(&state.integrations.hr.sap_successfactors)
    {
        Ok(config) => config,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, &message),
    };
    let checkpoint_before =
        match load_hr_provider_checkpoint(persistence, &config.provider_id).await {
            Ok(checkpoint) => checkpoint,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load SAP SuccessFactors checkpoint",
                );
            }
        };

    let page = match fetch_sap_successfactors_snapshot(&config).await {
        Ok(page) => page,
        Err(message) => {
            let checkpoint = append_sap_successfactors_runtime_audit(
                state.clone(),
                &config,
                ProviderRuntimeAudit {
                    operation: "snapshot",
                    checkpoint_before: checkpoint_before.event_cursor.as_deref(),
                    checkpoint_after: checkpoint_before.event_cursor.as_deref(),
                    snapshot_watermark: None,
                    synced_user_count: 0,
                    received_event_count: 0,
                    applied_event_count: 0,
                    result: ActionResult::Failure,
                    error: Some(&message),
                },
            )
            .await;
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": message,
                    "audit_checkpoint_id": checkpoint.checkpoint_id
                })),
            )
                .into_response();
        }
    };
    let snapshot_cursor_after = page
        .next_cursor
        .clone()
        .or(checkpoint_before.snapshot_cursor.clone());
    let users = page.into_org_users();
    for user in &users {
        if upsert_org_user(
            persistence,
            &SyncSource::SapSuccessFactors,
            Some(&config.provider_id),
            user,
        )
        .await
        .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist SAP SuccessFactors snapshot user",
            );
        }
    }
    if save_sap_successfactors_provider_checkpoint(
        persistence,
        &config,
        checkpoint_before.event_cursor.as_deref(),
        snapshot_cursor_after.as_deref(),
        SapSuccessFactorsCheckpointOperation::Snapshot,
    )
    .await
    .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist SAP SuccessFactors snapshot checkpoint",
        );
    }

    let checkpoint = append_sap_successfactors_runtime_audit(
        state.clone(),
        &config,
        ProviderRuntimeAudit {
            operation: "snapshot",
            checkpoint_before: checkpoint_before.event_cursor.as_deref(),
            checkpoint_after: checkpoint_before.event_cursor.as_deref(),
            snapshot_watermark: None,
            synced_user_count: users.len(),
            received_event_count: 0,
            applied_event_count: 0,
            result: ActionResult::Success,
            error: None,
        },
    )
    .await;
    let provider_id = config.provider_id.clone();
    let auth_mode = config.auth.mode().to_string();

    Json(SapSuccessFactorsHrRuntimeResponse {
        provider_id,
        runtime_mode: "real_http_odata".into(),
        auth_mode,
        operation: "snapshot".into(),
        checkpoint_before: checkpoint_before.event_cursor,
        checkpoint_after: None,
        snapshot_cursor_after,
        synced_user_count: users.len(),
        received_event_count: 0,
        applied_event_count: 0,
        skipped_event_count: 0,
        revoked_grants: 0,
        suspended_grants: 0,
        resumed_grants: 0,
        expired_grants: 0,
        lifecycle_transitions: Vec::new(),
        audit_checkpoint_id: checkpoint.checkpoint_id,
    })
    .into_response()
}

pub async fn sap_successfactors_event_poll_handler(State(state): State<Arc<ApiState>>) -> Response {
    let Some(persistence) = state.persistence.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "SAP SuccessFactors event polling requires persistent runtime",
        );
    };
    let config = match sap_successfactors_provider_config(&state.integrations.hr.sap_successfactors)
    {
        Ok(config) => config,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, &message),
    };
    let checkpoint_before =
        match load_hr_provider_checkpoint(persistence, &config.provider_id).await {
            Ok(checkpoint) => checkpoint,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load SAP SuccessFactors checkpoint",
                );
            }
        };
    let page =
        match fetch_sap_successfactors_events(&config, checkpoint_before.event_cursor.as_deref())
            .await
        {
            Ok(page) => page,
            Err(message) => {
                let checkpoint = append_sap_successfactors_runtime_audit(
                    state.clone(),
                    &config,
                    ProviderRuntimeAudit {
                        operation: "event_poll",
                        checkpoint_before: checkpoint_before.event_cursor.as_deref(),
                        checkpoint_after: checkpoint_before.event_cursor.as_deref(),
                        snapshot_watermark: None,
                        synced_user_count: 0,
                        received_event_count: 0,
                        applied_event_count: 0,
                        result: ActionResult::Failure,
                        error: Some(&message),
                    },
                )
                .await;
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "error": message,
                        "audit_checkpoint_id": checkpoint.checkpoint_id
                    })),
                )
                    .into_response();
            }
        };
    apply_sap_successfactors_event_page(
        state.clone(),
        persistence,
        config,
        checkpoint_before,
        page,
        SapSuccessFactorsCheckpointOperation::EventPoll,
        "event_poll",
    )
    .await
}

pub async fn sap_successfactors_webhook_handler(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(envelope): Json<SapSuccessFactorsWebhookEnvelope>,
) -> Response {
    let Some(persistence) = state.persistence.as_ref() else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "SAP SuccessFactors webhook ingestion requires persistent runtime",
        );
    };
    let config = match sap_successfactors_provider_config(&state.integrations.hr.sap_successfactors)
    {
        Ok(config) => config,
        Err(message) => return json_error(StatusCode::BAD_REQUEST, &message),
    };
    if let Some(expected) = config.webhook_secret.as_deref()
        && !expected.trim().is_empty()
    {
        let received = headers
            .get("x-sap-successfactors-webhook-secret")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if received != expected {
            return json_error(
                StatusCode::UNAUTHORIZED,
                "invalid SAP SuccessFactors webhook secret",
            );
        }
    }
    let checkpoint_before =
        match load_hr_provider_checkpoint(persistence, &config.provider_id).await {
            Ok(checkpoint) => checkpoint,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load SAP SuccessFactors checkpoint",
                );
            }
        };

    apply_sap_successfactors_event_page(
        state.clone(),
        persistence,
        config,
        checkpoint_before,
        envelope.into_event_page(),
        SapSuccessFactorsCheckpointOperation::Webhook,
        "webhook",
    )
    .await
}

#[derive(Debug, Clone, Copy)]
enum SapSuccessFactorsCheckpointOperation {
    Snapshot,
    EventPoll,
    Webhook,
}

impl SapSuccessFactorsCheckpointOperation {
    fn marks_snapshot(self) -> bool {
        matches!(self, Self::Snapshot)
    }

    fn marks_event_poll(self) -> bool {
        matches!(self, Self::EventPoll)
    }

    fn marks_webhook(self) -> bool {
        matches!(self, Self::Webhook)
    }
}

async fn apply_sap_successfactors_event_page(
    state: Arc<ApiState>,
    persistence: &ApiPersistence,
    config: SapSuccessFactorsProviderConfig,
    checkpoint_before: HrProviderCheckpoint,
    page: SapSuccessFactorsEventPage,
    operation: SapSuccessFactorsCheckpointOperation,
    operation_label: &'static str,
) -> Response {
    let provider_next_cursor = page.next_cursor.clone();
    let events = page.into_hr_events();
    let report = match process_sap_successfactors_events(
        state.clone(),
        persistence,
        &config.provider_id,
        events,
        provider_next_cursor.as_deref(),
    )
    .await
    {
        Ok(report) => report,
        Err(message) => {
            return json_error(StatusCode::BAD_REQUEST, &message);
        }
    };
    let checkpoint_after = provider_next_cursor
        .or(report.last_event_id.clone())
        .or(checkpoint_before.event_cursor.clone());

    if save_sap_successfactors_provider_checkpoint(
        persistence,
        &config,
        checkpoint_after.as_deref(),
        checkpoint_before.snapshot_cursor.as_deref(),
        operation,
    )
    .await
    .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist SAP SuccessFactors event checkpoint",
        );
    }

    let stats = lifecycle_transition_stats(&report.lifecycle_transitions);
    let checkpoint = append_sap_successfactors_runtime_audit(
        state,
        &config,
        ProviderRuntimeAudit {
            operation: operation_label,
            checkpoint_before: checkpoint_before.event_cursor.as_deref(),
            checkpoint_after: checkpoint_after.as_deref(),
            snapshot_watermark: None,
            synced_user_count: 0,
            received_event_count: report.received_event_count,
            applied_event_count: report.applied_event_count,
            result: ActionResult::Success,
            error: None,
        },
    )
    .await;
    let provider_id = config.provider_id.clone();
    let auth_mode = config.auth.mode().to_string();
    Json(SapSuccessFactorsHrRuntimeResponse {
        provider_id,
        runtime_mode: "real_http_odata".into(),
        auth_mode,
        operation: operation_label.into(),
        checkpoint_before: checkpoint_before.event_cursor,
        checkpoint_after,
        snapshot_cursor_after: checkpoint_before.snapshot_cursor,
        synced_user_count: 0,
        received_event_count: report.received_event_count,
        applied_event_count: report.applied_event_count,
        skipped_event_count: report.skipped_event_count,
        revoked_grants: stats.revoked,
        suspended_grants: stats.suspended,
        resumed_grants: stats.resumed,
        expired_grants: stats.expired,
        lifecycle_transitions: report
            .lifecycle_transitions
            .iter()
            .map(lifecycle_transition_response)
            .collect(),
        audit_checkpoint_id: checkpoint.checkpoint_id,
    })
    .into_response()
}

async fn process_sap_successfactors_events(
    state: Arc<ApiState>,
    persistence: &ApiPersistence,
    provider_id: &str,
    events: Vec<HrEvent>,
    provider_cursor: Option<&str>,
) -> Result<HrEventProcessingReport, String> {
    let mut directory = load_org_directory(persistence)
        .await
        .map_err(|_| "failed to load org data".to_string())?;
    let received_event_count = events.len();
    let mut applied_event_count = 0;
    let mut skipped_event_count = 0;
    let mut last_event_id = None;
    let mut lifecycle_transitions = Vec::new();

    for event in events {
        last_event_id = Some(event.event_id.clone());
        let inserted = insert_hr_event_if_new(
            persistence,
            &SyncSource::SapSuccessFactors,
            &event,
            Some(provider_id),
            provider_cursor,
        )
        .await
        .map_err(|_| "failed to persist SAP SuccessFactors event".to_string())?;
        if !inserted {
            skipped_event_count += 1;
            continue;
        }

        let commands = directory
            .apply_event(event.clone())
            .map_err(|_| "SAP SuccessFactors event could not be applied".to_string())?;
        if let Some(user) = directory.get_user(&event.user_id) {
            upsert_org_user(
                persistence,
                &SyncSource::SapSuccessFactors,
                Some(provider_id),
                user,
            )
            .await
            .map_err(|_| "failed to persist SAP SuccessFactors org directory update".to_string())?;
        }
        let mut transitions = apply_hr_lifecycle_for_user(
            state.clone(),
            &directory,
            &event.user_id,
            None,
            Some(&event.event_id),
            Utc::now(),
        )
        .await
        .map_err(|_| "failed to persist HR-linked permission lifecycle".to_string())?;
        for command in commands {
            if command.user_id == event.user_id {
                continue;
            }
            let mut extra = apply_hr_lifecycle_for_user(
                state.clone(),
                &directory,
                &command.user_id,
                command.project_id.as_deref(),
                Some(&event.event_id),
                Utc::now(),
            )
            .await
            .map_err(|_| "failed to persist HR-linked permission lifecycle".to_string())?;
            transitions.append(&mut extra);
        }
        lifecycle_transitions.append(&mut transitions);
        applied_event_count += 1;
    }

    Ok(HrEventProcessingReport {
        received_event_count,
        applied_event_count,
        skipped_event_count,
        last_event_id,
        lifecycle_transitions,
    })
}

fn sap_successfactors_provider_config(
    settings: &SapSuccessFactorsIntegrationSettings,
) -> Result<SapSuccessFactorsProviderConfig, String> {
    let auth = match settings.auth_mode.trim().to_ascii_lowercase().as_str() {
        "oauth" | "oauth_client_credentials" | "client_credentials" => {
            SapSuccessFactorsProviderAuth::OAuthClientCredentials {
                token_url: settings.token_url.clone(),
                client_id: settings.client_id.clone(),
                client_secret: settings.client_secret.clone(),
                scope: (!settings.scope.trim().is_empty()).then(|| settings.scope.clone()),
            }
        }
        "bearer" | "bearer_token" => SapSuccessFactorsProviderAuth::BearerToken {
            token: settings.bearer_token.clone(),
        },
        "basic" | "basic_auth" => SapSuccessFactorsProviderAuth::BasicAuth {
            username: settings.username.clone(),
            password: settings.password.clone(),
        },
        other => {
            return Err(format!("unsupported SAP SuccessFactors auth mode: {other}"));
        }
    };
    let config = SapSuccessFactorsProviderConfig {
        provider_id: settings.provider_id.clone(),
        company_id: settings.company_id.clone(),
        base_url: settings.base_url.clone(),
        auth,
        users_path: settings.users_path.clone(),
        events_path: settings.events_path.clone(),
        webhook_secret: (!settings.webhook_secret.trim().is_empty())
            .then(|| settings.webhook_secret.clone()),
        page_size: settings.page_size as usize,
        timeout_ms: settings.timeout_ms,
    };
    config
        .validate_real_runtime()
        .map_err(|error| error.to_string())?;
    Ok(config)
}

#[derive(Debug, Deserialize)]
struct SapSuccessFactorsOAuthTokenResponse {
    access_token: String,
}

enum SapSuccessFactorsRequestAuth {
    Bearer(String),
    Basic { username: String, password: String },
}

async fn fetch_sap_successfactors_snapshot(
    config: &SapSuccessFactorsProviderConfig,
) -> Result<sdqp_hr_integration::SapSuccessFactorsSnapshotPage, String> {
    let client = sap_successfactors_http_client(config)?;
    let auth = sap_successfactors_request_auth(&client, config).await?;
    let mut url = sap_successfactors_endpoint_url(&config.base_url, &config.users_path)?;
    url.query_pairs_mut()
        .append_pair("companyId", &config.company_id)
        .append_pair("$top", &config.page_size.to_string());
    let request = apply_sap_successfactors_auth(client.get(url), auth);
    let response = request
        .send()
        .await
        .map_err(|error| format!("SAP SuccessFactors snapshot request failed: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "SAP SuccessFactors snapshot request returned {status}"
        ));
    }
    response
        .json::<SapSuccessFactorsSnapshotPayload>()
        .await
        .map(SapSuccessFactorsSnapshotPayload::into_page)
        .map_err(|error| format!("SAP SuccessFactors snapshot response was invalid: {error}"))
}

async fn fetch_sap_successfactors_events(
    config: &SapSuccessFactorsProviderConfig,
    cursor: Option<&str>,
) -> Result<SapSuccessFactorsEventPage, String> {
    let client = sap_successfactors_http_client(config)?;
    let auth = sap_successfactors_request_auth(&client, config).await?;
    let mut url = sap_successfactors_endpoint_url(&config.base_url, &config.events_path)?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("companyId", &config.company_id)
            .append_pair("$top", &config.page_size.to_string());
        if let Some(cursor) = cursor.filter(|cursor| !cursor.trim().is_empty()) {
            query.append_pair("$skiptoken", cursor);
        }
    }
    let request = apply_sap_successfactors_auth(client.get(url), auth);
    let response = request
        .send()
        .await
        .map_err(|error| format!("SAP SuccessFactors event poll request failed: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "SAP SuccessFactors event poll request returned {status}"
        ));
    }
    response
        .json::<SapSuccessFactorsEventPayload>()
        .await
        .map(SapSuccessFactorsEventPayload::into_page)
        .map_err(|error| format!("SAP SuccessFactors event poll response was invalid: {error}"))
}

fn sap_successfactors_http_client(
    config: &SapSuccessFactorsProviderConfig,
) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .build()
        .map_err(|error| format!("failed to build SAP SuccessFactors HTTP client: {error}"))
}

async fn sap_successfactors_request_auth(
    client: &reqwest::Client,
    config: &SapSuccessFactorsProviderConfig,
) -> Result<SapSuccessFactorsRequestAuth, String> {
    match &config.auth {
        SapSuccessFactorsProviderAuth::BearerToken { token } => {
            Ok(SapSuccessFactorsRequestAuth::Bearer(token.clone()))
        }
        SapSuccessFactorsProviderAuth::BasicAuth { username, password } => {
            Ok(SapSuccessFactorsRequestAuth::Basic {
                username: username.clone(),
                password: password.clone(),
            })
        }
        SapSuccessFactorsProviderAuth::OAuthClientCredentials {
            token_url,
            client_id,
            client_secret,
            scope,
        } => {
            let mut form = vec![
                ("grant_type", "client_credentials".to_string()),
                ("client_id", client_id.clone()),
                ("client_secret", client_secret.clone()),
            ];
            if let Some(scope) = scope {
                form.push(("scope", scope.clone()));
            }
            let response = client
                .post(token_url)
                .form(&form)
                .send()
                .await
                .map_err(|error| {
                    format!("SAP SuccessFactors OAuth token request failed: {error}")
                })?;
            let status = response.status();
            if !status.is_success() {
                return Err(format!(
                    "SAP SuccessFactors OAuth token request returned {status}"
                ));
            }
            let token = response
                .json::<SapSuccessFactorsOAuthTokenResponse>()
                .await
                .map_err(|error| {
                    format!("SAP SuccessFactors OAuth token response was invalid: {error}")
                })?;
            if token.access_token.trim().is_empty() {
                return Err(
                    "SAP SuccessFactors OAuth token response did not include access_token".into(),
                );
            }
            Ok(SapSuccessFactorsRequestAuth::Bearer(token.access_token))
        }
    }
}

fn apply_sap_successfactors_auth(
    request: reqwest::RequestBuilder,
    auth: SapSuccessFactorsRequestAuth,
) -> reqwest::RequestBuilder {
    match auth {
        SapSuccessFactorsRequestAuth::Bearer(token) => request.bearer_auth(token),
        SapSuccessFactorsRequestAuth::Basic { username, password } => {
            request.basic_auth(username, Some(password))
        }
    }
}

fn sap_successfactors_endpoint_url(base_url: &str, path: &str) -> Result<reqwest::Url, String> {
    let raw = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    };
    reqwest::Url::parse(&raw)
        .map_err(|error| format!("invalid SAP SuccessFactors endpoint URL: {error}"))
}

async fn save_sap_successfactors_provider_checkpoint(
    persistence: &ApiPersistence,
    config: &SapSuccessFactorsProviderConfig,
    event_cursor: Option<&str>,
    snapshot_cursor: Option<&str>,
    operation: SapSuccessFactorsCheckpointOperation,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO hr_sync_checkpoints (
            provider_id,
            source,
            event_cursor,
            snapshot_cursor,
            last_snapshot_at,
            last_event_poll_at,
            last_webhook_at,
            auth_mode,
            provider_base_url,
            updated_at
        )
        VALUES (
            $1,
            $2,
            $3,
            $4,
            CASE WHEN $5 THEN NOW() ELSE NULL END,
            CASE WHEN $6 THEN NOW() ELSE NULL END,
            CASE WHEN $7 THEN NOW() ELSE NULL END,
            $8,
            $9,
            NOW()
        )
        ON CONFLICT (provider_id) DO UPDATE SET
            source = EXCLUDED.source,
            event_cursor = EXCLUDED.event_cursor,
            snapshot_cursor = EXCLUDED.snapshot_cursor,
            last_snapshot_at = CASE
                WHEN $5 THEN NOW()
                ELSE hr_sync_checkpoints.last_snapshot_at
            END,
            last_event_poll_at = CASE
                WHEN $6 THEN NOW()
                ELSE hr_sync_checkpoints.last_event_poll_at
            END,
            last_webhook_at = CASE
                WHEN $7 THEN NOW()
                ELSE hr_sync_checkpoints.last_webhook_at
            END,
            auth_mode = EXCLUDED.auth_mode,
            provider_base_url = EXCLUDED.provider_base_url,
            updated_at = NOW()
        "#,
    )
    .bind(&config.provider_id)
    .bind(sync_source_label(&SyncSource::SapSuccessFactors))
    .bind(event_cursor)
    .bind(snapshot_cursor)
    .bind(operation.marks_snapshot())
    .bind(operation.marks_event_poll())
    .bind(operation.marks_webhook())
    .bind(config.auth.mode())
    .bind(&config.base_url)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

async fn append_sap_successfactors_runtime_audit(
    state: Arc<ApiState>,
    config: &SapSuccessFactorsProviderConfig,
    audit: ProviderRuntimeAudit<'_>,
) -> sdqp_audit::AuditCheckpoint {
    let ProviderRuntimeAudit {
        operation,
        checkpoint_before,
        checkpoint_after,
        synced_user_count,
        received_event_count,
        applied_event_count,
        result,
        error,
        ..
    } = audit;
    let mut builder = AuditContextFields::builder()
        .field("provider", "sap_successfactors")
        .field("provider_id", config.provider_id.clone())
        .field("company_id", config.company_id.clone())
        .field("runtime_mode", "real_http_odata")
        .field("auth_mode", config.auth.mode())
        .field("operation", operation)
        .field(
            "checkpoint_before",
            checkpoint_before.unwrap_or_default().to_string(),
        )
        .field(
            "checkpoint_after",
            checkpoint_after.unwrap_or_default().to_string(),
        )
        .field("synced_user_count", synced_user_count.to_string())
        .field("received_event_count", received_event_count.to_string())
        .field("applied_event_count", applied_event_count.to_string());
    if let Some(error) = error {
        builder = builder.field("error", error.to_string());
    }
    crate::record_audit_event_from_parts_with_fields(
        &state,
        ActorInfo {
            user_id: "sap-successfactors-hr-provider".into(),
            session_id: format!("sap-successfactors-{operation}"),
            ip_address: "127.0.0.1".into(),
        },
        ActionType::PermissionApply,
        TargetRef {
            tenant_id: "tenant-alpha".into(),
            project_id: None,
            resource_id: config.provider_id.clone(),
        },
        format!("sap successfactors hr provider {operation}"),
        builder.build(),
        result,
        None,
    )
    .await
}

pub async fn audit_permission_transition_handler(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<AuditPermissionTransitionRequest>,
) -> Response {
    if state.persistence.is_none() {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "audit permission transitions require persistent runtime",
        );
    }

    let Some(trigger) = parse_audit_lifecycle_trigger(&payload.action) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "unsupported audit permission transition action",
        );
    };
    let reason = payload
        .reason
        .as_deref()
        .unwrap_or("audit-triggered permission lifecycle signal");
    let transitions = match apply_audit_permission_signal_for_user(
        state,
        &payload.user_id,
        payload.project_id.as_deref(),
        trigger,
        payload.source_event_id.as_deref(),
        reason,
    )
    .await
    {
        Ok(transitions) => transitions,
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to apply audit permission transition",
            );
        }
    };
    let stats = lifecycle_transition_stats(&transitions);

    Json(AuditPermissionTransitionResponse {
        applied: transitions.len(),
        revoked_grants: stats.revoked,
        suspended_grants: stats.suspended,
        resumed_grants: stats.resumed,
        expired_grants: stats.expired,
        lifecycle_transitions: transitions
            .iter()
            .map(lifecycle_transition_response)
            .collect(),
    })
    .into_response()
}

async fn run_governance_tick(state: Arc<ApiState>) -> Result<(), PersistenceError> {
    let Some(persistence) = state.persistence.as_ref() else {
        return Ok(());
    };
    let now = Utc::now();

    run_permission_lifecycle_scheduler(state.clone(), now).await?;

    let approver_policy = approver_resolution_policy_from_state(&state);
    for bundle in load_due_approval_instances(persistence, now).await? {
        let directory = load_org_directory(persistence).await?;
        let mut notifier = QueueingNotificationSink::default();
        let mut instance = bundle.instance.clone();
        ApprovalEngine::tick_timeouts_with_policy(
            &mut instance,
            &bundle.flow,
            &bundle.request,
            &directory,
            &approver_policy,
            now,
            &mut notifier,
        )
        .map_err(|error| PersistenceError::Governance(error.to_string()))?;
        save_approval_instance(
            persistence,
            &bundle.application,
            &bundle.flow,
            &bundle.request,
            &instance,
        )
        .await?;
        if instance.status == ApprovalStatus::Rejected {
            let denied_application = PermissionApplication {
                status: GrantStatus::Denied,
                ..bundle.application.clone()
            };
            save_permission_application(
                persistence,
                &denied_application,
                &denied_application.merge_key(),
            )
            .await?;
            state
                .permissions
                .lock()
                .expect("permission registry")
                .restore_application(denied_application);
        }
        queue_notifications(
            persistence,
            Some(&instance.instance_id),
            &notifier.notifications,
        )
        .await?;
    }

    for delivery in load_due_notifications(persistence, now).await? {
        let delivery_result = send_notification(state.clone(), &delivery).await;
        if delivery_result.is_ok() {
            mark_notification_sent(persistence, &delivery.delivery_id).await?;
            append_notification_delivery_audit(
                state.clone(),
                &delivery,
                "sent",
                delivery.attempt_count + 1,
                None,
                None,
            )
            .await;
        } else {
            let error_message = delivery_result
                .err()
                .unwrap_or_else(|| "delivery failed".to_string());
            let terminal = delivery.attempt_count + 1 >= NOTIFICATION_MAX_ATTEMPTS;
            let next_attempt_at = now
                + chrono::Duration::milliseconds(
                    state.integrations.notifications.retry_backoff_ms as i64,
                );
            mark_notification_retry(
                persistence,
                &delivery.delivery_id,
                delivery.attempt_count + 1,
                next_attempt_at,
                &error_message,
                terminal,
            )
            .await?;
            append_notification_delivery_audit(
                state.clone(),
                &delivery,
                if terminal { "failed" } else { "retryable" },
                delivery.attempt_count + 1,
                Some(next_attempt_at),
                Some(error_message.as_str()),
            )
            .await;
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotificationChannelKind {
    Feishu,
    Slack,
    Email,
    Telegram,
    DingTalk,
}

impl NotificationChannelKind {
    fn label(self) -> &'static str {
        match self {
            Self::Feishu => "feishu",
            Self::Slack => "slack",
            Self::Email => "email",
            Self::Telegram => "telegram",
            Self::DingTalk => "dingtalk",
        }
    }

    fn parse(label: &str) -> Result<Self, PersistenceError> {
        match label.trim().to_ascii_lowercase().as_str() {
            "feishu" => Ok(Self::Feishu),
            "slack" => Ok(Self::Slack),
            "email" => Ok(Self::Email),
            "telegram" => Ok(Self::Telegram),
            "dingtalk" => Ok(Self::DingTalk),
            other => Err(PersistenceError::Governance(format!(
                "unknown notification channel: {other}"
            ))),
        }
    }
}

trait NotificationChannelAdapter: Send + Sync {
    fn kind(&self) -> NotificationChannelKind;
    fn endpoint<'a>(&self, state: &'a ApiState) -> &'a str;
    fn build_payload(&self, delivery: &NotificationDeliveryRow) -> serde_json::Value;
}

struct FeishuNotificationChannel;

impl NotificationChannelAdapter for FeishuNotificationChannel {
    fn kind(&self) -> NotificationChannelKind {
        NotificationChannelKind::Feishu
    }

    fn endpoint<'a>(&self, state: &'a ApiState) -> &'a str {
        state.integrations.notifications.feishu_webhook_url.as_str()
    }

    fn build_payload(&self, delivery: &NotificationDeliveryRow) -> serde_json::Value {
        json!({
            "msg_type": "interactive",
            "card": {
                "schema": "2.0",
                "header": {
                    "template": feishu_template(&delivery.notification.kind),
                    "title": {
                        "tag": "plain_text",
                        "content": notification_title(&delivery.notification),
                    },
                },
                "elements": [
                    {
                        "tag": "markdown",
                        "content": delivery.notification.message.as_str(),
                    }
                ],
                "actions": delivery
                    .notification
                    .callback
                    .as_ref()
                    .map(feishu_action_buttons)
                    .unwrap_or_default(),
            },
            "sdqp_metadata": notification_metadata(self.kind(), delivery),
        })
    }
}

struct SlackNotificationChannel;

impl NotificationChannelAdapter for SlackNotificationChannel {
    fn kind(&self) -> NotificationChannelKind {
        NotificationChannelKind::Slack
    }

    fn endpoint<'a>(&self, state: &'a ApiState) -> &'a str {
        state.integrations.notifications.slack_webhook_url.as_str()
    }

    fn build_payload(&self, delivery: &NotificationDeliveryRow) -> serde_json::Value {
        let mut blocks = vec![
            json!({
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": notification_title(&delivery.notification),
                }
            }),
            json!({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": delivery.notification.message,
                }
            }),
        ];
        if let Some(callback) = delivery.notification.callback.as_ref() {
            blocks.push(json!({
                "type": "actions",
                "elements": slack_action_buttons(callback),
            }));
        }

        json!({
            "channel": delivery.notification.recipient.as_str(),
            "text": delivery.notification.message.as_str(),
            "blocks": blocks,
            "sdqp_metadata": notification_metadata(self.kind(), delivery),
        })
    }
}

struct EmailNotificationChannel;

impl NotificationChannelAdapter for EmailNotificationChannel {
    fn kind(&self) -> NotificationChannelKind {
        NotificationChannelKind::Email
    }

    fn endpoint<'a>(&self, state: &'a ApiState) -> &'a str {
        state.integrations.notifications.email_api_url.as_str()
    }

    fn build_payload(&self, delivery: &NotificationDeliveryRow) -> serde_json::Value {
        json!({
            "to": delivery.notification.recipient.as_str(),
            "subject": notification_title(&delivery.notification),
            "text": delivery.notification.message.as_str(),
            "html": notification_email_html(delivery),
            "actions": delivery
                .notification
                .callback
                .as_ref()
                .map(email_actions)
                .unwrap_or_default(),
            "sdqp_metadata": notification_metadata(self.kind(), delivery),
        })
    }
}

struct TelegramNotificationChannel;

impl NotificationChannelAdapter for TelegramNotificationChannel {
    fn kind(&self) -> NotificationChannelKind {
        NotificationChannelKind::Telegram
    }

    fn endpoint<'a>(&self, state: &'a ApiState) -> &'a str {
        state
            .integrations
            .notifications
            .telegram_bot_api_url
            .as_str()
    }

    fn build_payload(&self, delivery: &NotificationDeliveryRow) -> serde_json::Value {
        json!({
            "chat_id": delivery.notification.recipient.as_str(),
            "text": notification_telegram_text(delivery),
            "parse_mode": "Markdown",
            "reply_markup": {
                "inline_keyboard": delivery
                    .notification
                    .callback
                    .as_ref()
                    .map(telegram_action_buttons)
                    .unwrap_or_default(),
            },
            "sdqp_metadata": notification_metadata(self.kind(), delivery),
        })
    }
}

struct DingTalkNotificationChannel;

impl NotificationChannelAdapter for DingTalkNotificationChannel {
    fn kind(&self) -> NotificationChannelKind {
        NotificationChannelKind::DingTalk
    }

    fn endpoint<'a>(&self, state: &'a ApiState) -> &'a str {
        state
            .integrations
            .notifications
            .dingtalk_webhook_url
            .as_str()
    }

    fn build_payload(&self, delivery: &NotificationDeliveryRow) -> serde_json::Value {
        json!({
            "msgtype": "actionCard",
            "actionCard": {
                "title": notification_title(&delivery.notification),
                "text": notification_dingtalk_markdown(delivery),
                "btnOrientation": "0",
                "btns": delivery
                    .notification
                    .callback
                    .as_ref()
                    .map(dingtalk_action_buttons)
                    .unwrap_or_default(),
            },
            "sdqp_metadata": notification_metadata(self.kind(), delivery),
        })
    }
}

async fn send_notification(
    state: Arc<ApiState>,
    delivery: &NotificationDeliveryRow,
) -> Result<(), String> {
    let kind = NotificationChannelKind::parse(delivery.channel.as_str())
        .map_err(|error| error.to_string())?;
    let adapter = notification_channel_adapter(kind);
    let url = adapter.endpoint(state.as_ref()).trim().to_string();
    if url.is_empty() {
        return Err(format!(
            "notification channel {} is not configured",
            kind.label()
        ));
    }
    reqwest::Client::new()
        .post(url)
        .json(&adapter.build_payload(delivery))
        .send()
        .await
        .map_err(|error| error.to_string())?
        .error_for_status()
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn notification_channel_adapter(
    kind: NotificationChannelKind,
) -> Box<dyn NotificationChannelAdapter> {
    match kind {
        NotificationChannelKind::Feishu => Box::new(FeishuNotificationChannel),
        NotificationChannelKind::Slack => Box::new(SlackNotificationChannel),
        NotificationChannelKind::Email => Box::new(EmailNotificationChannel),
        NotificationChannelKind::Telegram => Box::new(TelegramNotificationChannel),
        NotificationChannelKind::DingTalk => Box::new(DingTalkNotificationChannel),
    }
}

fn notification_metadata(
    channel: NotificationChannelKind,
    delivery: &NotificationDeliveryRow,
) -> serde_json::Value {
    json!({
        "delivery_id": delivery.delivery_id.as_str(),
        "instance_id": delivery.instance_id.as_deref(),
        "recipient": delivery.notification.recipient.as_str(),
        "message": delivery.notification.message.as_str(),
        "kind": notification_kind_label(&delivery.notification.kind),
        "step_id": delivery.notification.step_id.as_deref(),
        "callback": delivery
            .notification
            .callback
            .as_ref()
            .map(|callback| notification_callback_contract(channel, callback)),
    })
}

fn notification_callback_contract(
    channel: NotificationChannelKind,
    callback: &NotificationCallback,
) -> serde_json::Value {
    json!({
        "method": "POST",
        "path": "/v1/approvals/callback",
        "channel": channel.label(),
        "actions": callback
            .actions
            .iter()
            .map(|action| notification_action_contract(action, callback.instance_id.as_str()))
            .collect::<Vec<_>>(),
    })
}

fn notification_action_contract(
    action: &NotificationAction,
    instance_id: &str,
) -> serde_json::Value {
    json!({
        "label": notification_action_display(action),
        "body": {
            "instance_id": instance_id,
            "action": notification_action_label(action),
        }
    })
}

fn notification_title(notification: &Notification) -> String {
    let step_suffix = notification
        .step_id
        .as_deref()
        .map(|step_id| format!(" [{step_id}]"))
        .unwrap_or_default();
    match notification.kind {
        NotificationKind::ApprovalRequired => format!("SDQP Approval Required{step_suffix}"),
        NotificationKind::ApprovalDelegated => format!("SDQP Approval Delegated{step_suffix}"),
        NotificationKind::ApprovalEscalated => format!("SDQP Approval Escalated{step_suffix}"),
        NotificationKind::RequestApproved => "SDQP Access Request Approved".to_string(),
        NotificationKind::RequestRejected => "SDQP Access Request Rejected".to_string(),
        NotificationKind::Informational => "SDQP Notification".to_string(),
    }
}

fn notification_kind_label(kind: &NotificationKind) -> &'static str {
    match kind {
        NotificationKind::ApprovalRequired => "approval_required",
        NotificationKind::ApprovalDelegated => "approval_delegated",
        NotificationKind::ApprovalEscalated => "approval_escalated",
        NotificationKind::RequestApproved => "request_approved",
        NotificationKind::RequestRejected => "request_rejected",
        NotificationKind::Informational => "informational",
    }
}

fn notification_action_label(action: &NotificationAction) -> &'static str {
    match action {
        NotificationAction::Approve => "approve",
        NotificationAction::Reject => "reject",
        NotificationAction::Delegate => "delegate",
    }
}

fn notification_action_display(action: &NotificationAction) -> &'static str {
    match action {
        NotificationAction::Approve => "Approve",
        NotificationAction::Reject => "Reject",
        NotificationAction::Delegate => "Delegate",
    }
}

fn feishu_template(kind: &NotificationKind) -> &'static str {
    match kind {
        NotificationKind::ApprovalRequired => "blue",
        NotificationKind::ApprovalDelegated => "orange",
        NotificationKind::ApprovalEscalated => "red",
        NotificationKind::RequestApproved => "green",
        NotificationKind::RequestRejected => "red",
        NotificationKind::Informational => "grey",
    }
}

fn feishu_action_buttons(callback: &NotificationCallback) -> Vec<serde_json::Value> {
    callback
        .actions
        .iter()
        .map(|action| {
            json!({
                "tag": "button",
                "text": {
                    "tag": "plain_text",
                    "content": notification_action_display(action),
                },
                "type": match action {
                    NotificationAction::Approve => "primary",
                    NotificationAction::Reject => "danger",
                    NotificationAction::Delegate => "default",
                },
                "value": {
                    "instance_id": callback.instance_id.as_str(),
                    "action": notification_action_label(action),
                }
            })
        })
        .collect()
}

fn slack_action_buttons(callback: &NotificationCallback) -> Vec<serde_json::Value> {
    callback
        .actions
        .iter()
        .map(|action| {
            let payload = json!({
                "instance_id": callback.instance_id.as_str(),
                "action": notification_action_label(action),
            });
            json!({
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": notification_action_display(action),
                },
                "style": match action {
                    NotificationAction::Approve => "primary",
                    NotificationAction::Reject => "danger",
                    NotificationAction::Delegate => "default",
                },
                "action_id": format!("sdqp-{}", notification_action_label(action)),
                "value": serde_json::to_string(&payload).unwrap_or_default(),
            })
        })
        .collect()
}

fn email_actions(callback: &NotificationCallback) -> Vec<serde_json::Value> {
    callback
        .actions
        .iter()
        .map(|action| {
            json!({
                "label": notification_action_display(action),
                "method": "POST",
                "path": "/v1/approvals/callback",
                "body": {
                    "instance_id": callback.instance_id.as_str(),
                    "action": notification_action_label(action),
                }
            })
        })
        .collect()
}

fn telegram_action_buttons(callback: &NotificationCallback) -> Vec<Vec<serde_json::Value>> {
    vec![
        callback
            .actions
            .iter()
            .map(|action| {
                let payload = json!({
                    "instance_id": callback.instance_id.as_str(),
                    "action": notification_action_label(action),
                });
                json!({
                    "text": notification_action_display(action),
                    "callback_data": serde_json::to_string(&payload).unwrap_or_default(),
                })
            })
            .collect(),
    ]
}

fn dingtalk_action_buttons(callback: &NotificationCallback) -> Vec<serde_json::Value> {
    callback
        .actions
        .iter()
        .map(|action| {
            json!({
                "title": notification_action_display(action),
                "actionURL": format!(
                    "https://sdqp.local/v1/approvals/callback?action={}&instance_id={}",
                    notification_action_label(action),
                    callback.instance_id
                ),
            })
        })
        .collect()
}

fn notification_telegram_text(delivery: &NotificationDeliveryRow) -> String {
    format!(
        "*{}*\n{}",
        notification_title(&delivery.notification),
        delivery.notification.message
    )
}

fn notification_dingtalk_markdown(delivery: &NotificationDeliveryRow) -> String {
    format!(
        "### {}\n\n{}",
        notification_title(&delivery.notification),
        delivery.notification.message
    )
}

fn notification_email_html(delivery: &NotificationDeliveryRow) -> String {
    let actions_html = delivery
        .notification
        .callback
        .as_ref()
        .map(|callback| {
            callback
                .actions
                .iter()
                .map(|action| {
                    let payload = json!({
                        "instance_id": callback.instance_id.as_str(),
                        "action": notification_action_label(action),
                    });
                    format!(
                        "<li><strong>{}</strong>: POST /v1/approvals/callback with {}</li>",
                        notification_action_display(action),
                        escape_html(&serde_json::to_string(&payload).unwrap_or_default()),
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    format!(
        "<h1>{}</h1><p>{}</p>{}",
        escape_html(&notification_title(&delivery.notification)),
        escape_html(&delivery.notification.message),
        if actions_html.is_empty() {
            String::new()
        } else {
            format!("<ul>{actions_html}</ul>")
        }
    )
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&#39;")
}

async fn load_pending_application_by_merge_key(
    persistence: &ApiPersistence,
    merge_key: &str,
) -> Result<Option<PermissionApplication>, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT
            application_id,
            applicant_user_id,
            project_id,
            data_source_id,
            requested_fields_json,
            status,
            approval_instance_id,
            merged_into_application_id
        FROM permission_applications
        WHERE merge_key = $1 AND status = 'pending'
        ORDER BY updated_at DESC
        LIMIT 1
        "#,
    )
    .bind(merge_key)
    .fetch_optional(persistence.pool())
    .await?;

    row.as_ref()
        .map(parse_permission_application_row)
        .transpose()
}

async fn save_permission_application(
    persistence: &ApiPersistence,
    application: &PermissionApplication,
    merge_key: &str,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO permission_applications (
            application_id,
            applicant_user_id,
            project_id,
            data_source_id,
            requested_fields_json,
            status,
            approval_instance_id,
            merge_key,
            merged_into_application_id,
            created_at,
            updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
        ON CONFLICT (application_id) DO UPDATE SET
            applicant_user_id = EXCLUDED.applicant_user_id,
            project_id = EXCLUDED.project_id,
            data_source_id = EXCLUDED.data_source_id,
            requested_fields_json = EXCLUDED.requested_fields_json,
            status = EXCLUDED.status,
            approval_instance_id = EXCLUDED.approval_instance_id,
            merge_key = EXCLUDED.merge_key,
            merged_into_application_id = EXCLUDED.merged_into_application_id,
            updated_at = NOW()
        "#,
    )
    .bind(&application.application_id)
    .bind(&application.applicant_user_id)
    .bind(&application.project_id)
    .bind(&application.data_source_id)
    .bind(SqlJson(&application.requested_fields))
    .bind(grant_status_label(&application.status))
    .bind(&application.approval_instance_id)
    .bind(merge_key)
    .bind(&application.merged_into_application_id)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

async fn save_permission_grant(
    persistence: &ApiPersistence,
    grant: &PermissionGrant,
    approval_instance_id: &str,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO permission_grants (
            grant_id,
            applicant_user_id,
            project_id,
            data_source_id,
            status,
            fields_json,
            conditions_json,
            valid_from,
            valid_until,
            org_binding_json,
            approval_instance_id,
            created_at,
            updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
        ON CONFLICT (grant_id) DO UPDATE SET
            status = EXCLUDED.status,
            fields_json = EXCLUDED.fields_json,
            conditions_json = EXCLUDED.conditions_json,
            valid_from = EXCLUDED.valid_from,
            valid_until = EXCLUDED.valid_until,
            org_binding_json = EXCLUDED.org_binding_json,
            approval_instance_id = EXCLUDED.approval_instance_id,
            updated_at = NOW()
        "#,
    )
    .bind(&grant.grant_id)
    .bind(&grant.applicant_user_id)
    .bind(&grant.project_id)
    .bind(&grant.data_source_id)
    .bind(grant_status_label(&grant.status))
    .bind(SqlJson(&grant.fields))
    .bind(SqlJson(&grant.conditions))
    .bind(grant.valid_from)
    .bind(grant.valid_until)
    .bind(SqlJson(&grant.org_binding))
    .bind(approval_instance_id)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

async fn load_grants_for_user(
    persistence: &ApiPersistence,
    applicant_user_id: &str,
    project_id: &str,
) -> Result<Vec<PermissionGrant>, PersistenceError> {
    let rows = sqlx::query(
        r#"
        SELECT
            grant_id,
            applicant_user_id,
            project_id,
            data_source_id,
            fields_json,
            conditions_json,
            valid_from,
            valid_until,
            org_binding_json,
            status
        FROM permission_grants
        WHERE applicant_user_id = $1 AND project_id = $2
        ORDER BY updated_at DESC, grant_id
        "#,
    )
    .bind(applicant_user_id)
    .bind(project_id)
    .fetch_all(persistence.pool())
    .await?;

    rows.iter().map(parse_permission_grant_row).collect()
}

async fn load_lifecycle_grants(
    persistence: &ApiPersistence,
) -> Result<Vec<PermissionGrant>, PersistenceError> {
    let rows = sqlx::query(
        r#"
        SELECT
            grant_id,
            applicant_user_id,
            project_id,
            data_source_id,
            fields_json,
            conditions_json,
            valid_from,
            valid_until,
            org_binding_json,
            status
        FROM permission_grants
        WHERE status IN ('active', 'suspended')
        ORDER BY updated_at, grant_id
        "#,
    )
    .fetch_all(persistence.pool())
    .await?;

    rows.iter().map(parse_permission_grant_row).collect()
}

async fn load_lifecycle_grants_for_user(
    persistence: &ApiPersistence,
    applicant_user_id: &str,
    project_id: Option<&str>,
) -> Result<Vec<PermissionGrant>, PersistenceError> {
    let rows = match project_id {
        Some(project_id) => {
            sqlx::query(
                r#"
                SELECT
                    grant_id,
                    applicant_user_id,
                    project_id,
                    data_source_id,
                    fields_json,
                    conditions_json,
                    valid_from,
                    valid_until,
                    org_binding_json,
                    status
                FROM permission_grants
                WHERE applicant_user_id = $1
                  AND project_id = $2
                  AND status IN ('active', 'suspended')
                ORDER BY updated_at, grant_id
                "#,
            )
            .bind(applicant_user_id)
            .bind(project_id)
            .fetch_all(persistence.pool())
            .await?
        }
        None => {
            sqlx::query(
                r#"
                SELECT
                    grant_id,
                    applicant_user_id,
                    project_id,
                    data_source_id,
                    fields_json,
                    conditions_json,
                    valid_from,
                    valid_until,
                    org_binding_json,
                    status
                FROM permission_grants
                WHERE applicant_user_id = $1
                  AND status IN ('active', 'suspended')
                ORDER BY updated_at, grant_id
                "#,
            )
            .bind(applicant_user_id)
            .fetch_all(persistence.pool())
            .await?
        }
    };

    rows.iter().map(parse_permission_grant_row).collect()
}

async fn load_eligibility_rule_for_project(
    persistence: &ApiPersistence,
    project_id: &str,
) -> Result<ApplicantEligibilityRule, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT
            rule_id,
            project_id,
            allowed_department_ids_json,
            allowed_user_ids_json,
            allowed_role_names_json,
            require_active_hr_record
        FROM permission_eligibility_rules
        WHERE project_id = $1
        ORDER BY updated_at DESC, rule_id DESC
        LIMIT 1
        "#,
    )
    .bind(project_id)
    .fetch_optional(persistence.pool())
    .await?;

    row.as_ref()
        .map(parse_eligibility_rule_row)
        .transpose()
        .map(|rule| rule.unwrap_or_else(|| ApplicantEligibilityRule::active_hr_only(project_id)))
}

async fn load_eligibility_rules(
    persistence: &ApiPersistence,
) -> Result<std::collections::HashMap<String, ApplicantEligibilityRule>, PersistenceError> {
    let rows = sqlx::query(
        r#"
        SELECT
            rule_id,
            project_id,
            allowed_department_ids_json,
            allowed_user_ids_json,
            allowed_role_names_json,
            require_active_hr_record
        FROM permission_eligibility_rules
        ORDER BY updated_at, rule_id
        "#,
    )
    .fetch_all(persistence.pool())
    .await?;

    let mut rules = std::collections::HashMap::new();
    for row in rows {
        let rule = parse_eligibility_rule_row(&row)?;
        rules.insert(rule.project_id.clone(), rule);
    }
    Ok(rules)
}

fn parse_eligibility_rule_row(row: &PgRow) -> Result<ApplicantEligibilityRule, PersistenceError> {
    Ok(ApplicantEligibilityRule {
        rule_id: row.try_get("rule_id")?,
        project_id: row.try_get("project_id")?,
        allowed_department_ids: row
            .try_get::<SqlJson<Vec<String>>, _>("allowed_department_ids_json")?
            .0
            .into_iter()
            .collect(),
        allowed_user_ids: row
            .try_get::<SqlJson<Vec<String>>, _>("allowed_user_ids_json")?
            .0
            .into_iter()
            .collect(),
        allowed_role_names: row
            .try_get::<SqlJson<Vec<String>>, _>("allowed_role_names_json")?
            .0
            .into_iter()
            .collect(),
        require_active_hr_record: row.try_get("require_active_hr_record")?,
    })
}

async fn load_org_directory(
    persistence: &ApiPersistence,
) -> Result<OrgDirectory, PersistenceError> {
    let rows = sqlx::query(
        r#"
        SELECT user_id, source, department_id, manager_id, status, availability, delegate_user_id
        FROM hr_directory_users
        ORDER BY synced_at, user_id
        "#,
    )
    .fetch_all(persistence.pool())
    .await?;

    let mut directory = OrgDirectory::default();
    for row in rows {
        directory.sync_snapshot(
            parse_sync_source(&row.try_get::<String, _>("source")?)?,
            vec![OrgUser {
                user_id: row.try_get("user_id")?,
                department_id: row.try_get("department_id")?,
                manager_id: row.try_get("manager_id")?,
                status: parse_employment_status(&row.try_get::<String, _>("status")?)?,
                approver_profile: Some(ApproverProfile {
                    availability: parse_approver_availability(
                        &row.try_get::<String, _>("availability")?,
                    )?,
                    delegate_user_id: row.try_get("delegate_user_id")?,
                }),
            }],
        );
    }

    Ok(directory)
}

async fn upsert_org_user(
    persistence: &ApiPersistence,
    source: &SyncSource,
    provider_id: Option<&str>,
    user: &OrgUser,
) -> Result<(), PersistenceError> {
    let profile_provided = user.approver_profile.is_some();
    let availability = user
        .approver_profile
        .as_ref()
        .map(|profile| approver_availability_label(&profile.availability))
        .unwrap_or("available");
    let delegate_user_id = user
        .approver_profile
        .as_ref()
        .and_then(|profile| profile.delegate_user_id.as_deref());
    sqlx::query(
        r#"
        INSERT INTO hr_directory_users (
            user_id,
            source,
            department_id,
            manager_id,
            status,
            provider_id,
            availability,
            delegate_user_id,
            synced_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        ON CONFLICT (user_id) DO UPDATE SET
            source = EXCLUDED.source,
            department_id = EXCLUDED.department_id,
            manager_id = EXCLUDED.manager_id,
            status = EXCLUDED.status,
            provider_id = COALESCE(EXCLUDED.provider_id, hr_directory_users.provider_id),
            availability = CASE
                WHEN $9 THEN EXCLUDED.availability
                ELSE hr_directory_users.availability
            END,
            delegate_user_id = CASE
                WHEN $9 THEN EXCLUDED.delegate_user_id
                ELSE hr_directory_users.delegate_user_id
            END,
            synced_at = NOW()
        "#,
    )
    .bind(&user.user_id)
    .bind(sync_source_label(source))
    .bind(&user.department_id)
    .bind(&user.manager_id)
    .bind(employment_status_label(&user.status))
    .bind(provider_id)
    .bind(availability)
    .bind(delegate_user_id)
    .bind(profile_provided)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

fn requested_approver_profile(
    payload: &HrEventRequest,
    directory: &OrgDirectory,
) -> Result<Option<ApproverProfile>, PersistenceError> {
    let availability = payload
        .approver_availability
        .as_deref()
        .map(str::trim)
        .filter(|label| !label.is_empty())
        .map(parse_approver_availability)
        .transpose()?;
    let delegate_marker = payload.delegate_user_id.as_ref().map(|delegate_user_id| {
        let trimmed = delegate_user_id.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });

    if availability.is_none() && delegate_marker.is_none() {
        return Ok(None);
    }

    let current_profile = directory
        .approver_profile(&payload.user_id)
        .cloned()
        .unwrap_or_default();
    Ok(Some(ApproverProfile {
        availability: availability.unwrap_or(current_profile.availability),
        delegate_user_id: delegate_marker.unwrap_or(current_profile.delegate_user_id),
    }))
}

async fn insert_hr_event_if_new(
    persistence: &ApiPersistence,
    source: &SyncSource,
    event: &HrEvent,
    provider_id: Option<&str>,
    provider_cursor: Option<&str>,
) -> Result<bool, PersistenceError> {
    let rows = sqlx::query(
        r#"
        INSERT INTO hr_sync_events (
            event_id,
            source,
            user_id,
            event_type,
            provider_id,
            provider_cursor,
            payload_json,
            processed_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        ON CONFLICT (event_id) DO NOTHING
        "#,
    )
    .bind(&event.event_id)
    .bind(sync_source_label(source))
    .bind(&event.user_id)
    .bind(hr_event_type_label(&event.event_type))
    .bind(provider_id)
    .bind(provider_cursor)
    .bind(SqlJson(event))
    .execute(persistence.pool())
    .await?
    .rows_affected();
    Ok(rows == 1)
}

async fn load_approval_flow(
    persistence: &ApiPersistence,
    project_id: &str,
) -> Result<ApprovalFlowDefinition, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT definition_json
        FROM approval_flows
        WHERE project_id = $1
        ORDER BY created_at DESC, flow_id DESC
        LIMIT 1
        "#,
    )
    .bind(project_id)
    .fetch_optional(persistence.pool())
    .await?;
    let Some(row) = row else {
        return Err(PersistenceError::Governance(
            "approval flow is missing".to_string(),
        ));
    };
    Ok(row
        .try_get::<SqlJson<ApprovalFlowDefinition>, _>("definition_json")?
        .0)
}

async fn save_approval_instance(
    persistence: &ApiPersistence,
    application: &PermissionApplication,
    flow: &ApprovalFlowDefinition,
    request: &ApprovalRequest,
    instance: &ApprovalInstance,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO approval_instances (
            instance_id,
            application_id,
            project_id,
            status,
            flow_json,
            created_at,
            updated_at,
            applicant_user_id,
            data_source_id,
            flow_id_ref,
            request_json,
            step_states_json,
            audit_log_json,
            current_step_index,
            approval_key
        )
        VALUES (
            $1, $2, $3, $4, $5, NOW(), NOW(),
            $6, $7, $8, $9, $10, $11, $12, $13
        )
        ON CONFLICT (instance_id) DO UPDATE SET
            application_id = EXCLUDED.application_id,
            project_id = EXCLUDED.project_id,
            status = EXCLUDED.status,
            flow_json = EXCLUDED.flow_json,
            updated_at = NOW(),
            applicant_user_id = EXCLUDED.applicant_user_id,
            data_source_id = EXCLUDED.data_source_id,
            flow_id_ref = EXCLUDED.flow_id_ref,
            request_json = EXCLUDED.request_json,
            step_states_json = EXCLUDED.step_states_json,
            audit_log_json = EXCLUDED.audit_log_json,
            current_step_index = EXCLUDED.current_step_index,
            approval_key = EXCLUDED.approval_key
        "#,
    )
    .bind(&instance.instance_id)
    .bind(&application.application_id)
    .bind(&application.project_id)
    .bind(approval_status_label(&instance.status))
    .bind(SqlJson(flow))
    .bind(&application.applicant_user_id)
    .bind(&application.data_source_id)
    .bind(&flow.flow_id)
    .bind(SqlJson(request))
    .bind(SqlJson(&instance.step_states))
    .bind(SqlJson(&instance.audit_log))
    .bind(instance.current_step_index as i32)
    .bind(application.merge_key())
    .execute(persistence.pool())
    .await?;
    Ok(())
}

async fn load_approval_bundle(
    persistence: &ApiPersistence,
    instance_id: &str,
) -> Result<Option<ApprovalBundle>, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT
            ai.instance_id,
            ai.application_id,
            ai.project_id,
            ai.status AS approval_status,
            ai.flow_json,
            ai.request_json,
            ai.step_states_json,
            ai.audit_log_json,
            ai.current_step_index,
            pa.applicant_user_id,
            pa.project_id AS application_project_id,
            pa.data_source_id,
            pa.requested_fields_json,
            pa.status AS application_status,
            pa.approval_instance_id,
            pa.merged_into_application_id
        FROM approval_instances ai
        JOIN permission_applications pa
          ON pa.application_id = ai.application_id
        WHERE ai.instance_id = $1
        "#,
    )
    .bind(instance_id)
    .fetch_optional(persistence.pool())
    .await?;

    row.as_ref().map(parse_approval_bundle_row).transpose()
}

async fn save_approval_action(
    persistence: &ApiPersistence,
    instance_id: &str,
    approver_user_id: &str,
    action: &str,
    delegate_to: Option<&str>,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO approval_actions (
            action_id,
            instance_id,
            approver_user_id,
            action,
            payload_json,
            created_at
        )
        VALUES ($1, $2, $3, $4, $5, NOW())
        "#,
    )
    .bind(Ulid::new().to_string())
    .bind(instance_id)
    .bind(approver_user_id)
    .bind(action)
    .bind(SqlJson(json!({ "delegate_to": delegate_to })))
    .execute(persistence.pool())
    .await?;
    Ok(())
}

async fn list_pending_tasks_for_approver(
    persistence: &ApiPersistence,
    project_id: &str,
    approver_user_id: &str,
) -> Result<Vec<ApprovalTaskResponse>, PersistenceError> {
    let rows = sqlx::query(
        r#"
        SELECT
            ai.instance_id,
            ai.application_id,
            ai.project_id,
            ai.status AS approval_status,
            ai.request_json,
            ai.step_states_json,
            ai.current_step_index,
            pa.applicant_user_id,
            pa.data_source_id,
            pa.requested_fields_json
        FROM approval_instances ai
        JOIN permission_applications pa
          ON pa.application_id = ai.application_id
        WHERE ai.project_id = $1
          AND ai.status = 'pending'
        ORDER BY ai.updated_at, ai.instance_id
        "#,
    )
    .bind(project_id)
    .fetch_all(persistence.pool())
    .await?;

    let mut tasks = Vec::new();
    for row in rows {
        let step_states = row
            .try_get::<SqlJson<Vec<StepState>>, _>("step_states_json")?
            .0;
        let current_step_index = row.try_get::<i32, _>("current_step_index")? as usize;
        let Some(step_state) = step_states.get(current_step_index) else {
            continue;
        };
        if !step_state
            .pending_approvers
            .iter()
            .any(|approver| approver == approver_user_id)
        {
            continue;
        }

        tasks.push(ApprovalTaskResponse {
            instance_id: row.try_get("instance_id")?,
            application_id: row.try_get("application_id")?,
            applicant_user_id: row.try_get("applicant_user_id")?,
            data_source_id: row.try_get("data_source_id")?,
            step_id: step_state.step_id.clone(),
            status: row.try_get::<String, _>("approval_status")?,
            pending_approvers: step_state.pending_approvers.clone(),
            requested_fields: row
                .try_get::<SqlJson<Vec<String>>, _>("requested_fields_json")?
                .0,
            due_at: step_state.due_at,
            escalation_target: step_state.escalation_target.clone(),
            delegated_to: step_state.delegated_to.clone(),
            routing: step_state.routing.clone(),
        });
    }

    Ok(tasks)
}

async fn load_due_approval_instances(
    persistence: &ApiPersistence,
    now: DateTime<Utc>,
) -> Result<Vec<ApprovalBundle>, PersistenceError> {
    let rows = sqlx::query(
        r#"
        SELECT
            ai.instance_id,
            ai.application_id,
            ai.project_id,
            ai.status AS approval_status,
            ai.flow_json,
            ai.request_json,
            ai.step_states_json,
            ai.audit_log_json,
            ai.current_step_index,
            pa.applicant_user_id,
            pa.project_id AS application_project_id,
            pa.data_source_id,
            pa.requested_fields_json,
            pa.status AS application_status,
            pa.approval_instance_id,
            pa.merged_into_application_id
        FROM approval_instances ai
        JOIN permission_applications pa
          ON pa.application_id = ai.application_id
        WHERE ai.status = 'pending'
        ORDER BY ai.updated_at, ai.instance_id
        "#,
    )
    .fetch_all(persistence.pool())
    .await?;

    let mut bundles = Vec::new();
    for row in rows {
        let bundle = parse_approval_bundle_row(&row)?;
        let Some(step_state) = bundle
            .instance
            .step_states
            .get(bundle.instance.current_step_index)
        else {
            continue;
        };
        if step_state.due_at <= now {
            bundles.push(bundle);
        }
    }

    Ok(bundles)
}

async fn queue_notifications(
    persistence: &ApiPersistence,
    instance_id: Option<&str>,
    notifications: &[Notification],
) -> Result<(), PersistenceError> {
    for notification in notifications {
        persistence
            .queue_notification_delivery(instance_id, notification)
            .await?;
    }
    Ok(())
}

async fn load_due_notifications(
    persistence: &ApiPersistence,
    now: DateTime<Utc>,
) -> Result<Vec<NotificationDeliveryRow>, PersistenceError> {
    let rows = sqlx::query(
        r#"
        SELECT
            nd.delivery_id,
            nd.instance_id,
            ai.project_id,
            nd.channel,
            nd.recipient,
            nd.message,
            nd.notification_json,
            nd.attempt_count
        FROM notification_deliveries nd
        LEFT JOIN approval_instances ai
          ON ai.instance_id = nd.instance_id
        WHERE nd.status IN ('pending', 'retryable')
          AND nd.next_attempt_at <= $1
        ORDER BY nd.next_attempt_at, nd.created_at, nd.delivery_id
        "#,
    )
    .bind(now)
    .fetch_all(persistence.pool())
    .await?;

    rows.into_iter()
        .map(|row| {
            let fallback = Notification::informational(
                row.try_get::<String, _>("recipient")?,
                row.try_get::<String, _>("message")?,
            );
            let notification = row
                .try_get::<Option<SqlJson<Notification>>, _>("notification_json")?
                .map(|value| value.0)
                .unwrap_or(fallback);
            Ok(NotificationDeliveryRow {
                delivery_id: row.try_get("delivery_id")?,
                instance_id: row.try_get("instance_id")?,
                project_id: row.try_get("project_id")?,
                channel: row.try_get("channel")?,
                notification,
                attempt_count: row.try_get("attempt_count")?,
            })
        })
        .collect()
}

async fn mark_notification_sent(
    persistence: &ApiPersistence,
    delivery_id: &str,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        UPDATE notification_deliveries
        SET status = 'sent', updated_at = NOW(), attempt_count = attempt_count + 1, last_error = NULL
        WHERE delivery_id = $1
        "#,
    )
    .bind(delivery_id)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

async fn mark_notification_retry(
    persistence: &ApiPersistence,
    delivery_id: &str,
    attempt_count: i32,
    next_attempt_at: DateTime<Utc>,
    last_error: &str,
    terminal: bool,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        UPDATE notification_deliveries
        SET
            status = $2,
            attempt_count = $3,
            next_attempt_at = $4,
            last_error = $5,
            updated_at = NOW()
        WHERE delivery_id = $1
        "#,
    )
    .bind(delivery_id)
    .bind(if terminal { "failed" } else { "retryable" })
    .bind(attempt_count)
    .bind(next_attempt_at)
    .bind(last_error)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

async fn update_permission_grant_lifecycle_status(
    persistence: &ApiPersistence,
    transition: &GrantLifecycleTransition,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        UPDATE permission_grants
        SET
            status = $2,
            lifecycle_reason = $3,
            lifecycle_trigger = $4,
            lifecycle_transitioned_at = $5,
            lifecycle_source_event_id = $6,
            updated_at = NOW()
        WHERE grant_id = $1
          AND status = $7
        "#,
    )
    .bind(&transition.grant_id)
    .bind(grant_status_label(&transition.to_status))
    .bind(&transition.reason)
    .bind(transition.trigger.as_str())
    .bind(transition.effective_at)
    .bind(&transition.source_event_id)
    .bind(grant_status_label(&transition.from_status))
    .execute(persistence.pool())
    .await?;
    Ok(())
}

async fn save_permission_lifecycle_event(
    persistence: &ApiPersistence,
    transition: &GrantLifecycleTransition,
    audit_checkpoint_id: &str,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO permission_grant_lifecycle_events (
            transition_id,
            grant_id,
            applicant_user_id,
            project_id,
            data_source_id,
            from_status,
            to_status,
            trigger,
            reason,
            source_event_id,
            audit_checkpoint_id,
            context_json,
            created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        ON CONFLICT (transition_id) DO NOTHING
        "#,
    )
    .bind(&transition.transition_id)
    .bind(&transition.grant_id)
    .bind(&transition.applicant_user_id)
    .bind(&transition.project_id)
    .bind(&transition.data_source_id)
    .bind(grant_status_label(&transition.from_status))
    .bind(grant_status_label(&transition.to_status))
    .bind(transition.trigger.as_str())
    .bind(&transition.reason)
    .bind(&transition.source_event_id)
    .bind(audit_checkpoint_id)
    .bind(SqlJson(json!({
        "trigger": transition.trigger.as_str(),
        "source_event_id": transition.source_event_id.as_deref(),
        "effective_at": transition.effective_at,
    })))
    .bind(transition.effective_at)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

async fn update_grants_for_project_status(
    persistence: &ApiPersistence,
    project_id: &str,
    from_status: &str,
    to_status: &str,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        UPDATE permission_grants
        SET status = $2, updated_at = NOW()
        WHERE project_id = $1 AND status = $3
        "#,
    )
    .bind(project_id)
    .bind(to_status)
    .bind(from_status)
    .execute(persistence.pool())
    .await?;
    Ok(())
}

fn parse_permission_application_row(
    row: &PgRow,
) -> Result<PermissionApplication, PersistenceError> {
    Ok(PermissionApplication {
        application_id: row.try_get("application_id")?,
        applicant_user_id: row.try_get("applicant_user_id")?,
        project_id: row.try_get("project_id")?,
        data_source_id: row.try_get("data_source_id")?,
        requested_fields: row
            .try_get::<SqlJson<Vec<String>>, _>("requested_fields_json")?
            .0,
        status: parse_grant_status(&row.try_get::<String, _>("status")?)?,
        approval_instance_id: row.try_get("approval_instance_id")?,
        merged_into_application_id: row.try_get("merged_into_application_id")?,
    })
}

fn parse_permission_grant_row(row: &PgRow) -> Result<PermissionGrant, PersistenceError> {
    Ok(PermissionGrant {
        grant_id: row.try_get("grant_id")?,
        applicant_user_id: row.try_get("applicant_user_id")?,
        project_id: row.try_get("project_id")?,
        data_source_id: row.try_get("data_source_id")?,
        fields: row
            .try_get::<SqlJson<Vec<FieldPermission>>, _>("fields_json")?
            .0,
        conditions: row
            .try_get::<SqlJson<Vec<sdqp_core::FilterCondition>>, _>("conditions_json")?
            .0,
        condition_groups: Vec::new(),
        valid_from: row.try_get("valid_from")?,
        valid_until: row.try_get("valid_until")?,
        org_binding: row.try_get::<SqlJson<OrgBinding>, _>("org_binding_json")?.0,
        status: parse_grant_status(&row.try_get::<String, _>("status")?)?,
    })
}

fn parse_approval_bundle_row(row: &PgRow) -> Result<ApprovalBundle, PersistenceError> {
    let flow = row
        .try_get::<SqlJson<ApprovalFlowDefinition>, _>("flow_json")?
        .0;
    let request = row
        .try_get::<SqlJson<ApprovalRequest>, _>("request_json")?
        .0;
    let step_states = row
        .try_get::<SqlJson<Vec<StepState>>, _>("step_states_json")?
        .0;
    let audit_log = row.try_get::<SqlJson<Vec<String>>, _>("audit_log_json")?.0;

    Ok(ApprovalBundle {
        application: PermissionApplication {
            application_id: row.try_get("application_id")?,
            applicant_user_id: row.try_get("applicant_user_id")?,
            project_id: row.try_get("application_project_id")?,
            data_source_id: row.try_get("data_source_id")?,
            requested_fields: row
                .try_get::<SqlJson<Vec<String>>, _>("requested_fields_json")?
                .0,
            status: parse_grant_status(&row.try_get::<String, _>("application_status")?)?,
            approval_instance_id: row.try_get("approval_instance_id")?,
            merged_into_application_id: row.try_get("merged_into_application_id")?,
        },
        request,
        instance: ApprovalInstance {
            instance_id: row.try_get("instance_id")?,
            flow_id: flow.flow_id.clone(),
            request_id: row.try_get("application_id")?,
            current_step_index: row.try_get::<i32, _>("current_step_index")? as usize,
            step_states,
            status: parse_approval_status(&row.try_get::<String, _>("approval_status")?)?,
            audit_log,
        },
        flow,
    })
}

fn can_approve(roles: &[Role]) -> bool {
    roles
        .iter()
        .any(|role| matches!(role, Role::Approver | Role::SystemAdmin))
}

fn approver_resolution_policy_from_state(state: &ApiState) -> ApproverResolutionPolicy {
    let settings = &state.integrations.hr.approver_resolution;
    ApproverResolutionPolicy {
        system_fallback_user_id: settings.system_fallback_user_id.clone(),
        escalation_user_ids: settings.escalation_user_ids.clone(),
        max_manager_hops: settings.max_manager_hops as usize,
        allow_delegation: settings.allow_delegation,
    }
}

fn approver_resolution_response(
    route: &ApproverRoute,
    policy: &ApproverResolutionPolicy,
) -> ApproverResolutionResponse {
    ApproverResolutionResponse {
        requested_user_id: route.requested_user_id.clone(),
        resolved_user_id: route.resolved_user_id.clone(),
        route_kind: approver_route_kind_label(&route.route_kind).to_string(),
        delegated_from: route.delegated_from.clone(),
        escalation_target: route.escalation_target.clone(),
        used_system_fallback: route.used_system_fallback,
        traversed_user_ids: route.traversed_user_ids.clone(),
        unavailable_user_ids: route.unavailable_user_ids.clone(),
        policy_system_fallback_user_id: policy.system_fallback_user_id.clone(),
        policy_escalation_user_ids: policy.escalation_user_ids.clone(),
        policy_max_manager_hops: policy.max_manager_hops,
        policy_allow_delegation: policy.allow_delegation,
    }
}

fn approver_route_kind_label(kind: &ApproverRouteKind) -> &'static str {
    match kind {
        ApproverRouteKind::Direct => "direct",
        ApproverRouteKind::Delegated => "delegated",
        ApproverRouteKind::EscalatedToManager => "escalated_to_manager",
        ApproverRouteKind::EscalatedToConfiguredTarget => "escalated_to_configured_target",
        ApproverRouteKind::SystemFallback => "system_fallback",
    }
}

fn grant_status_label(status: &GrantStatus) -> &'static str {
    match status {
        GrantStatus::Pending => "pending",
        GrantStatus::Active => "active",
        GrantStatus::Suspended => "suspended",
        GrantStatus::Expired => "expired",
        GrantStatus::Revoked => "revoked",
        GrantStatus::Denied => "denied",
    }
}

fn parse_grant_status(label: &str) -> Result<GrantStatus, PersistenceError> {
    match label {
        "pending" => Ok(GrantStatus::Pending),
        "active" => Ok(GrantStatus::Active),
        "suspended" => Ok(GrantStatus::Suspended),
        "expired" => Ok(GrantStatus::Expired),
        "revoked" => Ok(GrantStatus::Revoked),
        "denied" => Ok(GrantStatus::Denied),
        other => Err(PersistenceError::Governance(format!(
            "unknown grant status: {other}"
        ))),
    }
}

fn approval_status_label(status: &ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Pending => "pending",
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Rejected => "rejected",
    }
}

fn parse_approval_status(label: &str) -> Result<ApprovalStatus, PersistenceError> {
    match label {
        "pending" => Ok(ApprovalStatus::Pending),
        "approved" => Ok(ApprovalStatus::Approved),
        "rejected" => Ok(ApprovalStatus::Rejected),
        other => Err(PersistenceError::Governance(format!(
            "unknown approval status: {other}"
        ))),
    }
}

fn sync_source_label(source: &SyncSource) -> &'static str {
    match source {
        SyncSource::Feishu => "feishu",
        SyncSource::FeishuMock => "feishu_mock",
        SyncSource::Workday => "workday",
        SyncSource::WorkdayMock => "workday_mock",
        SyncSource::SapSuccessFactors => "sap_successfactors",
        SyncSource::SapSuccessFactorsMock => "sap_successfactors_mock",
        SyncSource::Ldap => "ldap",
        SyncSource::LdapMock => "ldap_mock",
        SyncSource::CsvFallback => "csv",
    }
}

fn parse_sync_source(label: &str) -> Result<SyncSource, PersistenceError> {
    match label.to_ascii_lowercase().as_str() {
        "feishu" => Ok(SyncSource::Feishu),
        "feishu_mock" | "feishumock" => Ok(SyncSource::FeishuMock),
        "workday" => Ok(SyncSource::Workday),
        "workday_mock" | "workdaymock" => Ok(SyncSource::WorkdayMock),
        "sap" | "successfactors" | "sap_successfactors" | "sapsuccessfactors" => {
            Ok(SyncSource::SapSuccessFactors)
        }
        "sap_successfactors_mock" | "sapsuccessfactorsmock" | "sap_successfactorsmock" => {
            Ok(SyncSource::SapSuccessFactorsMock)
        }
        "ldap" => Ok(SyncSource::Ldap),
        "ldap_mock" | "ldapmock" => Ok(SyncSource::LdapMock),
        "csv" | "csvfallback" => Ok(SyncSource::CsvFallback),
        other => Err(PersistenceError::Governance(format!(
            "unknown hr source: {other}"
        ))),
    }
}

fn employment_status_label(status: &EmploymentStatus) -> &'static str {
    match status {
        EmploymentStatus::Active => "active",
        EmploymentStatus::Departed => "departed",
    }
}

fn parse_employment_status(label: &str) -> Result<EmploymentStatus, PersistenceError> {
    match label {
        "active" => Ok(EmploymentStatus::Active),
        "departed" => Ok(EmploymentStatus::Departed),
        other => Err(PersistenceError::Governance(format!(
            "unknown employment status: {other}"
        ))),
    }
}

fn parse_approver_availability(label: &str) -> Result<ApproverAvailability, PersistenceError> {
    match label.to_ascii_lowercase().as_str() {
        "available" => Ok(ApproverAvailability::Available),
        "unavailable" => Ok(ApproverAvailability::Unavailable),
        other => Err(PersistenceError::Governance(format!(
            "unknown approver availability: {other}"
        ))),
    }
}

fn approver_availability_label(availability: &ApproverAvailability) -> &'static str {
    match availability {
        ApproverAvailability::Available => "available",
        ApproverAvailability::Unavailable => "unavailable",
    }
}

fn hr_event_type_label(event_type: &HrEventType) -> &'static str {
    match event_type {
        HrEventType::Onboard => "onboard",
        HrEventType::Transfer => "transfer",
        HrEventType::Departure => "departure",
        HrEventType::ManagerChange => "manager_change",
    }
}

fn parse_hr_event_type(label: &str) -> Result<HrEventType, PersistenceError> {
    match label.to_ascii_lowercase().as_str() {
        "onboard" => Ok(HrEventType::Onboard),
        "transfer" => Ok(HrEventType::Transfer),
        "departure" => Ok(HrEventType::Departure),
        "manager_change" | "managerchange" => Ok(HrEventType::ManagerChange),
        other => Err(PersistenceError::Governance(format!(
            "unknown hr event type: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use sdqp_hr_integration::SyncSource;

    use super::{parse_sync_source, sync_source_label};

    #[test]
    fn workday_and_sap_sync_sources_round_trip_through_api_governance_labels() {
        assert_eq!(sync_source_label(&SyncSource::Feishu), "feishu");
        assert!(matches!(
            parse_sync_source("feishu").expect("feishu source"),
            SyncSource::Feishu
        ));
        assert_eq!(sync_source_label(&SyncSource::FeishuMock), "feishu_mock");
        assert!(matches!(
            parse_sync_source("feishu_mock").expect("feishu mock source"),
            SyncSource::FeishuMock
        ));

        assert_eq!(sync_source_label(&SyncSource::Workday), "workday");
        assert!(matches!(
            parse_sync_source("workday").expect("workday source"),
            SyncSource::Workday
        ));
        assert_eq!(sync_source_label(&SyncSource::WorkdayMock), "workday_mock");
        assert!(matches!(
            parse_sync_source("workday_mock").expect("workday mock source"),
            SyncSource::WorkdayMock
        ));
        assert!(matches!(
            parse_sync_source("workdaymock").expect("workday mock source"),
            SyncSource::WorkdayMock
        ));

        assert_eq!(
            sync_source_label(&SyncSource::SapSuccessFactors),
            "sap_successfactors"
        );
        assert!(matches!(
            parse_sync_source("sap_successfactors").expect("sap source"),
            SyncSource::SapSuccessFactors
        ));
        assert_eq!(
            sync_source_label(&SyncSource::SapSuccessFactorsMock),
            "sap_successfactors_mock"
        );
        assert!(matches!(
            parse_sync_source("sap_successfactors_mock").expect("sap mock source"),
            SyncSource::SapSuccessFactorsMock
        ));
        assert!(matches!(
            parse_sync_source("successfactors").expect("successfactors source"),
            SyncSource::SapSuccessFactors
        ));
        assert_eq!(sync_source_label(&SyncSource::Ldap), "ldap");
        assert!(matches!(
            parse_sync_source("ldap").expect("ldap source"),
            SyncSource::Ldap
        ));
        assert_eq!(sync_source_label(&SyncSource::LdapMock), "ldap_mock");
        assert!(matches!(
            parse_sync_source("ldap_mock").expect("ldap mock source"),
            SyncSource::LdapMock
        ));
    }
}
