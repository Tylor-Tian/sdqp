use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use sdqp_approval_engine::Notification;
use sdqp_audit::{ActionResult, ActionType, AuditEvent};
use sdqp_config::settings::UebaSettings;
use sdqp_core::{RequestContext, compute_sha256_hex};
use sdqp_permission_engine::{GrantLifecycleTrigger, GrantStatus};
use sdqp_system_security::Role;
use sdqp_ueba::{
    EntityBaseline, MitigationAction, UebaAlert, UebaCalibrationResult, UebaReplaySummary,
    UebaRule, UebaRuleDefinition, UebaRulePattern, UebaRuleStatus, UebaRuleThresholds,
    UebaRuleTuning, UebaRuleVersion, UebaTuningObjective, build_entity_baselines,
    build_role_baselines, build_user_baselines, calibrate_ueba_rules, evaluate_alerts,
    propose_rule_tuning, replay_ueba_rules,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{ApiState, AuthenticatedSession, persistence, phase2};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaAlertResponse {
    pub alert_id: String,
    pub user_id: String,
    pub rule: String,
    pub risk_score: u8,
    pub action: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaAlertsResponse {
    pub alerts: Vec<UebaAlertResponse>,
    pub step_up_sessions: usize,
    pub permissions_suspended: usize,
    pub permissions_revoked: usize,
    pub terminated_sessions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaUserBaselineResponse {
    pub user_id: String,
    pub baseline_window: String,
    pub query_count: usize,
    pub export_count: usize,
    pub denied_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaEntityBaselineResponse {
    pub entity_type: String,
    pub entity_id: String,
    pub baseline_window: String,
    pub query_count: usize,
    pub export_count: usize,
    pub denied_count: usize,
    pub distinct_users: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaBaselinesResponse {
    pub user_baselines: Vec<UebaUserBaselineResponse>,
    pub entity_baselines: Vec<UebaEntityBaselineResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaGovernanceRuleResponse {
    pub rule_version_id: String,
    pub tenant_id: String,
    pub rule_name: String,
    pub version: u32,
    pub status: String,
    pub enabled: bool,
    pub threshold: u32,
    pub risk_score: u8,
    pub mitigation_action: String,
    pub description: Option<String>,
    pub tuning: BTreeMap<String, String>,
    pub base_rule_version_id: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
    pub retired_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaRulesResponse {
    pub rules: Vec<UebaGovernanceRuleResponse>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UebaRuleCreateRequest {
    pub rule_name: String,
    pub threshold: Option<u32>,
    pub risk_score: Option<u8>,
    pub mitigation_action: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub activate: bool,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UebaRuleTuneRequest {
    pub threshold: Option<u32>,
    pub risk_score: Option<u8>,
    pub mitigation_action: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub activate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaReplaySummaryResponse {
    pub events_replayed: usize,
    pub rules_evaluated: usize,
    pub hit_count_by_rule: BTreeMap<String, usize>,
    pub alert_count_by_action: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaReplayRunResponse {
    pub run_id: String,
    pub tenant_id: String,
    pub requested_rule_version_id: Option<String>,
    pub state: String,
    pub event_count: usize,
    pub hit_count: usize,
    pub alert_count: usize,
    pub hits: Vec<UebaAlertResponse>,
    pub alerts: Vec<UebaAlertResponse>,
    pub summary: UebaReplaySummaryResponse,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UebaReplayRequest {
    pub rule_version_id: Option<String>,
    pub rule_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaTuningProposalResponse {
    pub proposal_id: String,
    pub tenant_id: String,
    pub replay_run_id: Option<String>,
    pub source_rule_version_id: String,
    pub rule_name: String,
    pub proposed_threshold: u32,
    pub proposed_risk_score: u8,
    pub proposed_mitigation_action: String,
    pub target_hit_rate_per_1000: Option<u32>,
    pub rationale: String,
    pub status: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub applied_rule_version_id: Option<String>,
    pub applied_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaTuningProposalApplyResponse {
    pub proposal: UebaTuningProposalResponse,
    pub applied_rule: UebaGovernanceRuleResponse,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UebaTuningProposalRequest {
    pub replay_run_id: Option<String>,
    pub rule_version_id: Option<String>,
    pub rule_name: Option<String>,
    pub threshold_delta: Option<i32>,
    pub target_hit_rate_per_1000: Option<u32>,
    pub mitigation_action: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UebaTuningProposalApplyRequest {
    #[serde(default = "default_true")]
    pub activate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaCalibrationResultResponse {
    pub runtime_mode: String,
    pub deterministic: bool,
    pub external_final_uat_required: bool,
    pub recommended_thresholds: BTreeMap<String, u32>,
    pub observed_counts: BTreeMap<String, usize>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaCalibrationRunResponse {
    pub calibration_id: String,
    pub tenant_id: String,
    pub status: String,
    pub model_version: String,
    pub event_count: usize,
    pub rule_count: usize,
    pub result: UebaCalibrationResultResponse,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UebaCalibrationRequest {
    pub model_version: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct UebaGovernanceRuntime {
    pub rules_by_tenant: HashMap<String, Vec<UebaGovernanceRuleResponse>>,
    pub replay_runs: HashMap<String, UebaReplayRunResponse>,
    pub tuning_proposals: HashMap<String, UebaTuningProposalResponse>,
    pub calibration_runs: HashMap<String, UebaCalibrationRunResponse>,
}

#[derive(Debug, Default)]
pub(crate) struct MitigationStats {
    pub step_up_sessions: usize,
    pub permissions_suspended: usize,
    pub permissions_revoked: usize,
    pub terminated_sessions: usize,
}

pub async fn ueba_alerts_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    if let Some(persistence) = state.persistence.clone() {
        return match persistent_ueba_alerts_response(state, persistence, request_context, session)
            .await
        {
            Ok(payload) => Json(payload).into_response(),
            Err(error) => {
                tracing::error!(?error, "failed to load persistent ueba alerts");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "failed to load ueba alerts"
                    })),
                )
                    .into_response()
            }
        };
    }

    legacy_ueba_alerts_handler(state, request_context, session).await
}

pub async fn ueba_baselines_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    if let Some(persistence) = state.persistence.clone() {
        return match persistent_ueba_baselines_response(
            state,
            persistence,
            request_context,
            session,
        )
        .await
        {
            Ok(payload) => Json(payload).into_response(),
            Err(error) => {
                tracing::error!(?error, "failed to load persistent ueba baselines");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "failed to load ueba baselines"
                    })),
                )
                    .into_response()
            }
        };
    }

    let audit_events = tenant_audit_events(&state, &request_context);
    let signal_events = filter_ueba_signal_events(&audit_events);
    let user_baselines = build_user_baselines(&signal_events)
        .into_iter()
        .map(|(user_id, baseline)| UebaUserBaselineResponse {
            user_id,
            baseline_window: "rolling-all".into(),
            query_count: baseline.query_count,
            export_count: baseline.export_count,
            denied_count: baseline.denied_count,
        })
        .collect::<Vec<_>>();

    let entity_baselines = build_entity_baselines(&signal_events)
        .into_iter()
        .map(|(key, baseline)| {
            to_entity_baseline_response(
                key.entity_type,
                key.entity_id,
                "rolling-all".into(),
                baseline,
            )
        })
        .collect::<Vec<_>>();

    phase2::append_phase2_audit(
        &state,
        &session,
        &request_context,
        ActionType::View,
        ActionResult::Success,
        "ueba-baselines",
        "ueba baselines viewed",
        None,
    )
    .await;

    Json(UebaBaselinesResponse {
        user_baselines,
        entity_baselines,
    })
    .into_response()
}

pub async fn ueba_rules_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    if !can_manage_ueba_governance(&session) {
        return ueba_json_error(
            StatusCode::FORBIDDEN,
            "system admin role required for ueba governance",
        );
    }

    match load_or_seed_ueba_rules(
        &state,
        request_context.tenant_id.as_str(),
        &session.claims.user_id,
    )
    .await
    {
        Ok(rules) => {
            append_ueba_audit(
                &state,
                &session,
                &request_context,
                ActionType::View,
                "ueba-governance-rules",
                "ueba governance rules listed",
            )
            .await;
            Json(UebaRulesResponse { rules }).into_response()
        }
        Err(error) => ueba_persistence_error(error, "failed to load ueba governance rules"),
    }
}

pub async fn create_ueba_rule_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(request): Json<UebaRuleCreateRequest>,
) -> Response {
    if !can_manage_ueba_governance(&session) {
        return ueba_json_error(
            StatusCode::FORBIDDEN,
            "system admin role required for ueba governance",
        );
    }

    let tenant_id = request_context.tenant_id.as_str();
    let rules = match load_or_seed_ueba_rules(&state, tenant_id, &session.claims.user_id).await {
        Ok(rules) => rules,
        Err(error) => return ueba_persistence_error(error, "failed to load ueba governance rules"),
    };
    let rule = match build_created_rule(
        &state.ueba,
        tenant_id,
        &session.claims.user_id,
        request,
        &rules,
    ) {
        Ok(rule) => rule,
        Err(response) => return *response,
    };

    match save_rule_version(&state, rule.clone(), rule.status == "active").await {
        Ok(rule) => {
            append_ueba_audit(
                &state,
                &session,
                &request_context,
                ActionType::ConfigChange,
                &rule.rule_version_id,
                &format!("ueba governance rule created: {}", rule.rule_name),
            )
            .await;
            (StatusCode::CREATED, Json(rule)).into_response()
        }
        Err(error) => ueba_persistence_error(error, "failed to create ueba governance rule"),
    }
}

pub async fn activate_ueba_rule_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(rule_version_id): Path<String>,
) -> Response {
    change_ueba_rule_state(
        state,
        request_context,
        session,
        rule_version_id,
        UebaRuleStateChange::Activate,
    )
    .await
}

pub async fn enable_ueba_rule_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(rule_version_id): Path<String>,
) -> Response {
    change_ueba_rule_state(
        state,
        request_context,
        session,
        rule_version_id,
        UebaRuleStateChange::Enable,
    )
    .await
}

pub async fn disable_ueba_rule_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(rule_version_id): Path<String>,
) -> Response {
    change_ueba_rule_state(
        state,
        request_context,
        session,
        rule_version_id,
        UebaRuleStateChange::Disable,
    )
    .await
}

pub async fn retire_ueba_rule_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(rule_version_id): Path<String>,
) -> Response {
    change_ueba_rule_state(
        state,
        request_context,
        session,
        rule_version_id,
        UebaRuleStateChange::Retire,
    )
    .await
}

pub async fn tune_ueba_rule_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(rule_version_id): Path<String>,
    Json(request): Json<UebaRuleTuneRequest>,
) -> Response {
    if !can_manage_ueba_governance(&session) {
        return ueba_json_error(
            StatusCode::FORBIDDEN,
            "system admin role required for ueba governance",
        );
    }

    let tenant_id = request_context.tenant_id.as_str();
    let rules = match load_or_seed_ueba_rules(&state, tenant_id, &session.claims.user_id).await {
        Ok(rules) => rules,
        Err(error) => return ueba_persistence_error(error, "failed to load ueba governance rules"),
    };
    let Some(source) = rules
        .iter()
        .find(|rule| rule.rule_version_id == rule_version_id)
        .cloned()
    else {
        return ueba_json_error(
            StatusCode::NOT_FOUND,
            "ueba governance rule version not found",
        );
    };
    let tuned = build_tuned_rule(&source, &session.claims.user_id, request, &rules);

    match save_rule_version(&state, tuned.clone(), tuned.status == "active").await {
        Ok(rule) => {
            append_ueba_audit(
                &state,
                &session,
                &request_context,
                ActionType::ConfigChange,
                &rule.rule_version_id,
                &format!("ueba governance rule tuned: {}", rule.rule_name),
            )
            .await;
            Json(rule).into_response()
        }
        Err(error) => ueba_persistence_error(error, "failed to tune ueba governance rule"),
    }
}

pub async fn create_ueba_replay_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(request): Json<UebaReplayRequest>,
) -> Response {
    if !can_manage_ueba_governance(&session) {
        return ueba_json_error(
            StatusCode::FORBIDDEN,
            "system admin role required for ueba governance",
        );
    }

    match run_ueba_replay(state.clone(), &request_context, &session, request).await {
        Ok(run) => Json(run).into_response(),
        Err(error) => error,
    }
}

pub async fn get_ueba_replay_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(run_id): Path<String>,
) -> Response {
    if !can_manage_ueba_governance(&session) {
        return ueba_json_error(
            StatusCode::FORBIDDEN,
            "system admin role required for ueba governance",
        );
    }

    match load_ueba_replay_run(&state, request_context.tenant_id.as_str(), &run_id).await {
        Ok(Some(run)) => Json(run).into_response(),
        Ok(None) => ueba_json_error(StatusCode::NOT_FOUND, "ueba replay run not found"),
        Err(error) => ueba_persistence_error(error, "failed to load ueba replay run"),
    }
}

pub async fn create_ueba_tuning_proposal_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(request): Json<UebaTuningProposalRequest>,
) -> Response {
    if !can_manage_ueba_governance(&session) {
        return ueba_json_error(
            StatusCode::FORBIDDEN,
            "system admin role required for ueba governance",
        );
    }

    let proposal = match build_tuning_proposal(
        &state,
        request_context.tenant_id.as_str(),
        &session.claims.user_id,
        request,
    )
    .await
    {
        Ok(proposal) => proposal,
        Err(response) => return response,
    };

    match save_tuning_proposal(&state, proposal.clone()).await {
        Ok(proposal) => {
            append_ueba_audit(
                &state,
                &session,
                &request_context,
                ActionType::ConfigChange,
                &proposal.proposal_id,
                &format!("ueba tuning proposal created: {}", proposal.rule_name),
            )
            .await;
            (StatusCode::CREATED, Json(proposal)).into_response()
        }
        Err(error) => ueba_persistence_error(error, "failed to create ueba tuning proposal"),
    }
}

pub async fn apply_ueba_tuning_proposal_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(proposal_id): Path<String>,
    Json(request): Json<UebaTuningProposalApplyRequest>,
) -> Response {
    if !can_manage_ueba_governance(&session) {
        return ueba_json_error(
            StatusCode::FORBIDDEN,
            "system admin role required for ueba governance",
        );
    }

    match apply_tuning_proposal(
        &state,
        request_context.tenant_id.as_str(),
        &session.claims.user_id,
        &proposal_id,
        request.activate,
    )
    .await
    {
        Ok(response) => {
            append_ueba_audit(
                &state,
                &session,
                &request_context,
                ActionType::ConfigChange,
                &proposal_id,
                "ueba tuning proposal applied",
            )
            .await;
            Json(response).into_response()
        }
        Err(response) => response,
    }
}

pub async fn create_ueba_calibration_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(request): Json<UebaCalibrationRequest>,
) -> Response {
    if !can_manage_ueba_governance(&session) {
        return ueba_json_error(
            StatusCode::FORBIDDEN,
            "system admin role required for ueba governance",
        );
    }

    match run_ueba_calibration(state.clone(), &request_context, &session, request).await {
        Ok(run) => Json(run).into_response(),
        Err(response) => response,
    }
}

pub async fn get_ueba_calibration_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Path(calibration_id): Path<String>,
) -> Response {
    if !can_manage_ueba_governance(&session) {
        return ueba_json_error(
            StatusCode::FORBIDDEN,
            "system admin role required for ueba governance",
        );
    }

    match load_calibration_run(&state, request_context.tenant_id.as_str(), &calibration_id).await {
        Ok(Some(run)) => Json(run).into_response(),
        Ok(None) => ueba_json_error(StatusCode::NOT_FOUND, "ueba calibration run not found"),
        Err(error) => ueba_persistence_error(error, "failed to load ueba calibration run"),
    }
}

pub(crate) async fn process_persistent_ueba_tenant(
    state: &Arc<ApiState>,
    persistence: &Arc<persistence::ApiPersistence>,
    tenant_id: &str,
    staged_events: &[AuditEvent],
) -> Result<MitigationStats, persistence::PersistenceError> {
    let mut audit_events = persistence.load_tenant_audit_events(tenant_id).await?;
    let mut known_hashes = audit_events
        .iter()
        .map(|event| event.event_hash.clone())
        .collect::<std::collections::HashSet<_>>();
    for event in staged_events {
        if known_hashes.insert(event.event_hash.clone()) {
            audit_events.push(event.clone());
        }
    }
    let signal_events = filter_ueba_signal_events(&audit_events);
    let user_baselines = build_user_baselines(&signal_events);
    for (user_id, baseline) in &user_baselines {
        persistence
            .save_ueba_user_baseline(tenant_id, user_id, "rolling-all", baseline)
            .await?;
    }

    let roles_by_user = roles_by_user(state);
    let role_baselines = build_role_baselines(&signal_events, &roles_by_user);
    for (role, baseline) in &role_baselines {
        persistence
            .save_ueba_entity_baseline(tenant_id, "role", role, "rolling-all", baseline)
            .await?;
    }

    let entity_baselines = build_entity_baselines(&signal_events);
    for (key, baseline) in &entity_baselines {
        persistence
            .save_ueba_entity_baseline(
                tenant_id,
                &key.entity_type,
                &key.entity_id,
                "rolling-all",
                baseline,
            )
            .await?;
    }

    let alerts = evaluate_alerts(&signal_events, &user_baselines);
    let existing_signatures = persistence.load_ueba_alert_signatures(tenant_id).await?;
    let new_alerts = alerts
        .into_iter()
        .filter(|alert| !existing_signatures.contains(&alert_signature(alert)))
        .collect::<Vec<_>>();

    let mitigation = apply_persistent_mitigations(state, persistence, &new_alerts).await?;

    for alert in &new_alerts {
        persistence.save_ueba_alert(alert).await?;
        persistence.save_ueba_rule_hit(alert).await?;
        persistence
            .queue_notification_delivery(
                None,
                &Notification::informational(
                    "security-operations",
                    format!(
                        "[{}] UEBA {:?} for user {} -> {:?}: {}",
                        alert.tenant_id, alert.rule, alert.user_id, alert.action, alert.evidence
                    ),
                ),
            )
            .await?;
    }

    Ok(mitigation)
}

async fn legacy_ueba_alerts_handler(
    state: Arc<ApiState>,
    request_context: RequestContext,
    session: AuthenticatedSession,
) -> Response {
    let audit_events = tenant_audit_events(&state, &request_context);
    let signal_events = filter_ueba_signal_events(&audit_events);
    let alerts = evaluate_alerts(&signal_events, &build_user_baselines(&signal_events));
    let highest_actions = highest_action_by_user(&alerts);

    let mut step_up_sessions = 0;
    let mut terminated_sessions = 0;
    {
        let mut sessions = state.sessions.lock().expect("session registry");
        for (user_id, action) in &highest_actions {
            match action {
                MitigationAction::StepUpAuth => {
                    for active in sessions.active.values_mut() {
                        if active.claims.user_id == *user_id
                            && !active.revoked
                            && !active.step_up_required
                        {
                            active.step_up_required = true;
                            step_up_sessions += 1;
                        }
                    }
                }
                MitigationAction::TerminateSession => {
                    for active in sessions.active.values_mut() {
                        if active.claims.user_id == *user_id && !active.revoked {
                            active.revoked = true;
                            terminated_sessions += 1;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let mut permissions_suspended = 0;
    let permissions_revoked = 0;
    {
        let mut permissions = state.permissions.lock().expect("permission registry");
        for (user_id, action) in &highest_actions {
            if *action == MitigationAction::SuspendPermissions {
                permissions_suspended += permissions.suspend_grants_for_user(user_id, None);
            }
        }
    }

    for alert in &alerts {
        phase2::append_phase2_audit(
            &state,
            &session,
            &request_context,
            ActionType::View,
            ActionResult::Success,
            &alert.alert_id,
            &format!(
                "ueba alert: {:?} -> {:?} ({})",
                alert.rule, alert.action, alert.evidence
            ),
            None,
        )
        .await;
    }

    Json(UebaAlertsResponse {
        alerts: alerts.iter().map(to_response).collect(),
        step_up_sessions,
        permissions_suspended,
        permissions_revoked,
        terminated_sessions,
    })
    .into_response()
}

async fn persistent_ueba_alerts_response(
    state: Arc<ApiState>,
    persistence: Arc<persistence::ApiPersistence>,
    request_context: RequestContext,
    session: AuthenticatedSession,
) -> Result<UebaAlertsResponse, persistence::PersistenceError> {
    let tenant_id = request_context.tenant_id.as_str().to_string();
    let alerts = persistence.load_ueba_alerts(&tenant_id).await?;

    phase2::append_phase2_audit(
        &state,
        &session,
        &request_context,
        ActionType::View,
        ActionResult::Success,
        "ueba-alerts",
        "ueba alerts viewed",
        Some(compute_sha256_hex(&tenant_id)),
    )
    .await;

    let highest_actions = highest_action_by_user(&alerts);
    Ok(UebaAlertsResponse {
        alerts: alerts.iter().map(to_response).collect(),
        step_up_sessions: highest_actions
            .values()
            .filter(|action| **action == MitigationAction::StepUpAuth)
            .count(),
        permissions_suspended: highest_actions
            .values()
            .filter(|action| **action == MitigationAction::SuspendPermissions)
            .count(),
        permissions_revoked: highest_actions
            .values()
            .filter(|action| **action == MitigationAction::TerminateSession)
            .count(),
        terminated_sessions: highest_actions
            .values()
            .filter(|action| **action == MitigationAction::TerminateSession)
            .count(),
    })
}

async fn persistent_ueba_baselines_response(
    state: Arc<ApiState>,
    persistence: Arc<persistence::ApiPersistence>,
    request_context: RequestContext,
    session: AuthenticatedSession,
) -> Result<UebaBaselinesResponse, persistence::PersistenceError> {
    let tenant_id = request_context.tenant_id.as_str().to_string();
    let user_baselines = persistence
        .load_ueba_user_baselines(&tenant_id)
        .await?
        .into_iter()
        .map(|baseline| UebaUserBaselineResponse {
            user_id: baseline.user_id,
            baseline_window: baseline.baseline_window,
            query_count: baseline.baseline.query_count,
            export_count: baseline.baseline.export_count,
            denied_count: baseline.baseline.denied_count,
        })
        .collect::<Vec<_>>();
    let entity_baselines = persistence
        .load_ueba_entity_baselines(&tenant_id)
        .await?
        .into_iter()
        .map(|baseline| {
            to_entity_baseline_response(
                baseline.entity_type,
                baseline.entity_id,
                baseline.baseline_window,
                baseline.baseline,
            )
        })
        .collect::<Vec<_>>();

    phase2::append_phase2_audit(
        &state,
        &session,
        &request_context,
        ActionType::View,
        ActionResult::Success,
        "ueba-baselines",
        "ueba baselines viewed",
        Some(compute_sha256_hex(&tenant_id)),
    )
    .await;

    Ok(UebaBaselinesResponse {
        user_baselines,
        entity_baselines,
    })
}

#[derive(Debug, Clone, Copy)]
enum UebaRuleStateChange {
    Activate,
    Enable,
    Disable,
    Retire,
}

async fn change_ueba_rule_state(
    state: Arc<ApiState>,
    request_context: RequestContext,
    session: AuthenticatedSession,
    rule_version_id: String,
    change: UebaRuleStateChange,
) -> Response {
    if !can_manage_ueba_governance(&session) {
        return ueba_json_error(
            StatusCode::FORBIDDEN,
            "system admin role required for ueba governance",
        );
    }

    let tenant_id = request_context.tenant_id.as_str();
    let result = if let Some(persistence) = state.persistence.as_ref() {
        match change {
            UebaRuleStateChange::Activate => {
                persistence
                    .activate_ueba_governance_rule(tenant_id, &rule_version_id)
                    .await
            }
            UebaRuleStateChange::Enable => {
                persistence
                    .set_ueba_governance_rule_enabled(tenant_id, &rule_version_id, true)
                    .await
            }
            UebaRuleStateChange::Disable => {
                persistence
                    .set_ueba_governance_rule_enabled(tenant_id, &rule_version_id, false)
                    .await
            }
            UebaRuleStateChange::Retire => {
                persistence
                    .retire_ueba_governance_rule(tenant_id, &rule_version_id)
                    .await
            }
        }
    } else {
        Ok(change_in_memory_rule_state(
            &state,
            tenant_id,
            &rule_version_id,
            change,
        ))
    };

    match result {
        Ok(Some(rule)) => {
            append_ueba_audit(
                &state,
                &session,
                &request_context,
                ActionType::ConfigChange,
                &rule.rule_version_id,
                &format!(
                    "ueba governance rule {}: {}",
                    rule_state_change_label(change),
                    rule.rule_name
                ),
            )
            .await;
            Json(rule).into_response()
        }
        Ok(None) => ueba_json_error(
            StatusCode::NOT_FOUND,
            "ueba governance rule version not found",
        ),
        Err(error) => ueba_persistence_error(error, "failed to change ueba governance rule state"),
    }
}

async fn load_or_seed_ueba_rules(
    state: &Arc<ApiState>,
    tenant_id: &str,
    actor_user_id: &str,
) -> Result<Vec<UebaGovernanceRuleResponse>, persistence::PersistenceError> {
    if let Some(persistence) = state.persistence.as_ref() {
        let mut rules = persistence.load_ueba_governance_rules(tenant_id).await?;
        if rules.is_empty() {
            for rule in default_ueba_governance_rules(&state.ueba, tenant_id, actor_user_id) {
                persistence.save_ueba_governance_rule(&rule).await?;
            }
            rules = persistence.load_ueba_governance_rules(tenant_id).await?;
        }
        return Ok(rules);
    }

    let mut runtime = state.ueba_governance.lock().expect("ueba governance");
    let rules = runtime
        .rules_by_tenant
        .entry(tenant_id.to_string())
        .or_insert_with(|| default_ueba_governance_rules(&state.ueba, tenant_id, actor_user_id));
    Ok(rules.clone())
}

fn default_ueba_governance_rules(
    settings: &UebaSettings,
    tenant_id: &str,
    actor_user_id: &str,
) -> Vec<UebaGovernanceRuleResponse> {
    [
        UebaRule::HighFrequencyQuery,
        UebaRule::ExportSpike,
        UebaRule::UnauthorizedQueryBurst,
        UebaRule::AfterHoursAccess,
        UebaRule::HiddenChannelDns,
        UebaRule::HiddenChannelHttp,
    ]
    .into_iter()
    .map(|rule| {
        let rule_name = ueba_rule_label(&rule).to_string();
        UebaGovernanceRuleResponse {
            rule_version_id: deterministic_rule_version_id(tenant_id, &rule_name, 1),
            tenant_id: tenant_id.to_string(),
            rule_name: rule_name.clone(),
            version: 1,
            status: "active".into(),
            enabled: true,
            threshold: default_rule_threshold(settings, &rule),
            risk_score: default_rule_risk_score(settings, &rule),
            mitigation_action: default_rule_mitigation_action(&rule).into(),
            description: Some("repo-local default governance rule".into()),
            tuning: BTreeMap::new(),
            base_rule_version_id: None,
            created_by: actor_user_id.to_string(),
            created_at: Utc::now(),
            activated_at: Some(Utc::now()),
            retired_at: None,
        }
    })
    .collect()
}

fn default_enabled() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn build_created_rule(
    settings: &UebaSettings,
    tenant_id: &str,
    actor_user_id: &str,
    request: UebaRuleCreateRequest,
    existing: &[UebaGovernanceRuleResponse],
) -> Result<UebaGovernanceRuleResponse, Box<Response>> {
    let rule = parse_ueba_rule_label(&request.rule_name).ok_or_else(|| {
        Box::new(ueba_json_error(
            StatusCode::BAD_REQUEST,
            "unknown ueba rule name",
        ))
    })?;
    let rule_name = ueba_rule_label(&rule).to_string();
    let version = next_rule_version(existing, &rule_name);
    let mitigation_action = match request.mitigation_action {
        Some(action) => parse_mitigation_action_label(&action)
            .and_then(|_| canonical_mitigation_action_label(&action).map(str::to_string))
            .ok_or_else(|| {
                Box::new(ueba_json_error(
                    StatusCode::BAD_REQUEST,
                    "unknown ueba mitigation action",
                ))
            })?,
        None => default_rule_mitigation_action(&rule).into(),
    };
    let mut tuning = BTreeMap::new();
    tuning.insert("source".into(), "manual-create".into());

    Ok(UebaGovernanceRuleResponse {
        rule_version_id: format!("ueba-rule-{}", ulid::Ulid::new()),
        tenant_id: tenant_id.to_string(),
        rule_name,
        version,
        status: if request.activate { "active" } else { "draft" }.into(),
        enabled: request.enabled,
        threshold: request
            .threshold
            .unwrap_or_else(|| default_rule_threshold(settings, &rule)),
        risk_score: request
            .risk_score
            .unwrap_or_else(|| default_rule_risk_score(settings, &rule)),
        mitigation_action,
        description: request.description,
        tuning,
        base_rule_version_id: None,
        created_by: actor_user_id.to_string(),
        created_at: Utc::now(),
        activated_at: request.activate.then(Utc::now),
        retired_at: None,
    })
}

fn build_tuned_rule(
    source: &UebaGovernanceRuleResponse,
    actor_user_id: &str,
    request: UebaRuleTuneRequest,
    existing: &[UebaGovernanceRuleResponse],
) -> UebaGovernanceRuleResponse {
    let mut tuning = BTreeMap::new();
    tuning.insert("source".into(), "manual-tune".into());
    tuning.insert(
        "base_rule_version_id".into(),
        source.rule_version_id.clone(),
    );
    if let Some(threshold) = request.threshold {
        tuning.insert("threshold".into(), threshold.to_string());
    }
    if let Some(risk_score) = request.risk_score {
        tuning.insert("risk_score".into(), risk_score.to_string());
    }
    if let Some(action) = &request.mitigation_action {
        tuning.insert("mitigation_action".into(), action.clone());
    }

    UebaGovernanceRuleResponse {
        rule_version_id: format!("ueba-rule-{}", ulid::Ulid::new()),
        tenant_id: source.tenant_id.clone(),
        rule_name: source.rule_name.clone(),
        version: next_rule_version(existing, &source.rule_name),
        status: if request.activate { "active" } else { "draft" }.into(),
        enabled: true,
        threshold: request.threshold.unwrap_or(source.threshold),
        risk_score: request.risk_score.unwrap_or(source.risk_score),
        mitigation_action: request
            .mitigation_action
            .and_then(|action| canonical_mitigation_action_label(&action).map(str::to_string))
            .unwrap_or_else(|| source.mitigation_action.clone()),
        description: request.description.or_else(|| source.description.clone()),
        tuning,
        base_rule_version_id: Some(source.rule_version_id.clone()),
        created_by: actor_user_id.to_string(),
        created_at: Utc::now(),
        activated_at: request.activate.then(Utc::now),
        retired_at: None,
    }
}

async fn save_rule_version(
    state: &Arc<ApiState>,
    rule: UebaGovernanceRuleResponse,
    activate: bool,
) -> Result<UebaGovernanceRuleResponse, persistence::PersistenceError> {
    if let Some(persistence) = state.persistence.as_ref() {
        persistence.save_ueba_governance_rule(&rule).await?;
        if activate {
            return persistence
                .activate_ueba_governance_rule(&rule.tenant_id, &rule.rule_version_id)
                .await?
                .ok_or_else(|| {
                    persistence::PersistenceError::Governance(
                        "created ueba rule was not found for activation".into(),
                    )
                });
        }
        return Ok(rule);
    }

    let mut runtime = state.ueba_governance.lock().expect("ueba governance");
    let rules = runtime
        .rules_by_tenant
        .entry(rule.tenant_id.clone())
        .or_default();
    rules.push(rule.clone());
    if activate {
        drop(runtime);
        return Ok(change_in_memory_rule_state(
            state,
            &rule.tenant_id,
            &rule.rule_version_id,
            UebaRuleStateChange::Activate,
        )
        .expect("created rule activation"));
    }
    Ok(rule)
}

fn change_in_memory_rule_state(
    state: &Arc<ApiState>,
    tenant_id: &str,
    rule_version_id: &str,
    change: UebaRuleStateChange,
) -> Option<UebaGovernanceRuleResponse> {
    let mut runtime = state.ueba_governance.lock().expect("ueba governance");
    let rules = runtime.rules_by_tenant.get_mut(tenant_id)?;
    let index = rules
        .iter()
        .position(|rule| rule.rule_version_id == rule_version_id)?;
    let rule_name = rules[index].rule_name.clone();
    let now = Utc::now();
    match change {
        UebaRuleStateChange::Activate => {
            for rule in rules.iter_mut() {
                if rule.rule_name == rule_name
                    && rule.rule_version_id != rule_version_id
                    && rule.status == "active"
                {
                    rule.status = "retired".into();
                    rule.enabled = false;
                    rule.retired_at = Some(now);
                }
            }
            rules[index].status = "active".into();
            rules[index].enabled = true;
            rules[index].activated_at = Some(now);
            rules[index].retired_at = None;
        }
        UebaRuleStateChange::Enable => {
            if rules[index].status != "retired" {
                rules[index].enabled = true;
            }
        }
        UebaRuleStateChange::Disable => {
            rules[index].enabled = false;
        }
        UebaRuleStateChange::Retire => {
            rules[index].status = "retired".into();
            rules[index].enabled = false;
            rules[index].retired_at = Some(now);
        }
    }
    Some(rules[index].clone())
}

async fn run_ueba_replay(
    state: Arc<ApiState>,
    request_context: &RequestContext,
    session: &AuthenticatedSession,
    request: UebaReplayRequest,
) -> Result<UebaReplayRunResponse, Response> {
    let tenant_id = request_context.tenant_id.as_str();
    let rules = load_or_seed_ueba_rules(&state, tenant_id, &session.claims.user_id)
        .await
        .map_err(|error| ueba_persistence_error(error, "failed to load ueba governance rules"))?;
    let selected_rules = select_replay_rules(&rules, &request).map_err(|response| *response)?;
    let audit_events = load_governance_audit_events(&state, tenant_id).await?;
    let signal_events = filter_ueba_signal_events(&audit_events);
    let baselines = build_user_baselines(&signal_events);
    let replay = replay_ueba_rules(
        &signal_events,
        &baselines,
        &governance_rules_to_core(&selected_rules),
    );
    let now = Utc::now();
    let run = UebaReplayRunResponse {
        run_id: format!("ueba-replay-{}", ulid::Ulid::new()),
        tenant_id: tenant_id.to_string(),
        requested_rule_version_id: request.rule_version_id,
        state: "completed".into(),
        event_count: replay.event_count,
        hit_count: replay.hit_count,
        alert_count: replay.alert_count,
        hits: replay_hits_to_responses(&replay),
        alerts: replay.alerts.iter().map(to_response).collect(),
        summary: replay_summary_response(&replay),
        created_by: session.claims.user_id.clone(),
        created_at: now,
        completed_at: Some(now),
    };
    save_ueba_replay_run(&state, run.clone()).await?;
    append_ueba_audit(
        &state,
        session,
        request_context,
        ActionType::View,
        &run.run_id,
        "ueba replay completed",
    )
    .await;
    Ok(run)
}

async fn load_governance_audit_events(
    state: &Arc<ApiState>,
    tenant_id: &str,
) -> Result<Vec<AuditEvent>, Response> {
    if let Some(persistence) = state.persistence.as_ref() {
        return persistence
            .load_tenant_audit_events(tenant_id)
            .await
            .map_err(|error| ueba_persistence_error(error, "failed to load replay audit events"));
    }

    Ok(state.audit.lock().expect("audit").tenant_events(tenant_id))
}

fn select_replay_rules(
    rules: &[UebaGovernanceRuleResponse],
    request: &UebaReplayRequest,
) -> Result<Vec<UebaGovernanceRuleResponse>, Box<Response>> {
    let selected = rules
        .iter()
        .filter(|rule| {
            request
                .rule_version_id
                .as_ref()
                .map(|id| &rule.rule_version_id == id)
                .unwrap_or(true)
        })
        .filter(|rule| {
            request
                .rule_name
                .as_ref()
                .map(|name| rule.rule_name.eq_ignore_ascii_case(name))
                .unwrap_or(true)
        })
        .cloned()
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Err(Box::new(ueba_json_error(
            StatusCode::NOT_FOUND,
            "no ueba governance rule matched replay request",
        )));
    }
    Ok(selected)
}

async fn load_ueba_replay_run(
    state: &Arc<ApiState>,
    tenant_id: &str,
    run_id: &str,
) -> Result<Option<UebaReplayRunResponse>, persistence::PersistenceError> {
    if let Some(persistence) = state.persistence.as_ref() {
        return persistence.load_ueba_replay_run(tenant_id, run_id).await;
    }

    Ok(state
        .ueba_governance
        .lock()
        .expect("ueba governance")
        .replay_runs
        .get(run_id)
        .filter(|run| run.tenant_id == tenant_id)
        .cloned())
}

async fn save_ueba_replay_run(
    state: &Arc<ApiState>,
    run: UebaReplayRunResponse,
) -> Result<(), Response> {
    if let Some(persistence) = state.persistence.as_ref() {
        return persistence
            .save_ueba_replay_run(&run)
            .await
            .map_err(|error| ueba_persistence_error(error, "failed to persist ueba replay run"));
    }

    state
        .ueba_governance
        .lock()
        .expect("ueba governance")
        .replay_runs
        .insert(run.run_id.clone(), run);
    Ok(())
}

async fn build_tuning_proposal(
    state: &Arc<ApiState>,
    tenant_id: &str,
    actor_user_id: &str,
    request: UebaTuningProposalRequest,
) -> Result<UebaTuningProposalResponse, Response> {
    let rules = load_or_seed_ueba_rules(state, tenant_id, actor_user_id)
        .await
        .map_err(|error| ueba_persistence_error(error, "failed to load ueba governance rules"))?;
    let replay = if let Some(run_id) = request.replay_run_id.as_ref() {
        load_ueba_replay_run(state, tenant_id, run_id)
            .await
            .map_err(|error| ueba_persistence_error(error, "failed to load ueba replay run"))?
            .ok_or_else(|| ueba_json_error(StatusCode::NOT_FOUND, "ueba replay run not found"))?
    } else {
        let replay_request = UebaReplayRequest {
            rule_version_id: request.rule_version_id.clone(),
            rule_name: request.rule_name.clone(),
        };
        let synthetic_session = AuthenticatedSession {
            claims: session_claims_for_actor(actor_user_id, tenant_id),
            roles: vec![Role::SystemAdmin],
        };
        let synthetic_context = RequestContext::new(
            sdqp_core::TenantId::new(tenant_id).expect("tenant"),
            sdqp_core::UserId::new(actor_user_id).expect("user"),
        );
        run_ueba_replay(
            state.clone(),
            &synthetic_context,
            &synthetic_session,
            replay_request,
        )
        .await?
    };

    let source =
        select_tuning_source_rule(&rules, &request, &replay).map_err(|response| *response)?;
    let target_volume = request.target_hit_rate_per_1000.map(|rate| {
        ((replay.event_count as u128 * rate as u128) / 1_000)
            .try_into()
            .unwrap_or(usize::MAX)
    });
    let core_rules = governance_rules_to_core(std::slice::from_ref(&source));
    let core_replay = replay_response_to_core_summary(&replay);
    let core_proposal = propose_rule_tuning(
        &core_replay,
        &core_rules,
        &UebaTuningObjective {
            target_alert_volume: target_volume,
            target_precision: None,
        },
    )
    .into_iter()
    .next();

    let observed_hits = replay
        .summary
        .hit_count_by_rule
        .get(&source.rule_name)
        .copied()
        .unwrap_or_default();
    let proposed_threshold = core_proposal
        .as_ref()
        .map(|proposal| proposal.proposed_tuning.thresholds.min_events as u32)
        .unwrap_or_else(|| {
            let delta = request.threshold_delta.unwrap_or_else(|| {
                if target_volume
                    .map(|target| observed_hits > target)
                    .unwrap_or(false)
                {
                    1
                } else {
                    0
                }
            });
            apply_threshold_delta(source.threshold, delta)
        });
    let proposed_risk_score = core_proposal
        .as_ref()
        .map(|proposal| proposal.proposed_tuning.thresholds.risk_score)
        .unwrap_or(source.risk_score);
    let proposed_mitigation_action = request
        .mitigation_action
        .as_deref()
        .and_then(canonical_mitigation_action_label)
        .map(str::to_string)
        .or_else(|| {
            core_proposal
                .as_ref()
                .and_then(|proposal| proposal.proposed_tuning.action_override.as_ref())
                .map(|action| format!("{action:?}"))
        })
        .unwrap_or_else(|| source.mitigation_action.clone());

    Ok(UebaTuningProposalResponse {
        proposal_id: format!("ueba-tuning-{}", ulid::Ulid::new()),
        tenant_id: tenant_id.to_string(),
        replay_run_id: Some(replay.run_id),
        source_rule_version_id: source.rule_version_id.clone(),
        rule_name: source.rule_name.clone(),
        proposed_threshold,
        proposed_risk_score,
        proposed_mitigation_action,
        target_hit_rate_per_1000: request.target_hit_rate_per_1000,
        rationale: core_proposal
            .map(|proposal| proposal.rationale)
            .filter(|rationale| !rationale.is_empty())
            .unwrap_or_else(|| "manual tuning objective applied to replay result".into()),
        status: "proposed".into(),
        created_by: actor_user_id.to_string(),
        created_at: Utc::now(),
        applied_rule_version_id: None,
        applied_at: None,
    })
}

fn session_claims_for_actor(
    actor_user_id: &str,
    tenant_id: &str,
) -> sdqp_system_security::SessionClaims {
    let request_context = RequestContext::new(
        sdqp_core::TenantId::new(tenant_id).expect("tenant"),
        sdqp_core::UserId::new(actor_user_id).expect("user"),
    );
    sdqp_system_security::SessionPolicy { ttl_minutes: 15 }.issue(
        &request_context,
        sdqp_system_security::SessionBinding {
            ip_address: "127.0.0.1".into(),
            device_fingerprint: "ueba-governance-runtime".into(),
        },
    )
}

fn select_tuning_source_rule(
    rules: &[UebaGovernanceRuleResponse],
    request: &UebaTuningProposalRequest,
    replay: &UebaReplayRunResponse,
) -> Result<UebaGovernanceRuleResponse, Box<Response>> {
    rules
        .iter()
        .find(|rule| {
            request
                .rule_version_id
                .as_ref()
                .map(|id| &rule.rule_version_id == id)
                .unwrap_or(true)
        })
        .filter(|rule| {
            request
                .rule_name
                .as_ref()
                .map(|name| rule.rule_name.eq_ignore_ascii_case(name))
                .unwrap_or(true)
        })
        .or_else(|| {
            replay
                .summary
                .hit_count_by_rule
                .keys()
                .next()
                .and_then(|rule_name| rules.iter().find(|rule| &rule.rule_name == rule_name))
        })
        .or_else(|| {
            rules
                .iter()
                .find(|rule| rule.status == "active" && rule.enabled)
        })
        .cloned()
        .ok_or_else(|| {
            Box::new(ueba_json_error(
                StatusCode::NOT_FOUND,
                "ueba tuning source rule not found",
            ))
        })
}

async fn save_tuning_proposal(
    state: &Arc<ApiState>,
    proposal: UebaTuningProposalResponse,
) -> Result<UebaTuningProposalResponse, persistence::PersistenceError> {
    if let Some(persistence) = state.persistence.as_ref() {
        persistence.save_ueba_tuning_proposal(&proposal).await?;
        return Ok(proposal);
    }

    state
        .ueba_governance
        .lock()
        .expect("ueba governance")
        .tuning_proposals
        .insert(proposal.proposal_id.clone(), proposal.clone());
    Ok(proposal)
}

async fn load_tuning_proposal(
    state: &Arc<ApiState>,
    tenant_id: &str,
    proposal_id: &str,
) -> Result<Option<UebaTuningProposalResponse>, persistence::PersistenceError> {
    if let Some(persistence) = state.persistence.as_ref() {
        return persistence
            .load_ueba_tuning_proposal(tenant_id, proposal_id)
            .await;
    }

    Ok(state
        .ueba_governance
        .lock()
        .expect("ueba governance")
        .tuning_proposals
        .get(proposal_id)
        .filter(|proposal| proposal.tenant_id == tenant_id)
        .cloned())
}

async fn apply_tuning_proposal(
    state: &Arc<ApiState>,
    tenant_id: &str,
    actor_user_id: &str,
    proposal_id: &str,
    activate: bool,
) -> Result<UebaTuningProposalApplyResponse, Response> {
    let mut proposal = load_tuning_proposal(state, tenant_id, proposal_id)
        .await
        .map_err(|error| ueba_persistence_error(error, "failed to load ueba tuning proposal"))?
        .ok_or_else(|| ueba_json_error(StatusCode::NOT_FOUND, "ueba tuning proposal not found"))?;
    if proposal.applied_rule_version_id.is_some() {
        return Err(ueba_json_error(
            StatusCode::CONFLICT,
            "ueba tuning proposal already applied",
        ));
    }
    let rules = load_or_seed_ueba_rules(state, tenant_id, actor_user_id)
        .await
        .map_err(|error| ueba_persistence_error(error, "failed to load ueba governance rules"))?;
    let source = rules
        .iter()
        .find(|rule| rule.rule_version_id == proposal.source_rule_version_id)
        .cloned()
        .ok_or_else(|| ueba_json_error(StatusCode::NOT_FOUND, "source ueba rule not found"))?;
    let rule = build_tuned_rule(
        &source,
        actor_user_id,
        UebaRuleTuneRequest {
            threshold: Some(proposal.proposed_threshold),
            risk_score: Some(proposal.proposed_risk_score),
            mitigation_action: Some(proposal.proposed_mitigation_action.clone()),
            activate,
            description: Some(format!(
                "applied from tuning proposal {}",
                proposal.proposal_id
            )),
        },
        &rules,
    );
    let applied_rule = save_rule_version(state, rule, activate)
        .await
        .map_err(|error| ueba_persistence_error(error, "failed to apply ueba tuning proposal"))?;
    proposal.applied_rule_version_id = Some(applied_rule.rule_version_id.clone());
    proposal.applied_at = Some(Utc::now());
    proposal.status = "applied".into();
    save_tuning_proposal(state, proposal.clone())
        .await
        .map_err(|error| {
            ueba_persistence_error(error, "failed to persist applied tuning proposal")
        })?;
    Ok(UebaTuningProposalApplyResponse {
        proposal,
        applied_rule,
    })
}

async fn run_ueba_calibration(
    state: Arc<ApiState>,
    request_context: &RequestContext,
    session: &AuthenticatedSession,
    request: UebaCalibrationRequest,
) -> Result<UebaCalibrationRunResponse, Response> {
    if !state.ueba.calibration.enabled {
        return Err(ueba_json_error(
            StatusCode::CONFLICT,
            "ueba calibration is disabled by configuration",
        ));
    }
    let tenant_id = request_context.tenant_id.as_str();
    let audit_events = load_governance_audit_events(&state, tenant_id).await?;
    let signal_events = filter_ueba_signal_events(&audit_events);
    if signal_events.len() < state.ueba.calibration.min_events {
        return Err(ueba_json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "not enough ueba signal events for calibration",
        ));
    }
    let mut result = calibrate_ueba_rules(&signal_events);
    if let Some(model_version) = request.model_version {
        result.model_version = model_version;
    } else {
        result.model_version = state.ueba.calibration.model_version.clone();
    }
    let now = Utc::now();
    let run = UebaCalibrationRunResponse {
        calibration_id: format!("ueba-calibration-{}", ulid::Ulid::new()),
        tenant_id: tenant_id.to_string(),
        status: format!("{:?}", result.status),
        model_version: result.model_version.clone(),
        event_count: result.sample_count,
        rule_count: result.recommendations.len(),
        result: calibration_result_response(&result),
        created_by: session.claims.user_id.clone(),
        created_at: now,
        completed_at: Some(now),
    };
    save_calibration_run(&state, run.clone()).await?;
    append_ueba_audit(
        &state,
        session,
        request_context,
        ActionType::ConfigChange,
        &run.calibration_id,
        "ueba calibration completed",
    )
    .await;
    Ok(run)
}

async fn load_calibration_run(
    state: &Arc<ApiState>,
    tenant_id: &str,
    calibration_id: &str,
) -> Result<Option<UebaCalibrationRunResponse>, persistence::PersistenceError> {
    if let Some(persistence) = state.persistence.as_ref() {
        return persistence
            .load_ueba_calibration_run(tenant_id, calibration_id)
            .await;
    }

    Ok(state
        .ueba_governance
        .lock()
        .expect("ueba governance")
        .calibration_runs
        .get(calibration_id)
        .filter(|run| run.tenant_id == tenant_id)
        .cloned())
}

async fn save_calibration_run(
    state: &Arc<ApiState>,
    run: UebaCalibrationRunResponse,
) -> Result<(), Response> {
    if let Some(persistence) = state.persistence.as_ref() {
        return persistence
            .save_ueba_calibration_run(&run)
            .await
            .map_err(|error| {
                ueba_persistence_error(error, "failed to persist ueba calibration run")
            });
    }

    state
        .ueba_governance
        .lock()
        .expect("ueba governance")
        .calibration_runs
        .insert(run.calibration_id.clone(), run);
    Ok(())
}

fn governance_rules_to_core(rules: &[UebaGovernanceRuleResponse]) -> Vec<UebaRuleDefinition> {
    let mut grouped: BTreeMap<String, UebaRuleDefinition> = BTreeMap::new();
    for rule in rules {
        let Some(ueba_rule) = parse_ueba_rule_label(&rule.rule_name) else {
            continue;
        };
        let status = if rule.status == "retired" {
            UebaRuleStatus::Retired
        } else if !rule.enabled {
            UebaRuleStatus::Disabled
        } else if rule.status == "active" {
            UebaRuleStatus::Active
        } else {
            UebaRuleStatus::Draft
        };
        let definition =
            grouped
                .entry(rule.rule_name.clone())
                .or_insert_with(|| UebaRuleDefinition {
                    rule_id: ueba_rule.rule_id().to_string(),
                    rule: ueba_rule.clone(),
                    name: rule.rule_name.clone(),
                    description: rule.description.clone().unwrap_or_default(),
                    versions: Vec::new(),
                });
        definition.versions.push(UebaRuleVersion {
            version: rule.version,
            status,
            tuning: governance_rule_tuning(rule, &ueba_rule),
        });
    }
    grouped.into_values().collect()
}

fn governance_rule_tuning(
    rule: &UebaGovernanceRuleResponse,
    ueba_rule: &UebaRule,
) -> UebaRuleTuning {
    let (baseline_multiplier, baseline_offset) = match ueba_rule {
        UebaRule::HighFrequencyQuery => (2.0, 0),
        UebaRule::ExportSpike => (1.0, 1),
        _ => (0.0, 0),
    };
    UebaRuleTuning {
        thresholds: UebaRuleThresholds {
            min_events: rule.threshold as usize,
            baseline_multiplier,
            baseline_offset,
            risk_score: rule.risk_score,
            business_hours_start_utc: Some(6),
            business_hours_end_utc: Some(22),
        },
        action_override: parse_mitigation_action_label(&rule.mitigation_action),
        pattern: match ueba_rule {
            UebaRule::HiddenChannelDns => Some(UebaRulePattern {
                any_terms: vec!["dns://".into(), " txt ".into(), "base32".into()],
                all_terms: Vec::new(),
            }),
            UebaRule::HiddenChannelHttp => Some(UebaRulePattern {
                any_terms: vec!["http://".into(), "https://".into()],
                all_terms: vec!["chunk=".into()],
            }),
            _ => None,
        },
    }
}

fn replay_hits_to_responses(replay: &UebaReplaySummary) -> Vec<UebaAlertResponse> {
    replay
        .hits
        .iter()
        .map(|hit| UebaAlertResponse {
            alert_id: format!("hit-{}-{}-{}", hit.rule_id, hit.version, hit.user_id),
            user_id: hit.user_id.clone(),
            rule: ueba_rule_label(&hit.rule).to_string(),
            risk_score: hit.risk_score,
            action: format!("{:?}", hit.action),
            evidence: hit.evidence.clone(),
        })
        .collect()
}

fn replay_summary_response(replay: &UebaReplaySummary) -> UebaReplaySummaryResponse {
    let mut hit_count_by_rule = BTreeMap::new();
    let mut alert_count_by_action = BTreeMap::new();
    for hit in &replay.hits {
        *hit_count_by_rule
            .entry(ueba_rule_label(&hit.rule).to_string())
            .or_insert(0) += 1;
        *alert_count_by_action
            .entry(format!("{:?}", hit.action))
            .or_insert(0) += 1;
    }
    UebaReplaySummaryResponse {
        events_replayed: replay.event_count,
        rules_evaluated: replay.rules_evaluated,
        hit_count_by_rule,
        alert_count_by_action,
    }
}

fn replay_response_to_core_summary(run: &UebaReplayRunResponse) -> UebaReplaySummary {
    UebaReplaySummary {
        event_count: run.event_count,
        users_evaluated: 0,
        rules_evaluated: run.summary.rules_evaluated,
        hit_count: run.hit_count,
        alert_count: run.alert_count,
        rule_summaries: Vec::new(),
        hits: Vec::new(),
        alerts: run
            .alerts
            .iter()
            .filter_map(|alert| response_to_alert(alert, &run.tenant_id))
            .collect(),
    }
}

fn response_to_alert(alert: &UebaAlertResponse, tenant_id: &str) -> Option<UebaAlert> {
    Some(UebaAlert {
        alert_id: alert.alert_id.clone(),
        user_id: alert.user_id.clone(),
        tenant_id: tenant_id.to_string(),
        project_id: None,
        rule: parse_ueba_rule_label(&alert.rule)?,
        risk_score: alert.risk_score,
        action: parse_mitigation_action_label(&alert.action)?,
        evidence: alert.evidence.clone(),
    })
}

fn calibration_result_response(result: &UebaCalibrationResult) -> UebaCalibrationResultResponse {
    let mut recommended_thresholds = BTreeMap::new();
    let mut observed_counts = BTreeMap::new();
    for recommendation in &result.recommendations {
        recommended_thresholds.insert(
            ueba_rule_label(&recommendation.rule).to_string(),
            recommendation.recommended_thresholds.min_events as u32,
        );
        observed_counts.insert(
            ueba_rule_label(&recommendation.rule).to_string(),
            recommendation.sample_p95,
        );
    }
    UebaCalibrationResultResponse {
        runtime_mode: "repo_local_statistical".into(),
        deterministic: true,
        external_final_uat_required: false,
        recommended_thresholds,
        observed_counts,
        summary: format!(
            "{} samples across {} users, quality {:.2}, status {:?}",
            result.sample_count, result.distinct_users, result.quality_score, result.status
        ),
    }
}

fn can_manage_ueba_governance(session: &AuthenticatedSession) -> bool {
    session
        .roles
        .iter()
        .any(|role| matches!(role, Role::SystemAdmin | Role::Auditor))
}

async fn append_ueba_audit(
    state: &Arc<ApiState>,
    session: &AuthenticatedSession,
    request_context: &RequestContext,
    action: ActionType,
    resource_id: &str,
    context: &str,
) {
    phase2::append_phase2_audit(
        state,
        session,
        request_context,
        action,
        ActionResult::Success,
        resource_id,
        context,
        Some(compute_sha256_hex(context)),
    )
    .await
}

fn ueba_json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn ueba_persistence_error(error: persistence::PersistenceError, message: &str) -> Response {
    tracing::error!(?error, "{message}");
    ueba_json_error(StatusCode::INTERNAL_SERVER_ERROR, message)
}

fn ueba_rule_label(rule: &UebaRule) -> &'static str {
    match rule {
        UebaRule::HighFrequencyQuery => "HighFrequencyQuery",
        UebaRule::ExportSpike => "ExportSpike",
        UebaRule::UnauthorizedQueryBurst => "UnauthorizedQueryBurst",
        UebaRule::AfterHoursAccess => "AfterHoursAccess",
        UebaRule::HiddenChannelDns => "HiddenChannelDns",
        UebaRule::HiddenChannelHttp => "HiddenChannelHttp",
    }
}

fn parse_ueba_rule_label(label: &str) -> Option<UebaRule> {
    match label.trim().to_ascii_lowercase().as_str() {
        "highfrequencyquery" | "high_frequency_query" => Some(UebaRule::HighFrequencyQuery),
        "exportspike" | "export_spike" => Some(UebaRule::ExportSpike),
        "unauthorizedqueryburst" | "unauthorized_query_burst" => {
            Some(UebaRule::UnauthorizedQueryBurst)
        }
        "afterhoursaccess" | "after_hours_access" => Some(UebaRule::AfterHoursAccess),
        "hiddenchanneldns" | "hidden_channel_dns" => Some(UebaRule::HiddenChannelDns),
        "hiddenchannelhttp" | "hidden_channel_http" => Some(UebaRule::HiddenChannelHttp),
        _ => None,
    }
}

fn parse_mitigation_action_label(label: &str) -> Option<MitigationAction> {
    match label.trim().to_ascii_lowercase().as_str() {
        "observe" => Some(MitigationAction::Observe),
        "stepupauth" | "step_up_auth" => Some(MitigationAction::StepUpAuth),
        "suspendpermissions" | "suspend_permissions" => Some(MitigationAction::SuspendPermissions),
        "terminatesession" | "terminate_session" => Some(MitigationAction::TerminateSession),
        _ => None,
    }
}

fn canonical_mitigation_action_label(label: &str) -> Option<&'static str> {
    Some(match parse_mitigation_action_label(label)? {
        MitigationAction::Observe => "Observe",
        MitigationAction::StepUpAuth => "StepUpAuth",
        MitigationAction::SuspendPermissions => "SuspendPermissions",
        MitigationAction::TerminateSession => "TerminateSession",
    })
}

fn default_rule_threshold(settings: &UebaSettings, rule: &UebaRule) -> u32 {
    match rule {
        UebaRule::HighFrequencyQuery => settings.governance.query_burst_threshold,
        UebaRule::ExportSpike => settings.governance.export_spike_threshold,
        UebaRule::UnauthorizedQueryBurst => settings.governance.denied_query_threshold,
        UebaRule::AfterHoursAccess | UebaRule::HiddenChannelDns | UebaRule::HiddenChannelHttp => 1,
    }
}

fn default_rule_risk_score(settings: &UebaSettings, rule: &UebaRule) -> u8 {
    match rule {
        UebaRule::HighFrequencyQuery => 58,
        UebaRule::AfterHoursAccess => 44,
        UebaRule::UnauthorizedQueryBurst => settings.governance.high_risk_score.max(70),
        UebaRule::ExportSpike | UebaRule::HiddenChannelDns | UebaRule::HiddenChannelHttp => {
            settings.governance.critical_risk_score.max(90)
        }
    }
}

fn default_rule_mitigation_action(rule: &UebaRule) -> &'static str {
    match rule {
        UebaRule::HighFrequencyQuery => "StepUpAuth",
        UebaRule::AfterHoursAccess => "Observe",
        UebaRule::UnauthorizedQueryBurst => "SuspendPermissions",
        UebaRule::ExportSpike | UebaRule::HiddenChannelDns | UebaRule::HiddenChannelHttp => {
            "TerminateSession"
        }
    }
}

fn deterministic_rule_version_id(tenant_id: &str, rule_name: &str, version: u32) -> String {
    let rule = rule_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    format!("ueba-rule-{tenant_id}-{rule}-v{version}")
}

fn next_rule_version(existing: &[UebaGovernanceRuleResponse], rule_name: &str) -> u32 {
    existing
        .iter()
        .filter(|rule| rule.rule_name == rule_name)
        .map(|rule| rule.version)
        .max()
        .unwrap_or(0)
        + 1
}

fn rule_state_change_label(change: UebaRuleStateChange) -> &'static str {
    match change {
        UebaRuleStateChange::Activate => "activated",
        UebaRuleStateChange::Enable => "enabled",
        UebaRuleStateChange::Disable => "disabled",
        UebaRuleStateChange::Retire => "retired",
    }
}

fn apply_threshold_delta(current: u32, delta: i32) -> u32 {
    if delta.is_negative() {
        current.saturating_sub(delta.unsigned_abs()).max(1)
    } else {
        current.saturating_add(delta as u32).max(1)
    }
}

fn tenant_audit_events(state: &Arc<ApiState>, request_context: &RequestContext) -> Vec<AuditEvent> {
    state
        .audit
        .lock()
        .expect("audit")
        .tenant_events(request_context.tenant_id.as_str())
}

fn filter_ueba_signal_events(events: &[AuditEvent]) -> Vec<AuditEvent> {
    events
        .iter()
        .filter(|event| !is_control_plane_observability_event(event))
        .cloned()
        .collect()
}

fn is_control_plane_observability_event(event: &AuditEvent) -> bool {
    match event.action {
        ActionType::Query => {
            if event.result != ActionResult::Success {
                return false;
            }

            !matches!(
                event.context.as_str(),
                "query submitted"
                    | "query completed from encrypted snapshot cache"
                    | "query completed from persisted cache"
            )
        }
        ActionType::Export => false,
        ActionType::View => {
            matches!(
                event.target.resource_id.as_str(),
                "project-context"
                    | "projects"
                    | "ueba-alerts"
                    | "ueba-baselines"
                    | "audit/events/search"
            ) || event.context.starts_with("ueba alert:")
        }
        _ => true,
    }
}

fn roles_by_user(state: &Arc<ApiState>) -> HashMap<String, Vec<String>> {
    state
        .users
        .lock()
        .expect("users")
        .values()
        .map(|user| {
            (
                user.user_id.clone(),
                user.roles
                    .iter()
                    .map(|role| format!("{role:?}").to_ascii_lowercase())
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

async fn apply_persistent_mitigations(
    state: &Arc<ApiState>,
    persistence: &Arc<persistence::ApiPersistence>,
    alerts: &[UebaAlert],
) -> Result<MitigationStats, persistence::PersistenceError> {
    let highest_actions = highest_action_by_user(alerts);
    let mut stats = MitigationStats::default();
    let mut sessions_to_save = Vec::new();

    {
        let mut sessions = state.sessions.lock().expect("session registry");
        for (user_id, action) in &highest_actions {
            match action {
                MitigationAction::StepUpAuth => {
                    for active in sessions.active.values_mut() {
                        if active.claims.user_id == *user_id
                            && !active.revoked
                            && !active.step_up_required
                        {
                            active.step_up_required = true;
                            stats.step_up_sessions += 1;
                            sessions_to_save.push(active.clone());
                        }
                    }
                }
                MitigationAction::TerminateSession => {
                    for active in sessions.active.values_mut() {
                        if active.claims.user_id == *user_id && !active.revoked {
                            active.revoked = true;
                            active.step_up_required = false;
                            stats.terminated_sessions += 1;
                            sessions_to_save.push(active.clone());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    for active in sessions_to_save {
        persistence.save_active_session(&active).await?;
    }

    for alert in alerts {
        match alert.action {
            MitigationAction::SuspendPermissions => {
                let transitions = crate::stage7_governance::apply_audit_permission_signal_for_user(
                    state.clone(),
                    &alert.user_id,
                    alert.project_id.as_deref(),
                    GrantLifecycleTrigger::AuditAnomaly,
                    Some(&alert.alert_id),
                    &format!("UEBA {:?}: {}", alert.rule, alert.evidence),
                )
                .await?;
                stats.permissions_suspended += transitions
                    .iter()
                    .filter(|transition| transition.to_status == GrantStatus::Suspended)
                    .count();
            }
            MitigationAction::TerminateSession => {
                let transitions = crate::stage7_governance::apply_audit_permission_signal_for_user(
                    state.clone(),
                    &alert.user_id,
                    alert.project_id.as_deref(),
                    GrantLifecycleTrigger::AuditConfirmedCompromise,
                    Some(&alert.alert_id),
                    &format!("UEBA {:?}: {}", alert.rule, alert.evidence),
                )
                .await?;
                stats.permissions_revoked += transitions
                    .iter()
                    .filter(|transition| transition.to_status == GrantStatus::Revoked)
                    .count();
            }
            _ => {}
        }
    }

    Ok(stats)
}

fn highest_action_by_user(alerts: &[UebaAlert]) -> HashMap<String, MitigationAction> {
    let mut actions: HashMap<String, MitigationAction> = HashMap::new();
    for alert in alerts {
        actions
            .entry(alert.user_id.clone())
            .and_modify(|current| {
                if alert.action.severity() > current.severity() {
                    *current = alert.action.clone();
                }
            })
            .or_insert_with(|| alert.action.clone());
    }
    actions
}

pub(crate) fn alert_signature(alert: &UebaAlert) -> String {
    format!(
        "{}|{:?}|{}|{}",
        alert.user_id, alert.rule, alert.risk_score, alert.evidence
    )
}

fn to_response(alert: &UebaAlert) -> UebaAlertResponse {
    UebaAlertResponse {
        alert_id: alert.alert_id.clone(),
        user_id: alert.user_id.clone(),
        rule: format!("{:?}", alert.rule),
        risk_score: alert.risk_score,
        action: format!("{:?}", alert.action),
        evidence: alert.evidence.clone(),
    }
}

fn to_entity_baseline_response(
    entity_type: String,
    entity_id: String,
    baseline_window: String,
    baseline: EntityBaseline,
) -> UebaEntityBaselineResponse {
    UebaEntityBaselineResponse {
        entity_type,
        entity_id,
        baseline_window,
        query_count: baseline.query_count,
        export_count: baseline.export_count,
        denied_count: baseline.denied_count,
        distinct_users: baseline.distinct_users,
    }
}

#[cfg(test)]
mod tests {
    use sdqp_audit::{ActionResult, ActionType, ActorInfo, AuditEvent, TargetRef};
    use sdqp_ueba::{MitigationAction, UebaAlert, UebaRule};

    use super::{
        alert_signature, filter_ueba_signal_events, highest_action_by_user,
        is_control_plane_observability_event,
    };

    #[test]
    fn highest_action_prefers_stronger_mitigation_per_user() {
        let actions = highest_action_by_user(&[
            UebaAlert {
                alert_id: "1".into(),
                user_id: "user-a".into(),
                tenant_id: "tenant-alpha".into(),
                project_id: Some("project-alpha".into()),
                rule: UebaRule::HighFrequencyQuery,
                risk_score: 58,
                action: MitigationAction::StepUpAuth,
                evidence: "query burst".into(),
            },
            UebaAlert {
                alert_id: "2".into(),
                user_id: "user-a".into(),
                tenant_id: "tenant-alpha".into(),
                project_id: Some("project-alpha".into()),
                rule: UebaRule::ExportSpike,
                risk_score: 92,
                action: MitigationAction::TerminateSession,
                evidence: "export spike".into(),
            },
        ]);

        assert_eq!(
            actions.get("user-a"),
            Some(&MitigationAction::TerminateSession)
        );
    }

    #[test]
    fn alert_signature_is_stable_for_deduplication() {
        let alert = UebaAlert {
            alert_id: "1".into(),
            user_id: "user-a".into(),
            tenant_id: "tenant-alpha".into(),
            project_id: Some("project-alpha".into()),
            rule: UebaRule::HighFrequencyQuery,
            risk_score: 58,
            action: MitigationAction::StepUpAuth,
            evidence: "query burst".into(),
        };

        assert_eq!(
            alert_signature(&alert),
            "user-a|HighFrequencyQuery|58|query burst"
        );
    }

    fn audit_event(
        action: ActionType,
        result: ActionResult,
        resource_id: &str,
        context: &str,
    ) -> AuditEvent {
        AuditEvent::new(
            ActorInfo {
                user_id: "user-a".into(),
                session_id: "session-a".into(),
                ip_address: "127.0.0.1".into(),
            },
            action,
            TargetRef {
                tenant_id: "tenant-alpha".into(),
                project_id: Some("project-alpha".into()),
                resource_id: resource_id.into(),
            },
            context,
            result,
            None,
            None,
        )
    }

    #[test]
    fn control_plane_and_non_data_plane_events_are_excluded_from_ueba_signal_input() {
        assert!(is_control_plane_observability_event(&audit_event(
            ActionType::Login,
            ActionResult::Success,
            "auth/login",
            "mfa verified",
        )));
        assert!(is_control_plane_observability_event(&audit_event(
            ActionType::View,
            ActionResult::Success,
            "project-context",
            "project access granted",
        )));
        assert!(is_control_plane_observability_event(&audit_event(
            ActionType::View,
            ActionResult::Success,
            "ueba-alerts",
            "ueba alerts viewed",
        )));
        assert!(is_control_plane_observability_event(&audit_event(
            ActionType::View,
            ActionResult::Success,
            "ueba-baselines",
            "ueba baselines viewed",
        )));
        assert!(is_control_plane_observability_event(&audit_event(
            ActionType::View,
            ActionResult::Denied,
            "audit/events/search",
            "system admin role required for audit search",
        )));
        assert!(is_control_plane_observability_event(&audit_event(
            ActionType::View,
            ActionResult::Success,
            "alert-123",
            "ueba alert: HighFrequencyQuery -> StepUpAuth (query burst)",
        )));
        assert!(!is_control_plane_observability_event(&audit_event(
            ActionType::View,
            ActionResult::Success,
            "snapshot-123",
            "after hours access",
        )));
        assert!(!is_control_plane_observability_event(&audit_event(
            ActionType::Query,
            ActionResult::Success,
            "task-123",
            "query submitted",
        )));
        assert!(!is_control_plane_observability_event(&audit_event(
            ActionType::Query,
            ActionResult::Success,
            "task-124",
            "query completed from encrypted snapshot cache",
        )));
        assert!(!is_control_plane_observability_event(&audit_event(
            ActionType::Query,
            ActionResult::Success,
            "task-125",
            "query completed from persisted cache",
        )));
        assert!(is_control_plane_observability_event(&audit_event(
            ActionType::Query,
            ActionResult::Success,
            "snapshot-999",
            "encrypted snapshot persisted",
        )));
        assert!(is_control_plane_observability_event(&audit_event(
            ActionType::Query,
            ActionResult::Success,
            "task-126",
            "query completed by worker",
        )));
    }

    #[test]
    fn ueba_signal_filter_keeps_data_plane_events_only() {
        let filtered = filter_ueba_signal_events(&[
            audit_event(
                ActionType::Login,
                ActionResult::Success,
                "auth/login",
                "mfa verified",
            ),
            audit_event(
                ActionType::View,
                ActionResult::Success,
                "project-context",
                "project access granted",
            ),
            audit_event(
                ActionType::View,
                ActionResult::Success,
                "ueba-alerts",
                "ueba alerts viewed",
            ),
            audit_event(
                ActionType::View,
                ActionResult::Success,
                "alert-123",
                "ueba alert: HighFrequencyQuery -> StepUpAuth (query burst)",
            ),
            audit_event(
                ActionType::Query,
                ActionResult::Success,
                "task-123",
                "query submitted",
            ),
            audit_event(
                ActionType::Query,
                ActionResult::Success,
                "snapshot-999",
                "encrypted snapshot persisted",
            ),
            audit_event(
                ActionType::View,
                ActionResult::Success,
                "snapshot-123",
                "after hours access",
            ),
        ]);

        assert_eq!(filtered.len(), 2);
        assert!(
            filtered
                .iter()
                .any(|event| event.target.resource_id == "task-123")
        );
        assert!(
            filtered
                .iter()
                .any(|event| event.target.resource_id == "snapshot-123")
        );
    }
}
