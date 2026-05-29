use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Query as QueryParams, State},
    response::{IntoResponse, Response},
};
use sdqp_audit::{ActionResult, ActionType, AuditContextFields, AuditEvent};
use sdqp_core::RequestContext;
use sdqp_system_security::Role;
use serde::{Deserialize, Serialize};

use crate::{ApiState, AuthenticatedSession, json_error, phase2};
use axum::http::StatusCode;

const DEFAULT_SEARCH_LIMIT: usize = 25;
const MAX_SEARCH_LIMIT: usize = 100;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditSearchRequest {
    pub action: Option<String>,
    pub result: Option<String>,
    pub actor_user_id: Option<String>,
    pub resource_id_contains: Option<String>,
    pub include_projectless: Option<bool>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedAuditSearchRequest {
    action: Option<ActionType>,
    result: Option<ActionResult>,
    actor_user_id: Option<String>,
    resource_id_contains: Option<String>,
    include_projectless: bool,
    limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventResponse {
    pub event_id: String,
    pub timestamp: String,
    pub actor_user_id: String,
    pub action: String,
    pub result: String,
    pub tenant_id: String,
    pub project_id: Option<String>,
    pub resource_id: String,
    pub context: String,
    #[serde(default, skip_serializing_if = "AuditContextFields::is_empty")]
    pub context_fields: AuditContextFields,
    pub data_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSearchResponse {
    pub events: Vec<AuditEventResponse>,
    pub chain_valid: bool,
    pub total_matches: usize,
}

pub async fn audit_search_handler(
    State(state): State<Arc<ApiState>>,
    QueryParams(params): QueryParams<AuditSearchRequest>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    if !session.roles.iter().any(|role| role == &Role::SystemAdmin) {
        phase2::append_phase2_audit(
            &state,
            &session,
            &request_context,
            ActionType::View,
            ActionResult::Denied,
            "audit/events/search",
            "system admin role required for audit search",
            None,
        )
        .await;
        return json_error(StatusCode::FORBIDDEN, "system admin role required");
    }

    let filters = match normalize_search_request(params) {
        Ok(filters) => filters,
        Err(message) => {
            phase2::append_phase2_audit(
                &state,
                &session,
                &request_context,
                ActionType::View,
                ActionResult::Denied,
                "audit/events/search",
                message,
                None,
            )
            .await;
            return json_error(StatusCode::BAD_REQUEST, message);
        }
    };

    let (matched_events, chain_valid, total_matches) = {
        let audit = state.audit.lock().expect("audit");
        let mut matched_events = audit
            .scoped_events(
                request_context.tenant_id.as_str(),
                request_context
                    .project_id
                    .as_ref()
                    .map(|project_id| project_id.as_str()),
                filters.include_projectless,
            )
            .into_iter()
            .rev()
            .filter(|event| event_matches_filters(event, &filters))
            .collect::<Vec<_>>();
        let total_matches = matched_events.len();
        matched_events.truncate(filters.limit);
        (matched_events, audit.chain_valid(), total_matches)
    };

    phase2::append_phase2_audit(
        &state,
        &session,
        &request_context,
        ActionType::View,
        ActionResult::Success,
        "audit/events/search",
        &format!("audit search returned {total_matches} matching events"),
        None,
    )
    .await;

    Json(AuditSearchResponse {
        events: matched_events
            .iter()
            .map(AuditEventResponse::from)
            .collect(),
        chain_valid,
        total_matches,
    })
    .into_response()
}

fn normalize_search_request(
    request: AuditSearchRequest,
) -> Result<NormalizedAuditSearchRequest, &'static str> {
    Ok(NormalizedAuditSearchRequest {
        action: parse_action(request.action.as_deref())?,
        result: parse_result(request.result.as_deref())?,
        actor_user_id: request.actor_user_id,
        resource_id_contains: request
            .resource_id_contains
            .map(|value| value.to_ascii_lowercase()),
        include_projectless: request.include_projectless.unwrap_or(false),
        limit: request
            .limit
            .unwrap_or(DEFAULT_SEARCH_LIMIT)
            .clamp(1, MAX_SEARCH_LIMIT),
    })
}

fn parse_action(value: Option<&str>) -> Result<Option<ActionType>, &'static str> {
    match value.map(|value| value.trim().to_ascii_lowercase()) {
        None => Ok(None),
        Some(value) if value.is_empty() => Ok(None),
        Some(value) => ActionType::parse_label(&value)
            .ok_or("unsupported audit action filter")
            .map(Some),
    }
}

fn parse_result(value: Option<&str>) -> Result<Option<ActionResult>, &'static str> {
    match value.map(|value| value.trim().to_ascii_lowercase()) {
        None => Ok(None),
        Some(value) if value.is_empty() => Ok(None),
        Some(value) => ActionResult::parse_label(&value)
            .ok_or("unsupported audit result filter")
            .map(Some),
    }
}

fn event_matches_filters(event: &AuditEvent, filters: &NormalizedAuditSearchRequest) -> bool {
    if filters
        .action
        .as_ref()
        .is_some_and(|action| event.action != *action)
    {
        return false;
    }

    if filters
        .result
        .as_ref()
        .is_some_and(|result| event.result != *result)
    {
        return false;
    }

    if filters
        .actor_user_id
        .as_ref()
        .is_some_and(|user_id| event.actor.user_id != *user_id)
    {
        return false;
    }

    if let Some(pattern) = &filters.resource_id_contains
        && !event
            .target
            .resource_id
            .to_ascii_lowercase()
            .contains(pattern)
    {
        return false;
    }

    true
}

impl From<&AuditEvent> for AuditEventResponse {
    fn from(value: &AuditEvent) -> Self {
        Self {
            event_id: value.event_id.clone(),
            timestamp: value.timestamp.to_rfc3339(),
            actor_user_id: value.actor.user_id.clone(),
            action: format!("{:?}", value.action).to_ascii_lowercase(),
            result: format!("{:?}", value.result).to_ascii_lowercase(),
            tenant_id: value.target.tenant_id.clone(),
            project_id: value.target.project_id.clone(),
            resource_id: value.target.resource_id.clone(),
            context: value.context.clone(),
            context_fields: value.context_fields.clone(),
            data_fingerprint: value.data_fingerprint.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use sdqp_audit::{ActorInfo, AuditContextFields, TargetRef};
    use sdqp_core::{ProjectId, TenantId, UserId};

    use super::{
        AuditEventResponse, AuditSearchRequest, NormalizedAuditSearchRequest,
        event_matches_filters, normalize_search_request,
    };
    use sdqp_audit::{ActionResult, ActionType, AuditEvent, AuditTrail};
    use sdqp_core::RequestContext;

    fn request_context() -> RequestContext {
        RequestContext::new(
            TenantId::new("tenant-alpha").expect("tenant"),
            UserId::new("user-admin").expect("user"),
        )
        .with_project(ProjectId::new("project-alpha").expect("project"))
    }

    fn audit_event(action: ActionType, result: ActionResult) -> AuditEvent {
        AuditEvent {
            event_id: "event-1".into(),
            timestamp: Utc::now(),
            actor: ActorInfo {
                user_id: "user-analyst".into(),
                session_id: "session-1".into(),
                ip_address: "127.0.0.1".into(),
            },
            action,
            target: TargetRef {
                tenant_id: "tenant-alpha".into(),
                project_id: Some("project-alpha".into()),
                resource_id: "queries/task-1".into(),
            },
            context: "search fixture".into(),
            context_fields: AuditContextFields::builder()
                .field("task_id", "task-1")
                .field("requested_fields", vec!["employee_id".to_string()])
                .build(),
            result,
            data_fingerprint: Some("fingerprint-1".into()),
            prev_hash: "GENESIS".into(),
            event_hash: "hash-1".into(),
        }
    }

    #[test]
    fn normalize_request_caps_limit_and_parses_filters() {
        let filters = normalize_search_request(AuditSearchRequest {
            action: Some("query".into()),
            result: Some("success".into()),
            actor_user_id: Some("user-analyst".into()),
            resource_id_contains: Some("Task".into()),
            include_projectless: Some(true),
            limit: Some(500),
        })
        .expect("normalized");

        assert_eq!(
            filters,
            NormalizedAuditSearchRequest {
                action: Some(ActionType::Query),
                result: Some(ActionResult::Success),
                actor_user_id: Some("user-analyst".into()),
                resource_id_contains: Some("task".into()),
                include_projectless: true,
                limit: 100,
            }
        );
    }

    #[test]
    fn event_filter_matches_action_result_actor_and_resource_pattern() {
        let event = audit_event(ActionType::Query, ActionResult::Success);
        let filters = normalize_search_request(AuditSearchRequest {
            action: Some("query".into()),
            result: Some("success".into()),
            actor_user_id: Some("user-analyst".into()),
            resource_id_contains: Some("task-1".into()),
            include_projectless: Some(false),
            limit: Some(10),
        })
        .expect("normalized");

        assert!(event_matches_filters(&event, &filters));
    }

    #[test]
    fn audit_trail_scope_includes_projectless_when_requested() {
        let mut trail = AuditTrail::default();
        let event = audit_event(ActionType::Query, ActionResult::Success);
        trail.append(event.clone());
        let mut projectless = event;
        projectless.target.project_id = None;
        projectless.prev_hash = trail.latest_event_hash().expect("hash");
        projectless.event_hash = projectless.recompute_hash();
        trail.append(projectless);

        let scoped = trail.scoped_events(
            request_context().tenant_id.as_str(),
            request_context()
                .project_id
                .as_ref()
                .map(|project_id| project_id.as_str()),
            true,
        );

        assert_eq!(scoped.len(), 2);
    }

    #[test]
    fn audit_event_response_preserves_structured_context_fields() {
        let response =
            AuditEventResponse::from(&audit_event(ActionType::Export, ActionResult::Success));

        assert_eq!(response.context, "search fixture");
        assert_eq!(
            response
                .context_fields
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            vec!["requested_fields", "task_id"]
        );
    }
}
