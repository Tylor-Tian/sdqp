use chrono::{DateTime, Duration, Utc};
use sdqp_hr_integration::{
    ApproverResolutionPolicy, ApproverRoute, ApproverRouteKind, OrgDirectory,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

const SYSTEM_ADMIN_FALLBACK_USER_ID: &str = "user-sysadmin";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalMode {
    Serial,
    ParallelAll,
    AnyOne,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum ApproverSelector {
    User(String),
    Manager,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalStepDefinition {
    pub step_id: String,
    pub mode: ApprovalMode,
    pub approvers: Vec<ApproverSelector>,
    pub timeout_minutes: i64,
    pub escalation: Option<ApproverSelector>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalFlowDefinition {
    pub flow_id: String,
    pub version: u32,
    pub steps: Vec<ApprovalStepDefinition>,
}

impl ApprovalFlowDefinition {
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(self)
    }

    pub fn from_toml(value: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub request_id: String,
    pub applicant_user_id: String,
    pub project_id: String,
    pub data_source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStatus {
    Pending,
    Approved,
    Rejected,
    Escalated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepState {
    pub step_id: String,
    pub status: StepStatus,
    pub pending_approvers: Vec<String>,
    pub approved_by: Vec<String>,
    pub escalation_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_to: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routing: Vec<ApprovalRouteTrace>,
    pub due_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRouteTrace {
    pub requested_user_id: String,
    pub resolved_user_id: String,
    pub route_kind: ApproverRouteKind,
    pub delegated_from: Option<String>,
    pub escalation_target: Option<String>,
    pub used_system_fallback: bool,
    pub traversed_user_ids: Vec<String>,
    pub unavailable_user_ids: Vec<String>,
}

impl From<&ApproverRoute> for ApprovalRouteTrace {
    fn from(route: &ApproverRoute) -> Self {
        Self {
            requested_user_id: route.requested_user_id.clone(),
            resolved_user_id: route.resolved_user_id.clone(),
            route_kind: route.route_kind.clone(),
            delegated_from: route.delegated_from.clone(),
            escalation_target: route.escalation_target.clone(),
            used_system_fallback: route.used_system_fallback,
            traversed_user_ids: route.traversed_user_ids.clone(),
            unavailable_user_ids: route.unavailable_user_ids.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalInstance {
    pub instance_id: String,
    pub flow_id: String,
    pub request_id: String,
    pub current_step_index: usize,
    pub step_states: Vec<StepState>,
    pub status: ApprovalStatus,
    pub audit_log: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    ApprovalRequired,
    ApprovalDelegated,
    ApprovalEscalated,
    RequestApproved,
    RequestRejected,
    #[default]
    Informational,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationAction {
    Approve,
    Reject,
    Delegate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationCallback {
    pub instance_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<NotificationAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notification {
    pub recipient: String,
    pub message: String,
    #[serde(default)]
    pub kind: NotificationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback: Option<NotificationCallback>,
}

impl Notification {
    pub fn informational(recipient: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            recipient: recipient.into(),
            message: message.into(),
            kind: NotificationKind::Informational,
            step_id: None,
            callback: None,
        }
    }

    pub fn approval_required(
        recipient: impl Into<String>,
        request_id: &str,
        step_id: &str,
        instance_id: &str,
    ) -> Self {
        Self {
            recipient: recipient.into(),
            message: format!("Approval required for request {request_id} at step {step_id}"),
            kind: NotificationKind::ApprovalRequired,
            step_id: Some(step_id.to_string()),
            callback: Some(NotificationCallback {
                instance_id: instance_id.to_string(),
                actions: vec![
                    NotificationAction::Approve,
                    NotificationAction::Reject,
                    NotificationAction::Delegate,
                ],
            }),
        }
    }

    pub fn delegated(
        recipient: impl Into<String>,
        request_id: &str,
        step_id: &str,
        instance_id: &str,
    ) -> Self {
        Self {
            recipient: recipient.into(),
            message: format!("Approval delegated for request {request_id}"),
            kind: NotificationKind::ApprovalDelegated,
            step_id: Some(step_id.to_string()),
            callback: Some(NotificationCallback {
                instance_id: instance_id.to_string(),
                actions: vec![
                    NotificationAction::Approve,
                    NotificationAction::Reject,
                    NotificationAction::Delegate,
                ],
            }),
        }
    }

    pub fn escalated(
        recipient: impl Into<String>,
        request_id: &str,
        step_id: &str,
        instance_id: &str,
    ) -> Self {
        Self {
            recipient: recipient.into(),
            message: format!("Approval escalated for request {request_id}"),
            kind: NotificationKind::ApprovalEscalated,
            step_id: Some(step_id.to_string()),
            callback: Some(NotificationCallback {
                instance_id: instance_id.to_string(),
                actions: vec![
                    NotificationAction::Approve,
                    NotificationAction::Reject,
                    NotificationAction::Delegate,
                ],
            }),
        }
    }

    pub fn request_approved(recipient: impl Into<String>, request_id: &str) -> Self {
        Self {
            recipient: recipient.into(),
            message: format!("Access request {request_id} approved"),
            kind: NotificationKind::RequestApproved,
            step_id: None,
            callback: None,
        }
    }

    pub fn request_rejected(recipient: impl Into<String>, request_id: &str) -> Self {
        Self {
            recipient: recipient.into(),
            message: format!("Access request {request_id} rejected"),
            kind: NotificationKind::RequestRejected,
            step_id: None,
            callback: None,
        }
    }
}

pub trait NotificationSink {
    fn push_notification(&mut self, notification: Notification);

    fn notify(&mut self, recipient: String, message: String) {
        self.push_notification(Notification::informational(recipient, message));
    }
}

#[derive(Debug, Default)]
pub struct MockNotificationSink {
    pub notifications: Vec<Notification>,
}

impl NotificationSink for MockNotificationSink {
    fn push_notification(&mut self, notification: Notification) {
        self.notifications.push(notification);
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApprovalError {
    #[error("approval flow has no steps")]
    EmptyFlow,
    #[error("approver is not assigned to current step: {0}")]
    ApproverNotAssigned(String),
    #[error("serial approval requires the first pending approver")]
    SerialOrderViolation,
    #[error("approval instance is already terminal")]
    TerminalInstance,
    #[error("manager approver could not be resolved")]
    MissingManager,
    #[error("delegate target is empty")]
    EmptyDelegateTarget,
}

pub struct ApprovalEngine;

impl ApprovalEngine {
    pub fn start_instance(
        flow: &ApprovalFlowDefinition,
        request: &ApprovalRequest,
        directory: &OrgDirectory,
        now: DateTime<Utc>,
        notifier: &mut dyn NotificationSink,
    ) -> Result<ApprovalInstance, ApprovalError> {
        Self::start_instance_with_policy(
            flow,
            request,
            directory,
            &default_approver_policy(),
            now,
            notifier,
        )
    }

    pub fn start_instance_with_policy(
        flow: &ApprovalFlowDefinition,
        request: &ApprovalRequest,
        directory: &OrgDirectory,
        policy: &ApproverResolutionPolicy,
        now: DateTime<Utc>,
        notifier: &mut dyn NotificationSink,
    ) -> Result<ApprovalInstance, ApprovalError> {
        let Some(first_step) = flow.steps.first() else {
            return Err(ApprovalError::EmptyFlow);
        };

        let instance_id = Ulid::new().to_string();
        let step_state = build_step_state(first_step, request, directory, policy, now)?;
        notify_step(
            notifier,
            instance_id.as_str(),
            &step_state,
            request,
            first_step,
        );

        Ok(ApprovalInstance {
            instance_id,
            flow_id: flow.flow_id.clone(),
            request_id: request.request_id.clone(),
            current_step_index: 0,
            step_states: vec![step_state],
            status: ApprovalStatus::Pending,
            audit_log: vec![format!(
                "instance-started:{}:{}",
                request.request_id, flow.version
            )],
        })
    }

    pub fn approve(
        instance: &mut ApprovalInstance,
        flow: &ApprovalFlowDefinition,
        request: &ApprovalRequest,
        directory: &OrgDirectory,
        actor: &str,
        now: DateTime<Utc>,
        notifier: &mut dyn NotificationSink,
    ) -> Result<(), ApprovalError> {
        Self::approve_with_policy(
            instance,
            flow,
            request,
            directory,
            &default_approver_policy(),
            actor,
            now,
            notifier,
        )
    }

    pub fn approve_with_policy(
        instance: &mut ApprovalInstance,
        flow: &ApprovalFlowDefinition,
        request: &ApprovalRequest,
        directory: &OrgDirectory,
        policy: &ApproverResolutionPolicy,
        actor: &str,
        now: DateTime<Utc>,
        notifier: &mut dyn NotificationSink,
    ) -> Result<(), ApprovalError> {
        if instance.status != ApprovalStatus::Pending {
            return Err(ApprovalError::TerminalInstance);
        }
        let step_definition = &flow.steps[instance.current_step_index];
        let step_state = &mut instance.step_states[instance.current_step_index];

        if !step_state
            .pending_approvers
            .iter()
            .any(|approver| approver == actor)
        {
            return Err(ApprovalError::ApproverNotAssigned(actor.to_string()));
        }

        match step_definition.mode {
            ApprovalMode::Serial => {
                if step_state.pending_approvers.first().map(String::as_str) != Some(actor) {
                    return Err(ApprovalError::SerialOrderViolation);
                }
                step_state.pending_approvers.remove(0);
            }
            ApprovalMode::ParallelAll => {
                step_state
                    .pending_approvers
                    .retain(|approver| approver != actor);
            }
            ApprovalMode::AnyOne => {
                step_state.pending_approvers.clear();
            }
        }
        step_state.approved_by.push(actor.to_string());
        instance.audit_log.push(format!(
            "approval-recorded:{}:{}",
            step_state.step_id, actor
        ));

        if step_state.pending_approvers.is_empty() {
            step_state.status = StepStatus::Approved;
            advance_instance(instance, flow, request, directory, policy, now, notifier)?;
        }

        Ok(())
    }

    pub fn reject(instance: &mut ApprovalInstance, actor: &str) -> Result<(), ApprovalError> {
        if instance.status != ApprovalStatus::Pending {
            return Err(ApprovalError::TerminalInstance);
        }
        let step_state = &mut instance.step_states[instance.current_step_index];
        step_state.status = StepStatus::Rejected;
        instance.status = ApprovalStatus::Rejected;
        instance
            .audit_log
            .push(format!("approval-rejected:{}:{actor}", step_state.step_id));
        Ok(())
    }

    pub fn delegate(
        instance: &mut ApprovalInstance,
        request: &ApprovalRequest,
        actor: &str,
        delegate_to: &str,
        notifier: &mut dyn NotificationSink,
    ) -> Result<(), ApprovalError> {
        Self::delegate_internal(
            instance,
            request,
            actor,
            delegate_to,
            None,
            &default_approver_policy(),
            notifier,
        )
    }

    pub fn delegate_with_directory(
        instance: &mut ApprovalInstance,
        request: &ApprovalRequest,
        actor: &str,
        delegate_to: &str,
        directory: &OrgDirectory,
        notifier: &mut dyn NotificationSink,
    ) -> Result<(), ApprovalError> {
        Self::delegate_internal(
            instance,
            request,
            actor,
            delegate_to,
            Some(directory),
            &default_approver_policy(),
            notifier,
        )
    }

    pub fn delegate_with_directory_and_policy(
        instance: &mut ApprovalInstance,
        request: &ApprovalRequest,
        actor: &str,
        delegate_to: &str,
        directory: &OrgDirectory,
        policy: &ApproverResolutionPolicy,
        notifier: &mut dyn NotificationSink,
    ) -> Result<(), ApprovalError> {
        Self::delegate_internal(
            instance,
            request,
            actor,
            delegate_to,
            Some(directory),
            policy,
            notifier,
        )
    }

    fn delegate_internal(
        instance: &mut ApprovalInstance,
        request: &ApprovalRequest,
        actor: &str,
        delegate_to: &str,
        directory: Option<&OrgDirectory>,
        policy: &ApproverResolutionPolicy,
        notifier: &mut dyn NotificationSink,
    ) -> Result<(), ApprovalError> {
        if instance.status != ApprovalStatus::Pending {
            return Err(ApprovalError::TerminalInstance);
        }
        if delegate_to.trim().is_empty() {
            return Err(ApprovalError::EmptyDelegateTarget);
        }

        let step_state = &mut instance.step_states[instance.current_step_index];
        let Some(position) = step_state
            .pending_approvers
            .iter()
            .position(|approver| approver == actor)
        else {
            return Err(ApprovalError::ApproverNotAssigned(actor.to_string()));
        };

        let requested_delegate = delegate_to.to_string();
        let routed_delegate = directory
            .map(|directory| {
                directory
                    .resolve_effective_approver_with_policy(requested_delegate.as_str(), policy)
            })
            .transpose()
            .map_err(|_| ApprovalError::MissingManager)?;
        let resolved_delegate = routed_delegate
            .as_ref()
            .map(|route| route.resolved_user_id.clone())
            .unwrap_or_else(|| requested_delegate.clone());

        step_state.pending_approvers[position] = resolved_delegate.clone();
        step_state.delegated_to = Some(resolved_delegate.clone());
        if routed_delegate
            .as_ref()
            .is_some_and(|route| route.escalation_target.is_some() || route.used_system_fallback)
        {
            step_state.escalation_target = Some(resolved_delegate.clone());
        }
        if let Some(route) = routed_delegate.as_ref() {
            step_state.routing.push(ApprovalRouteTrace::from(route));
        }
        instance.audit_log.push(format!(
            "approval-delegated:{}:{}:{}:{}",
            step_state.step_id, actor, requested_delegate, resolved_delegate
        ));
        notifier.push_notification(Notification::delegated(
            resolved_delegate,
            request.request_id.as_str(),
            step_state.step_id.as_str(),
            instance.instance_id.as_str(),
        ));
        Ok(())
    }

    pub fn tick_timeouts(
        instance: &mut ApprovalInstance,
        flow: &ApprovalFlowDefinition,
        request: &ApprovalRequest,
        directory: &OrgDirectory,
        now: DateTime<Utc>,
        notifier: &mut dyn NotificationSink,
    ) -> Result<(), ApprovalError> {
        Self::tick_timeouts_with_policy(
            instance,
            flow,
            request,
            directory,
            &default_approver_policy(),
            now,
            notifier,
        )
    }

    pub fn tick_timeouts_with_policy(
        instance: &mut ApprovalInstance,
        flow: &ApprovalFlowDefinition,
        request: &ApprovalRequest,
        directory: &OrgDirectory,
        policy: &ApproverResolutionPolicy,
        now: DateTime<Utc>,
        notifier: &mut dyn NotificationSink,
    ) -> Result<(), ApprovalError> {
        if instance.status != ApprovalStatus::Pending {
            return Err(ApprovalError::TerminalInstance);
        }
        let step_definition = &flow.steps[instance.current_step_index];
        let step_state = &mut instance.step_states[instance.current_step_index];
        if now < step_state.due_at {
            return Ok(());
        }

        let route = if let Some(selector) = &step_definition.escalation {
            let candidate = resolve_selector_candidate(selector, request, directory)
                .ok_or(ApprovalError::MissingManager)?;
            directory
                .resolve_effective_approver_with_policy(&candidate, policy)
                .map_err(|_| ApprovalError::MissingManager)?
        } else {
            let overdue_approver = step_state
                .pending_approvers
                .first()
                .cloned()
                .ok_or(ApprovalError::MissingManager)?;
            directory
                .reroute_unavailable_approver_with_policy(overdue_approver.as_str(), policy)
                .map_err(|_| ApprovalError::MissingManager)?
        };

        if !route.resolved_user_id.is_empty() {
            step_state.pending_approvers = vec![route.resolved_user_id.clone()];
            step_state.delegated_to = route
                .delegated_from
                .as_ref()
                .map(|_| route.resolved_user_id.clone());
            step_state.escalation_target = Some(route.resolved_user_id.clone());
            step_state.status = StepStatus::Escalated;
            step_state.due_at = now + Duration::minutes(step_definition.timeout_minutes);
            step_state.routing.push(ApprovalRouteTrace::from(&route));
            notifier.push_notification(Notification::escalated(
                route.resolved_user_id.clone(),
                request.request_id.as_str(),
                step_state.step_id.as_str(),
                instance.instance_id.as_str(),
            ));
            instance.audit_log.push(format!(
                "approval-escalated:{}:{}",
                step_state.step_id, route.resolved_user_id
            ));
            return Ok(());
        }

        step_state.status = StepStatus::Rejected;
        instance.status = ApprovalStatus::Rejected;
        instance
            .audit_log
            .push(format!("approval-timeout-rejected:{}", step_state.step_id));

        Ok(())
    }
}

fn build_step_state(
    step: &ApprovalStepDefinition,
    request: &ApprovalRequest,
    directory: &OrgDirectory,
    policy: &ApproverResolutionPolicy,
    now: DateTime<Utc>,
) -> Result<StepState, ApprovalError> {
    let routes = step
        .approvers
        .iter()
        .map(|selector| {
            let candidate = resolve_selector_candidate(selector, request, directory)
                .ok_or(ApprovalError::MissingManager)?;
            directory
                .resolve_effective_approver_with_policy(&candidate, policy)
                .map_err(|_| ApprovalError::MissingManager)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let pending_approvers = routes
        .iter()
        .map(|route| route.resolved_user_id.clone())
        .collect::<Vec<_>>();
    let delegated_to = routes.iter().find_map(|route| {
        route
            .delegated_from
            .as_ref()
            .map(|_| route.resolved_user_id.clone())
    });
    let escalation_target = routes
        .iter()
        .find_map(|route| route.escalation_target.clone());
    let routing = routes
        .iter()
        .map(ApprovalRouteTrace::from)
        .collect::<Vec<_>>();

    Ok(StepState {
        step_id: step.step_id.clone(),
        status: StepStatus::Pending,
        pending_approvers,
        approved_by: Vec::new(),
        escalation_target,
        delegated_to,
        routing,
        due_at: now + Duration::minutes(step.timeout_minutes),
    })
}

fn resolve_selector_candidate(
    selector: &ApproverSelector,
    request: &ApprovalRequest,
    directory: &OrgDirectory,
) -> Option<String> {
    match selector {
        ApproverSelector::User(user_id) => Some(user_id.clone()),
        ApproverSelector::Manager => directory.resolve_manager(&request.applicant_user_id).ok(),
    }
}

fn default_approver_policy() -> ApproverResolutionPolicy {
    ApproverResolutionPolicy::with_system_fallback(SYSTEM_ADMIN_FALLBACK_USER_ID)
}

fn notify_step(
    notifier: &mut dyn NotificationSink,
    instance_id: &str,
    step_state: &StepState,
    request: &ApprovalRequest,
    step_definition: &ApprovalStepDefinition,
) {
    for approver in &step_state.pending_approvers {
        notifier.push_notification(Notification::approval_required(
            approver.clone(),
            request.request_id.as_str(),
            step_definition.step_id.as_str(),
            instance_id,
        ));
    }
}

fn advance_instance(
    instance: &mut ApprovalInstance,
    flow: &ApprovalFlowDefinition,
    request: &ApprovalRequest,
    directory: &OrgDirectory,
    policy: &ApproverResolutionPolicy,
    now: DateTime<Utc>,
    notifier: &mut dyn NotificationSink,
) -> Result<(), ApprovalError> {
    let next_index = instance.current_step_index + 1;
    if next_index >= flow.steps.len() {
        instance.status = ApprovalStatus::Approved;
        instance
            .audit_log
            .push(format!("approval-approved:{}", request.request_id));
        return Ok(());
    }

    instance.current_step_index = next_index;
    let next_step = &flow.steps[next_index];
    let next_step_state = build_step_state(next_step, request, directory, policy, now)?;
    notify_step(
        notifier,
        instance.instance_id.as_str(),
        &next_step_state,
        request,
        next_step,
    );
    instance.step_states.push(next_step_state);
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use sdqp_hr_integration::{
        ApproverAvailability, ApproverRouteKind, EmploymentStatus, OrgDirectory, OrgUser,
        SyncSource,
    };

    use super::{
        ApprovalEngine, ApprovalFlowDefinition, ApprovalMode, ApprovalRequest, ApprovalStatus,
        ApprovalStepDefinition, ApproverSelector, MockNotificationSink, NotificationAction,
        NotificationKind, StepStatus,
    };

    fn directory() -> OrgDirectory {
        let mut directory = OrgDirectory::default();
        directory.sync_snapshot(
            SyncSource::FeishuMock,
            vec![
                OrgUser {
                    user_id: "user-sysadmin".into(),
                    department_id: "dept-admin".into(),
                    manager_id: None,
                    status: EmploymentStatus::Active,
                    approver_profile: None,
                },
                OrgUser {
                    user_id: "manager-a".into(),
                    department_id: "dept-risk".into(),
                    manager_id: Some("user-sysadmin".into()),
                    status: EmploymentStatus::Active,
                    approver_profile: None,
                },
                OrgUser {
                    user_id: "approver-b".into(),
                    department_id: "dept-risk".into(),
                    manager_id: Some("user-sysadmin".into()),
                    status: EmploymentStatus::Active,
                    approver_profile: None,
                },
                OrgUser {
                    user_id: "delegate-c".into(),
                    department_id: "dept-risk".into(),
                    manager_id: Some("approver-b".into()),
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

    fn request() -> ApprovalRequest {
        ApprovalRequest {
            request_id: "req-a".into(),
            applicant_user_id: "user-a".into(),
            project_id: "project-alpha".into(),
            data_source_id: "datasource-rest".into(),
        }
    }

    #[test]
    fn approval_flow_round_trips_through_toml() {
        let flow = ApprovalFlowDefinition {
            flow_id: "flow-a".into(),
            version: 1,
            steps: vec![ApprovalStepDefinition {
                step_id: "step-1".into(),
                mode: ApprovalMode::Serial,
                approvers: vec![ApproverSelector::Manager],
                timeout_minutes: 30,
                escalation: None,
            }],
        };

        let encoded = flow.to_toml().expect("toml");
        let decoded = ApprovalFlowDefinition::from_toml(&encoded).expect("flow");
        assert_eq!(decoded.flow_id, "flow-a");
        assert_eq!(decoded.steps.len(), 1);
    }

    #[test]
    fn serial_flow_requires_in_order_approvals() {
        let flow = ApprovalFlowDefinition {
            flow_id: "flow-a".into(),
            version: 1,
            steps: vec![ApprovalStepDefinition {
                step_id: "step-1".into(),
                mode: ApprovalMode::Serial,
                approvers: vec![
                    ApproverSelector::Manager,
                    ApproverSelector::User("approver-b".into()),
                ],
                timeout_minutes: 30,
                escalation: None,
            }],
        };
        let mut notifier = MockNotificationSink::default();
        let mut instance = ApprovalEngine::start_instance(
            &flow,
            &request(),
            &directory(),
            Utc::now(),
            &mut notifier,
        )
        .expect("instance");

        ApprovalEngine::approve(
            &mut instance,
            &flow,
            &request(),
            &directory(),
            "manager-a",
            Utc::now(),
            &mut notifier,
        )
        .expect("first approval");
        ApprovalEngine::approve(
            &mut instance,
            &flow,
            &request(),
            &directory(),
            "approver-b",
            Utc::now(),
            &mut notifier,
        )
        .expect("second approval");

        assert_eq!(instance.status, ApprovalStatus::Approved);
    }

    #[test]
    fn approval_notifications_include_callback_contract_metadata() {
        let flow = ApprovalFlowDefinition {
            flow_id: "flow-a".into(),
            version: 1,
            steps: vec![ApprovalStepDefinition {
                step_id: "step-1".into(),
                mode: ApprovalMode::Serial,
                approvers: vec![ApproverSelector::Manager],
                timeout_minutes: 30,
                escalation: None,
            }],
        };
        let mut notifier = MockNotificationSink::default();
        let instance = ApprovalEngine::start_instance(
            &flow,
            &request(),
            &directory(),
            Utc::now(),
            &mut notifier,
        )
        .expect("instance");

        let notification = notifier.notifications.first().expect("notification");
        assert_eq!(notification.kind, NotificationKind::ApprovalRequired);
        assert_eq!(notification.step_id.as_deref(), Some("step-1"));
        assert_eq!(notification.recipient, "manager-a");
        let callback = notification.callback.as_ref().expect("callback metadata");
        assert_eq!(callback.instance_id, instance.instance_id);
        assert_eq!(
            callback.actions,
            vec![
                NotificationAction::Approve,
                NotificationAction::Reject,
                NotificationAction::Delegate,
            ]
        );
    }

    #[test]
    fn timeout_escalation_replaces_pending_approver() {
        let flow = ApprovalFlowDefinition {
            flow_id: "flow-a".into(),
            version: 1,
            steps: vec![ApprovalStepDefinition {
                step_id: "step-1".into(),
                mode: ApprovalMode::Serial,
                approvers: vec![ApproverSelector::Manager],
                timeout_minutes: 1,
                escalation: Some(ApproverSelector::User("approver-b".into())),
            }],
        };
        let mut notifier = MockNotificationSink::default();
        let mut instance = ApprovalEngine::start_instance(
            &flow,
            &request(),
            &directory(),
            Utc::now(),
            &mut notifier,
        )
        .expect("instance");

        ApprovalEngine::tick_timeouts(
            &mut instance,
            &flow,
            &request(),
            &directory(),
            Utc::now() + Duration::minutes(2),
            &mut notifier,
        )
        .expect("timeout");

        assert_eq!(instance.step_states[0].status, StepStatus::Escalated);
        assert_eq!(
            instance.step_states[0].escalation_target.as_deref(),
            Some("approver-b")
        );
    }

    #[test]
    fn delegated_step_reassigns_pending_approver_and_notifies_delegate() {
        let flow = ApprovalFlowDefinition {
            flow_id: "flow-a".into(),
            version: 1,
            steps: vec![ApprovalStepDefinition {
                step_id: "step-1".into(),
                mode: ApprovalMode::Serial,
                approvers: vec![ApproverSelector::Manager],
                timeout_minutes: 5,
                escalation: None,
            }],
        };
        let request = request();
        let mut notifier = MockNotificationSink::default();
        let mut instance = ApprovalEngine::start_instance(
            &flow,
            &request,
            &directory(),
            Utc::now(),
            &mut notifier,
        )
        .expect("instance");

        ApprovalEngine::delegate(
            &mut instance,
            &request,
            "manager-a",
            "approver-b",
            &mut notifier,
        )
        .expect("delegate");

        assert_eq!(
            instance.step_states[0].pending_approvers,
            vec!["approver-b".to_string()]
        );
        assert_eq!(
            instance.step_states[0].delegated_to.as_deref(),
            Some("approver-b")
        );
        assert!(
            notifier
                .notifications
                .iter()
                .any(|notification| notification.recipient == "approver-b")
        );
    }

    #[test]
    fn unavailable_manager_prefers_delegate_during_instance_start() {
        let flow = ApprovalFlowDefinition {
            flow_id: "flow-a".into(),
            version: 1,
            steps: vec![ApprovalStepDefinition {
                step_id: "step-1".into(),
                mode: ApprovalMode::Serial,
                approvers: vec![ApproverSelector::Manager],
                timeout_minutes: 5,
                escalation: None,
            }],
        };
        let mut directory = directory();
        directory
            .set_approver_availability("manager-a", ApproverAvailability::Unavailable)
            .expect("availability");
        directory
            .set_approver_delegate("manager-a", Some("approver-b".into()))
            .expect("delegate");
        let mut notifier = MockNotificationSink::default();

        let instance = ApprovalEngine::start_instance(
            &flow,
            &request(),
            &directory,
            Utc::now(),
            &mut notifier,
        )
        .expect("instance");

        assert_eq!(
            instance.step_states[0].pending_approvers,
            vec!["approver-b"]
        );
        assert_eq!(
            instance.step_states[0].delegated_to.as_deref(),
            Some("approver-b")
        );
        assert!(instance.step_states[0].routing.iter().any(|trace| {
            trace.route_kind == ApproverRouteKind::Delegated
                && trace.delegated_from.as_deref() == Some("manager-a")
                && trace.resolved_user_id == "approver-b"
        }));
    }

    #[test]
    fn timeout_without_static_escalation_uses_hr_chain() {
        let flow = ApprovalFlowDefinition {
            flow_id: "flow-a".into(),
            version: 1,
            steps: vec![ApprovalStepDefinition {
                step_id: "step-1".into(),
                mode: ApprovalMode::Serial,
                approvers: vec![ApproverSelector::Manager],
                timeout_minutes: 1,
                escalation: None,
            }],
        };
        let request = request();
        let start_directory = directory();
        let mut timeout_directory = directory();
        timeout_directory
            .set_approver_availability("manager-a", ApproverAvailability::Unavailable)
            .expect("availability");
        let mut notifier = MockNotificationSink::default();
        let mut instance = ApprovalEngine::start_instance(
            &flow,
            &request,
            &start_directory,
            Utc::now(),
            &mut notifier,
        )
        .expect("instance");

        ApprovalEngine::tick_timeouts(
            &mut instance,
            &flow,
            &request,
            &timeout_directory,
            Utc::now() + Duration::minutes(2),
            &mut notifier,
        )
        .expect("timeout");

        assert_eq!(instance.step_states[0].status, StepStatus::Escalated);
        assert_eq!(
            instance.step_states[0].escalation_target.as_deref(),
            Some("user-sysadmin")
        );
        assert_eq!(
            instance.step_states[0].pending_approvers,
            vec!["user-sysadmin".to_string()]
        );
    }

    #[test]
    fn delegate_with_directory_routes_to_available_delegate_target() {
        let flow = ApprovalFlowDefinition {
            flow_id: "flow-a".into(),
            version: 1,
            steps: vec![ApprovalStepDefinition {
                step_id: "step-1".into(),
                mode: ApprovalMode::Serial,
                approvers: vec![ApproverSelector::Manager],
                timeout_minutes: 5,
                escalation: None,
            }],
        };
        let request = request();
        let mut routed_directory = directory();
        routed_directory
            .set_approver_availability("approver-b", ApproverAvailability::Unavailable)
            .expect("availability");
        routed_directory
            .set_approver_delegate("approver-b", Some("delegate-c".into()))
            .expect("delegate");
        let mut notifier = MockNotificationSink::default();
        let mut instance = ApprovalEngine::start_instance(
            &flow,
            &request,
            &directory(),
            Utc::now(),
            &mut notifier,
        )
        .expect("instance");

        ApprovalEngine::delegate_with_directory(
            &mut instance,
            &request,
            "manager-a",
            "approver-b",
            &routed_directory,
            &mut notifier,
        )
        .expect("delegate");

        assert_eq!(
            instance.step_states[0].pending_approvers,
            vec!["delegate-c".to_string()]
        );
        assert_eq!(
            instance.step_states[0].delegated_to.as_deref(),
            Some("delegate-c")
        );
    }
}
