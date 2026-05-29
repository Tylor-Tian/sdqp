use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{GrantStatus, PermissionGrant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmploymentState {
    Active,
    Departed,
    Missing,
}

impl EmploymentState {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicantRuntimeProfile {
    pub user_id: String,
    pub department_id: Option<String>,
    pub manager_id: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    pub employment: EmploymentState,
}

impl ApplicantRuntimeProfile {
    pub fn missing(user_id: impl Into<String>, roles: Vec<String>) -> Self {
        Self {
            user_id: user_id.into(),
            department_id: None,
            manager_id: None,
            roles,
            employment: EmploymentState::Missing,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicantEligibilityRule {
    pub rule_id: String,
    pub project_id: String,
    #[serde(default)]
    pub allowed_department_ids: BTreeSet<String>,
    #[serde(default)]
    pub allowed_user_ids: BTreeSet<String>,
    #[serde(default)]
    pub allowed_role_names: BTreeSet<String>,
    pub require_active_hr_record: bool,
}

impl ApplicantEligibilityRule {
    pub fn active_hr_only(project_id: impl Into<String>) -> Self {
        let project_id = project_id.into();
        Self {
            rule_id: format!("eligibility-{project_id}-active-hr"),
            project_id,
            allowed_department_ids: BTreeSet::new(),
            allowed_user_ids: BTreeSet::new(),
            allowed_role_names: BTreeSet::new(),
            require_active_hr_record: true,
        }
    }

    pub fn evaluate(&self, profile: &ApplicantRuntimeProfile) -> ApplicantEligibilityDecision {
        if self.require_active_hr_record && !profile.employment.is_active() {
            return ApplicantEligibilityDecision::denied(format!(
                "applicant HR state is {:?}",
                profile.employment
            ));
        }

        let has_selector = !self.allowed_department_ids.is_empty()
            || !self.allowed_user_ids.is_empty()
            || !self.allowed_role_names.is_empty();
        if !has_selector {
            return ApplicantEligibilityDecision::allowed("active_hr_record");
        }

        if self.allowed_user_ids.contains(&profile.user_id) {
            return ApplicantEligibilityDecision::allowed("user");
        }
        if let Some(department_id) = profile.department_id.as_deref()
            && self.allowed_department_ids.contains(department_id)
        {
            return ApplicantEligibilityDecision::allowed("department");
        }
        if profile
            .roles
            .iter()
            .any(|role| self.allowed_role_names.contains(role))
        {
            return ApplicantEligibilityDecision::allowed("role");
        }

        ApplicantEligibilityDecision::denied("applicant does not match project eligibility rule")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicantEligibilityDecision {
    pub eligible: bool,
    pub matched_by: Option<String>,
    pub reason: String,
}

impl ApplicantEligibilityDecision {
    fn allowed(matched_by: impl Into<String>) -> Self {
        let matched_by = matched_by.into();
        Self {
            eligible: true,
            reason: format!("matched by {matched_by}"),
            matched_by: Some(matched_by),
        }
    }

    fn denied(reason: impl Into<String>) -> Self {
        Self {
            eligible: false,
            matched_by: None,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantLifecycleTrigger {
    SchedulerTick,
    HrSync,
    AuditAnomaly,
    AuditCleared,
    AuditConfirmedCompromise,
    ProjectFrozen,
    ProjectResumed,
    ProjectClosed,
}

impl GrantLifecycleTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SchedulerTick => "scheduler_tick",
            Self::HrSync => "hr_sync",
            Self::AuditAnomaly => "audit_anomaly",
            Self::AuditCleared => "audit_cleared",
            Self::AuditConfirmedCompromise => "audit_confirmed_compromise",
            Self::ProjectFrozen => "project_frozen",
            Self::ProjectResumed => "project_resumed",
            Self::ProjectClosed => "project_closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantLifecycleTransition {
    pub transition_id: String,
    pub grant_id: String,
    pub applicant_user_id: String,
    pub project_id: String,
    pub data_source_id: String,
    pub from_status: GrantStatus,
    pub to_status: GrantStatus,
    pub trigger: GrantLifecycleTrigger,
    pub reason: String,
    pub effective_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_event_id: Option<String>,
}

impl GrantLifecycleTransition {
    pub fn with_source_event(mut self, source_event_id: impl Into<String>) -> Self {
        self.source_event_id = Some(source_event_id.into());
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct GrantLifecycleScheduler;

impl GrantLifecycleScheduler {
    pub fn evaluate_activation(
        &self,
        profile: &ApplicantRuntimeProfile,
        rule: &ApplicantEligibilityRule,
    ) -> ApplicantEligibilityDecision {
        rule.evaluate(profile)
    }

    pub fn evaluate_grant(
        &self,
        grant: &PermissionGrant,
        profile: &ApplicantRuntimeProfile,
        rule: &ApplicantEligibilityRule,
        now: DateTime<Utc>,
        trigger: GrantLifecycleTrigger,
    ) -> Option<GrantLifecycleTransition> {
        if !matches!(grant.status, GrantStatus::Active | GrantStatus::Suspended) {
            return None;
        }

        if grant.valid_until <= now {
            return transition(
                grant,
                GrantStatus::Expired,
                GrantLifecycleTrigger::SchedulerTick,
                "grant validity window elapsed",
                now,
            );
        }

        match trigger {
            GrantLifecycleTrigger::AuditAnomaly => transition(
                grant,
                GrantStatus::Suspended,
                trigger,
                "audit anomaly requires investigation",
                now,
            ),
            GrantLifecycleTrigger::AuditConfirmedCompromise => transition(
                grant,
                GrantStatus::Revoked,
                trigger,
                "audit investigation confirmed misuse",
                now,
            ),
            GrantLifecycleTrigger::AuditCleared => {
                if grant.status != GrantStatus::Suspended {
                    return None;
                }
                if !org_binding_matches(grant, profile) {
                    return transition(
                        grant,
                        GrantStatus::Revoked,
                        GrantLifecycleTrigger::HrSync,
                        "HR binding no longer matches grant snapshot",
                        now,
                    );
                }
                let decision = rule.evaluate(profile);
                if decision.eligible {
                    transition(
                        grant,
                        GrantStatus::Active,
                        trigger,
                        "audit investigation cleared and applicant remains eligible",
                        now,
                    )
                } else {
                    None
                }
            }
            GrantLifecycleTrigger::ProjectFrozen => transition(
                grant,
                GrantStatus::Suspended,
                trigger,
                "project lifecycle is frozen",
                now,
            ),
            GrantLifecycleTrigger::ProjectResumed => {
                if grant.status != GrantStatus::Suspended {
                    return None;
                }
                if org_binding_matches(grant, profile) && rule.evaluate(profile).eligible {
                    transition(
                        grant,
                        GrantStatus::Active,
                        trigger,
                        "project resumed and applicant remains eligible",
                        now,
                    )
                } else {
                    None
                }
            }
            GrantLifecycleTrigger::ProjectClosed => transition(
                grant,
                GrantStatus::Revoked,
                trigger,
                "project lifecycle closed",
                now,
            ),
            GrantLifecycleTrigger::HrSync | GrantLifecycleTrigger::SchedulerTick => {
                if !profile.employment.is_active() {
                    return transition(
                        grant,
                        GrantStatus::Revoked,
                        GrantLifecycleTrigger::HrSync,
                        "applicant is no longer active in HR",
                        now,
                    );
                }
                if !org_binding_matches(grant, profile) {
                    return transition(
                        grant,
                        GrantStatus::Revoked,
                        GrantLifecycleTrigger::HrSync,
                        "HR binding no longer matches grant snapshot",
                        now,
                    );
                }
                let decision = rule.evaluate(profile);
                if !decision.eligible && grant.status == GrantStatus::Active {
                    return transition(
                        grant,
                        GrantStatus::Suspended,
                        GrantLifecycleTrigger::HrSync,
                        format!("applicant eligibility lost: {}", decision.reason),
                        now,
                    );
                }
                None
            }
        }
    }
}

fn org_binding_matches(grant: &PermissionGrant, profile: &ApplicantRuntimeProfile) -> bool {
    profile.department_id.as_deref() == Some(grant.org_binding.department_id.as_str())
        && profile.manager_id == grant.org_binding.manager_id
}

fn transition(
    grant: &PermissionGrant,
    to_status: GrantStatus,
    trigger: GrantLifecycleTrigger,
    reason: impl Into<String>,
    effective_at: DateTime<Utc>,
) -> Option<GrantLifecycleTransition> {
    if grant.status == to_status {
        return None;
    }

    Some(GrantLifecycleTransition {
        transition_id: Ulid::new().to_string(),
        grant_id: grant.grant_id.clone(),
        applicant_user_id: grant.applicant_user_id.clone(),
        project_id: grant.project_id.clone(),
        data_source_id: grant.data_source_id.clone(),
        from_status: grant.status.clone(),
        to_status,
        trigger,
        reason: reason.into(),
        effective_at,
        source_event_id: None,
    })
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use crate::{FieldPermission, GrantLifecycle, OrgBinding, PermissionGrant};

    use super::{
        ApplicantEligibilityRule, ApplicantRuntimeProfile, EmploymentState,
        GrantLifecycleScheduler, GrantLifecycleTrigger,
    };

    fn profile() -> ApplicantRuntimeProfile {
        ApplicantRuntimeProfile {
            user_id: "user-analyst".into(),
            department_id: Some("dept-risk".into()),
            manager_id: Some("manager-a".into()),
            roles: vec!["analyst".into()],
            employment: EmploymentState::Active,
        }
    }

    fn rule() -> ApplicantEligibilityRule {
        let mut rule = ApplicantEligibilityRule::active_hr_only("project-alpha");
        rule.allowed_department_ids.insert("dept-risk".into());
        rule.allowed_role_names.insert("analyst".into());
        rule
    }

    fn grant() -> PermissionGrant {
        PermissionGrant::new(
            "user-analyst",
            "project-alpha",
            "datasource-rest",
            vec![FieldPermission {
                field_name: "employee_id".into(),
                denied: false,
            }],
            Vec::new(),
            GrantLifecycle {
                valid_from: Utc::now() - Duration::minutes(5),
                valid_until: Utc::now() + Duration::hours(1),
                org_binding: OrgBinding {
                    department_id: "dept-risk".into(),
                    manager_id: Some("manager-a".into()),
                },
                status: crate::GrantStatus::Active,
            },
        )
    }

    #[test]
    fn eligibility_requires_active_hr_and_project_rule_match() {
        let scheduler = GrantLifecycleScheduler;
        let allowed = scheduler.evaluate_activation(&profile(), &rule());
        assert!(allowed.eligible);

        let mut departed = profile();
        departed.employment = EmploymentState::Departed;
        let denied = scheduler.evaluate_activation(&departed, &rule());
        assert!(!denied.eligible);
    }

    #[test]
    fn scheduler_expires_and_hr_revokes_independently_of_merge_semantics() {
        let scheduler = GrantLifecycleScheduler;
        let now = Utc::now();
        let expired = PermissionGrant::new(
            "user-analyst",
            "project-alpha",
            "datasource-rest",
            Vec::new(),
            Vec::new(),
            GrantLifecycle {
                valid_from: now - Duration::hours(2),
                valid_until: now - Duration::minutes(1),
                org_binding: OrgBinding {
                    department_id: "dept-risk".into(),
                    manager_id: Some("manager-a".into()),
                },
                status: crate::GrantStatus::Active,
            },
        );
        assert_eq!(
            scheduler
                .evaluate_grant(
                    &expired,
                    &profile(),
                    &rule(),
                    now,
                    GrantLifecycleTrigger::SchedulerTick
                )
                .expect("expired")
                .to_status,
            crate::GrantStatus::Expired
        );

        let mut transferred = profile();
        transferred.department_id = Some("dept-fraud".into());
        assert_eq!(
            scheduler
                .evaluate_grant(
                    &grant(),
                    &transferred,
                    &rule(),
                    now,
                    GrantLifecycleTrigger::HrSync
                )
                .expect("revoked")
                .to_status,
            crate::GrantStatus::Revoked
        );
    }

    #[test]
    fn audit_signal_suspends_resumes_and_revokes() {
        let scheduler = GrantLifecycleScheduler;
        let now = Utc::now();
        let active = grant();

        let suspended = scheduler
            .evaluate_grant(
                &active,
                &profile(),
                &rule(),
                now,
                GrantLifecycleTrigger::AuditAnomaly,
            )
            .expect("suspended");
        assert_eq!(suspended.to_status, crate::GrantStatus::Suspended);

        let mut suspended_grant = active.clone();
        suspended_grant.status = crate::GrantStatus::Suspended;
        let resumed = scheduler
            .evaluate_grant(
                &suspended_grant,
                &profile(),
                &rule(),
                now,
                GrantLifecycleTrigger::AuditCleared,
            )
            .expect("resumed");
        assert_eq!(resumed.to_status, crate::GrantStatus::Active);

        let revoked = scheduler
            .evaluate_grant(
                &suspended_grant,
                &profile(),
                &rule(),
                now,
                GrantLifecycleTrigger::AuditConfirmedCompromise,
            )
            .expect("revoked");
        assert_eq!(revoked.to_status, crate::GrantStatus::Revoked);
    }
}
