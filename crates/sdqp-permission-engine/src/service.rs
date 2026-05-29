use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sdqp_core::FilterCondition;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    FieldPermission, GrantLifecycleTransition, GrantStatus, PermissionGrant, merge_grants,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionApplication {
    pub application_id: String,
    pub applicant_user_id: String,
    pub project_id: String,
    pub data_source_id: String,
    pub requested_fields: Vec<String>,
    pub status: GrantStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merged_into_application_id: Option<String>,
}

impl PermissionApplication {
    pub fn merge_key(&self) -> String {
        let mut requested_fields = self.requested_fields.clone();
        requested_fields.sort();
        format!(
            "{}::{}::{}::{}",
            self.applicant_user_id,
            self.project_id,
            self.data_source_id,
            requested_fields.join("|")
        )
    }
}

#[derive(Debug, Default)]
pub struct PermissionRegistry {
    applications: HashMap<String, PermissionApplication>,
    grants: Vec<PermissionGrant>,
}

impl PermissionRegistry {
    pub fn submit_application(
        &mut self,
        applicant_user_id: impl Into<String>,
        project_id: impl Into<String>,
        data_source_id: impl Into<String>,
        requested_fields: Vec<String>,
    ) -> PermissionApplication {
        let application = PermissionApplication {
            application_id: Ulid::new().to_string(),
            applicant_user_id: applicant_user_id.into(),
            project_id: project_id.into(),
            data_source_id: data_source_id.into(),
            requested_fields,
            status: GrantStatus::Pending,
            approval_instance_id: None,
            merged_into_application_id: None,
        };
        self.applications
            .insert(application.application_id.clone(), application.clone());
        application
    }

    pub fn restore_application(&mut self, application: PermissionApplication) {
        self.applications
            .insert(application.application_id.clone(), application);
    }

    pub fn register_grant(&mut self, grant: PermissionGrant) {
        self.grants.push(grant);
    }

    pub fn lifecycle_grants(&self) -> Vec<PermissionGrant> {
        self.grants
            .iter()
            .filter(|grant| matches!(grant.status, GrantStatus::Active | GrantStatus::Suspended))
            .cloned()
            .collect()
    }

    pub fn get_grant(&self, grant_id: &str) -> Option<PermissionGrant> {
        self.grants
            .iter()
            .find(|grant| grant.grant_id == grant_id)
            .cloned()
    }

    pub fn apply_lifecycle_transition(&mut self, transition: &GrantLifecycleTransition) -> bool {
        let Some(grant) = self
            .grants
            .iter_mut()
            .find(|grant| grant.grant_id == transition.grant_id)
        else {
            return false;
        };
        if grant.status != transition.from_status {
            return false;
        }
        grant.status = transition.to_status.clone();
        true
    }

    pub fn list_grants(
        &self,
        applicant_user_id: &str,
        project_id: Option<&str>,
        data_source_id: Option<&str>,
    ) -> Vec<PermissionGrant> {
        self.grants
            .iter()
            .filter(|grant| {
                grant.applicant_user_id == applicant_user_id
                    && project_id.is_none_or(|project_id| grant.project_id == project_id)
                    && data_source_id
                        .is_none_or(|data_source_id| grant.data_source_id == data_source_id)
            })
            .cloned()
            .collect()
    }

    pub fn get_application(&self, application_id: &str) -> Option<PermissionApplication> {
        self.applications.get(application_id).cloned()
    }

    pub fn activate_application(
        &mut self,
        application_id: &str,
        fields: Vec<FieldPermission>,
        conditions: Vec<FilterCondition>,
    ) -> Option<PermissionGrant> {
        let application = self.applications.get_mut(application_id)?;
        application.status = GrantStatus::Active;

        let grant = PermissionGrant::active(
            application.applicant_user_id.clone(),
            application.project_id.clone(),
            application.data_source_id.clone(),
            fields,
            conditions,
        );
        self.grants.push(grant.clone());
        Some(grant)
    }

    pub fn activate_application_with_grant(
        &mut self,
        application_id: &str,
        grant: PermissionGrant,
        approval_instance_id: Option<String>,
    ) -> Option<PermissionGrant> {
        let application = self.applications.get_mut(application_id)?;
        application.status = GrantStatus::Active;
        application.approval_instance_id = approval_instance_id;
        self.grants.push(grant.clone());
        Some(grant)
    }

    pub fn merged_active_grant(
        &self,
        applicant_user_id: &str,
        project_id: &str,
        data_source_id: &str,
    ) -> Option<PermissionGrant> {
        let grants = self
            .grants
            .iter()
            .filter(|grant| {
                grant.applicant_user_id == applicant_user_id
                    && grant.project_id == project_id
                    && grant.data_source_id == data_source_id
                    && grant.status == GrantStatus::Active
            })
            .cloned()
            .collect::<Vec<_>>();
        merge_grants(&grants)
    }

    pub fn application_count(&self) -> usize {
        self.applications.len()
    }

    pub fn revoke_grants_for_user(
        &mut self,
        applicant_user_id: &str,
        project_id: Option<&str>,
    ) -> usize {
        let mut revoked = 0;
        for grant in &mut self.grants {
            if grant.applicant_user_id == applicant_user_id
                && project_id.is_none_or(|project_id| grant.project_id == project_id)
                && grant.status == GrantStatus::Active
            {
                grant.status = GrantStatus::Revoked;
                revoked += 1;
            }
        }
        revoked
    }

    pub fn suspend_grants_for_user(
        &mut self,
        applicant_user_id: &str,
        project_id: Option<&str>,
    ) -> usize {
        let mut suspended = 0;
        for grant in &mut self.grants {
            if grant.applicant_user_id == applicant_user_id
                && project_id.is_none_or(|project_id| grant.project_id == project_id)
                && grant.status == GrantStatus::Active
            {
                grant.status = GrantStatus::Suspended;
                suspended += 1;
            }
        }
        suspended
    }

    pub fn suspend_grants_for_project(&mut self, project_id: &str) -> usize {
        let mut suspended = 0;
        for grant in &mut self.grants {
            if grant.project_id == project_id && grant.status == GrantStatus::Active {
                grant.status = GrantStatus::Suspended;
                suspended += 1;
            }
        }
        suspended
    }

    pub fn resume_grants_for_project(&mut self, project_id: &str) -> usize {
        let mut resumed = 0;
        for grant in &mut self.grants {
            if grant.project_id == project_id && grant.status == GrantStatus::Suspended {
                grant.status = GrantStatus::Active;
                resumed += 1;
            }
        }
        resumed
    }

    pub fn expire_grants(&mut self, now: DateTime<Utc>) -> usize {
        let mut expired = 0;
        for grant in &mut self.grants {
            if grant.status == GrantStatus::Active && grant.valid_until <= now {
                grant.status = GrantStatus::Expired;
                expired += 1;
            }
        }
        expired
    }

    pub fn active_grant_count(&self, applicant_user_id: &str, project_id: Option<&str>) -> usize {
        self.grants
            .iter()
            .filter(|grant| {
                grant.applicant_user_id == applicant_user_id
                    && project_id.is_none_or(|project_id| grant.project_id == project_id)
                    && grant.status == GrantStatus::Active
            })
            .count()
    }

    pub fn revoke_grants_for_project(&mut self, project_id: &str) -> usize {
        let mut revoked = 0;
        for grant in &mut self.grants {
            if grant.project_id == project_id
                && matches!(grant.status, GrantStatus::Active | GrantStatus::Suspended)
            {
                grant.status = GrantStatus::Revoked;
                revoked += 1;
            }
        }
        revoked
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use crate::{FieldPermission, GrantLifecycle, GrantStatus, OrgBinding, PermissionGrant};

    use super::PermissionRegistry;

    #[test]
    fn registry_tracks_applications_and_active_grants() {
        let mut registry = PermissionRegistry::default();
        let application = registry.submit_application(
            "user-a",
            "project-a",
            "datasource-a",
            vec!["employee_id".into()],
        );
        registry.activate_application(
            &application.application_id,
            vec![FieldPermission {
                field_name: "employee_id".into(),
                denied: false,
            }],
            Vec::new(),
        );
        registry.register_grant(PermissionGrant::active(
            "user-a",
            "project-a",
            "datasource-a",
            vec![FieldPermission {
                field_name: "employee_id".into(),
                denied: false,
            }],
            Vec::new(),
        ));

        assert_eq!(registry.application_count(), 1);
        assert!(
            registry
                .merged_active_grant("user-a", "project-a", "datasource-a")
                .is_some()
        );
    }

    #[test]
    fn registry_can_revoke_active_grants_for_user() {
        let mut registry = PermissionRegistry::default();
        registry.register_grant(PermissionGrant::active(
            "user-a",
            "project-a",
            "datasource-a",
            vec![FieldPermission {
                field_name: "employee_id".into(),
                denied: false,
            }],
            Vec::new(),
        ));

        assert_eq!(
            registry.revoke_grants_for_user("user-a", Some("project-a")),
            1
        );
        assert_eq!(registry.active_grant_count("user-a", Some("project-a")), 0);
    }

    #[test]
    fn registry_can_revoke_active_grants_for_project() {
        let mut registry = PermissionRegistry::default();
        registry.register_grant(PermissionGrant::active(
            "user-a",
            "project-a",
            "datasource-a",
            vec![FieldPermission {
                field_name: "employee_id".into(),
                denied: false,
            }],
            Vec::new(),
        ));

        assert_eq!(registry.revoke_grants_for_project("project-a"), 1);
        assert_eq!(registry.active_grant_count("user-a", Some("project-a")), 0);
    }

    #[test]
    fn registry_can_suspend_resume_and_expire_grants() {
        let mut registry = PermissionRegistry::default();
        let expired = PermissionGrant::new(
            "user-a",
            "project-a",
            "datasource-a",
            vec![FieldPermission {
                field_name: "employee_id".into(),
                denied: false,
            }],
            Vec::new(),
            GrantLifecycle {
                valid_from: Utc::now() - Duration::hours(2),
                valid_until: Utc::now() - Duration::minutes(1),
                org_binding: OrgBinding {
                    department_id: "dept-risk".into(),
                    manager_id: Some("manager-a".into()),
                },
                status: GrantStatus::Active,
            },
        );
        let active = PermissionGrant::active(
            "user-a",
            "project-a",
            "datasource-a",
            vec![FieldPermission {
                field_name: "employee_email".into(),
                denied: false,
            }],
            Vec::new(),
        );
        registry.register_grant(expired);
        registry.register_grant(active);

        assert_eq!(registry.expire_grants(Utc::now()), 1);
        assert_eq!(registry.suspend_grants_for_project("project-a"), 1);
        assert_eq!(registry.resume_grants_for_project("project-a"), 1);
    }

    #[test]
    fn registry_applies_lifecycle_transition_by_grant_id() {
        let mut registry = PermissionRegistry::default();
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
        let grant_id = grant.grant_id.clone();
        registry.register_grant(grant.clone());

        let transition = crate::GrantLifecycleTransition {
            transition_id: "transition-a".into(),
            grant_id: grant_id.clone(),
            applicant_user_id: grant.applicant_user_id.clone(),
            project_id: grant.project_id.clone(),
            data_source_id: grant.data_source_id.clone(),
            from_status: GrantStatus::Active,
            to_status: GrantStatus::Suspended,
            trigger: crate::GrantLifecycleTrigger::AuditAnomaly,
            reason: "test anomaly".into(),
            effective_at: Utc::now(),
            source_event_id: Some("audit-event-a".into()),
        };

        assert!(registry.apply_lifecycle_transition(&transition));
        assert_eq!(
            registry.get_grant(&grant_id).expect("grant").status,
            GrantStatus::Suspended
        );
    }
}
