use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use sdqp_core::{FilterCondition, FilterConditionGroup};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldPermission {
    pub field_name: String,
    pub denied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgBinding {
    pub department_id: String,
    pub manager_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantStatus {
    Pending,
    Active,
    Suspended,
    Expired,
    Revoked,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionGrant {
    pub grant_id: String,
    pub applicant_user_id: String,
    pub project_id: String,
    pub data_source_id: String,
    pub fields: Vec<FieldPermission>,
    pub conditions: Vec<FilterCondition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub condition_groups: Vec<FilterConditionGroup>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub org_binding: OrgBinding,
    pub status: GrantStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantLifecycle {
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub org_binding: OrgBinding,
    pub status: GrantStatus,
}

impl PermissionGrant {
    pub fn active(
        applicant_user_id: impl Into<String>,
        project_id: impl Into<String>,
        data_source_id: impl Into<String>,
        fields: Vec<FieldPermission>,
        conditions: Vec<FilterCondition>,
    ) -> Self {
        Self {
            grant_id: Ulid::new().to_string(),
            applicant_user_id: applicant_user_id.into(),
            project_id: project_id.into(),
            data_source_id: data_source_id.into(),
            fields,
            conditions,
            condition_groups: Vec::new(),
            valid_from: Utc::now(),
            valid_until: Utc::now() + chrono::Duration::hours(8),
            org_binding: OrgBinding {
                department_id: "dept-default".into(),
                manager_id: None,
            },
            status: GrantStatus::Active,
        }
    }

    pub fn new(
        applicant_user_id: impl Into<String>,
        project_id: impl Into<String>,
        data_source_id: impl Into<String>,
        fields: Vec<FieldPermission>,
        conditions: Vec<FilterCondition>,
        lifecycle: GrantLifecycle,
    ) -> Self {
        Self {
            grant_id: Ulid::new().to_string(),
            applicant_user_id: applicant_user_id.into(),
            project_id: project_id.into(),
            data_source_id: data_source_id.into(),
            fields,
            conditions,
            condition_groups: Vec::new(),
            valid_from: lifecycle.valid_from,
            valid_until: lifecycle.valid_until,
            org_binding: lifecycle.org_binding,
            status: lifecycle.status,
        }
    }

    pub fn condition_count(&self) -> usize {
        self.conditions.len()
            + self
                .condition_groups
                .iter()
                .map(|group| group.conditions.len())
                .sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldPermission, GrantStatus, PermissionGrant};

    #[test]
    fn active_grant_builder_sets_expected_defaults() {
        let grant = PermissionGrant::active(
            "user-a",
            "project-a",
            "datasource-a",
            vec![FieldPermission {
                field_name: "employee_email".into(),
                denied: false,
            }],
            Vec::new(),
        );
        assert_eq!(grant.status, GrantStatus::Active);
        assert_eq!(grant.fields.len(), 1);
    }
}
