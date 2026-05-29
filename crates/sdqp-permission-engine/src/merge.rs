use std::collections::{BTreeMap, BTreeSet};

use sdqp_core::FilterConditionGroup;

use crate::{FieldPermission, GrantStatus, PermissionGrant};

pub fn merge_grants(grants: &[PermissionGrant]) -> Option<PermissionGrant> {
    let active = grants
        .iter()
        .filter(|grant| grant.status == GrantStatus::Active)
        .cloned()
        .collect::<Vec<_>>();
    let first = active.first()?.clone();

    if active.len() == 1 {
        return Some(first);
    }

    let mut field_map = BTreeMap::<String, bool>::new();
    let mut condition_groups = Vec::<FilterConditionGroup>::new();
    let mut seen_group_signatures = BTreeSet::<String>::new();

    let valid_from = active
        .iter()
        .map(|grant| grant.valid_from)
        .max()
        .expect("active grants");
    let valid_until = active
        .iter()
        .map(|grant| grant.valid_until)
        .min()
        .expect("active grants");

    if valid_from > valid_until {
        return None;
    }

    for grant in &active {
        for field in &grant.fields {
            let existing = field_map.entry(field.field_name.clone()).or_insert(false);
            *existing = *existing || field.denied;
        }

        for group in expanded_condition_groups(grant) {
            let signature = group_signature(&group);
            if seen_group_signatures.insert(signature) {
                condition_groups.push(group);
            }
        }
    }

    Some(PermissionGrant {
        fields: field_map
            .into_iter()
            .map(|(field_name, denied)| FieldPermission { field_name, denied })
            .collect(),
        conditions: Vec::new(),
        condition_groups,
        valid_from,
        valid_until,
        ..first
    })
}

fn expanded_condition_groups(grant: &PermissionGrant) -> Vec<FilterConditionGroup> {
    if grant.condition_groups.is_empty() {
        return vec![FilterConditionGroup::new(grant.conditions.clone())];
    }

    grant
        .condition_groups
        .iter()
        .map(|group| {
            let mut conditions = grant.conditions.clone();
            conditions.extend(group.conditions.clone());
            FilterConditionGroup::new(conditions)
        })
        .collect()
}

fn group_signature(group: &FilterConditionGroup) -> String {
    group
        .conditions
        .iter()
        .map(|condition| {
            format!(
                "{}::{:?}::{}",
                condition.field, condition.operator, condition.value
            )
        })
        .collect::<Vec<_>>()
        .join("&&")
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use sdqp_core::{FilterCondition, FilterOperator};

    use crate::{FieldPermission, GrantLifecycle, OrgBinding, PermissionGrant};

    use super::merge_grants;

    #[test]
    fn merge_grants_applies_deny_wins() {
        let grant_a = PermissionGrant::active(
            "user-a",
            "project-a",
            "datasource-a",
            vec![FieldPermission {
                field_name: "employee_email".into(),
                denied: false,
            }],
            Vec::new(),
        );
        let grant_b = PermissionGrant::active(
            "user-a",
            "project-a",
            "datasource-a",
            vec![FieldPermission {
                field_name: "employee_email".into(),
                denied: true,
            }],
            Vec::new(),
        );

        let merged = merge_grants(&[grant_a, grant_b]).expect("merged");
        assert!(merged.fields.iter().any(|field| field.denied));
    }

    #[test]
    fn merge_grants_models_disjunctive_condition_groups_and_preserves_operators() {
        let grant_a = PermissionGrant::active(
            "user-a",
            "project-a",
            "datasource-a",
            vec![FieldPermission {
                field_name: "employee_id".into(),
                denied: false,
            }],
            vec![FilterCondition {
                field: "department".into(),
                operator: FilterOperator::Eq,
                value: "fraud".into(),
            }],
        );
        let grant_b = PermissionGrant::active(
            "user-a",
            "project-a",
            "datasource-a",
            vec![FieldPermission {
                field_name: "employee_email".into(),
                denied: false,
            }],
            vec![FilterCondition {
                field: "title".into(),
                operator: FilterOperator::Like,
                value: "senior%".into(),
            }],
        );

        let merged = merge_grants(&[grant_a, grant_b]).expect("merged");

        assert!(merged.conditions.is_empty());
        assert_eq!(merged.condition_groups.len(), 2);
        assert_eq!(
            merged.condition_groups[0].conditions[0].operator,
            FilterOperator::Eq
        );
        assert_eq!(
            merged.condition_groups[1].conditions[0].operator,
            FilterOperator::Like
        );
        assert_eq!(merged.fields.len(), 2);
    }

    #[test]
    fn merge_grants_intersects_time_windows() {
        let grant_a = PermissionGrant::new(
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
                valid_until: Utc::now() + Duration::hours(2),
                org_binding: OrgBinding {
                    department_id: "dept-a".into(),
                    manager_id: None,
                },
                status: crate::GrantStatus::Active,
            },
        );
        let grant_b = PermissionGrant::new(
            "user-a",
            "project-a",
            "datasource-a",
            vec![FieldPermission {
                field_name: "employee_email".into(),
                denied: false,
            }],
            Vec::new(),
            GrantLifecycle {
                valid_from: Utc::now() - Duration::hours(1),
                valid_until: Utc::now() + Duration::hours(1),
                org_binding: OrgBinding {
                    department_id: "dept-a".into(),
                    manager_id: None,
                },
                status: crate::GrantStatus::Active,
            },
        );

        let merged = merge_grants(&[grant_a.clone(), grant_b.clone()]).expect("merged");
        assert_eq!(merged.valid_from, grant_b.valid_from);
        assert_eq!(merged.valid_until, grant_b.valid_until);
    }

    #[test]
    fn merge_grants_returns_none_when_time_windows_do_not_overlap() {
        let grant_a = PermissionGrant::new(
            "user-a",
            "project-a",
            "datasource-a",
            vec![FieldPermission {
                field_name: "employee_id".into(),
                denied: false,
            }],
            Vec::new(),
            GrantLifecycle {
                valid_from: Utc::now() - Duration::hours(4),
                valid_until: Utc::now() - Duration::hours(2),
                org_binding: OrgBinding {
                    department_id: "dept-a".into(),
                    manager_id: None,
                },
                status: crate::GrantStatus::Active,
            },
        );
        let grant_b = PermissionGrant::new(
            "user-a",
            "project-a",
            "datasource-a",
            vec![FieldPermission {
                field_name: "employee_email".into(),
                denied: false,
            }],
            Vec::new(),
            GrantLifecycle {
                valid_from: Utc::now() - Duration::hours(1),
                valid_until: Utc::now() + Duration::hours(1),
                org_binding: OrgBinding {
                    department_id: "dept-a".into(),
                    manager_id: None,
                },
                status: crate::GrantStatus::Active,
            },
        );

        assert!(merge_grants(&[grant_a, grant_b]).is_none());
    }
}
