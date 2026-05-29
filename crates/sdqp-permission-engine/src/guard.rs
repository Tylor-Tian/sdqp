use thiserror::Error;

use sdqp_core::FieldSelector;
use sdqp_datasource_adapter::UnifiedQuery;

use crate::{GrantStatus, PermissionGrant};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GuardError {
    #[error("permission grant is not active")]
    InactiveGrant,
    #[error("requested field is not authorized: {0}")]
    UnauthorizedField(String),
}

pub fn apply_grant_to_query(
    grant: &PermissionGrant,
    requested_fields: &[FieldSelector],
) -> Result<UnifiedQuery, GuardError> {
    if grant.status != GrantStatus::Active {
        return Err(GuardError::InactiveGrant);
    }

    for requested in requested_fields {
        let allowed = grant
            .fields
            .iter()
            .any(|field| field.field_name == requested.as_str() && !field.denied);
        if !allowed {
            return Err(GuardError::UnauthorizedField(
                requested.as_str().to_string(),
            ));
        }
    }

    let mut query = UnifiedQuery::new(requested_fields.to_vec());
    query.conditions = grant.conditions.clone();
    query.condition_groups = grant.condition_groups.clone();
    Ok(query)
}

#[cfg(test)]
mod tests {
    use sdqp_core::FieldSelector;

    use crate::{FieldPermission, PermissionGrant};

    use super::{GuardError, apply_grant_to_query};

    #[test]
    fn guard_rejects_unauthorized_field() {
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

        assert_eq!(
            apply_grant_to_query(
                &grant,
                &[FieldSelector::new("employee_email").expect("field")]
            ),
            Err(GuardError::UnauthorizedField("employee_email".into()))
        );
    }

    #[test]
    fn guard_copies_disjunctive_condition_groups() {
        let mut grant = PermissionGrant::active(
            "user-a",
            "project-a",
            "datasource-a",
            vec![FieldPermission {
                field_name: "employee_id".into(),
                denied: false,
            }],
            Vec::new(),
        );
        grant.condition_groups = vec![sdqp_core::FilterConditionGroup::new(vec![
            sdqp_core::FilterCondition {
                field: "department".into(),
                operator: sdqp_core::FilterOperator::Eq,
                value: "fraud".into(),
            },
        ])];

        let query =
            apply_grant_to_query(&grant, &[FieldSelector::new("employee_id").expect("field")])
                .expect("query");

        assert_eq!(query.condition_groups, grant.condition_groups);
    }
}
