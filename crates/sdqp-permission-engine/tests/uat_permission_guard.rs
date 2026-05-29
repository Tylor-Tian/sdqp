use sdqp_core::{FieldSelector, FilterCondition, FilterOperator};
use sdqp_permission_engine::{
    FieldPermission, GrantStatus, PermissionGrant, PermissionRegistry, apply_grant_to_query,
    merge_grants,
};

#[test]
fn uat_active_grant_can_be_merged_and_applied_to_query() {
    let grant_a = PermissionGrant::active(
        "user-uat",
        "project-alpha",
        "datasource-alpha",
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
        "user-uat",
        "project-alpha",
        "datasource-alpha",
        vec![FieldPermission {
            field_name: "employee_email".into(),
            denied: false,
        }],
        vec![FilterCondition {
            field: "region".into(),
            operator: FilterOperator::Eq,
            value: "cn".into(),
        }],
    );

    let merged = merge_grants(&[grant_a, grant_b]).expect("merged");
    let query = apply_grant_to_query(
        &merged,
        &[
            FieldSelector::new("employee_id").expect("field"),
            FieldSelector::new("employee_email").expect("field"),
        ],
    )
    .expect("guarded query");

    assert_eq!(query.fields.len(), 2);
    assert!(query.conditions.is_empty());
    assert_eq!(query.condition_groups.len(), 2);
}

#[test]
fn uat_permission_registry_stores_application_and_resolves_merged_grant() {
    let mut registry = PermissionRegistry::default();
    let application = registry.submit_application(
        "user-uat",
        "project-alpha",
        "datasource-alpha",
        vec!["employee_id".into()],
    );
    registry.register_grant(PermissionGrant::active(
        "user-uat",
        "project-alpha",
        "datasource-alpha",
        vec![FieldPermission {
            field_name: "employee_id".into(),
            denied: false,
        }],
        Vec::new(),
    ));

    assert_eq!(registry.application_count(), 1);
    assert_eq!(application.status, GrantStatus::Pending);
    assert!(
        registry
            .merged_active_grant("user-uat", "project-alpha", "datasource-alpha")
            .is_some()
    );
}
