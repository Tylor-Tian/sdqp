use chrono::{Duration, Utc};
use sdqp_approval_engine::{
    ApprovalEngine, ApprovalFlowDefinition, ApprovalMode, ApprovalRequest, ApprovalStatus,
    ApprovalStepDefinition, ApproverSelector, MockNotificationSink,
};
use sdqp_data_classification::recommend_field_classification;
use sdqp_hr_integration::{
    EmploymentStatus, HrEvent, HrEventType, OrgDirectory, OrgUser, RevocationReason, SyncSource,
};
use sdqp_permission_engine::{FieldPermission, PermissionRegistry};

fn directory() -> OrgDirectory {
    let mut directory = OrgDirectory::default();
    directory.sync_snapshot(
        SyncSource::FeishuMock,
        vec![
            OrgUser {
                user_id: "manager-a".into(),
                department_id: "dept-risk".into(),
                manager_id: None,
                status: EmploymentStatus::Active,
                approver_profile: None,
            },
            OrgUser {
                user_id: "security-a".into(),
                department_id: "dept-security".into(),
                manager_id: None,
                status: EmploymentStatus::Active,
                approver_profile: None,
            },
            OrgUser {
                user_id: "security-b".into(),
                department_id: "dept-security".into(),
                manager_id: None,
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

#[test]
fn uat_application_approval_effective_and_hr_revocation_flow_succeeds() {
    let mut permission_registry = PermissionRegistry::default();
    let application = permission_registry.submit_application(
        "user-a",
        "project-alpha",
        "datasource-rest",
        vec!["employee_email".into()],
    );

    let flow = ApprovalFlowDefinition {
        flow_id: "flow-governance".into(),
        version: 1,
        steps: vec![ApprovalStepDefinition {
            step_id: "manager-approval".into(),
            mode: ApprovalMode::Serial,
            approvers: vec![ApproverSelector::Manager],
            timeout_minutes: 30,
            escalation: Some(ApproverSelector::User("security-a".into())),
        }],
    };
    let request = ApprovalRequest {
        request_id: application.application_id.clone(),
        applicant_user_id: application.applicant_user_id.clone(),
        project_id: application.project_id.clone(),
        data_source_id: application.data_source_id.clone(),
    };
    let mut notifier = MockNotificationSink::default();
    let mut directory = directory();
    let mut instance =
        ApprovalEngine::start_instance(&flow, &request, &directory, Utc::now(), &mut notifier)
            .expect("instance");

    ApprovalEngine::approve(
        &mut instance,
        &flow,
        &request,
        &directory,
        "manager-a",
        Utc::now(),
        &mut notifier,
    )
    .expect("approval");
    assert_eq!(instance.status, ApprovalStatus::Approved);

    let classification = recommend_field_classification("employee_email");
    let grant = permission_registry.activate_application(
        &application.application_id,
        vec![FieldPermission {
            field_name: classification.field_name.clone(),
            denied: false,
        }],
        Vec::new(),
    );
    assert!(grant.is_some());
    assert_eq!(
        permission_registry.active_grant_count("user-a", Some("project-alpha")),
        1
    );

    let revocations = directory
        .apply_event(HrEvent::new("user-a", HrEventType::Departure, None, None))
        .expect("hr event");
    assert_eq!(revocations[0].reason, RevocationReason::Departure);
    for command in revocations {
        permission_registry.revoke_grants_for_user(&command.user_id, command.project_id.as_deref());
    }

    assert_eq!(
        permission_registry.active_grant_count("user-a", Some("project-alpha")),
        0
    );
}

#[test]
fn uat_parallel_all_and_any_one_approval_modes_are_supported() {
    let directory = directory();
    let request = ApprovalRequest {
        request_id: "req-parallel".into(),
        applicant_user_id: "user-a".into(),
        project_id: "project-alpha".into(),
        data_source_id: "datasource-rest".into(),
    };

    let parallel_flow = ApprovalFlowDefinition {
        flow_id: "flow-parallel".into(),
        version: 1,
        steps: vec![ApprovalStepDefinition {
            step_id: "parallel-step".into(),
            mode: ApprovalMode::ParallelAll,
            approvers: vec![
                ApproverSelector::User("security-a".into()),
                ApproverSelector::User("security-b".into()),
            ],
            timeout_minutes: 30,
            escalation: None,
        }],
    };
    let mut notifier = MockNotificationSink::default();
    let mut instance = ApprovalEngine::start_instance(
        &parallel_flow,
        &request,
        &directory,
        Utc::now(),
        &mut notifier,
    )
    .expect("parallel");
    ApprovalEngine::approve(
        &mut instance,
        &parallel_flow,
        &request,
        &directory,
        "security-a",
        Utc::now(),
        &mut notifier,
    )
    .expect("first");
    ApprovalEngine::approve(
        &mut instance,
        &parallel_flow,
        &request,
        &directory,
        "security-b",
        Utc::now(),
        &mut notifier,
    )
    .expect("second");
    assert_eq!(instance.status, ApprovalStatus::Approved);

    let any_one_flow = ApprovalFlowDefinition {
        flow_id: "flow-any".into(),
        version: 1,
        steps: vec![ApprovalStepDefinition {
            step_id: "any-step".into(),
            mode: ApprovalMode::AnyOne,
            approvers: vec![
                ApproverSelector::User("security-a".into()),
                ApproverSelector::User("security-b".into()),
            ],
            timeout_minutes: 30,
            escalation: None,
        }],
    };
    let mut any_one_instance = ApprovalEngine::start_instance(
        &any_one_flow,
        &request,
        &directory,
        Utc::now() + Duration::minutes(1),
        &mut notifier,
    )
    .expect("any-one");
    ApprovalEngine::approve(
        &mut any_one_instance,
        &any_one_flow,
        &request,
        &directory,
        "security-a",
        Utc::now() + Duration::minutes(1),
        &mut notifier,
    )
    .expect("approval");
    assert_eq!(any_one_instance.status, ApprovalStatus::Approved);
}
