use chrono::Utc;
use sdqp_hr_integration::{
    ApproverAvailability, ApproverProfile, EmploymentStatus, FeishuAdapter, HrEvent,
    HrEventListener, HrEventType, HrSyncOrchestrator, OrgDirectory, OrgUser, RevocationReason,
    SapEmploymentState, SapSuccessFactorsAdapter, SapSuccessFactorsEmployeeRecord,
    SapSuccessFactorsEventRecord, SapSuccessFactorsEventType, SyncSource, WorkdayAdapter,
    WorkdayEventRecord, WorkdayEventType, WorkdayWorkerRecord,
};

#[test]
fn uat_hr_sync_and_events_drive_manager_resolution_and_revocation_commands() {
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
                user_id: "user-a".into(),
                department_id: "dept-risk".into(),
                manager_id: Some("manager-a".into()),
                status: EmploymentStatus::Active,
                approver_profile: None,
            },
        ],
    );

    assert_eq!(
        directory.resolve_manager("user-a").expect("manager"),
        "manager-a"
    );

    let transfer_commands = directory
        .apply_event(HrEvent::new(
            "user-a",
            HrEventType::Transfer,
            Some("dept-fraud".into()),
            Some("manager-a".into()),
        ))
        .expect("transfer");
    assert_eq!(transfer_commands[0].reason, RevocationReason::Transfer);

    let departure_commands = directory
        .apply_event(HrEvent::new("user-a", HrEventType::Departure, None, None))
        .expect("departure");
    assert_eq!(
        directory.get_user("user-a").expect("user").status,
        EmploymentStatus::Departed
    );
    assert_eq!(departure_commands[0].reason, RevocationReason::Departure);
}

#[test]
fn uat_workday_sync_orchestration_normalizes_provider_data_and_revokes_access() {
    let mut orchestrator = HrSyncOrchestrator::new(OrgDirectory::default());
    let termination_id = "evt-workday-termination-001".to_string();
    let adapter = WorkdayAdapter::new(
        vec![
            WorkdayWorkerRecord {
                worker_id: "manager-a".into(),
                supervisory_org_id: "sup-org-risk".into(),
                manager_worker_id: None,
                active: true,
            },
            WorkdayWorkerRecord {
                worker_id: "user-a".into(),
                supervisory_org_id: "sup-org-risk".into(),
                manager_worker_id: Some("manager-a".into()),
                active: true,
            },
        ],
        vec![WorkdayEventRecord {
            event_id: termination_id.clone(),
            worker_id: "user-a".into(),
            event_type: WorkdayEventType::Termination,
            supervisory_org_id: Some("sup-org-risk".into()),
            manager_worker_id: Some("manager-a".into()),
            occurred_at: Utc::now(),
        }],
    );

    let report = orchestrator
        .sync_connector(SyncSource::WorkdayMock, &adapter, None)
        .expect("workday sync");

    assert_eq!(report.synced_user_count, 2);
    assert_eq!(report.applied_event_count, 1);
    assert_eq!(report.next_cursor.as_deref(), Some(termination_id.as_str()));
    assert_eq!(
        orchestrator
            .directory()
            .resolve_manager("user-a")
            .expect("manager"),
        "manager-a"
    );
    assert_eq!(
        orchestrator
            .directory()
            .get_user("user-a")
            .expect("user")
            .status,
        EmploymentStatus::Departed
    );
    assert_eq!(
        report.revocation_commands[0].reason,
        RevocationReason::Departure
    );
}

#[test]
fn uat_sap_listener_orchestration_normalizes_provider_data_and_advances_cursor() {
    let mut orchestrator = HrSyncOrchestrator::new(OrgDirectory::default());
    let mut listener = HrEventListener::default();
    let transfer_id = "evt-sap-001-transfer".to_string();
    let departure_id = "evt-sap-002-departure".to_string();
    let adapter = SapSuccessFactorsAdapter::new(
        vec![
            SapSuccessFactorsEmployeeRecord {
                person_id_external: "manager-a".into(),
                department_external_code: "sf-risk".into(),
                manager_person_id_external: None,
                employment_status: SapEmploymentState::Active,
            },
            SapSuccessFactorsEmployeeRecord {
                person_id_external: "user-a".into(),
                department_external_code: "sf-risk".into(),
                manager_person_id_external: Some("manager-a".into()),
                employment_status: SapEmploymentState::Active,
            },
        ],
        vec![
            SapSuccessFactorsEventRecord {
                event_id: departure_id.clone(),
                person_id_external: "user-a".into(),
                event_type: SapSuccessFactorsEventType::Termination,
                department_external_code: Some("sf-risk".into()),
                manager_person_id_external: Some("manager-a".into()),
                occurred_at: Utc::now() + chrono::Duration::minutes(2),
            },
            SapSuccessFactorsEventRecord {
                event_id: transfer_id.clone(),
                person_id_external: "user-a".into(),
                event_type: SapSuccessFactorsEventType::DepartmentChange,
                department_external_code: Some("sf-fraud".into()),
                manager_person_id_external: Some("manager-a".into()),
                occurred_at: Utc::now() + chrono::Duration::minutes(1),
            },
        ],
    );

    let first_report = listener
        .process_connector(
            &mut orchestrator,
            SyncSource::SapSuccessFactorsMock,
            &adapter,
        )
        .expect("sap listener pass");

    assert_eq!(first_report.synced_user_count, 2);
    assert_eq!(first_report.applied_event_count, 2);
    assert_eq!(
        first_report.next_cursor.as_deref(),
        Some(departure_id.as_str())
    );
    assert_eq!(
        listener.checkpoint(&SyncSource::SapSuccessFactorsMock),
        Some(departure_id.as_str())
    );
    assert_eq!(
        orchestrator
            .directory()
            .resolve_manager("user-a")
            .expect("manager"),
        "manager-a"
    );
    assert_eq!(
        orchestrator
            .directory()
            .get_user("user-a")
            .expect("user")
            .status,
        EmploymentStatus::Departed
    );
    assert!(
        first_report
            .revocation_commands
            .iter()
            .any(|command| command.reason == RevocationReason::Transfer)
    );
    assert!(
        first_report
            .revocation_commands
            .iter()
            .any(|command| command.reason == RevocationReason::Departure)
    );

    let second_report = listener
        .process_connector(
            &mut orchestrator,
            SyncSource::SapSuccessFactorsMock,
            &adapter,
        )
        .expect("sap listener dedupe");
    assert_eq!(second_report.applied_event_count, 0);
    assert_eq!(
        second_report.next_cursor.as_deref(),
        Some(departure_id.as_str())
    );
}

#[test]
fn uat_feishu_listener_carries_approver_profiles_into_directory_routing() {
    let mut orchestrator = HrSyncOrchestrator::new(OrgDirectory::default());
    let mut listener = HrEventListener::default();
    let adapter = FeishuAdapter::new(
        vec![
            OrgUser {
                user_id: "user-security-a".into(),
                department_id: "dept-security".into(),
                manager_id: None,
                status: EmploymentStatus::Active,
                approver_profile: None,
            },
            OrgUser {
                user_id: "user-security-b".into(),
                department_id: "dept-security".into(),
                manager_id: Some("user-security-a".into()),
                status: EmploymentStatus::Active,
                approver_profile: None,
            },
            OrgUser {
                user_id: "user-manager-a".into(),
                department_id: "dept-risk".into(),
                manager_id: None,
                status: EmploymentStatus::Active,
                approver_profile: None,
            },
        ],
        vec![
            HrEvent::new("user-manager-a", HrEventType::ManagerChange, None, None)
                .with_approver_profile(ApproverProfile {
                    availability: ApproverAvailability::Unavailable,
                    delegate_user_id: Some("user-security-b".into()),
                }),
        ],
    );

    let report = listener
        .process_connector(&mut orchestrator, SyncSource::FeishuMock, &adapter)
        .expect("feishu listener pass");

    assert_eq!(report.synced_user_count, 3);
    assert_eq!(report.applied_event_count, 1);

    let manager_profile = orchestrator
        .directory()
        .approver_profile("user-manager-a")
        .expect("manager profile");
    assert_eq!(
        manager_profile.availability,
        ApproverAvailability::Unavailable
    );
    assert_eq!(
        manager_profile.delegate_user_id.as_deref(),
        Some("user-security-b")
    );

    let route = orchestrator
        .directory()
        .resolve_effective_approver("user-manager-a", "user-security-a")
        .expect("effective route");
    assert_eq!(route.resolved_user_id, "user-security-b");
    assert_eq!(route.delegated_from.as_deref(), Some("user-manager-a"));
}
