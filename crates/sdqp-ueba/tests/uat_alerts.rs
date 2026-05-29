use chrono::{Duration, TimeZone, Utc};
use sdqp_audit::{ActionResult, ActionType, ActorInfo, AuditEvent, TargetRef};
use sdqp_ueba::{MitigationAction, UebaRule, build_user_baselines, evaluate_alerts};

fn actor() -> ActorInfo {
    ActorInfo {
        user_id: "user-analyst".into(),
        session_id: "session-ueba".into(),
        ip_address: "127.0.0.1".into(),
    }
}

fn target() -> TargetRef {
    TargetRef {
        tenant_id: "tenant-alpha".into(),
        project_id: Some("project-alpha".into()),
        resource_id: "snapshot-ueba".into(),
    }
}

fn event(
    action: ActionType,
    result: ActionResult,
    context: &str,
    minutes_offset: i64,
) -> AuditEvent {
    let mut event = AuditEvent::new(actor(), action, target(), context, result, None, None);
    event.timestamp = Utc::now() + Duration::minutes(minutes_offset);
    event
}

#[test]
fn uat_engine_detects_six_anomaly_classes_and_assigns_mitigations() {
    let mut events = vec![
        event(ActionType::Query, ActionResult::Success, "query-1", 0),
        event(ActionType::Query, ActionResult::Success, "query-2", 1),
        event(ActionType::Query, ActionResult::Success, "query-3", 2),
        event(ActionType::Query, ActionResult::Success, "query-4", 3),
        event(ActionType::Query, ActionResult::Success, "query-5", 4),
        event(
            ActionType::Query,
            ActionResult::Denied,
            "forbidden employee_email",
            5,
        ),
        event(
            ActionType::Query,
            ActionResult::Denied,
            "forbidden salary",
            6,
        ),
        event(ActionType::Export, ActionResult::Success, "export-1", 7),
        event(ActionType::Export, ActionResult::Success, "export-2", 8),
        event(ActionType::Export, ActionResult::Success, "export-3", 9),
        event(
            ActionType::View,
            ActionResult::Success,
            "dns://exfil.example TXT base32",
            10,
        ),
        event(
            ActionType::View,
            ActionResult::Success,
            "https://exfil.example/beacon/pixel.gif?chunk=abc",
            11,
        ),
    ];
    events[10].timestamp = Utc
        .with_ymd_and_hms(2026, 3, 29, 23, 45, 0)
        .single()
        .expect("time");

    let alerts = evaluate_alerts(&events, &build_user_baselines(&events));
    let rules = alerts
        .iter()
        .map(|alert| alert.rule.clone())
        .collect::<Vec<_>>();
    let actions = alerts
        .iter()
        .map(|alert| alert.action.clone())
        .collect::<Vec<_>>();

    assert!(rules.contains(&UebaRule::HighFrequencyQuery));
    assert!(rules.contains(&UebaRule::UnauthorizedQueryBurst));
    assert!(rules.contains(&UebaRule::ExportSpike));
    assert!(rules.contains(&UebaRule::AfterHoursAccess));
    assert!(rules.contains(&UebaRule::HiddenChannelDns));
    assert!(rules.contains(&UebaRule::HiddenChannelHttp));
    assert!(actions.contains(&MitigationAction::StepUpAuth));
    assert!(actions.contains(&MitigationAction::SuspendPermissions));
    assert!(actions.contains(&MitigationAction::TerminateSession));
}
