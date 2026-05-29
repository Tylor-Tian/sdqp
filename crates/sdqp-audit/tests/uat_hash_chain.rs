use sdqp_audit::{ActionResult, ActionType, ActorInfo, AuditEvent, TargetRef, verify_chain};

#[test]
fn uat_hash_chain_tracks_follow_up_query_event() {
    let actor = ActorInfo {
        user_id: "user-uat".into(),
        session_id: "session-uat".into(),
        ip_address: "127.0.0.1".into(),
    };
    let target = TargetRef {
        tenant_id: "tenant-uat".into(),
        project_id: Some("project-uat".into()),
        resource_id: "snapshot-uat".into(),
    };

    let first = AuditEvent::new(
        actor.clone(),
        ActionType::Login,
        target.clone(),
        "login",
        ActionResult::Success,
        None,
        None,
    );
    let second = AuditEvent::new(
        actor,
        ActionType::Query,
        target,
        "query",
        ActionResult::Success,
        Some("sha256:payload".into()),
        Some(first.event_hash.clone()),
    );

    assert!(verify_chain(&[first, second]));
}
