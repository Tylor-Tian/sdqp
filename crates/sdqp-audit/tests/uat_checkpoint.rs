use sdqp_audit::{
    ActionResult, ActionType, ActorInfo, AuditEvent, TargetRef, create_checkpoint,
    verify_checkpoint,
};

#[test]
fn uat_checkpoint_can_be_created_from_audit_stream() {
    let event = AuditEvent::new(
        ActorInfo {
            user_id: "user-uat".into(),
            session_id: "session-uat".into(),
            ip_address: "127.0.0.1".into(),
        },
        ActionType::ConfigChange,
        TargetRef {
            tenant_id: "tenant-uat".into(),
            project_id: None,
            resource_id: "config.kms".into(),
        },
        "config change",
        ActionResult::Success,
        None,
        None,
    );

    let checkpoint = create_checkpoint(&[event]).expect("checkpoint");
    assert!(verify_checkpoint(&checkpoint));
    assert_eq!(checkpoint.event_count, 1);
}
