use std::path::PathBuf;

use sdqp_audit::{
    ActionResult, ActionType, ActorInfo, AuditEvent, AuditTrail, TargetRef, read_replica_file,
    verify_replica, write_replica_file,
};

fn event(prev_hash: Option<String>) -> AuditEvent {
    AuditEvent::new(
        ActorInfo {
            user_id: "user-uat".into(),
            session_id: "session-uat".into(),
            ip_address: "127.0.0.1".into(),
        },
        ActionType::View,
        TargetRef {
            tenant_id: "tenant-uat".into(),
            project_id: Some("project-uat".into()),
            resource_id: "snapshot-uat".into(),
        },
        "uat replica export",
        ActionResult::Success,
        Some("sha256:uat".into()),
        prev_hash,
    )
}

#[test]
fn uat_replica_export_round_trips_with_chain_intact() {
    let mut trail = AuditTrail::default();
    let first = event(None);
    let second = event(Some(first.event_hash.clone()));
    trail.append(first);
    trail.append(second);

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("uat-replica-export.json");
    write_replica_file(&path, &trail.export_replica()).expect("write replica");

    let replica = read_replica_file(&path).expect("replica");
    assert!(verify_replica(&replica));
    assert_eq!(replica.events.len(), 2);
    assert_eq!(replica.checkpoints.len(), 2);

    let _ = std::fs::remove_file(path);
}
