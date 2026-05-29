use crate::{AuditCheckpoint, AuditEvent, verify_checkpoint};

pub fn verify_chain(events: &[AuditEvent]) -> bool {
    verify_chain_with_anchor(events, None)
}

pub fn verify_chain_with_anchor(
    events: &[AuditEvent],
    anchor_checkpoint: Option<&AuditCheckpoint>,
) -> bool {
    if anchor_checkpoint.is_some_and(|checkpoint| !verify_checkpoint(checkpoint)) {
        return false;
    }

    if events.is_empty() {
        return true;
    }

    let expected_prev_hash = anchor_checkpoint
        .map(|checkpoint| checkpoint.last_event_hash.as_str())
        .unwrap_or("GENESIS");
    if events[0].prev_hash != expected_prev_hash || !events[0].verify_hash() {
        return false;
    }

    events
        .windows(2)
        .all(|pair| pair[1].verify_hash() && pair[1].prev_hash == pair[0].event_hash)
}

#[cfg(test)]
mod tests {
    use super::{verify_chain, verify_chain_with_anchor};
    use crate::{
        ActionResult, ActionType, ActorInfo, AuditEvent, TargetRef,
        build_checkpoint_signer_registry, signer::CheckpointSignerConfig,
    };

    fn actor() -> ActorInfo {
        ActorInfo {
            user_id: "user-a".into(),
            session_id: "session-a".into(),
            ip_address: "127.0.0.1".into(),
        }
    }

    fn target() -> TargetRef {
        TargetRef {
            tenant_id: "tenant-a".into(),
            project_id: Some("project-a".into()),
            resource_id: "grant-1".into(),
        }
    }

    #[test]
    fn verifies_linear_chain() {
        let first = AuditEvent::new(
            actor(),
            ActionType::Login,
            target(),
            "login",
            ActionResult::Success,
            None,
            None,
        );
        let second = AuditEvent::new(
            actor(),
            ActionType::Query,
            target(),
            "query",
            ActionResult::Success,
            Some("sha256:demo".into()),
            Some(first.event_hash.clone()),
        );

        assert!(verify_chain(&[first, second]));
    }

    #[test]
    fn rejects_tampered_event_hash() {
        let mut event = AuditEvent::new(
            actor(),
            ActionType::Login,
            target(),
            "login",
            ActionResult::Success,
            None,
            None,
        );
        event.event_hash = "tampered".into();

        assert!(!verify_chain(&[event]));
    }

    #[test]
    fn verifies_segment_chain_against_archived_anchor() {
        let signer = build_checkpoint_signer_registry(&CheckpointSignerConfig::default())
            .expect("registry")
            .active_signer()
            .expect("signer")
            .clone();
        let first = AuditEvent::new(
            actor(),
            ActionType::Login,
            target(),
            "login",
            ActionResult::Success,
            None,
            None,
        );
        let anchor = crate::create_checkpoint_with_signer(1, &first.event_hash, signer.as_ref())
            .expect("anchor");
        let second = AuditEvent::new(
            actor(),
            ActionType::Query,
            target(),
            "query",
            ActionResult::Success,
            Some("sha256:demo".into()),
            Some(first.event_hash.clone()),
        );

        assert!(verify_chain_with_anchor(&[second], Some(&anchor)));
    }
}
