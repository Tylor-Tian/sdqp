use std::{fs, path::Path};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    AuditCheckpoint, AuditEvent, CheckpointSigner, create_checkpoint,
    create_checkpoint_with_signer, verify_chain_with_anchor, verify_checkpoint,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditTrail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    anchor_checkpoint: Option<AuditCheckpoint>,
    events: Vec<AuditEvent>,
    checkpoints: Vec<AuditCheckpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReplica {
    pub exported_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_checkpoint: Option<AuditCheckpoint>,
    pub events: Vec<AuditEvent>,
    pub checkpoints: Vec<AuditCheckpoint>,
}

impl AuditTrail {
    pub fn from_parts(events: Vec<AuditEvent>, checkpoints: Vec<AuditCheckpoint>) -> Self {
        Self::from_parts_with_anchor(None, events, checkpoints)
    }

    pub fn from_parts_with_anchor(
        anchor_checkpoint: Option<AuditCheckpoint>,
        events: Vec<AuditEvent>,
        checkpoints: Vec<AuditCheckpoint>,
    ) -> Self {
        Self {
            anchor_checkpoint,
            events,
            checkpoints,
        }
    }

    pub fn append(&mut self, event: AuditEvent) -> AuditCheckpoint {
        let checkpoint =
            create_checkpoint(std::slice::from_ref(&event)).expect("checkpoint requires event");
        let signer = crate::signer::checkpoint_signer_from_metadata(
            &checkpoint.signer_provider,
            &checkpoint.signer_key_id,
            checkpoint.signer_key_version.as_deref(),
            &checkpoint.signature_algorithm,
        )
        .expect("default checkpoint signer");
        self.append_with_signer(event, signer.as_ref())
    }

    pub fn append_with_signer(
        &mut self,
        event: AuditEvent,
        signer: &dyn CheckpointSigner,
    ) -> AuditCheckpoint {
        self.events.push(event);
        let total_events = self
            .anchor_checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.event_count)
            .unwrap_or(0)
            + self.events.len();
        let checkpoint = create_checkpoint_with_signer(
            total_events,
            &self
                .events
                .last()
                .expect("checkpoint requires event")
                .event_hash,
            signer,
        )
        .expect("checkpoint requires event");
        self.checkpoints.push(checkpoint.clone());
        checkpoint
    }

    pub fn latest_event_hash(&self) -> Option<String> {
        self.events
            .last()
            .map(|event| event.event_hash.clone())
            .or_else(|| {
                self.anchor_checkpoint
                    .as_ref()
                    .map(|checkpoint| checkpoint.last_event_hash.clone())
            })
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn chain_valid(&self) -> bool {
        verify_chain_with_anchor(&self.events, self.anchor_checkpoint.as_ref())
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    pub fn anchor_checkpoint(&self) -> Option<&AuditCheckpoint> {
        self.anchor_checkpoint.as_ref()
    }

    pub fn checkpoints(&self) -> &[AuditCheckpoint] {
        &self.checkpoints
    }

    pub fn apply_archive_boundary(&mut self, boundary_checkpoint: AuditCheckpoint) {
        let previous_offset = self
            .anchor_checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.event_count)
            .unwrap_or(0);
        let archived_event_count = boundary_checkpoint
            .event_count
            .saturating_sub(previous_offset)
            .min(self.events.len());
        let archived_checkpoint_count = self
            .checkpoints
            .iter()
            .take_while(|checkpoint| checkpoint.event_count <= boundary_checkpoint.event_count)
            .count();
        self.events.drain(..archived_event_count);
        self.checkpoints.drain(..archived_checkpoint_count);
        self.anchor_checkpoint = Some(boundary_checkpoint);
    }

    pub fn tenant_events(&self, tenant_id: &str) -> Vec<AuditEvent> {
        self.events
            .iter()
            .filter(|event| event.target.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    pub fn scoped_events(
        &self,
        tenant_id: &str,
        project_id: Option<&str>,
        include_projectless: bool,
    ) -> Vec<AuditEvent> {
        self.events
            .iter()
            .filter(|event| event.target.tenant_id == tenant_id)
            .filter(|event| match project_id {
                Some(project_id) => {
                    event.target.project_id.as_deref() == Some(project_id)
                        || (include_projectless && event.target.project_id.is_none())
                }
                None => true,
            })
            .cloned()
            .collect()
    }

    pub fn export_replica(&self) -> AuditReplica {
        AuditReplica {
            exported_at: Utc::now(),
            anchor_checkpoint: self.anchor_checkpoint.clone(),
            events: self.events.clone(),
            checkpoints: self.checkpoints.clone(),
        }
    }
}

pub fn verify_replica(replica: &AuditReplica) -> bool {
    verify_chain_with_anchor(&replica.events, replica.anchor_checkpoint.as_ref())
        && replica.checkpoints.iter().all(verify_checkpoint)
        && replica.checkpoints.last().is_none_or(|checkpoint| {
            checkpoint.event_count
                == replica
                    .anchor_checkpoint
                    .as_ref()
                    .map(|anchor| anchor.event_count)
                    .unwrap_or(0)
                    + replica.events.len()
                && replica
                    .events
                    .last()
                    .is_some_and(|event| checkpoint.last_event_hash == event.event_hash)
        })
}

pub fn write_replica_file(path: impl AsRef<Path>, replica: &AuditReplica) -> std::io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(replica)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    fs::write(path, body)
}

pub fn read_replica_file(path: impl AsRef<Path>) -> std::io::Result<AuditReplica> {
    let body = fs::read_to_string(path)?;
    serde_json::from_str(&body).map_err(|error| std::io::Error::other(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{
        ActionResult, ActionType, ActorInfo, AuditContextFields, AuditEvent, TargetRef,
        build_checkpoint_signer_registry, signer::CheckpointSignerConfig,
    };

    use super::{AuditTrail, read_replica_file, verify_replica, write_replica_file};

    fn event(prev_hash: Option<String>) -> AuditEvent {
        AuditEvent::new_with_fields(
            ActorInfo {
                user_id: "user-a".into(),
                session_id: "session-a".into(),
                ip_address: "127.0.0.1".into(),
            },
            ActionType::Query,
            TargetRef {
                tenant_id: "tenant-a".into(),
                project_id: Some("project-a".into()),
                resource_id: "task-a".into(),
            },
            "store fixture",
            AuditContextFields::builder()
                .field("task_id", "task-a")
                .field("requested_fields", vec!["employee_id".to_string()])
                .build(),
            ActionResult::Success,
            None,
            prev_hash,
        )
    }

    #[test]
    fn audit_trail_exports_and_reloads_replica() {
        let mut trail = AuditTrail::default();
        let signer = build_checkpoint_signer_registry(&CheckpointSignerConfig::default())
            .expect("registry")
            .active_signer()
            .expect("signer")
            .clone();
        let first = event(None);
        let second = event(Some(first.event_hash.clone()));
        trail.append_with_signer(first, signer.as_ref());
        trail.append_with_signer(second, signer.as_ref());

        let replica = trail.export_replica();
        assert!(verify_replica(&replica));

        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("audit-trail-test.json");
        write_replica_file(&path, &replica).expect("write replica");
        let loaded = read_replica_file(&path).expect("read replica");
        assert!(verify_replica(&loaded));
        assert_eq!(
            loaded.events[0]
                .context_fields
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            vec!["requested_fields", "task_id"]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn archive_boundary_keeps_hot_segment_chain_valid() {
        let signer = build_checkpoint_signer_registry(&CheckpointSignerConfig::default())
            .expect("registry")
            .active_signer()
            .expect("signer")
            .clone();
        let mut trail = AuditTrail::default();
        let first = event(None);
        let second = event(Some(first.event_hash.clone()));
        let third = event(Some(second.event_hash.clone()));
        let boundary = trail.append_with_signer(first, signer.as_ref());
        trail.append_with_signer(second, signer.as_ref());
        trail.append_with_signer(third, signer.as_ref());

        trail.apply_archive_boundary(boundary);

        assert!(trail.chain_valid());
        assert_eq!(trail.anchor_checkpoint().expect("anchor").event_count, 1);
        assert_eq!(trail.events().len(), 2);
    }
}
