use std::{collections::BTreeMap, fs, path::Path};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ulid::Ulid;

use crate::{
    ActionType, ActorInfo, AuditCheckpoint, AuditEvent, verify_chain_with_anchor, verify_checkpoint,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRetentionCategory {
    AccessLog,
    PermissionLifecycle,
    Evidence,
    SystemManagement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRetentionConfig {
    pub enabled: bool,
    pub archive_after_secs: i64,
    pub access_log_retention_secs: i64,
    pub permission_lifecycle_retention_secs: i64,
    pub evidence_retention_secs: i64,
    pub system_management_retention_secs: i64,
}

impl Default for AuditRetentionConfig {
    fn default() -> Self {
        let day = 24 * 60 * 60;
        Self {
            enabled: true,
            archive_after_secs: 90 * day,
            access_log_retention_secs: 3 * 365 * day,
            permission_lifecycle_retention_secs: 5 * 365 * day,
            evidence_retention_secs: 10 * 365 * day,
            system_management_retention_secs: 5 * 365 * day,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditArchiveBundle {
    pub bundle_id: String,
    pub archived_at: DateTime<Utc>,
    pub retain_until: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_checkpoint: Option<AuditCheckpoint>,
    pub boundary_checkpoint: AuditCheckpoint,
    pub events: Vec<AuditEvent>,
    pub checkpoints: Vec<AuditCheckpoint>,
}

#[derive(Debug, Clone)]
pub struct AuditArchivePlan {
    pub bundle: AuditArchiveBundle,
    pub archived_event_count: usize,
    pub archived_checkpoint_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledDeletionSubjectKind {
    Snapshot,
    Project,
    AuditArchiveBundle,
}

impl ControlledDeletionSubjectKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Project => "project",
            Self::AuditArchiveBundle => "audit_archive_bundle",
        }
    }

    pub fn parse_label(value: &str) -> Option<Self> {
        match value {
            "snapshot" => Some(Self::Snapshot),
            "project" => Some(Self::Project),
            "audit_archive_bundle" => Some(Self::AuditArchiveBundle),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledDeletionState {
    Requested,
    Authorized,
    LogicalDeleted,
    ContentPurged,
    TombstoneWritten,
    AuditRecorded,
    Completed,
    Rejected,
}

impl ControlledDeletionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Authorized => "authorized",
            Self::LogicalDeleted => "logical_deleted",
            Self::ContentPurged => "content_purged",
            Self::TombstoneWritten => "tombstone_written",
            Self::AuditRecorded => "audit_recorded",
            Self::Completed => "completed",
            Self::Rejected => "rejected",
        }
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Requested, Self::Authorized)
                | (Self::Requested, Self::Rejected)
                | (Self::Authorized, Self::LogicalDeleted)
                | (Self::Authorized, Self::ContentPurged)
                | (Self::Authorized, Self::Rejected)
                | (Self::LogicalDeleted, Self::TombstoneWritten)
                | (Self::ContentPurged, Self::TombstoneWritten)
                | (Self::TombstoneWritten, Self::AuditRecorded)
                | (Self::AuditRecorded, Self::Completed)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlledDeletionSubject {
    pub kind: ControlledDeletionSubjectKind,
    pub tenant_id: String,
    pub project_id: Option<String>,
    pub resource_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlledDeletionContentRef {
    pub content_type: String,
    pub content_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub effect: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlledDeletionChainEvidence {
    pub captured_at: DateTime<Utc>,
    pub event_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_event_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlledDeletionTransition {
    pub from: ControlledDeletionState,
    pub to: ControlledDeletionState,
    pub actor_user_id: String,
    pub at: DateTime<Utc>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditTombstone {
    pub tombstone_id: String,
    pub created_at: DateTime<Utc>,
    pub subject: ControlledDeletionSubject,
    pub reason: String,
    pub requested_by_user_id: String,
    pub requested_session_id: String,
    pub logical_deleted_at: Option<DateTime<Utc>>,
    pub content_purged_at: Option<DateTime<Utc>>,
    pub retain_until: DateTime<Utc>,
    #[serde(default)]
    pub retained_fields: BTreeMap<String, String>,
    #[serde(default)]
    pub redacted_fields: Vec<String>,
    #[serde(default)]
    pub logically_deleted_content: Vec<ControlledDeletionContentRef>,
    #[serde(default)]
    pub purged_content: Vec<ControlledDeletionContentRef>,
    #[serde(default)]
    pub retained_evidence: Vec<ControlledDeletionContentRef>,
    pub pre_delete_chain: ControlledDeletionChainEvidence,
    pub tombstone_hash: String,
}

impl AuditTombstone {
    pub fn refresh_hash(&mut self) {
        self.tombstone_hash = self.recompute_hash();
    }

    pub fn recompute_hash(&self) -> String {
        let mut material = self.clone();
        material.tombstone_hash.clear();
        controlled_deletion_digest(
            &serde_json::to_vec(&material).expect("controlled deletion tombstone serializes"),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlledDeletionRecord {
    pub deletion_id: String,
    pub state: ControlledDeletionState,
    pub requested_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub tombstone: AuditTombstone,
    pub transitions: Vec<ControlledDeletionTransition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_delete_chain: Option<ControlledDeletionChainEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_event_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_checkpoint_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_hash: Option<String>,
}

impl ControlledDeletionRecord {
    pub fn refresh_evidence_hash(&mut self) {
        self.evidence_hash = self.post_delete_chain.as_ref().map(|post_delete_chain| {
            controlled_deletion_digest(
                &serde_json::to_vec(&ControlledDeletionEvidenceHashMaterial {
                    deletion_id: &self.deletion_id,
                    final_state: self.state,
                    tombstone_hash: &self.tombstone.tombstone_hash,
                    post_delete_chain,
                    audit_event_hash: self.audit_event_hash.as_deref(),
                    audit_checkpoint_id: self.audit_checkpoint_id.as_deref(),
                })
                .expect("controlled deletion evidence serializes"),
            )
        });
    }
}

#[derive(Serialize)]
struct ControlledDeletionEvidenceHashMaterial<'a> {
    deletion_id: &'a str,
    final_state: ControlledDeletionState,
    tombstone_hash: &'a str,
    post_delete_chain: &'a ControlledDeletionChainEvidence,
    audit_event_hash: Option<&'a str>,
    audit_checkpoint_id: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct ControlledDeletionFlow {
    record: ControlledDeletionRecord,
}

impl ControlledDeletionFlow {
    pub fn new(
        subject: ControlledDeletionSubject,
        actor: ActorInfo,
        reason: impl Into<String>,
        retain_until: DateTime<Utc>,
        pre_delete_chain: ControlledDeletionChainEvidence,
        now: DateTime<Utc>,
    ) -> Self {
        let reason = reason.into();
        let mut tombstone = AuditTombstone {
            tombstone_id: Ulid::new().to_string(),
            created_at: now,
            subject,
            reason: reason.clone(),
            requested_by_user_id: actor.user_id,
            requested_session_id: actor.session_id,
            logical_deleted_at: None,
            content_purged_at: None,
            retain_until,
            retained_fields: BTreeMap::new(),
            redacted_fields: Vec::new(),
            logically_deleted_content: Vec::new(),
            purged_content: Vec::new(),
            retained_evidence: Vec::new(),
            pre_delete_chain,
            tombstone_hash: String::new(),
        };
        tombstone.refresh_hash();

        Self {
            record: ControlledDeletionRecord {
                deletion_id: Ulid::new().to_string(),
                state: ControlledDeletionState::Requested,
                requested_at: now,
                completed_at: None,
                tombstone,
                transitions: Vec::new(),
                post_delete_chain: None,
                audit_event_hash: None,
                audit_checkpoint_id: None,
                evidence_hash: None,
            },
        }
    }

    pub fn record(&self) -> &ControlledDeletionRecord {
        &self.record
    }

    pub fn record_mut(&mut self) -> &mut ControlledDeletionRecord {
        &mut self.record
    }

    pub fn transition_to(
        &mut self,
        next: ControlledDeletionState,
        actor_user_id: impl Into<String>,
        reason: impl Into<String>,
        at: DateTime<Utc>,
    ) -> bool {
        let current = self.record.state;
        if !current.can_transition_to(next) {
            return false;
        }
        self.record.transitions.push(ControlledDeletionTransition {
            from: current,
            to: next,
            actor_user_id: actor_user_id.into(),
            at,
            reason: reason.into(),
        });
        self.record.state = next;
        if next == ControlledDeletionState::Completed {
            self.record.completed_at = Some(at);
        }
        self.record.tombstone.refresh_hash();
        true
    }

    pub fn seal_audit_evidence(
        &mut self,
        post_delete_chain: ControlledDeletionChainEvidence,
        audit_event_hash: Option<String>,
        audit_checkpoint_id: Option<String>,
    ) {
        self.record.post_delete_chain = Some(post_delete_chain);
        self.record.audit_event_hash = audit_event_hash;
        self.record.audit_checkpoint_id = audit_checkpoint_id;
        self.record.refresh_evidence_hash();
    }

    pub fn into_record(self) -> ControlledDeletionRecord {
        self.record
    }
}

pub fn verify_controlled_deletion_record(record: &ControlledDeletionRecord) -> bool {
    if record.tombstone.tombstone_hash != record.tombstone.recompute_hash() {
        return false;
    }
    let mut observed_state = ControlledDeletionState::Requested;
    for transition in &record.transitions {
        if transition.from != observed_state || !transition.from.can_transition_to(transition.to) {
            return false;
        }
        observed_state = transition.to;
    }
    if !record.transitions.is_empty() && observed_state != record.state {
        return false;
    }
    if let Some(expected) = &record.evidence_hash {
        let Some(post_delete_chain) = record.post_delete_chain.as_ref() else {
            return false;
        };
        let recomputed = controlled_deletion_digest(
            &serde_json::to_vec(&ControlledDeletionEvidenceHashMaterial {
                deletion_id: &record.deletion_id,
                final_state: record.state,
                tombstone_hash: &record.tombstone.tombstone_hash,
                post_delete_chain,
                audit_event_hash: record.audit_event_hash.as_deref(),
                audit_checkpoint_id: record.audit_checkpoint_id.as_deref(),
            })
            .expect("controlled deletion evidence serializes"),
        );
        if expected != &recomputed {
            return false;
        }
    }
    true
}

pub fn controlled_deletion_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub fn retention_category_for_event(event: &AuditEvent) -> AuditRetentionCategory {
    let context = event.context.to_ascii_lowercase();
    if matches!(event.action, ActionType::Export)
        || context.contains("evidence")
        || context.contains("controlled deletion")
        || context.contains("tombstone")
    {
        AuditRetentionCategory::Evidence
    } else if matches!(event.action, ActionType::PermissionApply) {
        AuditRetentionCategory::PermissionLifecycle
    } else if matches!(event.action, ActionType::ConfigChange) {
        AuditRetentionCategory::SystemManagement
    } else {
        AuditRetentionCategory::AccessLog
    }
}

pub fn retention_deadline(event: &AuditEvent, config: &AuditRetentionConfig) -> DateTime<Utc> {
    let seconds = match retention_category_for_event(event) {
        AuditRetentionCategory::AccessLog => config.access_log_retention_secs,
        AuditRetentionCategory::PermissionLifecycle => config.permission_lifecycle_retention_secs,
        AuditRetentionCategory::Evidence => config.evidence_retention_secs,
        AuditRetentionCategory::SystemManagement => config.system_management_retention_secs,
    };
    event.timestamp + Duration::seconds(seconds.max(0))
}

pub fn build_archive_plan(
    anchor_checkpoint: Option<&AuditCheckpoint>,
    events: &[AuditEvent],
    checkpoints: &[AuditCheckpoint],
    config: &AuditRetentionConfig,
    now: DateTime<Utc>,
) -> Option<AuditArchivePlan> {
    if !config.enabled || events.is_empty() || checkpoints.is_empty() {
        return None;
    }

    let archive_cutoff = now - Duration::seconds(config.archive_after_secs.max(0));
    let previous_offset = anchor_checkpoint
        .map(|checkpoint| checkpoint.event_count)
        .unwrap_or(0);
    let boundary_checkpoint = checkpoints
        .iter()
        .rfind(|checkpoint| {
            checkpoint.created_at <= archive_cutoff && checkpoint.event_count > previous_offset
        })?
        .clone();
    let archived_event_count = boundary_checkpoint
        .event_count
        .saturating_sub(previous_offset);
    if archived_event_count == 0 || archived_event_count > events.len() {
        return None;
    }

    let archived_checkpoint_count = checkpoints
        .iter()
        .take_while(|checkpoint| checkpoint.event_count <= boundary_checkpoint.event_count)
        .count();
    if archived_checkpoint_count == 0 {
        return None;
    }

    let archived_events = events[..archived_event_count].to_vec();
    let archived_checkpoints = checkpoints[..archived_checkpoint_count].to_vec();
    let retain_until = archived_events
        .iter()
        .map(|event| retention_deadline(event, config))
        .max()
        .unwrap_or(boundary_checkpoint.created_at);

    Some(AuditArchivePlan {
        bundle: AuditArchiveBundle {
            bundle_id: Ulid::new().to_string(),
            archived_at: now,
            retain_until,
            anchor_checkpoint: anchor_checkpoint.cloned(),
            boundary_checkpoint,
            events: archived_events,
            checkpoints: archived_checkpoints,
        },
        archived_event_count,
        archived_checkpoint_count,
    })
}

pub fn verify_archive_bundle(bundle: &AuditArchiveBundle) -> bool {
    verify_chain_with_anchor(&bundle.events, bundle.anchor_checkpoint.as_ref())
        && bundle.checkpoints.iter().all(verify_checkpoint)
        && bundle.checkpoints.last().is_some_and(|checkpoint| {
            checkpoint.checkpoint_id == bundle.boundary_checkpoint.checkpoint_id
        })
}

pub fn write_archive_bundle_file(
    path: impl AsRef<Path>,
    bundle: &AuditArchiveBundle,
) -> std::io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(bundle)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    fs::write(path, body)
}

pub fn read_archive_bundle_file(path: impl AsRef<Path>) -> std::io::Result<AuditArchiveBundle> {
    let body = fs::read_to_string(path)?;
    serde_json::from_str(&body).map_err(|error| std::io::Error::other(error.to_string()))
}

#[cfg(test)]
mod tests {
    use crate::{
        ActionResult, ActorInfo, AuditTrail, TargetRef, build_checkpoint_signer_registry,
        signer::CheckpointSignerConfig,
    };

    use super::{
        AuditRetentionConfig, ControlledDeletionChainEvidence, ControlledDeletionContentRef,
        ControlledDeletionFlow, ControlledDeletionState, ControlledDeletionSubject,
        ControlledDeletionSubjectKind, build_archive_plan, verify_archive_bundle,
        verify_controlled_deletion_record,
    };

    #[test]
    fn archive_plan_respects_boundary_checkpoint_and_retention_deadline() {
        let signer = build_checkpoint_signer_registry(&CheckpointSignerConfig::default())
            .expect("registry")
            .active_signer()
            .expect("signer")
            .clone();
        let mut trail = AuditTrail::default();
        for action in [crate::ActionType::Query, crate::ActionType::Export] {
            let event = crate::AuditEvent::new(
                ActorInfo {
                    user_id: "user-a".into(),
                    session_id: "session-a".into(),
                    ip_address: "127.0.0.1".into(),
                },
                action,
                TargetRef {
                    tenant_id: "tenant-a".into(),
                    project_id: Some("project-a".into()),
                    resource_id: "resource-a".into(),
                },
                "retention fixture",
                ActionResult::Success,
                None,
                trail.latest_event_hash(),
            );
            trail.append_with_signer(event, signer.as_ref());
        }

        let now = chrono::Utc::now();
        let plan = build_archive_plan(
            None,
            trail.events(),
            trail.checkpoints(),
            &AuditRetentionConfig {
                archive_after_secs: 0,
                ..AuditRetentionConfig::default()
            },
            now,
        )
        .expect("plan");

        assert_eq!(plan.archived_event_count, 2);
        assert_eq!(plan.bundle.boundary_checkpoint.event_count, 2);
        assert!(verify_archive_bundle(&plan.bundle));
        assert!(plan.bundle.retain_until >= now + chrono::Duration::days(365 * 3));
    }

    #[test]
    fn controlled_deletion_tombstone_hashes_state_flow_and_audit_evidence() {
        let now = chrono::Utc::now();
        let actor = ActorInfo {
            user_id: "admin-a".into(),
            session_id: "session-a".into(),
            ip_address: "127.0.0.1".into(),
        };
        let subject = ControlledDeletionSubject {
            kind: ControlledDeletionSubjectKind::Snapshot,
            tenant_id: "tenant-a".into(),
            project_id: Some("project-a".into()),
            resource_id: "snapshot-a".into(),
            content_fingerprint: Some("content-hash-a".into()),
            storage_fingerprint: Some("storage-hash-a".into()),
        };
        let pre_chain = ControlledDeletionChainEvidence {
            captured_at: now,
            event_count: 7,
            latest_event_hash: Some("pre-hash".into()),
            checkpoint_id: Some("checkpoint-pre".into()),
            checkpoint_signature: Some("signature-pre".into()),
        };
        let mut flow = ControlledDeletionFlow::new(
            subject,
            actor,
            "test controlled deletion",
            now + chrono::Duration::days(3650),
            pre_chain,
            now,
        );

        assert!(flow.transition_to(
            ControlledDeletionState::Authorized,
            "admin-a",
            "authorized",
            now
        ));
        flow.record_mut().tombstone.logically_deleted_content =
            vec![ControlledDeletionContentRef {
                content_type: "encrypted_snapshot".into(),
                content_id: "snapshot-a".into(),
                fingerprint: Some("content-hash-a".into()),
                effect: "logical_delete:lifecycle_non_active".into(),
            }];
        flow.record_mut()
            .tombstone
            .retained_fields
            .insert("snapshot_id".into(), "snapshot-a".into());
        flow.record_mut().tombstone.refresh_hash();
        assert!(flow.transition_to(
            ControlledDeletionState::LogicalDeleted,
            "admin-a",
            "logical delete",
            now
        ));
        assert!(flow.transition_to(
            ControlledDeletionState::TombstoneWritten,
            "admin-a",
            "tombstone written",
            now
        ));
        assert!(flow.transition_to(
            ControlledDeletionState::AuditRecorded,
            "admin-a",
            "audit recorded",
            now
        ));
        assert!(flow.transition_to(
            ControlledDeletionState::Completed,
            "admin-a",
            "completed",
            now
        ));
        flow.seal_audit_evidence(
            ControlledDeletionChainEvidence {
                captured_at: now,
                event_count: 8,
                latest_event_hash: Some("post-hash".into()),
                checkpoint_id: Some("checkpoint-post".into()),
                checkpoint_signature: Some("signature-post".into()),
            },
            Some("post-hash".into()),
            Some("checkpoint-post".into()),
        );

        let record = flow.into_record();
        assert_eq!(record.state, ControlledDeletionState::Completed);
        assert!(record.evidence_hash.is_some());
        assert!(verify_controlled_deletion_record(&record));
    }
}
