use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    AuditEvent,
    signer::{
        CheckpointSigner, CheckpointSignerConfig, build_checkpoint_signer_registry,
        checkpoint_signer_from_metadata,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    pub checkpoint_id: String,
    pub created_at: DateTime<Utc>,
    pub event_count: usize,
    pub last_event_hash: String,
    pub signature: String,
    #[serde(default = "default_signature_algorithm")]
    pub signature_algorithm: String,
    #[serde(default = "default_signer_provider")]
    pub signer_provider: String,
    #[serde(default = "default_signer_key_id")]
    pub signer_key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key_version: Option<String>,
}

pub fn create_checkpoint(events: &[AuditEvent]) -> Option<AuditCheckpoint> {
    let signer = build_checkpoint_signer_registry(&CheckpointSignerConfig::default())
        .ok()?
        .active_signer()?
        .clone();
    let last = events.last()?;
    create_checkpoint_with_signer(events.len(), &last.event_hash, signer.as_ref())
}

pub fn create_checkpoint_with_signer(
    event_count: usize,
    last_event_hash: &str,
    signer: &dyn CheckpointSigner,
) -> Option<AuditCheckpoint> {
    let created_at = Utc::now();
    let checkpoint_id = Ulid::new().to_string();
    let payload = checkpoint_payload(&checkpoint_id, created_at, event_count, last_event_hash);
    let signature = signer.sign_payload(&payload).ok()?;

    Some(AuditCheckpoint {
        checkpoint_id,
        created_at,
        event_count,
        last_event_hash: last_event_hash.to_string(),
        signature,
        signature_algorithm: signer.signature_algorithm().to_string(),
        signer_provider: signer.provider_name().to_string(),
        signer_key_id: signer.key_id().to_string(),
        signer_key_version: signer.key_version().map(str::to_string),
    })
}

pub fn verify_checkpoint(checkpoint: &AuditCheckpoint) -> bool {
    let Ok(signer) = checkpoint_signer_from_metadata(
        &checkpoint.signer_provider,
        &checkpoint.signer_key_id,
        checkpoint.signer_key_version.as_deref(),
        &checkpoint.signature_algorithm,
    ) else {
        return false;
    };
    signer
        .verify_payload(
            &checkpoint_payload(
                &checkpoint.checkpoint_id,
                checkpoint.created_at,
                checkpoint.event_count,
                &checkpoint.last_event_hash,
            ),
            &checkpoint.signature,
        )
        .unwrap_or(false)
}

fn checkpoint_payload(
    checkpoint_id: &str,
    created_at: DateTime<Utc>,
    event_count: usize,
    last_event_hash: &str,
) -> String {
    format!(
        "{}|{}|{}|{}",
        checkpoint_id,
        canonical_timestamp(created_at),
        event_count,
        last_event_hash
    )
}

fn canonical_timestamp(timestamp: DateTime<Utc>) -> String {
    timestamp.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn default_signature_algorithm() -> String {
    "sha256".into()
}

fn default_signer_provider() -> String {
    "legacy-sha256".into()
}

fn default_signer_key_id() -> String {
    "legacy-local-hash".into()
}

#[cfg(test)]
mod tests {
    use super::{create_checkpoint, create_checkpoint_with_signer, verify_checkpoint};
    use crate::signer::{CheckpointSignerConfig, build_checkpoint_signer_registry};
    use crate::{ActionResult, ActionType, ActorInfo, AuditEvent, TargetRef};

    #[test]
    fn checkpoint_round_trip_succeeds() {
        let event = AuditEvent::new(
            ActorInfo {
                user_id: "user-a".into(),
                session_id: "session-a".into(),
                ip_address: "127.0.0.1".into(),
            },
            ActionType::Login,
            TargetRef {
                tenant_id: "tenant-a".into(),
                project_id: Some("project-a".into()),
                resource_id: "resource-a".into(),
            },
            "login",
            ActionResult::Success,
            None,
            None,
        );

        let checkpoint = create_checkpoint(&[event]).expect("checkpoint");
        assert!(verify_checkpoint(&checkpoint));
        assert_eq!(checkpoint.signer_provider, "mock");
        assert_eq!(checkpoint.signature_algorithm, "hmac-sha256");
    }

    #[test]
    fn checkpoint_supports_cumulative_event_counts_with_signer_registry() {
        let signer = build_checkpoint_signer_registry(&CheckpointSignerConfig::default())
            .expect("registry")
            .active_signer()
            .expect("signer")
            .clone();

        let checkpoint =
            create_checkpoint_with_signer(42, "hash-42", signer.as_ref()).expect("checkpoint");

        assert_eq!(checkpoint.event_count, 42);
        assert_eq!(checkpoint.last_event_hash, "hash-42");
        assert!(verify_checkpoint(&checkpoint));
    }
}
