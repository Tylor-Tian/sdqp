use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

use crate::EncryptedPayload;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotDeleteState {
    Active,
    SoftDeleted,
    Purged,
}

impl SnapshotDeleteState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::SoftDeleted => "soft_deleted",
            Self::Purged => "purged",
        }
    }

    pub fn parse_label(label: &str) -> Option<Self> {
        match label {
            "active" => Some(Self::Active),
            "soft_deleted" => Some(Self::SoftDeleted),
            "purged" => Some(Self::Purged),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SnapshotPayloadFormat {
    #[default]
    JsonRows,
    Parquet,
}

impl SnapshotPayloadFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::JsonRows => "json_rows",
            Self::Parquet => "parquet",
        }
    }

    pub fn parse_label(label: &str) -> Option<Self> {
        match label {
            "json_rows" => Some(Self::JsonRows),
            "parquet" => Some(Self::Parquet),
            _ => None,
        }
    }

    fn storage_suffix(&self) -> &'static str {
        match self {
            Self::JsonRows => "snapshot.json.enc",
            Self::Parquet => "snapshot.parquet.enc",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotLifecycle {
    pub owner_user_id: String,
    pub grant_id: String,
    pub grant_expires_at: DateTime<Utc>,
    pub retention_until: DateTime<Utc>,
    pub data_fingerprint: String,
    pub object_bucket: String,
    pub object_size_bytes: usize,
    pub delete_state: SnapshotDeleteState,
    pub delete_reason: Option<String>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub purged_at: Option<DateTime<Utc>>,
    pub last_rewrapped_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotWriteRequest {
    pub tenant_id: String,
    pub project_id: String,
    pub owner_user_id: String,
    pub grant_id: String,
    pub grant_expires_at: DateTime<Utc>,
    pub retention_until: DateTime<Utc>,
    pub data_source_id: String,
    pub object_bucket: String,
    pub data_fingerprint: String,
    pub columns: Vec<String>,
    pub payload_format: SnapshotPayloadFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSnapshotRecord {
    pub snapshot_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub storage_key: String,
    pub created_at: DateTime<Utc>,
    pub data_source_id: String,
    pub encrypted_payload: EncryptedPayload,
    pub row_count: usize,
    #[serde(default)]
    pub columns: Vec<String>,
    #[serde(default)]
    pub payload_format: SnapshotPayloadFormat,
    pub lifecycle: SnapshotLifecycle,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SnapshotStoreError {
    #[error("snapshot not found")]
    NotFound,
    #[error("snapshot is not active")]
    NotActive,
    #[error("snapshot has been purged")]
    Purged,
}

pub trait SnapshotStore {
    fn put(
        &mut self,
        request: SnapshotWriteRequest,
        encrypted_payload: EncryptedPayload,
        row_count: usize,
    ) -> EncryptedSnapshotRecord;
    fn get(&self, snapshot_id: &str) -> Result<EncryptedSnapshotRecord, SnapshotStoreError>;
}

#[derive(Debug, Default)]
pub struct InMemorySnapshotStore {
    snapshots: HashMap<String, EncryptedSnapshotRecord>,
}

impl InMemorySnapshotStore {
    pub fn restore_record(&mut self, record: EncryptedSnapshotRecord) {
        self.snapshots.insert(record.snapshot_id.clone(), record);
    }

    pub fn get_any(
        &self,
        snapshot_id: &str,
    ) -> Result<EncryptedSnapshotRecord, SnapshotStoreError> {
        self.snapshots
            .get(snapshot_id)
            .cloned()
            .ok_or(SnapshotStoreError::NotFound)
    }

    pub fn soft_delete(
        &mut self,
        snapshot_id: &str,
        reason: impl Into<String>,
        when: DateTime<Utc>,
    ) -> Result<(), SnapshotStoreError> {
        let record = self
            .snapshots
            .get_mut(snapshot_id)
            .ok_or(SnapshotStoreError::NotFound)?;
        if record.lifecycle.delete_state == SnapshotDeleteState::Purged {
            return Err(SnapshotStoreError::Purged);
        }
        record.lifecycle.delete_state = SnapshotDeleteState::SoftDeleted;
        record.lifecycle.delete_reason = Some(reason.into());
        record.lifecycle.deleted_at = Some(when);
        Ok(())
    }

    pub fn restore(&mut self, snapshot_id: &str) -> Result<(), SnapshotStoreError> {
        let record = self
            .snapshots
            .get_mut(snapshot_id)
            .ok_or(SnapshotStoreError::NotFound)?;
        if record.lifecycle.delete_state == SnapshotDeleteState::Purged {
            return Err(SnapshotStoreError::Purged);
        }
        record.lifecycle.delete_state = SnapshotDeleteState::Active;
        record.lifecycle.delete_reason = None;
        record.lifecycle.deleted_at = None;
        Ok(())
    }

    pub fn mark_purged(
        &mut self,
        snapshot_id: &str,
        reason: impl Into<String>,
        when: DateTime<Utc>,
    ) -> Result<(), SnapshotStoreError> {
        let record = self
            .snapshots
            .get_mut(snapshot_id)
            .ok_or(SnapshotStoreError::NotFound)?;
        record.lifecycle.delete_state = SnapshotDeleteState::Purged;
        record.lifecycle.delete_reason = Some(reason.into());
        record.lifecycle.deleted_at = record.lifecycle.deleted_at.or(Some(when));
        record.lifecycle.purged_at = Some(when);
        record.encrypted_payload.ciphertext_b64.clear();
        Ok(())
    }

    pub fn mark_rewrapped(
        &mut self,
        snapshot_id: &str,
        payload: EncryptedPayload,
        when: DateTime<Utc>,
    ) -> Result<(), SnapshotStoreError> {
        let record = self
            .snapshots
            .get_mut(snapshot_id)
            .ok_or(SnapshotStoreError::NotFound)?;
        record.encrypted_payload = payload;
        record.lifecycle.last_rewrapped_at = Some(when);
        Ok(())
    }

    pub fn delete_project_snapshots(&mut self, project_id: &str) -> Vec<String> {
        let snapshot_ids = self
            .snapshots
            .iter()
            .filter(|(_, record)| record.project_id == project_id)
            .map(|(snapshot_id, _)| snapshot_id.clone())
            .collect::<Vec<_>>();

        for snapshot_id in &snapshot_ids {
            self.snapshots.remove(snapshot_id);
        }

        snapshot_ids
    }

    pub fn purge_project_snapshots(
        &mut self,
        project_id: &str,
        reason: impl Into<String>,
        when: DateTime<Utc>,
    ) -> Vec<EncryptedSnapshotRecord> {
        let reason = reason.into();
        let snapshot_ids = self
            .snapshots
            .iter()
            .filter(|(_, record)| record.project_id == project_id)
            .map(|(snapshot_id, _)| snapshot_id.clone())
            .collect::<Vec<_>>();

        let mut purged = Vec::with_capacity(snapshot_ids.len());
        for snapshot_id in snapshot_ids {
            if let Some(record) = self.snapshots.get_mut(&snapshot_id) {
                record.lifecycle.delete_state = SnapshotDeleteState::Purged;
                record.lifecycle.delete_reason = Some(reason.clone());
                record.lifecycle.deleted_at = record.lifecycle.deleted_at.or(Some(when));
                record.lifecycle.purged_at = Some(when);
                record.encrypted_payload.ciphertext_b64.clear();
                purged.push(record.clone());
            }
        }

        purged
    }
}

impl SnapshotStore for InMemorySnapshotStore {
    fn put(
        &mut self,
        request: SnapshotWriteRequest,
        encrypted_payload: EncryptedPayload,
        row_count: usize,
    ) -> EncryptedSnapshotRecord {
        let snapshot_id = Ulid::new().to_string();
        let record = EncryptedSnapshotRecord {
            snapshot_id: snapshot_id.clone(),
            tenant_id: request.tenant_id.clone(),
            project_id: request.project_id.clone(),
            storage_key: format!(
                "snapshots/{}/{}/{snapshot_id}.{}",
                request.tenant_id,
                request.project_id,
                request.payload_format.storage_suffix()
            ),
            created_at: Utc::now(),
            data_source_id: request.data_source_id,
            encrypted_payload,
            row_count,
            columns: request.columns,
            payload_format: request.payload_format,
            lifecycle: SnapshotLifecycle {
                owner_user_id: request.owner_user_id,
                grant_id: request.grant_id,
                grant_expires_at: request.grant_expires_at,
                retention_until: request.retention_until,
                data_fingerprint: request.data_fingerprint,
                object_bucket: request.object_bucket,
                object_size_bytes: 0,
                delete_state: SnapshotDeleteState::Active,
                delete_reason: None,
                deleted_at: None,
                purged_at: None,
                last_rewrapped_at: None,
            },
        };
        self.snapshots.insert(snapshot_id, record.clone());
        record
    }

    fn get(&self, snapshot_id: &str) -> Result<EncryptedSnapshotRecord, SnapshotStoreError> {
        let record = self
            .snapshots
            .get(snapshot_id)
            .cloned()
            .ok_or(SnapshotStoreError::NotFound)?;
        match record.lifecycle.delete_state {
            SnapshotDeleteState::Active => Ok(record),
            SnapshotDeleteState::SoftDeleted => Err(SnapshotStoreError::NotActive),
            SnapshotDeleteState::Purged => Err(SnapshotStoreError::Purged),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::{
        EncryptedSnapshotRecord, InMemorySnapshotStore, SnapshotDeleteState, SnapshotStore,
        SnapshotWriteRequest,
    };
    use crate::{DevelopmentEnvelopeCipher, EnvelopeCipher};

    fn write_request() -> SnapshotWriteRequest {
        SnapshotWriteRequest {
            tenant_id: "tenant-alpha".into(),
            project_id: "project-alpha".into(),
            owner_user_id: "user-analyst".into(),
            grant_id: "grant-alpha".into(),
            grant_expires_at: Utc::now() + Duration::hours(8),
            retention_until: Utc::now() + Duration::hours(8),
            data_source_id: "datasource-rest".into(),
            object_bucket: "sdqp-snapshots".into(),
            data_fingerprint: "fingerprint-a".into(),
            columns: vec!["employee_id".into()],
            payload_format: super::SnapshotPayloadFormat::JsonRows,
        }
    }

    #[test]
    fn in_memory_snapshot_store_persists_encrypted_payload() {
        let mut store = InMemorySnapshotStore::default();
        let cipher = DevelopmentEnvelopeCipher::new("dek-project-alpha", 0x2F);
        let payload = cipher.encrypt(b"phase2-snapshot").expect("payload");
        let record = store.put(write_request(), payload.clone(), 1);
        let loaded = store.get(&record.snapshot_id).expect("record");

        assert_eq!(loaded.encrypted_payload, payload);
        assert!(loaded.storage_key.ends_with(".snapshot.json.enc"));
        assert_eq!(loaded.tenant_id, "tenant-alpha");
        assert_eq!(loaded.project_id, "project-alpha");
        assert_eq!(loaded.lifecycle.grant_id, "grant-alpha");
        assert_eq!(loaded.columns, vec!["employee_id".to_string()]);
        assert_eq!(
            loaded.payload_format,
            super::SnapshotPayloadFormat::JsonRows
        );
    }

    #[test]
    fn in_memory_snapshot_store_restores_existing_record() {
        let mut store = InMemorySnapshotStore::default();
        let record = EncryptedSnapshotRecord {
            snapshot_id: "snapshot-restored".into(),
            tenant_id: "tenant-alpha".into(),
            project_id: "project-alpha".into(),
            storage_key:
                "snapshots/tenant-alpha/project-alpha/snapshot-restored.snapshot.parquet.enc".into(),
            created_at: chrono::Utc::now(),
            data_source_id: "datasource-rest".into(),
            encrypted_payload: DevelopmentEnvelopeCipher::new("dek-project-alpha", 0x2F)
                .encrypt(b"restored")
                .expect("payload"),
            row_count: 1,
            columns: vec!["employee_id".into()],
            payload_format: super::SnapshotPayloadFormat::Parquet,
            lifecycle: super::SnapshotLifecycle {
                owner_user_id: "user-analyst".into(),
                grant_id: "grant-alpha".into(),
                grant_expires_at: Utc::now() + Duration::hours(8),
                retention_until: Utc::now() + Duration::hours(8),
                data_fingerprint: "fingerprint".into(),
                object_bucket: "sdqp-snapshots".into(),
                object_size_bytes: 12,
                delete_state: SnapshotDeleteState::Active,
                delete_reason: None,
                deleted_at: None,
                purged_at: None,
                last_rewrapped_at: None,
            },
        };

        store.restore_record(record.clone());

        assert_eq!(
            store.get("snapshot-restored").expect("restored snapshot"),
            record
        );
    }

    #[test]
    fn in_memory_snapshot_store_supports_delete_restore_and_purge() {
        let mut store = InMemorySnapshotStore::default();
        let record = store.put(
            write_request(),
            DevelopmentEnvelopeCipher::new("dek-project-alpha", 0x2F)
                .encrypt(b"snapshot")
                .expect("payload"),
            1,
        );

        store
            .soft_delete(&record.snapshot_id, "manual delete", Utc::now())
            .expect("soft delete");
        assert!(store.get(&record.snapshot_id).is_err());

        store.restore(&record.snapshot_id).expect("restore");
        assert_eq!(
            store.get(&record.snapshot_id).expect("active").snapshot_id,
            record.snapshot_id
        );

        store
            .mark_purged(&record.snapshot_id, "hard delete", Utc::now())
            .expect("purge");
        assert!(store.get(&record.snapshot_id).is_err());
    }
}
