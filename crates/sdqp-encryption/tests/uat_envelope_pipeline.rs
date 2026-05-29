use chrono::{Duration, Utc};
use sdqp_encryption::{
    DecryptionPipelineConfig, DevelopmentEnvelopeCipher, EnvelopeCipher, InMemorySnapshotStore,
    SnapshotPayloadFormat, SnapshotStore, SnapshotWriteRequest,
};

#[test]
fn uat_envelope_cipher_and_pipeline_validation_work_together() {
    let cipher = DevelopmentEnvelopeCipher::new("dek-uat", 0x2F);
    let payload = cipher.encrypt(b"snapshot-payload").expect("payload");
    let plaintext = cipher.decrypt(&payload).expect("plaintext");

    let pipeline = DecryptionPipelineConfig {
        require_masking: true,
        require_watermark: true,
    };

    assert_eq!(plaintext, b"snapshot-payload");
    assert!(pipeline.validate().is_ok());
}

#[test]
fn uat_encrypted_snapshot_store_persists_ciphertext_only() {
    let cipher = DevelopmentEnvelopeCipher::new("dek-uat", 0x2F);
    let payload = cipher.encrypt(b"snapshot-payload").expect("payload");
    let mut store = InMemorySnapshotStore::default();
    let record = store.put(
        SnapshotWriteRequest {
            tenant_id: "tenant-alpha".into(),
            project_id: "project-alpha".into(),
            owner_user_id: "user-analyst".into(),
            grant_id: "grant-alpha".into(),
            grant_expires_at: Utc::now() + Duration::hours(8),
            retention_until: Utc::now() + Duration::hours(8),
            data_source_id: "datasource-alpha".into(),
            object_bucket: "sdqp-snapshots".into(),
            data_fingerprint: "fingerprint-uat".into(),
            columns: vec!["employee_id".into()],
            payload_format: SnapshotPayloadFormat::JsonRows,
        },
        payload,
        1,
    );
    let loaded = store.get(&record.snapshot_id).expect("loaded");

    assert!(loaded.storage_key.contains("tenant-alpha/project-alpha"));
    assert_ne!(loaded.encrypted_payload.ciphertext_b64, "snapshot-payload");
}
