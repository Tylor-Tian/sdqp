use chrono::Utc;
use sdqp_audit::{ActionResult, ActionType, ActorInfo, AuditEvent, TargetRef};
use sdqp_encryption::DevelopmentEnvelopeCipher;
use sdqp_evidence::{
    EvidenceBuildRequest, EvidenceBuilder, EvidenceMetadataManifest, EvidenceRecipient,
    EvidenceTemplate, MetadataDataSource, MetadataFieldDescriptor, MetadataQueryParameter,
    MockBlockchainAnchor, MockTimestampAuthority,
};
use sdqp_watermark::WatermarkPayload;

fn sample_events() -> Vec<AuditEvent> {
    let actor = ActorInfo {
        user_id: "user-analyst".into(),
        session_id: "session-phase5".into(),
        ip_address: "127.0.0.1".into(),
    };
    let target = TargetRef {
        tenant_id: "tenant-alpha".into(),
        project_id: Some("project-alpha".into()),
        resource_id: "snapshot-phase5".into(),
    };
    let first = AuditEvent::new(
        actor.clone(),
        ActionType::Query,
        target.clone(),
        "query completed",
        ActionResult::Success,
        Some("fp-1".into()),
        None,
    );
    let second = AuditEvent::new(
        actor,
        ActionType::Export,
        target,
        "evidence package requested",
        ActionResult::Success,
        Some("fp-2".into()),
        Some(first.event_hash.clone()),
    );

    vec![first, second]
}

#[tokio::test]
async fn uat_evidence_package_can_be_built_and_verified_offline() {
    let builder = EvidenceBuilder::new(
        MockTimestampAuthority::default(),
        MockBlockchainAnchor::default(),
        DevelopmentEnvelopeCipher::new("dek-evidence", 0x5A),
    );
    let audit_events = sample_events();
    let package = builder
        .build_package(EvidenceBuildRequest {
            snapshot_id: "snapshot-phase5".into(),
            template: EvidenceTemplate::UsLitigation,
            recipient: EvidenceRecipient {
                tenant_id: "tenant-alpha".into(),
                project_id: "project-alpha".into(),
                user_id: "user-analyst".into(),
                delivery_channel: "authorized-download".into(),
            },
            metadata_manifest: EvidenceMetadataManifest {
                field_descriptors: vec![MetadataFieldDescriptor {
                    field_name: "employee_id".into(),
                    ordinal: 0,
                }],
                query_parameters: vec![MetadataQueryParameter {
                    name: "snapshot_id".into(),
                    value: "snapshot-phase5".into(),
                }],
                permission_grant: None,
                data_source: MetadataDataSource {
                    data_source_id: "datasource-rest".into(),
                    storage_key: "tenant-alpha/project-alpha/snapshot-phase5.snapshot.json.enc"
                        .into(),
                    row_count: 2,
                    columns: vec!["employee_id".into()],
                },
            },
            watermark_payload: WatermarkPayload {
                tenant_id: "tenant-alpha".into(),
                project_id: "project-alpha".into(),
                user_id: "user-analyst".into(),
                sequence_number: 11,
                issued_at: Utc::now(),
                snapshot_id: Some("snapshot-phase5".into()),
            },
            audit_events: audit_events.clone(),
            export_body: "judicial export payload".into(),
        })
        .await
        .expect("package");

    let verification = builder.verify_package(&package, &audit_events).await;
    let decrypted = builder.decrypt_data_payload(&package).expect("decrypted");
    assert!(verification.verified);
    assert!(verification.anchor_valid);
    assert!(verification.hash_chain_valid);
    assert!(verification.metadata_manifest_valid);
    assert!(verification.data_payload_valid);
    assert!(verification.audit_extract_valid);
    assert!(verification.certificate_valid);
    assert_eq!(
        String::from_utf8(decrypted).expect("utf8"),
        "judicial export payload"
    );
    assert!(!package.exported_document.contains("[[SDQP-WM:"));
    assert!(
        package
            .exported_document
            .contains("Traceable Watermark: embedded")
    );
    assert_eq!(package.anchor_receipt.status.as_str(), "confirmed");
    assert_eq!(package.template, "us-litigation");
    assert_eq!(package.anchor_receipt.network, "mock-chain");
    assert_eq!(package.data_payload.recipient.user_id, "user-analyst");
}
