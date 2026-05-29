use chrono::{Duration, Utc};
use sdqp_data_classification::MaskingStrategy;
use sdqp_data_view::{
    EncryptedSnapshotProvider, PivotMetric, SnapshotAccessProfile, encode_rows_to_parquet,
};
use sdqp_datasource_adapter::FieldQueryResult;
use sdqp_encryption::{
    DevelopmentEnvelopeCipher, EnvelopeCipher, InMemorySnapshotStore, SnapshotPayloadFormat,
    SnapshotStore, SnapshotWriteRequest,
};

#[tokio::test]
async fn uat_encrypted_snapshot_provider_and_datafusion_support_detail_and_analysis() {
    let cipher = DevelopmentEnvelopeCipher::new("dek-view", 0x2F);
    let rows = vec![
        vec![
            FieldQueryResult {
                field: "department".into(),
                value: "fraud".into(),
            },
            FieldQueryResult {
                field: "employee_id".into(),
                value: "E-1".into(),
            },
        ],
        vec![
            FieldQueryResult {
                field: "department".into(),
                value: "fraud".into(),
            },
            FieldQueryResult {
                field: "employee_id".into(),
                value: "E-2".into(),
            },
        ],
        vec![
            FieldQueryResult {
                field: "department".into(),
                value: "risk".into(),
            },
            FieldQueryResult {
                field: "employee_id".into(),
                value: "E-3".into(),
            },
        ],
    ];
    let encoded = encode_rows_to_parquet(&rows, None).expect("parquet payload");

    let mut store = InMemorySnapshotStore::default();
    let record = store.put(
        SnapshotWriteRequest {
            tenant_id: "tenant-alpha".into(),
            project_id: "project-alpha".into(),
            owner_user_id: "user-analyst".into(),
            grant_id: "grant-alpha".into(),
            grant_expires_at: Utc::now() + Duration::hours(8),
            retention_until: Utc::now() + Duration::hours(8),
            data_source_id: "datasource-rest".into(),
            object_bucket: "sdqp-snapshots".into(),
            data_fingerprint: "fingerprint-uat".into(),
            columns: encoded.columns.clone(),
            payload_format: SnapshotPayloadFormat::Parquet,
        },
        cipher.encrypt(&encoded.payload).expect("encrypted rows"),
        rows.len(),
    );

    let provider = EncryptedSnapshotProvider::new(DevelopmentEnvelopeCipher::new("dek-view", 0x2F));
    let detail_profile =
        SnapshotAccessProfile::new(vec!["department".into(), "employee_id".into()]);
    let page = provider
        .read_page(
            &record,
            &detail_profile,
            &["department".into(), "employee_id".into()],
            2,
            None,
        )
        .await
        .expect("page");
    assert_eq!(page.rows.len(), 2);
    assert_eq!(page.next_cursor, Some(2));

    let buckets = provider
        .execute_pivot(
            &record,
            &SnapshotAccessProfile::new(vec!["department".into()])
                .with_masking_rule("department", MaskingStrategy::None),
            "department",
            PivotMetric::RecordCount,
        )
        .await
        .expect("pivot");
    assert_eq!(buckets.len(), 2);
    assert_eq!(buckets[0].key, "fraud");
    assert_eq!(buckets[0].value, 2.0);

    let drilldown = provider
        .execute_drilldown(
            &record,
            &detail_profile,
            "department",
            "fraud",
            &["employee_id".into(), "department".into()],
            10,
            None,
        )
        .await
        .expect("drilldown");
    assert_eq!(drilldown.rows.len(), 2);
}
