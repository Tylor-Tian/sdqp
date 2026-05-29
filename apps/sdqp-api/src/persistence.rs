use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sqlx::{
    Row,
    migrate::{Migration, MigrationType, Migrator},
    types::Json,
};
use sqlx_postgres::{PgPool, PgPoolOptions, PgQueryResult, PgRow};
use thiserror::Error;

use sdqp_approval_engine::Notification;
use sdqp_audit::{
    ActionResult, ActionType, ActorInfo, AuditArchiveBundle, AuditCheckpoint, AuditContextFields,
    AuditEvent, AuditTrail, ControlledDeletionRecord, ControlledDeletionSubjectKind, TargetRef,
    write_replica_file,
};
use sdqp_config::AppSettings;
use sdqp_data_classification::{
    ClassificationCatalogEntry, ClassificationPolicySource, ClassificationRule,
    ClassificationRuleVersion, ClassificationStatus, DataCategory, FieldClassificationPolicy,
    MaskingStrategy, RetentionDisposalAction, RetentionPolicy, RuleVersionStatus, SensitivityLevel,
    WatermarkStrength, apply_retention_overrides, confirm_field_policy_with_rule_version,
    default_rule_version, derive_catalog_entries, normalize_rule_version_catalog,
};
use sdqp_datasource_adapter::{
    SourceType, StoredQueryTask,
    task::{QueryTaskSnapshot, QueryTaskState},
};
use sdqp_encryption::{
    EncryptedPayload, EncryptedSnapshotRecord, KeyRotationDueState, KeyRotationOperation,
    KeyRotationRuntimeStatus, KeyRotationState, SnapshotDeleteState, SnapshotLifecycle,
    SnapshotPayloadFormat,
};
use sdqp_evidence::EvidencePackage;
use sdqp_system_security::{
    ApiKeyRecord, ConfigVersion, CredentialKind, CredentialRotationState, CredentialRotationStatus,
    MfaMethod, Role, ScimGroup, ScimSyncCursor, SessionClaims, TrustedAuthenticationSource,
};
use sdqp_tenant_isolation::{ProjectContext, ProjectObjectNamespace, ProjectState};
use sdqp_ueba::{EntityBaseline, MitigationAction, UebaAlert, UebaRule, UserBaseline};

use crate::{
    ActiveSession, PendingSession, SessionRegistry, UserAccount, build_project_registry,
    build_user_directory,
    phase2::{QueryWorkbenchRuntimeState, TaskScope},
    phase4::{AnalysisTemplateConfig, AnalysisTemplateRecord, AnalysisTemplateVisibility},
    phase5::{DownloadAuthorizationRecord, ExportTaskRecord},
    phase6::{
        UebaCalibrationRunResponse, UebaGovernanceRuleResponse, UebaReplayRunResponse,
        UebaTuningProposalResponse,
    },
};

#[derive(Debug, Clone)]
pub(crate) struct PendingAuditTask {
    pub scope: TaskScope,
    pub snapshot: QueryTaskSnapshot,
    pub data_source_id: String,
}

#[derive(Debug, Clone)]
pub(crate) struct StoredAuditForwardDelivery {
    pub delivery_id: String,
    pub event_id: String,
    pub checkpoint_id: String,
    pub provider: String,
    pub destination: String,
    pub status: String,
    pub payload_bytes: usize,
    pub error_message: Option<String>,
    pub delivered_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub(crate) struct StoredAuditRetentionRun {
    pub run_id: String,
    pub archived_bundle_id: Option<String>,
    pub archived_events: usize,
    pub archived_checkpoints: usize,
    pub purged_bundles: usize,
    pub archive_path: Option<String>,
    pub status: String,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Error)]
pub enum PersistenceError {
    #[error("postgres error: {0}")]
    Postgres(#[from] sqlx::Error),
    #[error("postgres migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("clickhouse init failed: {0}")]
    ClickHouse(#[from] reqwest::Error),
    #[error("audit replica export failed: {0}")]
    AuditReplica(#[from] std::io::Error),
    #[error("audit artifact parsing failed: {0}")]
    AuditArtifact(String),
    #[error("unknown role label: {0}")]
    UnknownRole(String),
    #[error("unknown mfa method label: {0}")]
    UnknownMfaMethod(String),
    #[error("unknown project state label: {0}")]
    UnknownProjectState(String),
    #[error("unknown query task state label: {0}")]
    UnknownQueryTaskState(String),
    #[error("unknown snapshot delete state label: {0}")]
    UnknownSnapshotDeleteState(String),
    #[error("unknown snapshot payload format label: {0}")]
    UnknownSnapshotPayloadFormat(String),
    #[error("unknown auth source label: {0}")]
    UnknownAuthSource(String),
    #[error("unknown UEBA rule label: {0}")]
    UnknownUebaRule(String),
    #[error("unknown UEBA mitigation action label: {0}")]
    UnknownUebaMitigationAction(String),
    #[error("unknown analysis template visibility label: {0}")]
    UnknownAnalysisTemplateVisibility(String),
    #[error("governance persistence error: {0}")]
    Governance(String),
}

#[derive(Debug, Clone)]
pub(crate) struct ApiPersistence {
    pool: PgPool,
    clickhouse_http_url: String,
    clickhouse_client: Client,
    audit_replica_path: PathBuf,
    audit_archive_dir: PathBuf,
}

#[derive(Debug, Serialize)]
struct AuditEventRow<'a> {
    event_id: &'a str,
    event_hash: &'a str,
    prev_hash: &'a str,
    tenant_id: &'a str,
    project_id: Option<&'a str>,
    resource_id: &'a str,
    actor_user_id: &'a str,
    session_id: &'a str,
    ip_address: &'a str,
    action_type: &'a str,
    action_result: &'a str,
    context: &'a str,
    context_fields_json: Option<&'a str>,
    data_fingerprint: Option<&'a str>,
    event_time: String,
}

#[derive(Debug, Serialize)]
struct AuditCheckpointRow<'a> {
    checkpoint_id: &'a str,
    event_count: u64,
    latest_event_hash: &'a str,
    signature: &'a str,
    signature_algorithm: &'a str,
    signer_provider: &'a str,
    signer_key_id: &'a str,
    signer_key_version: Option<&'a str>,
    checkpoint_time: String,
}

#[derive(Debug, Deserialize)]
struct AuditEventRowOwned {
    event_id: String,
    event_hash: String,
    prev_hash: String,
    tenant_id: String,
    project_id: Option<String>,
    resource_id: String,
    actor_user_id: String,
    session_id: String,
    ip_address: String,
    action_type: String,
    action_result: String,
    context: String,
    #[serde(default)]
    context_fields_json: Option<String>,
    data_fingerprint: Option<String>,
    #[serde(deserialize_with = "deserialize_clickhouse_datetime")]
    event_time: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
struct AuditCheckpointRowOwned {
    checkpoint_id: String,
    #[serde(deserialize_with = "deserialize_u64")]
    event_count: u64,
    latest_event_hash: String,
    signature: String,
    #[serde(default = "default_audit_signature_algorithm")]
    signature_algorithm: String,
    #[serde(default = "default_audit_signer_provider")]
    signer_provider: String,
    #[serde(default = "default_audit_signer_key_id")]
    signer_key_id: String,
    #[serde(default)]
    signer_key_version: Option<String>,
    #[serde(deserialize_with = "deserialize_clickhouse_datetime")]
    checkpoint_time: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
struct UebaUserBaselineRow<'a> {
    tenant_id: &'a str,
    user_id: &'a str,
    baseline_window: &'a str,
    baseline_json: &'a str,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StoredUebaUserBaseline {
    pub user_id: String,
    pub baseline_window: String,
    pub baseline: UserBaseline,
}

#[derive(Debug, Serialize)]
struct UebaEntityBaselineRow<'a> {
    tenant_id: &'a str,
    entity_type: &'a str,
    entity_id: &'a str,
    baseline_window: &'a str,
    baseline_json: &'a str,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct UebaEntityBaselineRowOwned {
    entity_type: String,
    entity_id: String,
    baseline_window: String,
    baseline_json: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StoredUebaEntityBaseline {
    pub entity_type: String,
    pub entity_id: String,
    pub baseline_window: String,
    pub baseline: EntityBaseline,
}

#[derive(Debug, Serialize)]
struct UebaAlertRow<'a> {
    alert_id: &'a str,
    tenant_id: &'a str,
    user_id: &'a str,
    severity: &'a str,
    mitigation_action: &'a str,
    reason: &'a str,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct UebaRuleHitRow<'a> {
    hit_id: &'a str,
    alert_id: &'a str,
    tenant_id: &'a str,
    rule_name: &'a str,
    score: u16,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct UebaAlertRowOwned {
    alert_id: String,
    tenant_id: String,
    user_id: String,
    mitigation_action: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct UebaExistingAlertRow {
    user_id: String,
    reason: String,
}

fn decode_optional_json<T>(
    value: Option<Json<Value>>,
    column: &'static str,
) -> Result<Option<T>, PersistenceError>
where
    T: DeserializeOwned,
{
    match value {
        None | Some(Json(Value::Null)) => Ok(None),
        Some(Json(value)) => serde_json::from_value(value)
            .map(Some)
            .map_err(|error| PersistenceError::AuditArtifact(format!("invalid {column}: {error}"))),
    }
}

fn decode_json_column<T>(value: Json<Value>, column: &'static str) -> Result<T, PersistenceError>
where
    T: DeserializeOwned,
{
    serde_json::from_value(value.0)
        .map_err(|error| PersistenceError::AuditArtifact(format!("invalid {column}: {error}")))
}

fn postgres_migrator() -> Migrator {
    Migrator {
        migrations: Cow::Owned(vec![
            Migration::new(
                20260329143000,
                Cow::Borrowed("stage3_core_schema"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260329143000_stage3_core_schema.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260329163000,
                Cow::Borrowed("stage4_security_schema"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260329163000_stage4_security_schema.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260329170000,
                Cow::Borrowed("stage6_query_runtime"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260329170000_stage6_query_runtime.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260329190000,
                Cow::Borrowed("stage7_governance_runtime"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260329190000_stage7_governance_runtime.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260329210000,
                Cow::Borrowed("stage8_snapshot_encryption"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260329210000_stage8_snapshot_encryption.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260329230000,
                Cow::Borrowed("stage9_datafusion_analysis"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260329230000_stage9_datafusion_analysis.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260330010000,
                Cow::Borrowed("stage10_evidence_exports"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260330010000_stage10_evidence_exports.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260330020000,
                Cow::Borrowed("stage11_ueba_stream_runtime"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260330020000_stage11_ueba_stream_runtime.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260418110000,
                Cow::Borrowed("stage11_audit_runtime"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260418110000_stage11_audit_runtime.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260405143000,
                Cow::Borrowed("wave3_analysis_templates"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260405143000_wave3_analysis_templates.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260426140000,
                Cow::Borrowed("module12_scim_sync_runtime"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260426140000_module12_scim_sync_runtime.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260426170000,
                Cow::Borrowed("module12_credential_rotation_runtime"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260426170000_module12_credential_rotation_runtime.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260426200000,
                Cow::Borrowed("module11_controlled_deletion_runtime"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260426200000_module11_controlled_deletion_runtime.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260426220000,
                Cow::Borrowed("module9_evidence_provider_runtime_hardening"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260426220000_module9_evidence_provider_runtime_hardening.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260426230000,
                Cow::Borrowed("module2_permission_lifecycle_eligibility"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260426230000_module2_permission_lifecycle_eligibility.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260426233000,
                Cow::Borrowed("module3_workday_hr_runtime"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260426233000_module3_workday_hr_runtime.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260426234500,
                Cow::Borrowed("module5_project_lifecycle_namespace"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260426234500_module5_project_lifecycle_namespace.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260428090000,
                Cow::Borrowed("module6_key_rotation_runtime"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260428090000_module6_key_rotation_runtime.up.sql"
                )),
                false,
            ),
            Migration::new(
                20260428110000,
                Cow::Borrowed("module7_classification_governance_runtime"),
                MigrationType::ReversibleUp,
                Cow::Borrowed(include_str!(
                    "../../../db/postgres/migrations/20260428110000_module7_classification_governance_runtime.up.sql"
                )),
                false,
            ),
        ]),
        ..Migrator::DEFAULT
    }
}

impl ApiPersistence {
    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub(crate) async fn initialize(settings: &AppSettings) -> Result<Arc<Self>, PersistenceError> {
        let pool = PgPoolOptions::new()
            .max_connections(settings.database.postgres.max_connections as u32)
            .connect(&settings.database.postgres.dsn)
            .await?;

        postgres_migrator().run(&pool).await?;

        let clickhouse_http_url = settings.database.clickhouse.http_url.clone();
        let audit_replica_path = audit_replica_path(&settings.database.postgres.dsn);
        let audit_archive_dir = audit_archive_dir(
            &settings.database.postgres.dsn,
            &settings.audit.retention.archive_dir,
        );
        let persistence = Arc::new(Self {
            pool,
            clickhouse_http_url,
            clickhouse_client: Client::new(),
            audit_replica_path,
            audit_archive_dir,
        });
        persistence.ensure_clickhouse_schema().await?;
        persistence.ensure_ueba_governance_schema().await?;
        persistence.seed_catalog(settings).await?;
        if !settings.api.external_query_worker {
            persistence.recover_inflight_query_tasks().await?;
        }
        Ok(persistence)
    }

    pub(crate) async fn load_audit_trail(&self) -> Result<AuditTrail, PersistenceError> {
        let events = self.load_audit_events().await?;
        let checkpoints = self.load_audit_checkpoints().await?;
        let anchor_checkpoint = self.load_active_audit_boundary().await?;
        Ok(AuditTrail::from_parts_with_anchor(
            anchor_checkpoint,
            events,
            checkpoints,
        ))
    }

    pub(crate) async fn load_tenant_audit_events(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<AuditEvent>, PersistenceError> {
        let events = self.load_audit_events().await?;
        Ok(events
            .into_iter()
            .filter(|event| event.target.tenant_id == tenant_id)
            .collect())
    }

    pub(crate) async fn save_ueba_user_baseline(
        &self,
        tenant_id: &str,
        user_id: &str,
        baseline_window: &str,
        baseline: &UserBaseline,
    ) -> Result<(), PersistenceError> {
        let baseline_json = serde_json::to_string(baseline)
            .map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?;
        let row = UebaUserBaselineRow {
            tenant_id,
            user_id,
            baseline_window,
            baseline_json: &baseline_json,
            updated_at: clickhouse_datetime(chrono::Utc::now()),
        };
        let body = serde_json::to_string(&row)
            .map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?;
        self.execute_clickhouse_query(
            "INSERT INTO sdqp.ueba_user_baselines FORMAT JSONEachRow".to_string(),
            Some(body),
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn load_ueba_user_baselines(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredUebaUserBaseline>, PersistenceError> {
        let query = format!(
            concat!(
                "SELECT user_id, baseline_window, baseline_json ",
                "FROM sdqp.ueba_user_baselines ",
                "WHERE tenant_id = '{}' ",
                "FORMAT JSONEachRow"
            ),
            escape_clickhouse_string(tenant_id)
        );
        let body = self.execute_clickhouse_query(query, None).await?;
        if body.trim().is_empty() {
            return Ok(Vec::new());
        }

        let mut baselines = Vec::new();
        for row in serde_json::Deserializer::from_str(&body).into_iter::<serde_json::Value>() {
            let row = row.map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?;
            let baseline_json = row
                .get("baseline_json")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("{}");
            baselines.push(StoredUebaUserBaseline {
                user_id: row
                    .get("user_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                baseline_window: row
                    .get("baseline_window")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                baseline: serde_json::from_str(baseline_json)
                    .map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?,
            });
        }
        Ok(baselines)
    }

    pub(crate) async fn save_ueba_entity_baseline(
        &self,
        tenant_id: &str,
        entity_type: &str,
        entity_id: &str,
        baseline_window: &str,
        baseline: &EntityBaseline,
    ) -> Result<(), PersistenceError> {
        let baseline_json = serde_json::to_string(baseline)
            .map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?;
        let row = UebaEntityBaselineRow {
            tenant_id,
            entity_type,
            entity_id,
            baseline_window,
            baseline_json: &baseline_json,
            updated_at: clickhouse_datetime(chrono::Utc::now()),
        };
        let body = serde_json::to_string(&row)
            .map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?;
        self.execute_clickhouse_query(
            "INSERT INTO sdqp.ueba_entity_baselines FORMAT JSONEachRow".to_string(),
            Some(body),
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn load_ueba_entity_baselines(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredUebaEntityBaseline>, PersistenceError> {
        let query = format!(
            concat!(
                "SELECT entity_type, entity_id, baseline_window, baseline_json ",
                "FROM sdqp.ueba_entity_baselines ",
                "WHERE tenant_id = '{}' ",
                "FORMAT JSONEachRow"
            ),
            escape_clickhouse_string(tenant_id)
        );
        let body = self.execute_clickhouse_query(query, None).await?;
        if body.trim().is_empty() {
            return Ok(Vec::new());
        }

        let mut baselines = Vec::new();
        for row in
            serde_json::Deserializer::from_str(&body).into_iter::<UebaEntityBaselineRowOwned>()
        {
            let row = row.map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?;
            baselines.push(StoredUebaEntityBaseline {
                entity_type: row.entity_type,
                entity_id: row.entity_id,
                baseline_window: row.baseline_window,
                baseline: serde_json::from_str(&row.baseline_json)
                    .map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?,
            });
        }
        Ok(baselines)
    }

    pub(crate) async fn load_ueba_alert_signatures(
        &self,
        tenant_id: &str,
    ) -> Result<HashSet<String>, PersistenceError> {
        let query = format!(
            concat!(
                "SELECT user_id, reason ",
                "FROM sdqp.ueba_alerts ",
                "WHERE tenant_id = '{}' ",
                "FORMAT JSONEachRow"
            ),
            escape_clickhouse_string(tenant_id)
        );
        let body = self.execute_clickhouse_query(query, None).await?;
        if body.trim().is_empty() {
            return Ok(HashSet::new());
        }

        let mut signatures = HashSet::new();
        for row in serde_json::Deserializer::from_str(&body).into_iter::<UebaExistingAlertRow>() {
            let row = row.map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?;
            signatures.insert(ueba_alert_signature(&row.user_id, &row.reason));
        }
        Ok(signatures)
    }

    pub(crate) async fn save_ueba_alert(&self, alert: &UebaAlert) -> Result<(), PersistenceError> {
        let reason = encode_ueba_reason(alert);
        let row = UebaAlertRow {
            alert_id: &alert.alert_id,
            tenant_id: &alert.tenant_id,
            user_id: &alert.user_id,
            severity: ueba_severity_label(alert.risk_score),
            mitigation_action: mitigation_action_label(&alert.action),
            reason: &reason,
            created_at: clickhouse_datetime(chrono::Utc::now()),
        };
        let body = serde_json::to_string(&row)
            .map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?;
        self.execute_clickhouse_query(
            "INSERT INTO sdqp.ueba_alerts FORMAT JSONEachRow".to_string(),
            Some(body),
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn save_ueba_rule_hit(
        &self,
        alert: &UebaAlert,
    ) -> Result<(), PersistenceError> {
        let hit_id = format!("hit-{}", &alert.alert_id);
        let row = UebaRuleHitRow {
            hit_id: &hit_id,
            alert_id: &alert.alert_id,
            tenant_id: &alert.tenant_id,
            rule_name: ueba_rule_label(&alert.rule),
            score: alert.risk_score as u16,
            created_at: clickhouse_datetime(chrono::Utc::now()),
        };
        let body = serde_json::to_string(&row)
            .map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?;
        self.execute_clickhouse_query(
            "INSERT INTO sdqp.ueba_rule_hits FORMAT JSONEachRow".to_string(),
            Some(body),
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn load_ueba_governance_rules(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<UebaGovernanceRuleResponse>, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT rule_json
            FROM ueba_governance_rules
            WHERE tenant_id = $1
            ORDER BY rule_name, version_number
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                decode_json_column(row.try_get("rule_json")?, "ueba_governance_rules.rule_json")
            })
            .collect()
    }

    pub(crate) async fn save_ueba_governance_rule(
        &self,
        rule: &UebaGovernanceRuleResponse,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO ueba_governance_rules (
                rule_version_id,
                tenant_id,
                rule_name,
                version_number,
                status,
                enabled,
                rule_json,
                created_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            ON CONFLICT (rule_version_id) DO UPDATE SET
                status = EXCLUDED.status,
                enabled = EXCLUDED.enabled,
                rule_json = EXCLUDED.rule_json,
                updated_at = NOW()
            "#,
        )
        .bind(&rule.rule_version_id)
        .bind(&rule.tenant_id)
        .bind(&rule.rule_name)
        .bind(rule.version as i32)
        .bind(&rule.status)
        .bind(rule.enabled)
        .bind(Json(rule))
        .bind(rule.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn activate_ueba_governance_rule(
        &self,
        tenant_id: &str,
        rule_version_id: &str,
    ) -> Result<Option<UebaGovernanceRuleResponse>, PersistenceError> {
        let Some(mut rule) = self
            .load_ueba_governance_rule(tenant_id, rule_version_id)
            .await?
        else {
            return Ok(None);
        };
        let now = chrono::Utc::now();
        let existing = self.load_ueba_governance_rules(tenant_id).await?;
        for mut current in existing.into_iter().filter(|current| {
            current.rule_name == rule.rule_name && current.rule_version_id != rule_version_id
        }) {
            if current.status == "active" {
                current.status = "retired".into();
                current.enabled = false;
                current.retired_at = Some(now);
                self.save_ueba_governance_rule(&current).await?;
            }
        }
        rule.status = "active".into();
        rule.enabled = true;
        rule.activated_at = Some(now);
        rule.retired_at = None;
        self.save_ueba_governance_rule(&rule).await?;
        Ok(Some(rule))
    }

    pub(crate) async fn set_ueba_governance_rule_enabled(
        &self,
        tenant_id: &str,
        rule_version_id: &str,
        enabled: bool,
    ) -> Result<Option<UebaGovernanceRuleResponse>, PersistenceError> {
        let Some(mut rule) = self
            .load_ueba_governance_rule(tenant_id, rule_version_id)
            .await?
        else {
            return Ok(None);
        };
        if rule.status != "retired" {
            rule.enabled = enabled;
            self.save_ueba_governance_rule(&rule).await?;
        }
        Ok(Some(rule))
    }

    pub(crate) async fn retire_ueba_governance_rule(
        &self,
        tenant_id: &str,
        rule_version_id: &str,
    ) -> Result<Option<UebaGovernanceRuleResponse>, PersistenceError> {
        let Some(mut rule) = self
            .load_ueba_governance_rule(tenant_id, rule_version_id)
            .await?
        else {
            return Ok(None);
        };
        rule.status = "retired".into();
        rule.enabled = false;
        rule.retired_at = Some(chrono::Utc::now());
        self.save_ueba_governance_rule(&rule).await?;
        Ok(Some(rule))
    }

    pub(crate) async fn save_ueba_replay_run(
        &self,
        run: &UebaReplayRunResponse,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO ueba_replay_runs (run_id, tenant_id, run_json, created_at, updated_at)
            VALUES ($1, $2, $3, $4, NOW())
            ON CONFLICT (run_id) DO UPDATE SET
                run_json = EXCLUDED.run_json,
                updated_at = NOW()
            "#,
        )
        .bind(&run.run_id)
        .bind(&run.tenant_id)
        .bind(Json(run))
        .bind(run.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn load_ueba_replay_run(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<Option<UebaReplayRunResponse>, PersistenceError> {
        self.load_json_record(
            "SELECT run_json FROM ueba_replay_runs WHERE tenant_id = $1 AND run_id = $2",
            tenant_id,
            run_id,
            "ueba_replay_runs.run_json",
        )
        .await
    }

    pub(crate) async fn save_ueba_tuning_proposal(
        &self,
        proposal: &UebaTuningProposalResponse,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO ueba_tuning_proposals (
                proposal_id,
                tenant_id,
                status,
                proposal_json,
                created_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (proposal_id) DO UPDATE SET
                status = EXCLUDED.status,
                proposal_json = EXCLUDED.proposal_json,
                updated_at = NOW()
            "#,
        )
        .bind(&proposal.proposal_id)
        .bind(&proposal.tenant_id)
        .bind(&proposal.status)
        .bind(Json(proposal))
        .bind(proposal.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn load_ueba_tuning_proposal(
        &self,
        tenant_id: &str,
        proposal_id: &str,
    ) -> Result<Option<UebaTuningProposalResponse>, PersistenceError> {
        self.load_json_record(
            "SELECT proposal_json FROM ueba_tuning_proposals WHERE tenant_id = $1 AND proposal_id = $2",
            tenant_id,
            proposal_id,
            "ueba_tuning_proposals.proposal_json",
        )
        .await
    }

    pub(crate) async fn save_ueba_calibration_run(
        &self,
        run: &UebaCalibrationRunResponse,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO ueba_calibration_runs (
                calibration_id,
                tenant_id,
                status,
                run_json,
                created_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (calibration_id) DO UPDATE SET
                status = EXCLUDED.status,
                run_json = EXCLUDED.run_json,
                updated_at = NOW()
            "#,
        )
        .bind(&run.calibration_id)
        .bind(&run.tenant_id)
        .bind(&run.status)
        .bind(Json(run))
        .bind(run.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn load_ueba_calibration_run(
        &self,
        tenant_id: &str,
        calibration_id: &str,
    ) -> Result<Option<UebaCalibrationRunResponse>, PersistenceError> {
        self.load_json_record(
            "SELECT run_json FROM ueba_calibration_runs WHERE tenant_id = $1 AND calibration_id = $2",
            tenant_id,
            calibration_id,
            "ueba_calibration_runs.run_json",
        )
        .await
    }

    async fn load_ueba_governance_rule(
        &self,
        tenant_id: &str,
        rule_version_id: &str,
    ) -> Result<Option<UebaGovernanceRuleResponse>, PersistenceError> {
        self.load_json_record(
            "SELECT rule_json FROM ueba_governance_rules WHERE tenant_id = $1 AND rule_version_id = $2",
            tenant_id,
            rule_version_id,
            "ueba_governance_rules.rule_json",
        )
        .await
    }

    async fn load_json_record<T>(
        &self,
        query: &str,
        tenant_id: &str,
        id: &str,
        column: &'static str,
    ) -> Result<Option<T>, PersistenceError>
    where
        T: DeserializeOwned,
    {
        let Some(row) = sqlx::query(query)
            .bind(tenant_id)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Ok(None);
        };

        decode_json_column(row.try_get(0)?, column).map(Some)
    }

    pub(crate) async fn load_ueba_alerts(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<UebaAlert>, PersistenceError> {
        let query = format!(
            concat!(
                "SELECT alert_id, tenant_id, user_id, mitigation_action, reason ",
                "FROM sdqp.ueba_alerts ",
                "WHERE tenant_id = '{}' ",
                "ORDER BY created_at DESC, alert_id DESC ",
                "FORMAT JSONEachRow"
            ),
            escape_clickhouse_string(tenant_id)
        );
        let body = self.execute_clickhouse_query(query, None).await?;
        if body.trim().is_empty() {
            return Ok(Vec::new());
        }

        let mut alerts = Vec::new();
        for row in serde_json::Deserializer::from_str(&body).into_iter::<UebaAlertRowOwned>() {
            let row = row.map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?;
            let (rule, risk_score, evidence) = decode_ueba_reason(&row.reason)?;
            alerts.push(UebaAlert {
                alert_id: row.alert_id,
                user_id: row.user_id,
                tenant_id: row.tenant_id,
                project_id: None,
                rule,
                risk_score,
                action: parse_mitigation_action(&row.mitigation_action)?,
                evidence,
            });
        }
        Ok(alerts)
    }

    pub(crate) async fn queue_notification_delivery(
        &self,
        instance_id: Option<&str>,
        notification: &Notification,
    ) -> Result<(), PersistenceError> {
        for channel in ["feishu", "slack", "email", "telegram", "dingtalk"] {
            sqlx::query(
                r#"
                INSERT INTO notification_deliveries (
                    delivery_id,
                    instance_id,
                    channel,
                    recipient,
                    message,
                    notification_json,
                    status,
                    attempt_count,
                    next_attempt_at,
                    created_at,
                    updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, 'pending', 0, NOW(), NOW(), NOW())
                "#,
            )
            .bind(ulid::Ulid::new().to_string())
            .bind(instance_id)
            .bind(channel)
            .bind(&notification.recipient)
            .bind(&notification.message)
            .bind(Json(notification))
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub(crate) async fn load_stream_offset(
        &self,
        stream_name: &str,
        partition_id: i32,
    ) -> Result<i64, PersistenceError> {
        let offset = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT next_offset
            FROM stream_offsets
            WHERE stream_name = $1 AND partition_id = $2
            "#,
        )
        .bind(stream_name)
        .bind(partition_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(offset.unwrap_or(0))
    }

    pub(crate) async fn save_stream_offset(
        &self,
        stream_name: &str,
        partition_id: i32,
        next_offset: i64,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO stream_offsets (stream_name, partition_id, next_offset, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (stream_name, partition_id) DO UPDATE SET
                next_offset = EXCLUDED.next_offset,
                updated_at = NOW()
            "#,
        )
        .bind(stream_name)
        .bind(partition_id)
        .bind(next_offset)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn load_runtime_config(
        &self,
    ) -> Result<HashMap<String, String>, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT ON (config_key) config_key, config_payload_json
            FROM config_versions
            ORDER BY config_key, created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut config = HashMap::new();
        for row in rows {
            let key: String = row.try_get("config_key")?;
            let payload = row.try_get::<Json<Value>, _>("config_payload_json")?.0;
            if let Some(value) = payload.get("value").and_then(Value::as_str) {
                config.insert(key, value.to_string());
            }
        }

        Ok(config)
    }

    pub(crate) async fn load_analysis_templates(
        &self,
    ) -> Result<HashMap<String, AnalysisTemplateRecord>, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT
                template_id,
                tenant_id,
                project_id,
                owner_user_id,
                data_source_id,
                name,
                description,
                visibility,
                config_json,
                published_at,
                created_at,
                updated_at
            FROM analysis_templates
            ORDER BY updated_at DESC, template_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut templates = HashMap::with_capacity(rows.len());
        for row in rows {
            let record = AnalysisTemplateRecord {
                template_id: row.try_get("template_id")?,
                tenant_id: row.try_get("tenant_id")?,
                project_id: row.try_get("project_id")?,
                owner_user_id: row.try_get("owner_user_id")?,
                data_source_id: row.try_get("data_source_id")?,
                name: row.try_get("name")?,
                description: row.try_get("description")?,
                visibility: parse_analysis_template_visibility(
                    &row.try_get::<String, _>("visibility")?,
                )?,
                config: row
                    .try_get::<Json<AnalysisTemplateConfig>, _>("config_json")?
                    .0,
                published_at: row.try_get("published_at")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
            };
            templates.insert(record.template_id.clone(), record);
        }

        Ok(templates)
    }

    pub(crate) async fn load_users(
        &self,
    ) -> Result<HashMap<String, UserAccount>, PersistenceError> {
        let user_rows = sqlx::query(
            r#"
            SELECT
                user_id,
                tenant_id,
                username,
                display_name,
                email,
                password_secret,
                mfa_method,
                external_id,
                active,
                auth_source
            FROM users
            ORDER BY username
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let role_rows = sqlx::query(
            r#"
            SELECT user_id, role_name
            FROM roles
            ORDER BY user_id, role_name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut roles_by_user = HashMap::<String, Vec<Role>>::new();
        for row in role_rows {
            let user_id: String = row.try_get("user_id")?;
            let role_name: String = row.try_get("role_name")?;
            roles_by_user
                .entry(user_id)
                .or_default()
                .push(parse_role(&role_name)?);
        }

        let mut users = HashMap::new();
        for row in user_rows {
            let user_id: String = row.try_get("user_id")?;
            let username: String = row.try_get("username")?;
            users.insert(
                username.clone(),
                UserAccount {
                    username,
                    display_name: row.try_get("display_name")?,
                    email: row.try_get("email")?,
                    password: row.try_get("password_secret")?,
                    user_id: user_id.clone(),
                    tenant_id: row.try_get("tenant_id")?,
                    external_id: row.try_get("external_id")?,
                    active: row.try_get("active")?,
                    auth_source: parse_auth_source(&row.try_get::<String, _>("auth_source")?)?,
                    roles: roles_by_user.remove(&user_id).unwrap_or_default(),
                    mfa_method: parse_mfa_method(&row.try_get::<String, _>("mfa_method")?)?,
                    mfa_registration: None,
                },
            );
        }

        Ok(users)
    }

    pub(crate) async fn load_scim_groups(
        &self,
    ) -> Result<HashMap<String, ScimGroup>, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT group_id, tenant_id, display_name, active, members_json
            FROM identity_groups
            ORDER BY group_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut groups = HashMap::new();
        for row in rows {
            let external_id: String = row.try_get("group_id")?;
            groups.insert(
                external_id.clone(),
                ScimGroup {
                    external_id,
                    tenant_id: row.try_get("tenant_id")?,
                    display_name: row.try_get("display_name")?,
                    active: row.try_get("active")?,
                    members: row.try_get::<Json<Vec<String>>, _>("members_json")?.0,
                },
            );
        }

        Ok(groups)
    }

    pub(crate) async fn load_scim_sync_cursor(
        &self,
        provider_id: &str,
    ) -> Result<Option<ScimSyncCursor>, PersistenceError> {
        let row = sqlx::query(
            r#"
            SELECT cursor_json
            FROM scim_sync_state
            WHERE provider_id = $1
            "#,
        )
        .bind(provider_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|row| {
            let cursor = row.try_get::<Json<Value>, _>("cursor_json")?.0;
            serde_json::from_value(cursor).map_err(|error| {
                PersistenceError::AuditArtifact(format!("invalid scim sync cursor: {error}"))
            })
        })
        .transpose()
    }

    pub(crate) async fn load_integration_api_keys(
        &self,
    ) -> Result<Vec<ApiKeyRecord>, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT key_id, secret, scopes_json, allowed_ips_json
            FROM integration_api_credentials
            ORDER BY key_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(ApiKeyRecord {
                    key_id: row.try_get("key_id")?,
                    secret: row.try_get("secret")?,
                    scopes: row.try_get::<Json<Vec<String>>, _>("scopes_json")?.0,
                    allowed_ips: row.try_get::<Json<Vec<String>>, _>("allowed_ips_json")?.0,
                })
            })
            .collect()
    }

    pub(crate) async fn load_credential_rotation_states(
        &self,
    ) -> Result<HashMap<String, CredentialRotationState>, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT
                credential_id,
                credential_kind,
                status,
                last_rotated_at,
                next_rotation_due_at,
                last_attempt_at,
                attempts,
                active_version,
                last_error,
                manual_intervention_reason,
                updated_at
            FROM credential_rotation_state
            ORDER BY credential_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut states = HashMap::new();
        for row in rows {
            let credential_id: String = row.try_get("credential_id")?;
            states.insert(
                credential_id.clone(),
                CredentialRotationState {
                    credential_id,
                    kind: parse_credential_kind(&row.try_get::<String, _>("credential_kind")?)?,
                    status: parse_credential_rotation_status(&row.try_get::<String, _>("status")?)?,
                    last_rotated_at: row.try_get("last_rotated_at")?,
                    next_rotation_due_at: row.try_get("next_rotation_due_at")?,
                    last_attempt_at: row.try_get("last_attempt_at")?,
                    attempts: row.try_get::<i32, _>("attempts")?.max(0) as u32,
                    active_version: row.try_get("active_version")?,
                    last_error: row.try_get("last_error")?,
                    manual_intervention_reason: row.try_get("manual_intervention_reason")?,
                    updated_at: row.try_get("updated_at")?,
                },
            );
        }

        Ok(states)
    }

    pub(crate) async fn load_key_rotation_states(
        &self,
    ) -> Result<HashMap<String, KeyRotationState>, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT
                inventory_id,
                snapshot_id,
                tenant_id,
                project_id,
                provider,
                kek_id,
                key_version,
                dek_id,
                created_at,
                last_rewrapped_at,
                next_dek_rotation_due_at,
                next_kek_rewrap_due_at,
                due_state,
                status,
                last_operation,
                last_cycle_id,
                last_error,
                updated_at
            FROM key_rotation_state
            ORDER BY tenant_id, project_id, snapshot_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut states = HashMap::new();
        for row in rows {
            let inventory_id: String = row.try_get("inventory_id")?;
            states.insert(
                inventory_id.clone(),
                KeyRotationState {
                    inventory_id,
                    snapshot_id: row.try_get("snapshot_id")?,
                    tenant_id: row.try_get("tenant_id")?,
                    project_id: row.try_get("project_id")?,
                    provider: row.try_get("provider")?,
                    kek_id: row.try_get("kek_id")?,
                    key_version: row.try_get("key_version")?,
                    dek_id: row.try_get("dek_id")?,
                    created_at: row.try_get("created_at")?,
                    last_rewrapped_at: row.try_get("last_rewrapped_at")?,
                    next_dek_rotation_due_at: row.try_get("next_dek_rotation_due_at")?,
                    next_kek_rewrap_due_at: row.try_get("next_kek_rewrap_due_at")?,
                    due_state: parse_key_rotation_due_state(
                        &row.try_get::<String, _>("due_state")?,
                    )?,
                    status: parse_key_rotation_runtime_status(
                        &row.try_get::<String, _>("status")?,
                    )?,
                    last_operation: parse_key_rotation_operation(
                        &row.try_get::<String, _>("last_operation")?,
                    )?,
                    last_cycle_id: row.try_get("last_cycle_id")?,
                    last_error: row.try_get("last_error")?,
                    updated_at: row.try_get("updated_at")?,
                },
            );
        }

        Ok(states)
    }

    pub(crate) async fn load_projects(
        &self,
    ) -> Result<HashMap<String, ProjectContext>, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT
                project_id,
                tenant_id,
                state,
                object_bucket,
                object_prefix,
                created_by_user_id,
                deletion_reason
            FROM projects
            ORDER BY project_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut projects = HashMap::new();
        for row in rows {
            let project_id: String = row.try_get("project_id")?;
            let tenant_id: String = row.try_get("tenant_id")?;
            let state: String = row.try_get("state")?;
            let object_bucket: String = row.try_get("object_bucket")?;
            let object_prefix: String = row.try_get("object_prefix")?;
            let tenant = sdqp_core::TenantId::new(tenant_id).expect("seeded tenant id");
            let project = sdqp_core::ProjectId::new(project_id.clone()).expect("seeded project id");
            let mut context = ProjectContext::new_with_namespace(
                tenant,
                project,
                parse_project_state(&state)?,
                ProjectObjectNamespace {
                    object_bucket,
                    key_prefix: object_prefix,
                },
            );
            context.created_by_user_id = row.try_get("created_by_user_id")?;
            context.deletion_reason = row.try_get("deletion_reason")?;
            projects.insert(project_id.clone(), context);
        }

        Ok(projects)
    }

    pub(crate) async fn load_sessions(&self) -> Result<SessionRegistry, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT
                session_id,
                session_kind,
                binding_json,
                pending_account_json,
                claims_json,
                refresh_token,
                previous_refresh_token_fingerprint,
                roles_json,
                auth_source,
                risk_score,
                device_posture_json,
                revoked,
                step_up_required
                ,step_up_challenge_json
                ,mfa_method
            FROM sessions
            ORDER BY created_at, session_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut registry = SessionRegistry::default();
        for row in rows {
            let session_id: String = row.try_get("session_id")?;
            let session_kind: String = row.try_get("session_kind")?;
            if session_kind == "pending" {
                let pending_account = row
                    .try_get::<Option<Json<PendingSession>>, _>("pending_account_json")?
                    .map(|value| value.0);
                if let Some(pending) = pending_account {
                    registry.pending.insert(session_id, pending);
                }
                continue;
            }

            let claims = row
                .try_get::<Option<Json<SessionClaims>>, _>("claims_json")?
                .map(|value| value.0);
            let roles = row
                .try_get::<Option<Json<Vec<Role>>>, _>("roles_json")?
                .map(|value| value.0);
            let refresh_token: Option<String> = row.try_get("refresh_token")?;
            let device_posture = decode_optional_json(
                row.try_get::<Option<Json<Value>>, _>("device_posture_json")?,
                "device_posture_json",
            )?;
            let step_up_challenge = decode_optional_json(
                row.try_get::<Option<Json<Value>>, _>("step_up_challenge_json")?,
                "step_up_challenge_json",
            )?;
            if let (Some(claims), Some(roles), Some(refresh_token)) = (claims, roles, refresh_token)
            {
                registry.active.insert(
                    session_id,
                    ActiveSession {
                        claims,
                        refresh_token,
                        previous_refresh_token_fingerprint: row
                            .try_get("previous_refresh_token_fingerprint")?,
                        roles,
                        mfa_method: parse_mfa_method(&row.try_get::<String, _>("mfa_method")?)?,
                        auth_source: parse_auth_source(&row.try_get::<String, _>("auth_source")?)?,
                        risk_score: row.try_get::<i32, _>("risk_score")? as u8,
                        device_posture,
                        revoked: row.try_get("revoked")?,
                        step_up_required: row.try_get("step_up_required")?,
                        step_up_challenge,
                    },
                );
            }
        }

        Ok(registry)
    }

    pub(crate) async fn load_query_tasks(
        &self,
    ) -> Result<Vec<(TaskScope, QueryTaskSnapshot)>, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT
                task_id,
                tenant_id,
                project_id,
                user_id,
                project_scope_key,
                state,
                snapshot_id,
                cache_hit,
                error
            FROM query_tasks
            ORDER BY created_at, task_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut tasks = Vec::with_capacity(rows.len());
        for row in rows {
            tasks.push((
                TaskScope {
                    project_scope_key: row.try_get("project_scope_key")?,
                    tenant_id: row.try_get("tenant_id")?,
                    project_id: row.try_get("project_id")?,
                    user_id: row.try_get("user_id")?,
                },
                QueryTaskSnapshot {
                    task_id: row.try_get("task_id")?,
                    state: parse_query_task_state(&row.try_get::<String, _>("state")?)?,
                    snapshot_id: row.try_get("snapshot_id")?,
                    cache_hit: row.try_get("cache_hit")?,
                    error: row.try_get("error")?,
                },
            ));
        }

        Ok(tasks)
    }

    pub(crate) async fn load_query_workbench_runtime_states(
        &self,
    ) -> Result<HashMap<String, QueryWorkbenchRuntimeState>, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT
                task_id,
                priority,
                state,
                snapshot_id,
                cache_hit,
                error
            FROM query_tasks
            ORDER BY updated_at, task_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut runtimes = HashMap::with_capacity(rows.len());
        for row in rows {
            let snapshot = QueryTaskSnapshot {
                task_id: row.try_get("task_id")?,
                state: parse_query_task_state(&row.try_get::<String, _>("state")?)?,
                snapshot_id: row.try_get("snapshot_id")?,
                cache_hit: row.try_get("cache_hit")?,
                error: row.try_get("error")?,
            };
            let priority = row.try_get::<i32, _>("priority")?;
            runtimes.insert(
                snapshot.task_id.clone(),
                QueryWorkbenchRuntimeState::from_snapshot(priority, &snapshot),
            );
        }

        Ok(runtimes)
    }

    pub(crate) async fn load_unaudited_terminal_tasks(
        &self,
    ) -> Result<Vec<PendingAuditTask>, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT
                task_id,
                tenant_id,
                project_id,
                user_id,
                project_scope_key,
                data_source_id,
                state,
                snapshot_id,
                cache_hit,
                error
            FROM query_tasks
            WHERE completion_audited = FALSE
              AND state IN ('completed', 'failed', 'cancelled')
            ORDER BY updated_at, task_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut tasks = Vec::with_capacity(rows.len());
        for row in rows {
            tasks.push(PendingAuditTask {
                scope: TaskScope {
                    project_scope_key: row.try_get("project_scope_key")?,
                    tenant_id: row.try_get("tenant_id")?,
                    project_id: row.try_get("project_id")?,
                    user_id: row.try_get("user_id")?,
                },
                snapshot: QueryTaskSnapshot {
                    task_id: row.try_get("task_id")?,
                    state: parse_query_task_state(&row.try_get::<String, _>("state")?)?,
                    snapshot_id: row.try_get("snapshot_id")?,
                    cache_hit: row.try_get("cache_hit")?,
                    error: row.try_get("error")?,
                },
                data_source_id: row.try_get("data_source_id")?,
            });
        }

        Ok(tasks)
    }

    pub(crate) async fn mark_task_completion_audited(
        &self,
        task_id: &str,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            UPDATE query_tasks
            SET completion_audited = TRUE, updated_at = NOW()
            WHERE task_id = $1
            "#,
        )
        .bind(task_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn load_snapshots(
        &self,
    ) -> Result<Vec<EncryptedSnapshotRecord>, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT
                snapshot_id,
                tenant_id,
                project_id,
                storage_key,
                created_at,
                data_source_id,
                encrypted_payload_json,
                row_count,
                payload_format,
                columns_json,
                owner_user_id,
                grant_id,
                grant_expires_at,
                retention_until,
                data_fingerprint,
                object_bucket,
                object_size_bytes,
                delete_state,
                delete_reason,
                deleted_at,
                purged_at,
                last_rewrapped_at
            FROM snapshots
            ORDER BY created_at, snapshot_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut snapshots = Vec::with_capacity(rows.len());
        for row in rows {
            snapshots.push(parse_snapshot_record(&row)?);
        }

        Ok(snapshots)
    }

    pub(crate) async fn load_snapshot(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<EncryptedSnapshotRecord>, PersistenceError> {
        let row = sqlx::query(
            r#"
            SELECT
                snapshot_id,
                tenant_id,
                project_id,
                storage_key,
                created_at,
                data_source_id,
                encrypted_payload_json,
                row_count,
                payload_format,
                columns_json,
                owner_user_id,
                grant_id,
                grant_expires_at,
                retention_until,
                data_fingerprint,
                object_bucket,
                object_size_bytes,
                delete_state,
                delete_reason,
                deleted_at,
                purged_at,
                last_rewrapped_at
            FROM snapshots
            WHERE snapshot_id = $1
            "#,
        )
        .bind(snapshot_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|row| parse_snapshot_record(&row)).transpose()
    }

    pub(crate) async fn load_export_task(
        &self,
        task_id: &str,
    ) -> Result<Option<ExportTaskRecord>, PersistenceError> {
        let row = sqlx::query(
            r#"
            SELECT payload_json
            FROM export_tasks
            WHERE task_id = $1
            "#,
        )
        .bind(task_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|row| {
            row.try_get::<Json<ExportTaskRecord>, _>("payload_json")
                .map(|json| json.0)
        })
        .transpose()
        .map_err(PersistenceError::from)
    }

    pub(crate) async fn load_download_authorization(
        &self,
        token: &str,
    ) -> Result<Option<DownloadAuthorizationRecord>, PersistenceError> {
        let row = sqlx::query(
            r#"
            SELECT payload_json
            FROM download_authorizations
            WHERE download_token = $1
            "#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|row| {
            row.try_get::<Json<DownloadAuthorizationRecord>, _>("payload_json")
                .map(|json| json.0)
        })
        .transpose()
        .map_err(PersistenceError::from)
    }

    pub(crate) async fn load_active_classification_rule_version(
        &self,
        project_id: &str,
        data_source_id: &str,
    ) -> Result<Option<ClassificationRuleVersion>, PersistenceError> {
        let row = sqlx::query(
            r#"
            SELECT
                rule_version_id,
                project_id,
                data_source_id,
                version_number,
                status,
                rules_json,
                catalog_json
            FROM classification_rule_versions
            WHERE project_id = $1 AND data_source_id = $2 AND status = 'active'
            ORDER BY version_number DESC, created_at DESC
            LIMIT 1
            "#,
        )
        .bind(project_id)
        .bind(data_source_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|row| parse_classification_rule_version(&row))
            .transpose()
    }

    pub(crate) async fn list_classification_rule_versions(
        &self,
        project_id: &str,
        data_source_id: &str,
    ) -> Result<Vec<ClassificationRuleVersion>, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT
                rule_version_id,
                project_id,
                data_source_id,
                version_number,
                status,
                rules_json,
                catalog_json
            FROM classification_rule_versions
            WHERE project_id = $1 AND data_source_id = $2
            ORDER BY version_number DESC, created_at DESC
            "#,
        )
        .bind(project_id)
        .bind(data_source_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| parse_classification_rule_version(&row))
            .collect()
    }

    pub(crate) async fn create_classification_rule_version(
        &self,
        project_id: &str,
        data_source_id: &str,
        rules: Vec<ClassificationRule>,
        created_by_user_id: &str,
        description: Option<&str>,
    ) -> Result<ClassificationRuleVersion, PersistenceError> {
        let next_version_number = sqlx::query(
            r#"
            SELECT COALESCE(MAX(version_number), 0) + 1 AS next_version_number
            FROM classification_rule_versions
            WHERE project_id = $1 AND data_source_id = $2
            "#,
        )
        .bind(project_id)
        .bind(data_source_id)
        .fetch_one(&self.pool)
        .await?
        .try_get::<i32, _>("next_version_number")?;

        let version = normalize_rule_version_catalog(ClassificationRuleVersion {
            rule_version_id: format!(
                "crv-{project_id}-{data_source_id}-v{}-{}",
                next_version_number,
                ulid::Ulid::new()
            ),
            project_id: project_id.to_string(),
            data_source_id: data_source_id.to_string(),
            version_number: next_version_number,
            status: RuleVersionStatus::Draft,
            rules,
            catalog_entries: Vec::new(),
        });

        sqlx::query(
            r#"
            INSERT INTO classification_rule_versions (
                rule_version_id,
                project_id,
                data_source_id,
                version_number,
                status,
                rules_json,
                catalog_json,
                created_by_user_id,
                description,
                created_at
            )
            VALUES ($1, $2, $3, $4, 'draft', $5, $6, $7, $8, NOW())
            "#,
        )
        .bind(&version.rule_version_id)
        .bind(project_id)
        .bind(data_source_id)
        .bind(version.version_number)
        .bind(Json(&version.rules))
        .bind(Json(&version.catalog_entries))
        .bind(created_by_user_id)
        .bind(description)
        .execute(&self.pool)
        .await?;

        Ok(version)
    }

    pub(crate) async fn activate_classification_rule_version(
        &self,
        project_id: &str,
        data_source_id: &str,
        rule_version_id: &str,
        actor_user_id: &str,
    ) -> Result<Option<ClassificationRuleVersion>, PersistenceError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            r#"
            UPDATE classification_rule_versions
            SET status = 'retired',
                retired_at = NOW(),
                governance_note = $4
            WHERE project_id = $1
              AND data_source_id = $2
              AND status = 'active'
              AND rule_version_id <> $3
            "#,
        )
        .bind(project_id)
        .bind(data_source_id)
        .bind(rule_version_id)
        .bind(format!("retired by activation from {actor_user_id}"))
        .execute(&mut *transaction)
        .await?;

        let result = sqlx::query(
            r#"
            UPDATE classification_rule_versions
            SET status = 'active',
                activated_at = NOW(),
                retired_at = NULL,
                governance_note = $4
            WHERE project_id = $1
              AND data_source_id = $2
              AND rule_version_id = $3
              AND status <> 'retired'
            "#,
        )
        .bind(project_id)
        .bind(data_source_id)
        .bind(rule_version_id)
        .bind(format!("activated by {actor_user_id}"))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }
        self.load_classification_rule_version_by_id(project_id, data_source_id, rule_version_id)
            .await
    }

    pub(crate) async fn retire_classification_rule_version(
        &self,
        project_id: &str,
        data_source_id: &str,
        rule_version_id: &str,
        actor_user_id: &str,
    ) -> Result<Option<ClassificationRuleVersion>, PersistenceError> {
        let result = sqlx::query(
            r#"
            UPDATE classification_rule_versions
            SET status = 'retired',
                retired_at = NOW(),
                governance_note = $4
            WHERE project_id = $1 AND data_source_id = $2 AND rule_version_id = $3
            "#,
        )
        .bind(project_id)
        .bind(data_source_id)
        .bind(rule_version_id)
        .bind(format!("retired by {actor_user_id}"))
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }
        self.load_classification_rule_version_by_id(project_id, data_source_id, rule_version_id)
            .await
    }

    async fn load_classification_rule_version_by_id(
        &self,
        project_id: &str,
        data_source_id: &str,
        rule_version_id: &str,
    ) -> Result<Option<ClassificationRuleVersion>, PersistenceError> {
        let row = sqlx::query(
            r#"
            SELECT
                rule_version_id,
                project_id,
                data_source_id,
                version_number,
                status,
                rules_json,
                catalog_json
            FROM classification_rule_versions
            WHERE project_id = $1 AND data_source_id = $2 AND rule_version_id = $3
            "#,
        )
        .bind(project_id)
        .bind(data_source_id)
        .bind(rule_version_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|row| parse_classification_rule_version(&row))
            .transpose()
    }

    pub(crate) async fn load_classification_policies(
        &self,
        project_id: &str,
        data_source_id: &str,
        fields: &[String],
    ) -> Result<Vec<FieldClassificationPolicy>, PersistenceError> {
        let rows = if fields.is_empty() {
            sqlx::query(
                r#"
                SELECT
                    field_name,
                    level,
                    status,
                    masking_strategy,
                    watermark_strength,
                    source,
                    rule_version_id,
                    detection_run_id,
                    sample_value,
                    pattern_hints_json,
                    data_category,
                    catalog_entry_id,
                    applicable_regulations_json,
                    retention_policy_json,
                    manual_confirmation_required
                FROM classification_field_policies
                WHERE project_id = $1 AND data_source_id = $2
                ORDER BY field_name
                "#,
            )
            .bind(project_id)
            .bind(data_source_id)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT
                    field_name,
                    level,
                    status,
                    masking_strategy,
                    watermark_strength,
                    source,
                    rule_version_id,
                    detection_run_id,
                    sample_value,
                    pattern_hints_json,
                    data_category,
                    catalog_entry_id,
                    applicable_regulations_json,
                    retention_policy_json,
                    manual_confirmation_required
                FROM classification_field_policies
                WHERE project_id = $1 AND data_source_id = $2 AND field_name = ANY($3)
                ORDER BY field_name
                "#,
            )
            .bind(project_id)
            .bind(data_source_id)
            .bind(fields)
            .fetch_all(&self.pool)
            .await?
        };

        rows.into_iter()
            .map(|row| parse_field_classification_policy(&row))
            .collect()
    }

    pub(crate) async fn save_classification_detection_run(
        &self,
        snapshot_id: &str,
        project_id: &str,
        data_source_id: &str,
        rule_version: &ClassificationRuleVersion,
        policies: &[FieldClassificationPolicy],
    ) -> Result<String, PersistenceError> {
        let detection_run_id = ulid::Ulid::new().to_string();

        sqlx::query(
            r#"
            INSERT INTO classification_detection_runs (
                detection_run_id,
                snapshot_id,
                project_id,
                data_source_id,
                rule_version_id,
                status,
                findings_json,
                catalog_json,
                created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            "#,
        )
        .bind(&detection_run_id)
        .bind(snapshot_id)
        .bind(project_id)
        .bind(data_source_id)
        .bind(&rule_version.rule_version_id)
        .bind("pending_confirmation")
        .bind(Json(policies))
        .bind(Json(&rule_version.catalog_entries))
        .execute(&self.pool)
        .await?;

        for policy in policies {
            sqlx::query(
                r#"
                INSERT INTO classification_field_policies (
                    policy_id,
                    project_id,
                    data_source_id,
                    field_name,
                    level,
                    status,
                    masking_strategy,
                    watermark_strength,
                    source,
                    rule_version_id,
                    detection_run_id,
                    sample_value,
                    pattern_hints_json,
                    data_category,
                    catalog_entry_id,
                    applicable_regulations_json,
                    retention_policy_json,
                    manual_confirmation_required,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                    $11, $12, $13, $14, $15, $16, $17, $18, NOW(), NOW()
                )
                ON CONFLICT (project_id, data_source_id, field_name) DO UPDATE SET
                    level = EXCLUDED.level,
                    status = EXCLUDED.status,
                    masking_strategy = EXCLUDED.masking_strategy,
                    watermark_strength = EXCLUDED.watermark_strength,
                    source = EXCLUDED.source,
                    rule_version_id = EXCLUDED.rule_version_id,
                    detection_run_id = EXCLUDED.detection_run_id,
                    sample_value = EXCLUDED.sample_value,
                    pattern_hints_json = EXCLUDED.pattern_hints_json,
                    data_category = EXCLUDED.data_category,
                    catalog_entry_id = EXCLUDED.catalog_entry_id,
                    applicable_regulations_json = EXCLUDED.applicable_regulations_json,
                    retention_policy_json = EXCLUDED.retention_policy_json,
                    manual_confirmation_required = EXCLUDED.manual_confirmation_required,
                    updated_at = NOW()
                "#,
            )
            .bind(format!(
                "cfp-{}-{}-{}",
                project_id, data_source_id, policy.field_name
            ))
            .bind(project_id)
            .bind(data_source_id)
            .bind(&policy.field_name)
            .bind(sensitivity_level_label(&policy.level))
            .bind(classification_status_label(&policy.status))
            .bind(masking_strategy_label(&policy.masking_strategy))
            .bind(watermark_strength_label(&policy.watermark_strength))
            .bind(policy_source_label(&policy.source))
            .bind(policy.rule_version_id.as_deref())
            .bind(Some(detection_run_id.as_str()))
            .bind(&policy.sample_value)
            .bind(Json(&policy.pattern_hints))
            .bind(data_category_label(&policy.data_category))
            .bind(policy.catalog_entry_id.as_deref())
            .bind(Json(&policy.applicable_regulations))
            .bind(Json(&policy.retention_policy))
            .bind(policy.manual_confirmation_required)
            .execute(&self.pool)
            .await?;
        }

        Ok(detection_run_id)
    }

    pub(crate) async fn confirm_classification_policies(
        &self,
        project_id: &str,
        data_source_id: &str,
        fields: &[String],
        confirmed_by_user_id: &str,
        rule_version: Option<&ClassificationRuleVersion>,
        reviewer_note: Option<&str>,
    ) -> Result<Vec<FieldClassificationPolicy>, PersistenceError> {
        if fields.is_empty() {
            return Ok(Vec::new());
        }

        let existing = self
            .load_classification_policies(project_id, data_source_id, fields)
            .await?;
        for policy in existing {
            let confirmed = rule_version
                .map(|version| confirm_field_policy_with_rule_version(&policy, version))
                .unwrap_or_else(|| {
                    let mut policy = policy;
                    policy.status = ClassificationStatus::Confirmed;
                    policy.source = ClassificationPolicySource::ManualConfirmation;
                    policy
                });

            sqlx::query(
                r#"
                UPDATE classification_field_policies
                SET
                    level = $4,
                    status = 'confirmed',
                    masking_strategy = $5,
                    watermark_strength = $6,
                    source = 'manual_confirmation',
                    rule_version_id = $7,
                    data_category = $8,
                    catalog_entry_id = $9,
                    applicable_regulations_json = $10,
                    retention_policy_json = $11,
                    manual_confirmation_required = $12,
                    confirmed_by_user_id = $13,
                    confirmed_at = NOW(),
                    reviewer_note = $14,
                    updated_at = NOW()
                WHERE project_id = $1 AND data_source_id = $2 AND field_name = $3
                "#,
            )
            .bind(project_id)
            .bind(data_source_id)
            .bind(&confirmed.field_name)
            .bind(sensitivity_level_label(&confirmed.level))
            .bind(masking_strategy_label(&confirmed.masking_strategy))
            .bind(watermark_strength_label(&confirmed.watermark_strength))
            .bind(confirmed.rule_version_id.as_deref())
            .bind(data_category_label(&confirmed.data_category))
            .bind(confirmed.catalog_entry_id.as_deref())
            .bind(Json(&confirmed.applicable_regulations))
            .bind(Json(&confirmed.retention_policy))
            .bind(confirmed.manual_confirmation_required)
            .bind(confirmed_by_user_id)
            .bind(reviewer_note)
            .execute(&self.pool)
            .await?;
        }

        sqlx::query(
            r#"
            UPDATE classification_detection_runs
            SET
                status = 'confirmed',
                confirmed_by_user_id = $4,
                confirmed_at = NOW()
            WHERE detection_run_id IN (
                SELECT DISTINCT detection_run_id
                FROM classification_field_policies
                WHERE project_id = $1
                  AND data_source_id = $2
                  AND field_name = ANY($3)
                  AND detection_run_id IS NOT NULL
            )
            "#,
        )
        .bind(project_id)
        .bind(data_source_id)
        .bind(fields)
        .bind(confirmed_by_user_id)
        .execute(&self.pool)
        .await?;

        self.load_classification_policies(project_id, data_source_id, fields)
            .await
    }

    pub(crate) async fn load_cache_index(
        &self,
    ) -> Result<HashMap<String, String>, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT cache_key, snapshot_id
            FROM snapshot_cache_entries
            ORDER BY created_at, cache_key
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut cache_index = HashMap::new();
        for row in rows {
            cache_index.insert(row.try_get("cache_key")?, row.try_get("snapshot_id")?);
        }
        Ok(cache_index)
    }

    pub(crate) async fn persist_audit_append(
        &self,
        event: &AuditEvent,
        checkpoint: &AuditCheckpoint,
        trail: &AuditTrail,
    ) -> Result<(), PersistenceError> {
        self.insert_audit_event(event).await?;
        self.insert_audit_checkpoint(checkpoint).await?;
        write_replica_file(&self.audit_replica_path, &trail.export_replica())?;
        Ok(())
    }

    pub(crate) fn persist_audit_replica(&self, trail: &AuditTrail) -> Result<(), PersistenceError> {
        write_replica_file(&self.audit_replica_path, &trail.export_replica())?;
        Ok(())
    }

    pub(crate) async fn save_audit_forward_delivery(
        &self,
        delivery: &StoredAuditForwardDelivery,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO audit_forward_deliveries (
                delivery_id,
                event_id,
                checkpoint_id,
                provider,
                destination,
                status,
                payload_bytes,
                error_message,
                delivered_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(&delivery.delivery_id)
        .bind(&delivery.event_id)
        .bind(&delivery.checkpoint_id)
        .bind(&delivery.provider)
        .bind(&delivery.destination)
        .bind(&delivery.status)
        .bind(delivery.payload_bytes as i32)
        .bind(&delivery.error_message)
        .bind(delivery.delivered_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn load_active_audit_boundary(
        &self,
    ) -> Result<Option<AuditCheckpoint>, PersistenceError> {
        let row = sqlx::query(
            r#"
            SELECT
                checkpoint_id,
                event_count,
                latest_event_hash,
                signature,
                signature_algorithm,
                signer_provider,
                signer_key_id,
                signer_key_version,
                created_at
            FROM audit_chain_boundaries
            WHERE active = TRUE
            ORDER BY created_at DESC, boundary_id DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| AuditCheckpoint {
            checkpoint_id: row.try_get("checkpoint_id").expect("checkpoint_id"),
            created_at: row.try_get("created_at").expect("created_at"),
            event_count: row
                .try_get::<i64, _>("event_count")
                .expect("event_count")
                .max(0) as usize,
            last_event_hash: row.try_get("latest_event_hash").expect("latest_event_hash"),
            signature: row.try_get("signature").expect("signature"),
            signature_algorithm: row
                .try_get("signature_algorithm")
                .expect("signature_algorithm"),
            signer_provider: row.try_get("signer_provider").expect("signer_provider"),
            signer_key_id: row.try_get("signer_key_id").expect("signer_key_id"),
            signer_key_version: row
                .try_get("signer_key_version")
                .expect("signer_key_version"),
        }))
    }

    pub(crate) async fn apply_audit_archive(
        &self,
        bundle: &AuditArchiveBundle,
    ) -> Result<PathBuf, PersistenceError> {
        let archive_path = self.archive_bundle_path(&bundle.bundle_id);
        sdqp_audit::write_archive_bundle_file(&archive_path, bundle)?;

        let first_event = bundle.events.first();
        let last_event = bundle.events.last();
        sqlx::query(
            r#"
            INSERT INTO audit_archive_bundles (
                bundle_id,
                archive_path,
                first_event_id,
                last_event_id,
                first_event_time,
                last_event_time,
                event_count,
                checkpoint_count,
                retain_until,
                boundary_checkpoint_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(&bundle.bundle_id)
        .bind(archive_path.to_string_lossy().to_string())
        .bind(first_event.map(|event| event.event_id.clone()))
        .bind(last_event.map(|event| event.event_id.clone()))
        .bind(first_event.map(|event| event.timestamp))
        .bind(last_event.map(|event| event.timestamp))
        .bind(bundle.events.len() as i32)
        .bind(bundle.checkpoints.len() as i32)
        .bind(bundle.retain_until)
        .bind(&bundle.boundary_checkpoint.checkpoint_id)
        .execute(&self.pool)
        .await?;

        sqlx::query("UPDATE audit_chain_boundaries SET active = FALSE WHERE active = TRUE")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            r#"
            INSERT INTO audit_chain_boundaries (
                boundary_id,
                archived_bundle_id,
                checkpoint_id,
                event_count,
                latest_event_hash,
                signature,
                signature_algorithm,
                signer_provider,
                signer_key_id,
                signer_key_version,
                created_at,
                active
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, TRUE)
            "#,
        )
        .bind(format!(
            "boundary-{}",
            bundle.boundary_checkpoint.checkpoint_id
        ))
        .bind(&bundle.bundle_id)
        .bind(&bundle.boundary_checkpoint.checkpoint_id)
        .bind(bundle.boundary_checkpoint.event_count as i64)
        .bind(&bundle.boundary_checkpoint.last_event_hash)
        .bind(&bundle.boundary_checkpoint.signature)
        .bind(&bundle.boundary_checkpoint.signature_algorithm)
        .bind(&bundle.boundary_checkpoint.signer_provider)
        .bind(&bundle.boundary_checkpoint.signer_key_id)
        .bind(&bundle.boundary_checkpoint.signer_key_version)
        .bind(bundle.boundary_checkpoint.created_at)
        .execute(&self.pool)
        .await?;

        self.delete_clickhouse_audit_events(
            &bundle
                .events
                .iter()
                .map(|event| event.event_hash.clone())
                .collect::<Vec<_>>(),
        )
        .await?;
        self.delete_clickhouse_audit_checkpoints(
            &bundle
                .checkpoints
                .iter()
                .map(|checkpoint| checkpoint.checkpoint_id.clone())
                .collect::<Vec<_>>(),
        )
        .await?;

        Ok(archive_path)
    }

    pub(crate) async fn cleanup_expired_audit_archives(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize, PersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT bundle_id, archive_path
            FROM audit_archive_bundles
            WHERE purged_at IS NULL AND retain_until <= $1
            "#,
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        let mut purged = 0_usize;
        for row in rows {
            let bundle_id: String = row.try_get("bundle_id")?;
            let archive_path: String = row.try_get("archive_path")?;
            let path = PathBuf::from(&archive_path);
            if path.exists() {
                let _ = std::fs::remove_file(&path);
            }
            sqlx::query("UPDATE audit_archive_bundles SET purged_at = NOW() WHERE bundle_id = $1")
                .bind(&bundle_id)
                .execute(&self.pool)
                .await?;
            purged += 1;
        }
        Ok(purged)
    }

    pub(crate) async fn save_audit_retention_run(
        &self,
        run: &StoredAuditRetentionRun,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO audit_retention_runs (
                run_id,
                archived_bundle_id,
                archived_events,
                archived_checkpoints,
                purged_bundles,
                archive_path,
                status,
                error_message,
                created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(&run.run_id)
        .bind(&run.archived_bundle_id)
        .bind(run.archived_events as i32)
        .bind(run.archived_checkpoints as i32)
        .bind(run.purged_bundles as i32)
        .bind(&run.archive_path)
        .bind(&run.status)
        .bind(&run.error_message)
        .bind(run.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn save_pending_session(
        &self,
        session_id: &str,
        pending: &PendingSession,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO sessions (
                session_id,
                session_kind,
                tenant_id,
                user_id,
                binding_json,
                pending_account_json,
                claims_json,
                refresh_token,
                previous_refresh_token_fingerprint,
                roles_json,
                auth_source,
                risk_score,
                device_posture_json,
                revoked,
                step_up_required,
                step_up_challenge_json,
                mfa_method,
                created_at,
                updated_at
            )
            VALUES ($1, 'pending', $2, $3, $4, $5, NULL, NULL, NULL, NULL, $6, 0, NULL, FALSE, FALSE, NULL, $7, NOW(), NOW())
            ON CONFLICT (session_id) DO UPDATE SET
                session_kind = EXCLUDED.session_kind,
                tenant_id = EXCLUDED.tenant_id,
                user_id = EXCLUDED.user_id,
                binding_json = EXCLUDED.binding_json,
                pending_account_json = EXCLUDED.pending_account_json,
                claims_json = NULL,
                refresh_token = NULL,
                previous_refresh_token_fingerprint = NULL,
                roles_json = NULL,
                auth_source = EXCLUDED.auth_source,
                risk_score = 0,
                device_posture_json = NULL,
                revoked = FALSE,
                step_up_required = FALSE,
                step_up_challenge_json = NULL,
                mfa_method = EXCLUDED.mfa_method,
                updated_at = NOW()
            "#,
        )
        .bind(session_id)
        .bind(&pending.account.tenant_id)
        .bind(&pending.account.user_id)
        .bind(Json(&pending.binding))
        .bind(Json(pending))
        .bind(auth_source_label(&pending.auth_source))
        .bind(mfa_method_label(&pending.account.mfa_method))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn remove_pending_session(
        &self,
        session_id: &str,
    ) -> Result<(), PersistenceError> {
        sqlx::query("DELETE FROM sessions WHERE session_id = $1 AND session_kind = 'pending'")
            .bind(session_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn save_active_session(
        &self,
        session: &ActiveSession,
    ) -> Result<(), PersistenceError> {
        let device_posture_json = session
            .device_posture
            .as_ref()
            .map(|value| Json(serde_json::to_value(value).expect("device posture json")));
        let step_up_challenge_json = session
            .step_up_challenge
            .as_ref()
            .map(|value| Json(serde_json::to_value(value).expect("step-up challenge json")));
        sqlx::query(
            r#"
            INSERT INTO sessions (
                session_id,
                session_kind,
                tenant_id,
                user_id,
                binding_json,
                pending_account_json,
                claims_json,
                refresh_token,
                previous_refresh_token_fingerprint,
                roles_json,
                auth_source,
                risk_score,
                device_posture_json,
                revoked,
                step_up_required,
                step_up_challenge_json,
                mfa_method,
                created_at,
                updated_at
            )
            VALUES ($1, 'active', $2, $3, $4, NULL, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW(), NOW())
            ON CONFLICT (session_id) DO UPDATE SET
                session_kind = EXCLUDED.session_kind,
                tenant_id = EXCLUDED.tenant_id,
                user_id = EXCLUDED.user_id,
                binding_json = EXCLUDED.binding_json,
                pending_account_json = NULL,
                claims_json = EXCLUDED.claims_json,
                refresh_token = EXCLUDED.refresh_token,
                previous_refresh_token_fingerprint = EXCLUDED.previous_refresh_token_fingerprint,
                roles_json = EXCLUDED.roles_json,
                auth_source = EXCLUDED.auth_source,
                risk_score = EXCLUDED.risk_score,
                device_posture_json = EXCLUDED.device_posture_json,
                revoked = EXCLUDED.revoked,
                step_up_required = EXCLUDED.step_up_required,
                step_up_challenge_json = EXCLUDED.step_up_challenge_json,
                mfa_method = EXCLUDED.mfa_method,
                updated_at = NOW()
            "#,
        )
        .bind(&session.claims.session_id)
        .bind(&session.claims.tenant_id)
        .bind(&session.claims.user_id)
        .bind(Json(&session.claims.binding))
        .bind(Json(&session.claims))
        .bind(&session.refresh_token)
        .bind(&session.previous_refresh_token_fingerprint)
        .bind(Json(&session.roles))
        .bind(auth_source_label(&session.auth_source))
        .bind(session.risk_score as i32)
        .bind(device_posture_json)
        .bind(session.revoked)
        .bind(session.step_up_required)
        .bind(step_up_challenge_json)
        .bind(mfa_method_label(&session.mfa_method))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn save_user_account(
        &self,
        user: &UserAccount,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO users (
                user_id,
                tenant_id,
                username,
                display_name,
                email,
                password_secret,
                mfa_method,
                external_id,
                active,
                auth_source,
                created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
            ON CONFLICT (user_id) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                username = EXCLUDED.username,
                display_name = EXCLUDED.display_name,
                email = EXCLUDED.email,
                password_secret = EXCLUDED.password_secret,
                mfa_method = EXCLUDED.mfa_method,
                external_id = EXCLUDED.external_id,
                active = EXCLUDED.active,
                auth_source = EXCLUDED.auth_source
            "#,
        )
        .bind(&user.user_id)
        .bind(&user.tenant_id)
        .bind(&user.username)
        .bind(&user.display_name)
        .bind(&user.email)
        .bind(&user.password)
        .bind(mfa_method_label(&user.mfa_method))
        .bind(&user.external_id)
        .bind(user.active)
        .bind(auth_source_label(&user.auth_source))
        .execute(&self.pool)
        .await?;

        sqlx::query("DELETE FROM roles WHERE user_id = $1")
            .bind(&user.user_id)
            .execute(&self.pool)
            .await?;

        for role in &user.roles {
            sqlx::query(
                r#"
                INSERT INTO roles (user_id, role_name)
                VALUES ($1, $2)
                ON CONFLICT (user_id, role_name) DO NOTHING
                "#,
            )
            .bind(&user.user_id)
            .bind(role_label(role))
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    pub(crate) async fn delete_user_account(
        &self,
        external_id: &str,
    ) -> Result<(), PersistenceError> {
        sqlx::query("DELETE FROM users WHERE external_id = $1")
            .bind(external_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn save_scim_group(&self, group: &ScimGroup) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO identity_groups (
                group_id,
                tenant_id,
                display_name,
                active,
                members_json,
                created_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
            ON CONFLICT (group_id) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                display_name = EXCLUDED.display_name,
                active = EXCLUDED.active,
                members_json = EXCLUDED.members_json,
                updated_at = NOW()
            "#,
        )
        .bind(&group.external_id)
        .bind(&group.tenant_id)
        .bind(&group.display_name)
        .bind(group.active)
        .bind(Json(&group.members))
        .execute(&self.pool)
        .await?;

        sqlx::query("DELETE FROM identity_group_members WHERE group_id = $1")
            .bind(&group.external_id)
            .execute(&self.pool)
            .await?;

        for member in &group.members {
            sqlx::query(
                r#"
                INSERT INTO identity_group_members (group_id, user_external_id, created_at)
                VALUES ($1, $2, NOW())
                ON CONFLICT (group_id, user_external_id) DO NOTHING
                "#,
            )
            .bind(&group.external_id)
            .bind(member)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub(crate) async fn delete_scim_group(
        &self,
        external_id: &str,
    ) -> Result<(), PersistenceError> {
        sqlx::query("DELETE FROM identity_groups WHERE group_id = $1")
            .bind(external_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn save_scim_sync_cursor(
        &self,
        cursor: &ScimSyncCursor,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO scim_sync_state (provider_id, cursor_json, updated_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (provider_id) DO UPDATE SET
                cursor_json = EXCLUDED.cursor_json,
                updated_at = NOW()
            "#,
        )
        .bind(&cursor.provider)
        .bind(Json(cursor))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn save_integration_api_key(
        &self,
        record: &ApiKeyRecord,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO integration_api_credentials (
                key_id,
                secret,
                scopes_json,
                allowed_ips_json,
                rotated_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, NOW(), NOW())
            ON CONFLICT (key_id) DO UPDATE SET
                secret = EXCLUDED.secret,
                scopes_json = EXCLUDED.scopes_json,
                allowed_ips_json = EXCLUDED.allowed_ips_json,
                rotated_at = EXCLUDED.rotated_at,
                updated_at = NOW()
            "#,
        )
        .bind(&record.key_id)
        .bind(&record.secret)
        .bind(Json(&record.scopes))
        .bind(Json(&record.allowed_ips))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn save_credential_rotation_state(
        &self,
        state: &CredentialRotationState,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO credential_rotation_state (
                credential_id,
                credential_kind,
                status,
                last_rotated_at,
                next_rotation_due_at,
                last_attempt_at,
                attempts,
                active_version,
                last_error,
                manual_intervention_reason,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (credential_id) DO UPDATE SET
                credential_kind = EXCLUDED.credential_kind,
                status = EXCLUDED.status,
                last_rotated_at = EXCLUDED.last_rotated_at,
                next_rotation_due_at = EXCLUDED.next_rotation_due_at,
                last_attempt_at = EXCLUDED.last_attempt_at,
                attempts = EXCLUDED.attempts,
                active_version = EXCLUDED.active_version,
                last_error = EXCLUDED.last_error,
                manual_intervention_reason = EXCLUDED.manual_intervention_reason,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(&state.credential_id)
        .bind(state.kind.as_str())
        .bind(state.status.as_str())
        .bind(state.last_rotated_at)
        .bind(state.next_rotation_due_at)
        .bind(state.last_attempt_at)
        .bind(state.attempts as i32)
        .bind(&state.active_version)
        .bind(&state.last_error)
        .bind(&state.manual_intervention_reason)
        .bind(state.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn save_key_rotation_state(
        &self,
        state: &KeyRotationState,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO key_rotation_state (
                inventory_id,
                snapshot_id,
                tenant_id,
                project_id,
                provider,
                kek_id,
                key_version,
                dek_id,
                created_at,
                last_rewrapped_at,
                next_dek_rotation_due_at,
                next_kek_rewrap_due_at,
                due_state,
                status,
                last_operation,
                last_cycle_id,
                last_error,
                updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9,
                $10, $11, $12, $13, $14, $15, $16, $17, $18
            )
            ON CONFLICT (inventory_id) DO UPDATE SET
                snapshot_id = EXCLUDED.snapshot_id,
                tenant_id = EXCLUDED.tenant_id,
                project_id = EXCLUDED.project_id,
                provider = EXCLUDED.provider,
                kek_id = EXCLUDED.kek_id,
                key_version = EXCLUDED.key_version,
                dek_id = EXCLUDED.dek_id,
                created_at = EXCLUDED.created_at,
                last_rewrapped_at = EXCLUDED.last_rewrapped_at,
                next_dek_rotation_due_at = EXCLUDED.next_dek_rotation_due_at,
                next_kek_rewrap_due_at = EXCLUDED.next_kek_rewrap_due_at,
                due_state = EXCLUDED.due_state,
                status = EXCLUDED.status,
                last_operation = EXCLUDED.last_operation,
                last_cycle_id = EXCLUDED.last_cycle_id,
                last_error = EXCLUDED.last_error,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(&state.inventory_id)
        .bind(&state.snapshot_id)
        .bind(&state.tenant_id)
        .bind(&state.project_id)
        .bind(&state.provider)
        .bind(&state.kek_id)
        .bind(&state.key_version)
        .bind(&state.dek_id)
        .bind(state.created_at)
        .bind(state.last_rewrapped_at)
        .bind(state.next_dek_rotation_due_at)
        .bind(state.next_kek_rewrap_due_at)
        .bind(state.due_state.as_str())
        .bind(state.status.as_str())
        .bind(state.last_operation.as_str())
        .bind(&state.last_cycle_id)
        .bind(&state.last_error)
        .bind(state.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn save_project_context(
        &self,
        project: &ProjectContext,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO projects (
                project_id,
                tenant_id,
                state,
                object_bucket,
                object_prefix,
                created_by_user_id,
                deletion_reason,
                deleted_at,
                created_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7,
                CASE WHEN $3 = 'deleted' THEN NOW() ELSE NULL END,
                NOW()
            )
            ON CONFLICT (project_id) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                state = EXCLUDED.state,
                object_bucket = EXCLUDED.object_bucket,
                object_prefix = EXCLUDED.object_prefix,
                created_by_user_id = COALESCE(projects.created_by_user_id, EXCLUDED.created_by_user_id),
                deletion_reason = EXCLUDED.deletion_reason,
                deleted_at = CASE
                    WHEN EXCLUDED.state = 'deleted' THEN COALESCE(projects.deleted_at, NOW())
                    ELSE NULL
                END
            "#,
        )
        .bind(project.project_id.as_str())
        .bind(project.tenant_id.as_str())
        .bind(project_state_label(project.state))
        .bind(&project.object_namespace.object_bucket)
        .bind(&project.object_namespace.key_prefix)
        .bind(&project.created_by_user_id)
        .bind(&project.deletion_reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn save_analysis_template(
        &self,
        template: &AnalysisTemplateRecord,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO analysis_templates (
                template_id,
                tenant_id,
                project_id,
                owner_user_id,
                data_source_id,
                name,
                description,
                visibility,
                config_json,
                published_at,
                created_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (template_id) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                project_id = EXCLUDED.project_id,
                owner_user_id = EXCLUDED.owner_user_id,
                data_source_id = EXCLUDED.data_source_id,
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                visibility = EXCLUDED.visibility,
                config_json = EXCLUDED.config_json,
                published_at = EXCLUDED.published_at,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(&template.template_id)
        .bind(&template.tenant_id)
        .bind(&template.project_id)
        .bind(&template.owner_user_id)
        .bind(&template.data_source_id)
        .bind(&template.name)
        .bind(&template.description)
        .bind(template.visibility.label())
        .bind(Json(&template.config))
        .bind(template.published_at)
        .bind(template.created_at)
        .bind(template.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn delete_analysis_template(
        &self,
        template_id: &str,
    ) -> Result<(), PersistenceError> {
        sqlx::query("DELETE FROM analysis_templates WHERE template_id = $1")
            .bind(template_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn save_controlled_deletion_record(
        &self,
        record: &ControlledDeletionRecord,
    ) -> Result<(), PersistenceError> {
        if !sdqp_audit::verify_controlled_deletion_record(record) {
            return Err(PersistenceError::AuditArtifact(
                "controlled deletion tombstone failed self verification".into(),
            ));
        }

        sqlx::query(
            r#"
            INSERT INTO audit_controlled_deletions (
                deletion_id,
                tombstone_id,
                tenant_id,
                project_id,
                resource_kind,
                resource_id,
                state,
                tombstone_hash,
                evidence_hash,
                requested_by_user_id,
                reason,
                retain_until,
                pre_delete_event_hash,
                post_delete_event_hash,
                audit_checkpoint_id,
                tombstone_json,
                created_at,
                updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16, $17, NOW()
            )
            ON CONFLICT (deletion_id) DO UPDATE SET
                state = EXCLUDED.state,
                tombstone_hash = EXCLUDED.tombstone_hash,
                evidence_hash = EXCLUDED.evidence_hash,
                retain_until = EXCLUDED.retain_until,
                post_delete_event_hash = EXCLUDED.post_delete_event_hash,
                audit_checkpoint_id = EXCLUDED.audit_checkpoint_id,
                tombstone_json = EXCLUDED.tombstone_json,
                updated_at = NOW()
            "#,
        )
        .bind(&record.deletion_id)
        .bind(&record.tombstone.tombstone_id)
        .bind(&record.tombstone.subject.tenant_id)
        .bind(record.tombstone.subject.project_id.as_deref())
        .bind(record.tombstone.subject.kind.as_str())
        .bind(&record.tombstone.subject.resource_id)
        .bind(record.state.as_str())
        .bind(&record.tombstone.tombstone_hash)
        .bind(record.evidence_hash.as_deref())
        .bind(&record.tombstone.requested_by_user_id)
        .bind(&record.tombstone.reason)
        .bind(record.tombstone.retain_until)
        .bind(
            record
                .tombstone
                .pre_delete_chain
                .latest_event_hash
                .as_deref(),
        )
        .bind(record.audit_event_hash.as_deref())
        .bind(record.audit_checkpoint_id.as_deref())
        .bind(Json(record))
        .bind(record.requested_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn load_controlled_deletion_record(
        &self,
        kind: ControlledDeletionSubjectKind,
        resource_id: &str,
    ) -> Result<Option<ControlledDeletionRecord>, PersistenceError> {
        let row = sqlx::query(
            r#"
            SELECT tombstone_json
            FROM audit_controlled_deletions
            WHERE resource_kind = $1 AND resource_id = $2
            ORDER BY updated_at DESC, created_at DESC, deletion_id DESC
            LIMIT 1
            "#,
        )
        .bind(kind.as_str())
        .bind(resource_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|row| {
            let record = row
                .try_get::<Json<ControlledDeletionRecord>, _>("tombstone_json")?
                .0;
            if sdqp_audit::verify_controlled_deletion_record(&record) {
                Ok(record)
            } else {
                Err(PersistenceError::AuditArtifact(
                    "controlled deletion tombstone failed self verification".into(),
                ))
            }
        })
        .transpose()
    }

    pub(crate) async fn delete_snapshots_for_project(
        &self,
        project_id: &str,
    ) -> Result<u64, PersistenceError> {
        Ok(sqlx::query(
            r#"
            UPDATE snapshots
            SET
                delete_state = 'purged',
                delete_reason = COALESCE(delete_reason, 'project lifecycle controlled deletion'),
                deleted_at = COALESCE(deleted_at, NOW()),
                purged_at = COALESCE(purged_at, NOW()),
                encrypted_payload_json = jsonb_set(
                    encrypted_payload_json,
                    '{ciphertext_b64}',
                    '""'::jsonb,
                    true
                )
            WHERE project_id = $1
            "#,
        )
        .bind(project_id)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    pub(crate) async fn save_config_version(
        &self,
        version: &ConfigVersion,
        value: &str,
        checkpoint_id: &str,
        approval_binding: &str,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO config_versions (
                version_id,
                config_key,
                config_payload_json,
                approved_by_user_id,
                created_at
            )
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(&version.version_id)
        .bind(&version.config_key)
        .bind(Json(json!({
            "value": value,
            "payload_hash": version.payload_hash,
            "checkpoint_id": checkpoint_id,
            "approval_binding": approval_binding,
        })))
        .bind(&version.approved_by_user_id)
        .bind(version.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn save_task(
        &self,
        task: &StoredQueryTask,
        snapshot: &QueryTaskSnapshot,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO query_tasks (
                task_id,
                tenant_id,
                project_id,
                user_id,
                project_scope_key,
                grant_id,
                grant_valid_until,
                data_source_id,
                source_type,
                query_payload_json,
                cache_key,
                priority,
                attempt_count,
                max_attempts,
                state,
                snapshot_id,
                cache_hit,
                error,
                created_at,
                updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16, $17, $18, NOW(), NOW()
            )
            ON CONFLICT (task_id) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                project_id = EXCLUDED.project_id,
                user_id = EXCLUDED.user_id,
                project_scope_key = EXCLUDED.project_scope_key,
                grant_id = EXCLUDED.grant_id,
                grant_valid_until = EXCLUDED.grant_valid_until,
                data_source_id = EXCLUDED.data_source_id,
                source_type = EXCLUDED.source_type,
                query_payload_json = EXCLUDED.query_payload_json,
                cache_key = EXCLUDED.cache_key,
                priority = EXCLUDED.priority,
                attempt_count = EXCLUDED.attempt_count,
                max_attempts = EXCLUDED.max_attempts,
                state = EXCLUDED.state,
                snapshot_id = EXCLUDED.snapshot_id,
                cache_hit = EXCLUDED.cache_hit,
                error = EXCLUDED.error,
                updated_at = NOW()
            "#,
        )
        .bind(&task.task_id)
        .bind(&task.tenant_id)
        .bind(&task.project_id)
        .bind(&task.user_id)
        .bind(&task.project_scope_key)
        .bind(&task.grant_id)
        .bind(task.grant_valid_until)
        .bind(&task.data_source_id)
        .bind(source_type_label(&task.source_type))
        .bind(Json(&task.query))
        .bind(&task.cache_key)
        .bind(task.priority)
        .bind(task.attempt_count as i32)
        .bind(task.max_attempts as i32)
        .bind(query_task_state_label(&snapshot.state))
        .bind(&snapshot.snapshot_id)
        .bind(snapshot.cache_hit)
        .bind(&snapshot.error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn save_task_state(
        &self,
        scope: &TaskScope,
        snapshot: &QueryTaskSnapshot,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            UPDATE query_tasks
            SET
                tenant_id = $2,
                project_id = $3,
                user_id = $4,
                project_scope_key = $5,
                state = $6,
                snapshot_id = $7,
                cache_hit = $8,
                error = $9,
                updated_at = NOW()
            WHERE task_id = $1
            "#,
        )
        .bind(&snapshot.task_id)
        .bind(&scope.tenant_id)
        .bind(&scope.project_id)
        .bind(&scope.user_id)
        .bind(&scope.project_scope_key)
        .bind(query_task_state_label(&snapshot.state))
        .bind(&snapshot.snapshot_id)
        .bind(snapshot.cache_hit)
        .bind(&snapshot.error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn save_snapshot(
        &self,
        record: &EncryptedSnapshotRecord,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO snapshots (
                snapshot_id,
                tenant_id,
                project_id,
                data_source_id,
                storage_key,
                created_at,
                row_count,
                dek_id,
                encrypted_payload_json,
                payload_format,
                columns_json,
                owner_user_id,
                grant_id,
                grant_expires_at,
                retention_until,
                data_fingerprint,
                object_bucket,
                object_size_bytes,
                delete_state,
                delete_reason,
                deleted_at,
                purged_at,
                last_rewrapped_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23
            )
            ON CONFLICT (snapshot_id) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                project_id = EXCLUDED.project_id,
                data_source_id = EXCLUDED.data_source_id,
                storage_key = EXCLUDED.storage_key,
                row_count = EXCLUDED.row_count,
                dek_id = EXCLUDED.dek_id,
                encrypted_payload_json = EXCLUDED.encrypted_payload_json,
                payload_format = EXCLUDED.payload_format,
                columns_json = EXCLUDED.columns_json,
                owner_user_id = EXCLUDED.owner_user_id,
                grant_id = EXCLUDED.grant_id,
                grant_expires_at = EXCLUDED.grant_expires_at,
                retention_until = EXCLUDED.retention_until,
                data_fingerprint = EXCLUDED.data_fingerprint,
                object_bucket = EXCLUDED.object_bucket,
                object_size_bytes = EXCLUDED.object_size_bytes,
                delete_state = EXCLUDED.delete_state,
                delete_reason = EXCLUDED.delete_reason,
                deleted_at = EXCLUDED.deleted_at,
                purged_at = EXCLUDED.purged_at,
                last_rewrapped_at = EXCLUDED.last_rewrapped_at
            "#,
        )
        .bind(&record.snapshot_id)
        .bind(&record.tenant_id)
        .bind(&record.project_id)
        .bind(&record.data_source_id)
        .bind(&record.storage_key)
        .bind(record.created_at)
        .bind(record.row_count as i64)
        .bind(&record.encrypted_payload.dek_id)
        .bind(Json(&record.encrypted_payload))
        .bind(record.payload_format.as_str())
        .bind(Json(&record.columns))
        .bind(&record.lifecycle.owner_user_id)
        .bind(&record.lifecycle.grant_id)
        .bind(record.lifecycle.grant_expires_at)
        .bind(record.lifecycle.retention_until)
        .bind(&record.lifecycle.data_fingerprint)
        .bind(&record.lifecycle.object_bucket)
        .bind(record.lifecycle.object_size_bytes as i64)
        .bind(snapshot_delete_state_label(&record.lifecycle.delete_state))
        .bind(&record.lifecycle.delete_reason)
        .bind(record.lifecycle.deleted_at)
        .bind(record.lifecycle.purged_at)
        .bind(record.lifecycle.last_rewrapped_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn save_evidence_package(
        &self,
        package: &EvidencePackage,
        tenant_id: &str,
        project_id: &str,
        created_by_user_id: &str,
        task_id: &str,
        file_name: &str,
        media_type: &str,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO evidence_packages (
                package_id,
                tenant_id,
                project_id,
                snapshot_id,
                template,
                manifest_digest,
                watermark_token,
                manifest_json,
                package_json,
                file_name,
                media_type,
                created_by_user_id,
                task_id,
                verification_status,
                anchor_status,
                provider_runtime_mode,
                external_final_uat_required,
                certificate_serial_number,
                created_at,
                updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16, $17, $18, NOW(), NOW()
            )
            ON CONFLICT (package_id) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                project_id = EXCLUDED.project_id,
                snapshot_id = EXCLUDED.snapshot_id,
                template = EXCLUDED.template,
                manifest_digest = EXCLUDED.manifest_digest,
                watermark_token = EXCLUDED.watermark_token,
                manifest_json = EXCLUDED.manifest_json,
                package_json = EXCLUDED.package_json,
                file_name = EXCLUDED.file_name,
                media_type = EXCLUDED.media_type,
                created_by_user_id = EXCLUDED.created_by_user_id,
                task_id = EXCLUDED.task_id,
                verification_status = EXCLUDED.verification_status,
                anchor_status = EXCLUDED.anchor_status,
                provider_runtime_mode = EXCLUDED.provider_runtime_mode,
                external_final_uat_required = EXCLUDED.external_final_uat_required,
                certificate_serial_number = EXCLUDED.certificate_serial_number,
                updated_at = NOW()
            "#,
        )
        .bind(&package.package_id)
        .bind(tenant_id)
        .bind(project_id)
        .bind(&package.snapshot_id)
        .bind(&package.template)
        .bind(&package.manifest_digest)
        .bind(&package.watermark_token)
        .bind(Json(&package.manifest))
        .bind(Json(package))
        .bind(file_name)
        .bind(media_type)
        .bind(created_by_user_id)
        .bind(task_id)
        .bind(package.manifest.verification_status.as_str())
        .bind(package.anchor_receipt.status.as_str())
        .bind(&package.provider_runtime.overall_mode)
        .bind(package.provider_runtime.external_final_uat_required)
        .bind(&package.certificate_of_authenticity.serial_number)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn save_export_task(
        &self,
        task: &ExportTaskRecord,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO export_tasks (
                task_id,
                tenant_id,
                project_id,
                snapshot_id,
                requested_by_user_id,
                package_id,
                status,
                payload_json,
                verification_status,
                integrity_verified,
                anchor_status,
                anchor_provider,
                timestamp_provider,
                provider_runtime_mode,
                external_final_uat_required,
                refresh_recommended,
                failure_reason,
                last_anchor_refresh_at,
                created_at,
                completed_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
            )
            ON CONFLICT (task_id) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                project_id = EXCLUDED.project_id,
                snapshot_id = EXCLUDED.snapshot_id,
                requested_by_user_id = EXCLUDED.requested_by_user_id,
                package_id = EXCLUDED.package_id,
                status = EXCLUDED.status,
                payload_json = EXCLUDED.payload_json,
                verification_status = EXCLUDED.verification_status,
                integrity_verified = EXCLUDED.integrity_verified,
                anchor_status = EXCLUDED.anchor_status,
                anchor_provider = EXCLUDED.anchor_provider,
                timestamp_provider = EXCLUDED.timestamp_provider,
                provider_runtime_mode = EXCLUDED.provider_runtime_mode,
                external_final_uat_required = EXCLUDED.external_final_uat_required,
                refresh_recommended = EXCLUDED.refresh_recommended,
                failure_reason = EXCLUDED.failure_reason,
                last_anchor_refresh_at = EXCLUDED.last_anchor_refresh_at,
                completed_at = EXCLUDED.completed_at
            "#,
        )
        .bind(&task.task_id)
        .bind(&task.tenant_id)
        .bind(&task.project_id)
        .bind(&task.snapshot_id)
        .bind(&task.user_id)
        .bind(&task.package_id)
        .bind(&task.status)
        .bind(Json(task))
        .bind(&task.verification_status)
        .bind(task.integrity_verified)
        .bind(&task.anchor_status)
        .bind(&task.anchor_provider)
        .bind(&task.timestamp_provider)
        .bind(&task.provider_runtime_mode)
        .bind(task.external_final_uat_required)
        .bind(task.refresh_recommended)
        .bind(&task.failure_reason)
        .bind(task.last_anchor_refresh_at)
        .bind(task.created_at)
        .bind(task.completed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn save_download_authorization(
        &self,
        auth: &DownloadAuthorizationRecord,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO download_authorizations (
                download_token,
                task_id,
                tenant_id,
                project_id,
                issued_to_user_id,
                expires_at,
                consumed_at,
                payload_json,
                created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            ON CONFLICT (download_token) DO UPDATE SET
                task_id = EXCLUDED.task_id,
                tenant_id = EXCLUDED.tenant_id,
                project_id = EXCLUDED.project_id,
                issued_to_user_id = EXCLUDED.issued_to_user_id,
                expires_at = EXCLUDED.expires_at,
                consumed_at = EXCLUDED.consumed_at,
                payload_json = EXCLUDED.payload_json
            "#,
        )
        .bind(&auth.download_token)
        .bind(&auth.task_id)
        .bind(&auth.tenant_id)
        .bind(&auth.project_id)
        .bind(&auth.user_id)
        .bind(auth.expires_at)
        .bind(auth.consumed_at)
        .bind(Json(auth))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn consume_download_authorization(
        &self,
        auth: &DownloadAuthorizationRecord,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            UPDATE download_authorizations
            SET consumed_at = $2, payload_json = $3
            WHERE download_token = $1
            "#,
        )
        .bind(&auth.download_token)
        .bind(auth.consumed_at)
        .bind(Json(auth))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn save_cache_entry(
        &self,
        cache_key: &str,
        snapshot_id: &str,
    ) -> Result<(), PersistenceError> {
        sqlx::query(
            r#"
            INSERT INTO snapshot_cache_entries (cache_key, snapshot_id, created_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (cache_key) DO UPDATE SET
                snapshot_id = EXCLUDED.snapshot_id
            "#,
        )
        .bind(cache_key)
        .bind(snapshot_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn delete_cache_entries_for_snapshot(
        &self,
        snapshot_id: &str,
    ) -> Result<u64, PersistenceError> {
        Ok(
            sqlx::query("DELETE FROM snapshot_cache_entries WHERE snapshot_id = $1")
                .bind(snapshot_id)
                .execute(&self.pool)
                .await?
                .rows_affected(),
        )
    }

    async fn ensure_clickhouse_schema(&self) -> Result<(), PersistenceError> {
        for script in [
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../db/clickhouse/init/001_stage3_core.sql"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../db/clickhouse/init/002_stage5_audit_schema.sql"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../db/clickhouse/init/003_wave1_structured_audit_context.sql"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../db/clickhouse/init/004_stage11_audit_runtime.sql"
            )),
        ] {
            for statement in script
                .split(';')
                .map(str::trim)
                .filter(|statement| !statement.is_empty())
            {
                self.execute_clickhouse_query(statement.to_string(), None)
                    .await?;
            }
        }
        Ok(())
    }

    async fn ensure_ueba_governance_schema(&self) -> Result<(), PersistenceError> {
        for statement in [
            r#"
            CREATE TABLE IF NOT EXISTS ueba_governance_rules (
                rule_version_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                version_number INTEGER NOT NULL,
                status TEXT NOT NULL,
                enabled BOOLEAN NOT NULL,
                rule_json JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            "#,
            r#"
            CREATE INDEX IF NOT EXISTS idx_ueba_governance_rules_tenant
            ON ueba_governance_rules (tenant_id, rule_name, version_number)
            "#,
            r#"
            CREATE TABLE IF NOT EXISTS ueba_replay_runs (
                run_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                run_json JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            "#,
            r#"
            CREATE INDEX IF NOT EXISTS idx_ueba_replay_runs_tenant
            ON ueba_replay_runs (tenant_id, created_at DESC)
            "#,
            r#"
            CREATE TABLE IF NOT EXISTS ueba_tuning_proposals (
                proposal_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                status TEXT NOT NULL,
                proposal_json JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            "#,
            r#"
            CREATE INDEX IF NOT EXISTS idx_ueba_tuning_proposals_tenant
            ON ueba_tuning_proposals (tenant_id, status, created_at DESC)
            "#,
            r#"
            CREATE TABLE IF NOT EXISTS ueba_calibration_runs (
                calibration_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                status TEXT NOT NULL,
                run_json JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            "#,
            r#"
            CREATE INDEX IF NOT EXISTS idx_ueba_calibration_runs_tenant
            ON ueba_calibration_runs (tenant_id, created_at DESC)
            "#,
        ] {
            sqlx::query(statement).execute(&self.pool).await?;
        }
        Ok(())
    }

    async fn seed_catalog(&self, settings: &AppSettings) -> Result<(), PersistenceError> {
        let users = build_user_directory(&AppSettings::local_dev().security);
        let projects = build_project_registry();

        sqlx::query(
            r#"
            INSERT INTO tenants (tenant_id, display_name, created_at)
            VALUES ('tenant-alpha', 'Tenant Alpha', NOW())
            ON CONFLICT (tenant_id) DO NOTHING
            "#,
        )
        .execute(&self.pool)
        .await?;

        for project in projects.values() {
            sqlx::query(
                r#"
                INSERT INTO projects (
                    project_id,
                    tenant_id,
                    state,
                    object_bucket,
                    object_prefix,
                    created_at
                )
                VALUES ($1, $2, $3, $4, $5, NOW())
                ON CONFLICT (project_id) DO NOTHING
                "#,
            )
            .bind(project.project_id.as_str())
            .bind(project.tenant_id.as_str())
            .bind(project_state_label(project.state))
            .bind(&project.object_namespace.object_bucket)
            .bind(&project.object_namespace.key_prefix)
            .execute(&self.pool)
            .await?;
        }

        for user in users.values() {
            sqlx::query(
                r#"
                INSERT INTO users (
                    user_id,
                    tenant_id,
                    username,
                    display_name,
                    email,
                    password_secret,
                    mfa_method,
                    external_id,
                    active,
                    auth_source,
                    created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
                ON CONFLICT (user_id) DO UPDATE SET
                    tenant_id = EXCLUDED.tenant_id,
                    username = EXCLUDED.username,
                    display_name = EXCLUDED.display_name,
                    email = EXCLUDED.email,
                    password_secret = EXCLUDED.password_secret,
                    mfa_method = EXCLUDED.mfa_method,
                    external_id = EXCLUDED.external_id,
                    active = EXCLUDED.active,
                    auth_source = EXCLUDED.auth_source
                "#,
            )
            .bind(&user.user_id)
            .bind(&user.tenant_id)
            .bind(&user.username)
            .bind(&user.display_name)
            .bind(&user.email)
            .bind(&user.password)
            .bind(mfa_method_label(&user.mfa_method))
            .bind(&user.external_id)
            .bind(user.active)
            .bind(auth_source_label(&user.auth_source))
            .execute(&self.pool)
            .await?;

            for role in &user.roles {
                sqlx::query(
                    r#"
                    INSERT INTO roles (user_id, role_name)
                    VALUES ($1, $2)
                    ON CONFLICT (user_id, role_name) DO NOTHING
                    "#,
                )
                .bind(&user.user_id)
                .bind(role_label(role))
                .execute(&self.pool)
                .await?;
            }

            sqlx::query(
                r#"
                INSERT INTO project_memberships (project_id, user_id, membership_role, created_at)
                VALUES ('project-alpha', $1, 'member', NOW())
                ON CONFLICT (project_id, user_id, membership_role) DO NOTHING
                "#,
            )
            .bind(&user.user_id)
            .execute(&self.pool)
            .await?;
        }

        for data_source in [
            (
                "datasource-rest",
                "project-alpha",
                "rest",
                "REST Employee Directory",
                "mock://rest".to_string(),
                json!({}),
            ),
            (
                "datasource-rpc",
                "project-alpha",
                "rpc",
                "RPC Employee Directory",
                "mock://rpc".to_string(),
                json!({}),
            ),
            persistent_hive_seed_data_source(),
        ] {
            sqlx::query(
                r#"
                INSERT INTO data_sources (
                    data_source_id,
                    project_id,
                    source_type,
                    display_name,
                    connection_uri,
                    adapter_config_json,
                    capabilities_json,
                    created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
                ON CONFLICT (data_source_id) DO UPDATE SET
                    project_id = EXCLUDED.project_id,
                    source_type = EXCLUDED.source_type,
                    display_name = EXCLUDED.display_name,
                    connection_uri = EXCLUDED.connection_uri,
                    adapter_config_json = EXCLUDED.adapter_config_json,
                    capabilities_json = EXCLUDED.capabilities_json
                "#,
            )
            .bind(data_source.0)
            .bind(data_source.1)
            .bind(data_source.2)
            .bind(data_source.3)
            .bind(data_source.4)
            .bind(Json(data_source.5.clone()))
            .bind(Json(json!({
                "execution_mode": "snapshot",
                "supports_filters": true,
                "supports_pagination": true
            })))
            .execute(&self.pool)
            .await?;
        }

        for field in [
            ("datasource-rest", "employee_id", "restricted"),
            ("datasource-rest", "department", "internal"),
            ("datasource-rpc", "employee_id", "restricted"),
            ("datasource-hive", "employee_id", "restricted"),
            ("datasource-hive", "department", "internal"),
        ] {
            sqlx::query(
                r#"
                INSERT INTO field_classifications (data_source_id, field_name, classification)
                VALUES ($1, $2, $3)
                ON CONFLICT (data_source_id, field_name) DO UPDATE SET
                    classification = EXCLUDED.classification
                "#,
            )
            .bind(field.0)
            .bind(field.1)
            .bind(field.2)
            .execute(&self.pool)
            .await?;
        }

        for data_source_id in ["datasource-rest", "datasource-rpc", "datasource-hive"] {
            let mut rule_version = default_rule_version("project-alpha", data_source_id);
            apply_retention_overrides(
                &mut rule_version,
                settings.classification.default_retention_days,
                settings.classification.restricted_retention_days,
            );
            sqlx::query(
                r#"
                INSERT INTO classification_rule_versions (
                    rule_version_id,
                    project_id,
                    data_source_id,
                    version_number,
                    status,
                    rules_json,
                    catalog_json,
                    created_by_user_id,
                    description,
                    activated_at,
                    created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
                ON CONFLICT (rule_version_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    rules_json = EXCLUDED.rules_json,
                    catalog_json = EXCLUDED.catalog_json
                "#,
            )
            .bind(&rule_version.rule_version_id)
            .bind("project-alpha")
            .bind(data_source_id)
            .bind(rule_version.version_number)
            .bind(rule_version_status_label(&rule_version.status))
            .bind(Json(&rule_version.rules))
            .bind(Json(&rule_version.catalog_entries))
            .bind("user-manager-a")
            .bind(
                "bootstrap seed catalog; governed runtime must use persisted active rule versions"
                    .to_string(),
            )
            .execute(&self.pool)
            .await?;
        }

        for policy in [
            (
                "datasource-rest",
                "employee_id",
                SensitivityLevel::L5Restricted,
                MaskingStrategy::Full,
                WatermarkStrength::Critical,
            ),
            (
                "datasource-rest",
                "department",
                SensitivityLevel::L2Internal,
                MaskingStrategy::None,
                WatermarkStrength::Low,
            ),
            (
                "datasource-rpc",
                "employee_id",
                SensitivityLevel::L5Restricted,
                MaskingStrategy::Full,
                WatermarkStrength::Critical,
            ),
            (
                "datasource-hive",
                "employee_id",
                SensitivityLevel::L5Restricted,
                MaskingStrategy::Full,
                WatermarkStrength::Critical,
            ),
            (
                "datasource-hive",
                "department",
                SensitivityLevel::L2Internal,
                MaskingStrategy::None,
                WatermarkStrength::Low,
            ),
        ] {
            let mut rule_version = default_rule_version("project-alpha", policy.0);
            apply_retention_overrides(
                &mut rule_version,
                settings.classification.default_retention_days,
                settings.classification.restricted_retention_days,
            );
            let catalog_entry = rule_version
                .catalog_entries
                .iter()
                .find(|entry| entry.level == policy.2)
                .or_else(|| rule_version.catalog_entries.first());
            let data_category = catalog_entry
                .map(|entry| data_category_label(&entry.data_category))
                .unwrap_or("general_confidential");
            let catalog_entry_id = catalog_entry.map(|entry| entry.catalog_entry_id.as_str());
            let applicable_regulations = catalog_entry
                .map(|entry| entry.applicable_regulations.clone())
                .unwrap_or_default();
            let retention_policy = catalog_entry
                .map(|entry| entry.retention_policy.clone())
                .unwrap_or_else(|| RetentionPolicy {
                    policy_id: "retention-general-confidential".into(),
                    retain_for_days: settings.classification.default_retention_days,
                    disposal_action: RetentionDisposalAction::Review,
                    legal_hold_supported: true,
                });
            let manual_confirmation_required = catalog_entry
                .map(|entry| entry.manual_confirmation_required)
                .unwrap_or(true);
            sqlx::query(
                r#"
                INSERT INTO classification_field_policies (
                    policy_id,
                    project_id,
                    data_source_id,
                    field_name,
                    level,
                    status,
                    masking_strategy,
                    watermark_strength,
                    source,
                    rule_version_id,
                    confirmed_by_user_id,
                    confirmed_at,
                    pattern_hints_json,
                    data_category,
                    catalog_entry_id,
                    applicable_regulations_json,
                    retention_policy_json,
                    manual_confirmation_required,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1, 'project-alpha', $2, $3, $4, 'confirmed', $5, $6, 'rule_engine',
                    $7, 'user-manager-a', NOW(), '[]'::jsonb, $8, $9, $10, $11, $12, NOW(), NOW()
                )
                ON CONFLICT (project_id, data_source_id, field_name) DO UPDATE SET
                    level = EXCLUDED.level,
                    status = EXCLUDED.status,
                    masking_strategy = EXCLUDED.masking_strategy,
                    watermark_strength = EXCLUDED.watermark_strength,
                    source = EXCLUDED.source,
                    rule_version_id = EXCLUDED.rule_version_id,
                    confirmed_by_user_id = EXCLUDED.confirmed_by_user_id,
                    confirmed_at = EXCLUDED.confirmed_at,
                    data_category = EXCLUDED.data_category,
                    catalog_entry_id = EXCLUDED.catalog_entry_id,
                    applicable_regulations_json = EXCLUDED.applicable_regulations_json,
                    retention_policy_json = EXCLUDED.retention_policy_json,
                    manual_confirmation_required = EXCLUDED.manual_confirmation_required,
                    updated_at = NOW()
                "#,
            )
            .bind(format!("cfp-project-alpha-{}-{}", policy.0, policy.1))
            .bind(policy.0)
            .bind(policy.1)
            .bind(sensitivity_level_label(&policy.2))
            .bind(masking_strategy_label(&policy.3))
            .bind(watermark_strength_label(&policy.4))
            .bind(&rule_version.rule_version_id)
            .bind(data_category)
            .bind(catalog_entry_id)
            .bind(Json(&applicable_regulations))
            .bind(Json(&retention_policy))
            .bind(manual_confirmation_required)
            .execute(&self.pool)
            .await?;
        }

        sqlx::query(
            r#"
            INSERT INTO approval_flows (flow_id, project_id, definition_json, created_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (flow_id) DO UPDATE SET
                project_id = EXCLUDED.project_id,
                definition_json = EXCLUDED.definition_json
            "#,
        )
        .bind("flow-project-alpha-default")
        .bind("project-alpha")
        .bind(Json(json!({
            "flow_id": "flow-project-alpha-default",
            "version": 1,
            "steps": [
                {
                    "step_id": "manager-review",
                    "mode": "Serial",
                    "approvers": [
                        { "kind": "Manager" }
                    ],
                    "timeout_minutes": 1,
                    "escalation": { "kind": "User", "value": "user-security-a" }
                }
            ]
        })))
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO permission_eligibility_rules (
                rule_id,
                project_id,
                allowed_department_ids_json,
                allowed_user_ids_json,
                allowed_role_names_json,
                require_active_hr_record,
                created_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, TRUE, NOW(), NOW())
            ON CONFLICT (rule_id) DO UPDATE SET
                project_id = EXCLUDED.project_id,
                allowed_department_ids_json = EXCLUDED.allowed_department_ids_json,
                allowed_user_ids_json = EXCLUDED.allowed_user_ids_json,
                allowed_role_names_json = EXCLUDED.allowed_role_names_json,
                require_active_hr_record = EXCLUDED.require_active_hr_record,
                updated_at = NOW()
            "#,
        )
        .bind("eligibility-project-alpha-default")
        .bind("project-alpha")
        .bind(Json(vec!["dept-risk".to_string()]))
        .bind(Json(vec!["user-analyst".to_string()]))
        .bind(Json(vec!["analyst".to_string()]))
        .execute(&self.pool)
        .await?;

        for directory_user in [
            (
                "user-manager-a",
                "feishu",
                "dept-risk",
                Option::<&str>::None,
                "active",
            ),
            (
                "user-analyst",
                "feishu",
                "dept-risk",
                Some("user-manager-a"),
                "active",
            ),
            (
                "user-security-a",
                "ldap",
                "dept-security",
                Option::<&str>::None,
                "active",
            ),
            (
                "user-security-b",
                "csv",
                "dept-security",
                Some("user-security-a"),
                "active",
            ),
        ] {
            sqlx::query(
                r#"
                INSERT INTO hr_directory_users (
                    user_id,
                    source,
                    department_id,
                    manager_id,
                    status,
                    synced_at
                )
                VALUES ($1, $2, $3, $4, $5, NOW())
                ON CONFLICT (user_id) DO UPDATE SET
                    source = EXCLUDED.source,
                    department_id = EXCLUDED.department_id,
                    manager_id = EXCLUDED.manager_id,
                    status = EXCLUDED.status,
                    synced_at = NOW()
                "#,
            )
            .bind(directory_user.0)
            .bind(directory_user.1)
            .bind(directory_user.2)
            .bind(directory_user.3)
            .bind(directory_user.4)
            .execute(&self.pool)
            .await?;
        }

        for grant in [
            (
                "grant-rest-analyst",
                "user-analyst",
                "project-alpha",
                "datasource-rest",
                json!([
                    { "field_name": "employee_id", "denied": false },
                    { "field_name": "department", "denied": false }
                ]),
                json!([
                    { "field": "department", "operator": "Eq", "value": "fraud" }
                ]),
                json!({
                    "department_id": "dept-risk",
                    "manager_id": "user-manager-a"
                }),
            ),
            (
                "grant-rpc-analyst",
                "user-analyst",
                "project-alpha",
                "datasource-rpc",
                json!([
                    { "field_name": "employee_id", "denied": false }
                ]),
                json!([]),
                json!({
                    "department_id": "dept-risk",
                    "manager_id": "user-manager-a"
                }),
            ),
            (
                "grant-hive-analyst",
                "user-analyst",
                "project-alpha",
                "datasource-hive",
                json!([
                    { "field_name": "employee_id", "denied": false },
                    { "field_name": "department", "denied": false }
                ]),
                json!([]),
                json!({
                    "department_id": "dept-risk",
                    "manager_id": "user-manager-a"
                }),
            ),
        ] {
            sqlx::query(
                r#"
                INSERT INTO permission_grants (
                    grant_id,
                    applicant_user_id,
                    project_id,
                    data_source_id,
                    status,
                    fields_json,
                    conditions_json,
                    valid_from,
                    valid_until,
                    org_binding_json,
                    created_at,
                    updated_at
                )
                VALUES ($1, $2, $3, $4, 'active', $5, $6, NOW(), NOW() + INTERVAL '8 hours', $7, NOW(), NOW())
                ON CONFLICT (grant_id) DO UPDATE SET
                    applicant_user_id = EXCLUDED.applicant_user_id,
                    project_id = EXCLUDED.project_id,
                    data_source_id = EXCLUDED.data_source_id,
                    status = EXCLUDED.status,
                    fields_json = EXCLUDED.fields_json,
                    conditions_json = EXCLUDED.conditions_json,
                    valid_from = EXCLUDED.valid_from,
                    valid_until = EXCLUDED.valid_until,
                    org_binding_json = EXCLUDED.org_binding_json,
                    updated_at = NOW()
                "#,
            )
            .bind(grant.0)
            .bind(grant.1)
            .bind(grant.2)
            .bind(grant.3)
            .bind(Json(grant.4.clone()))
            .bind(Json(grant.5.clone()))
            .bind(Json(grant.6.clone()))
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    async fn recover_inflight_query_tasks(&self) -> Result<PgQueryResult, PersistenceError> {
        Ok(sqlx::query(
            r#"
            UPDATE query_tasks
            SET
                state = 'failed',
                error = COALESCE(error, 'recovered after api restart'),
                updated_at = NOW()
            WHERE state IN ('pending', 'running')
            "#,
        )
        .execute(&self.pool)
        .await?)
    }

    async fn load_audit_events(&self) -> Result<Vec<AuditEvent>, PersistenceError> {
        let body = self
            .execute_clickhouse_query(
                concat!(
                    "SELECT event_id, event_hash, prev_hash, tenant_id, project_id, resource_id, ",
                    "actor_user_id, session_id, ip_address, action_type, action_result, context, ",
                    "context_fields_json, ",
                    "data_fingerprint, event_time ",
                    "FROM sdqp.audit_events ORDER BY event_time, event_hash FORMAT JSONEachRow"
                )
                .to_string(),
                None,
            )
            .await?;

        let mut events = Vec::new();
        for row in serde_json::Deserializer::from_str(&body).into_iter::<AuditEventRowOwned>() {
            let row = row.map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?;
            let action = ActionType::parse_label(&row.action_type)
                .ok_or_else(|| PersistenceError::AuditArtifact(row.action_type.clone()))?;
            let result = ActionResult::parse_label(&row.action_result)
                .ok_or_else(|| PersistenceError::AuditArtifact(row.action_result.clone()))?;
            events.push(AuditEvent {
                event_id: row.event_id,
                timestamp: row.event_time,
                actor: ActorInfo {
                    user_id: row.actor_user_id,
                    session_id: row.session_id,
                    ip_address: row.ip_address,
                },
                action,
                target: TargetRef {
                    tenant_id: row.tenant_id,
                    project_id: row.project_id,
                    resource_id: row.resource_id,
                },
                context: row.context,
                context_fields: deserialize_audit_context_fields(row.context_fields_json)?,
                result,
                data_fingerprint: row.data_fingerprint,
                prev_hash: row.prev_hash,
                event_hash: row.event_hash,
            });
        }

        Ok(events)
    }

    async fn load_audit_checkpoints(&self) -> Result<Vec<AuditCheckpoint>, PersistenceError> {
        let body = self
            .execute_clickhouse_query(
                concat!(
                    "SELECT checkpoint_id, event_count, latest_event_hash, signature, ",
                    "signature_algorithm, signer_provider, signer_key_id, signer_key_version, checkpoint_time ",
                    "FROM sdqp.audit_checkpoints ORDER BY checkpoint_time, checkpoint_id FORMAT JSONEachRow"
                )
                .to_string(),
                None,
            )
            .await?;

        let mut checkpoints = Vec::new();
        for row in serde_json::Deserializer::from_str(&body).into_iter::<AuditCheckpointRowOwned>()
        {
            let row = row.map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?;
            checkpoints.push(AuditCheckpoint {
                checkpoint_id: row.checkpoint_id,
                created_at: row.checkpoint_time,
                event_count: row.event_count as usize,
                last_event_hash: row.latest_event_hash,
                signature: row.signature,
                signature_algorithm: row.signature_algorithm,
                signer_provider: row.signer_provider,
                signer_key_id: row.signer_key_id,
                signer_key_version: row.signer_key_version,
            });
        }

        Ok(checkpoints)
    }

    async fn insert_audit_event(&self, event: &AuditEvent) -> Result<(), PersistenceError> {
        let context_fields_json = serialize_audit_context_fields(&event.context_fields)?;
        let row = AuditEventRow {
            event_id: &event.event_id,
            event_hash: &event.event_hash,
            prev_hash: &event.prev_hash,
            tenant_id: &event.target.tenant_id,
            project_id: event.target.project_id.as_deref(),
            resource_id: &event.target.resource_id,
            actor_user_id: &event.actor.user_id,
            session_id: &event.actor.session_id,
            ip_address: &event.actor.ip_address,
            action_type: event.action.as_str(),
            action_result: event.result.as_str(),
            context: &event.context,
            context_fields_json: context_fields_json.as_deref(),
            data_fingerprint: event.data_fingerprint.as_deref(),
            event_time: clickhouse_datetime(event.timestamp),
        };
        let body = serde_json::to_string(&row)
            .map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?;
        self.execute_clickhouse_query(
            "INSERT INTO sdqp.audit_events FORMAT JSONEachRow".to_string(),
            Some(body),
        )
        .await?;
        Ok(())
    }

    async fn insert_audit_checkpoint(
        &self,
        checkpoint: &AuditCheckpoint,
    ) -> Result<(), PersistenceError> {
        let row = AuditCheckpointRow {
            checkpoint_id: &checkpoint.checkpoint_id,
            event_count: checkpoint.event_count as u64,
            latest_event_hash: &checkpoint.last_event_hash,
            signature: &checkpoint.signature,
            signature_algorithm: &checkpoint.signature_algorithm,
            signer_provider: &checkpoint.signer_provider,
            signer_key_id: &checkpoint.signer_key_id,
            signer_key_version: checkpoint.signer_key_version.as_deref(),
            checkpoint_time: clickhouse_datetime(checkpoint.created_at),
        };
        let body = serde_json::to_string(&row)
            .map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?;
        self.execute_clickhouse_query(
            "INSERT INTO sdqp.audit_checkpoints FORMAT JSONEachRow".to_string(),
            Some(body),
        )
        .await?;
        Ok(())
    }

    async fn execute_clickhouse_query(
        &self,
        query: String,
        body: Option<String>,
    ) -> Result<String, PersistenceError> {
        let base_url = self.clickhouse_http_url.trim_end_matches('/');
        let request = match body {
            Some(body) => self
                .clickhouse_client
                .post(format!("{base_url}/"))
                .query(&[("wait_end_of_query", "1"), ("query", query.as_str())])
                .body(body),
            None => self
                .clickhouse_client
                .post(format!("{base_url}/"))
                .query(&[("wait_end_of_query", "1"), ("query", query.as_str())])
                .header(reqwest::header::CONTENT_LENGTH, "0")
                .body(String::new()),
        };

        Ok(request.send().await?.error_for_status()?.text().await?)
    }

    fn archive_bundle_path(&self, bundle_id: &str) -> PathBuf {
        self.audit_archive_dir.join(format!("{bundle_id}.json"))
    }

    async fn delete_clickhouse_audit_events(
        &self,
        event_hashes: &[String],
    ) -> Result<(), PersistenceError> {
        if event_hashes.is_empty() {
            return Ok(());
        }

        self.execute_clickhouse_query(
            format!(
                "ALTER TABLE sdqp.audit_events DELETE WHERE event_hash IN ({})",
                quoted_clickhouse_literals(event_hashes)
            ),
            None,
        )
        .await?;
        Ok(())
    }

    async fn delete_clickhouse_audit_checkpoints(
        &self,
        checkpoint_ids: &[String],
    ) -> Result<(), PersistenceError> {
        if checkpoint_ids.is_empty() {
            return Ok(());
        }

        self.execute_clickhouse_query(
            format!(
                "ALTER TABLE sdqp.audit_checkpoints DELETE WHERE checkpoint_id IN ({})",
                quoted_clickhouse_literals(checkpoint_ids)
            ),
            None,
        )
        .await?;
        Ok(())
    }
}

fn persistent_hive_seed_data_source() -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    String,
    Value,
) {
    let connection_uri =
        std::env::var("SDQP_HIVE_CONNECTION_URI").unwrap_or_else(|_| "mock://hive".into());
    if connection_uri.starts_with("mock://") {
        return (
            "datasource-hive",
            "project-alpha",
            "hive",
            "Hive Employee Warehouse",
            connection_uri,
            json!({
                "table": "stage6_employee_rows",
                "delay_ms": 150
            }),
        );
    }

    let mut adapter_config = json!({
        "provider": std::env::var("SDQP_HIVE_PROVIDER").unwrap_or_else(|_| "beeline".into()),
        "command": std::env::var("SDQP_HIVE_COMMAND").unwrap_or_else(|_| "beeline".into()),
        "username": std::env::var("SDQP_HIVE_USERNAME").unwrap_or_else(|_| "hive".into()),
        "table": std::env::var("SDQP_HIVE_TABLE").unwrap_or_else(|_| "sdqp_fixture_employees".into()),
        "max_concurrent_tasks": env_u64("SDQP_HIVE_MAX_CONCURRENT_TASKS", 2),
        "poll_interval_ms": env_u64("SDQP_HIVE_POLL_INTERVAL_MS", 100)
    });
    if let Ok(password) = std::env::var("SDQP_HIVE_PASSWORD")
        && !password.trim().is_empty()
    {
        adapter_config["password"] = Value::String(password);
    }
    if let Ok(args_json) = std::env::var("SDQP_HIVE_COMMAND_ARGS_JSON")
        && let Ok(args) = serde_json::from_str::<Value>(&args_json)
    {
        adapter_config["command_args"] = args;
    }

    (
        "datasource-hive",
        "project-alpha",
        "hive",
        "Hive Employee Warehouse",
        connection_uri,
        adapter_config,
    )
}

fn env_u64(key: &str, default_value: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default_value)
}

fn role_label(role: &Role) -> &'static str {
    match role {
        Role::SystemAdmin => "system_admin",
        Role::ProjectAdmin => "project_admin",
        Role::DataOwner => "data_owner",
        Role::Analyst => "analyst",
        Role::Auditor => "auditor",
        Role::Approver => "approver",
    }
}

fn parse_role(label: &str) -> Result<Role, PersistenceError> {
    match label {
        "system_admin" => Ok(Role::SystemAdmin),
        "project_admin" => Ok(Role::ProjectAdmin),
        "data_owner" => Ok(Role::DataOwner),
        "analyst" => Ok(Role::Analyst),
        "auditor" => Ok(Role::Auditor),
        "approver" => Ok(Role::Approver),
        other => Err(PersistenceError::UnknownRole(other.to_string())),
    }
}

fn mfa_method_label(method: &MfaMethod) -> &'static str {
    match method {
        MfaMethod::Totp => "totp",
        MfaMethod::WebAuthn => "webauthn",
        MfaMethod::Biometric => "biometric",
    }
}

fn parse_mfa_method(label: &str) -> Result<MfaMethod, PersistenceError> {
    match label {
        "totp" => Ok(MfaMethod::Totp),
        "webauthn" => Ok(MfaMethod::WebAuthn),
        "biometric" => Ok(MfaMethod::Biometric),
        other => Err(PersistenceError::UnknownMfaMethod(other.to_string())),
    }
}

fn auth_source_label(source: &TrustedAuthenticationSource) -> &'static str {
    match source {
        TrustedAuthenticationSource::LocalPassword => "local_password",
        TrustedAuthenticationSource::Oidc => "oidc",
        TrustedAuthenticationSource::Saml => "saml",
        TrustedAuthenticationSource::Scim => "scim",
    }
}

fn parse_auth_source(label: &str) -> Result<TrustedAuthenticationSource, PersistenceError> {
    match label {
        "local_password" => Ok(TrustedAuthenticationSource::LocalPassword),
        "oidc" => Ok(TrustedAuthenticationSource::Oidc),
        "saml" => Ok(TrustedAuthenticationSource::Saml),
        "scim" => Ok(TrustedAuthenticationSource::Scim),
        other => Err(PersistenceError::UnknownAuthSource(other.to_string())),
    }
}

fn parse_credential_kind(label: &str) -> Result<CredentialKind, PersistenceError> {
    match label {
        "integration_api_key" => Ok(CredentialKind::IntegrationApiKey),
        "scim_bearer_token" => Ok(CredentialKind::ScimBearerToken),
        "oidc_client_secret" => Ok(CredentialKind::OidcClientSecret),
        "saml_certificate" => Ok(CredentialKind::SamlCertificate),
        "mtls_certificate_metadata" => Ok(CredentialKind::MtlsCertificateMetadata),
        other => Err(PersistenceError::AuditArtifact(format!(
            "unknown credential kind label: {other}"
        ))),
    }
}

fn parse_credential_rotation_status(
    label: &str,
) -> Result<CredentialRotationStatus, PersistenceError> {
    match label {
        "active" => Ok(CredentialRotationStatus::Active),
        "due" => Ok(CredentialRotationStatus::Due),
        "rotating" => Ok(CredentialRotationStatus::Rotating),
        "rotated" => Ok(CredentialRotationStatus::Rotated),
        "failed_retryable" => Ok(CredentialRotationStatus::FailedRetryable),
        "manual_intervention_required" => Ok(CredentialRotationStatus::ManualInterventionRequired),
        "externally_managed" => Ok(CredentialRotationStatus::ExternallyManaged),
        "disabled" => Ok(CredentialRotationStatus::Disabled),
        other => Err(PersistenceError::AuditArtifact(format!(
            "unknown credential rotation status label: {other}"
        ))),
    }
}

fn parse_key_rotation_due_state(label: &str) -> Result<KeyRotationDueState, PersistenceError> {
    KeyRotationDueState::parse(label).ok_or_else(|| {
        PersistenceError::AuditArtifact(format!("unknown key rotation due state label: {label}"))
    })
}

fn parse_key_rotation_runtime_status(
    label: &str,
) -> Result<KeyRotationRuntimeStatus, PersistenceError> {
    KeyRotationRuntimeStatus::parse(label).ok_or_else(|| {
        PersistenceError::AuditArtifact(format!(
            "unknown key rotation runtime status label: {label}"
        ))
    })
}

fn parse_key_rotation_operation(label: &str) -> Result<KeyRotationOperation, PersistenceError> {
    KeyRotationOperation::parse(label).ok_or_else(|| {
        PersistenceError::AuditArtifact(format!("unknown key rotation operation label: {label}"))
    })
}

fn project_state_label(state: ProjectState) -> &'static str {
    match state {
        ProjectState::Created => "created",
        ProjectState::Active => "active",
        ProjectState::Frozen => "frozen",
        ProjectState::Archived => "archived",
        ProjectState::Deleted => "deleted",
    }
}

fn parse_project_state(label: &str) -> Result<ProjectState, PersistenceError> {
    match label {
        "created" => Ok(ProjectState::Created),
        "active" => Ok(ProjectState::Active),
        "frozen" => Ok(ProjectState::Frozen),
        "archived" => Ok(ProjectState::Archived),
        "deleted" => Ok(ProjectState::Deleted),
        other => Err(PersistenceError::UnknownProjectState(other.to_string())),
    }
}

fn source_type_label(source_type: &SourceType) -> &'static str {
    match source_type {
        SourceType::Rest => "rest",
        SourceType::Rpc => "rpc",
        SourceType::Hive => "hive",
        SourceType::Rdbms => "rdbms",
    }
}

fn query_task_state_label(state: &QueryTaskState) -> &'static str {
    match state {
        QueryTaskState::Pending => "pending",
        QueryTaskState::Running => "running",
        QueryTaskState::Completed => "completed",
        QueryTaskState::Failed => "failed",
        QueryTaskState::Cancelled => "cancelled",
    }
}

fn parse_query_task_state(label: &str) -> Result<QueryTaskState, PersistenceError> {
    match label {
        "pending" => Ok(QueryTaskState::Pending),
        "running" => Ok(QueryTaskState::Running),
        "completed" => Ok(QueryTaskState::Completed),
        "failed" => Ok(QueryTaskState::Failed),
        "cancelled" => Ok(QueryTaskState::Cancelled),
        other => Err(PersistenceError::UnknownQueryTaskState(other.to_string())),
    }
}

fn snapshot_delete_state_label(state: &SnapshotDeleteState) -> &'static str {
    state.as_str()
}

fn parse_snapshot_delete_state(label: &str) -> Result<SnapshotDeleteState, PersistenceError> {
    SnapshotDeleteState::parse_label(label)
        .ok_or_else(|| PersistenceError::UnknownSnapshotDeleteState(label.to_string()))
}

fn parse_snapshot_payload_format(label: &str) -> Result<SnapshotPayloadFormat, PersistenceError> {
    SnapshotPayloadFormat::parse_label(label)
        .ok_or_else(|| PersistenceError::UnknownSnapshotPayloadFormat(label.to_string()))
}

fn parse_analysis_template_visibility(
    label: &str,
) -> Result<AnalysisTemplateVisibility, PersistenceError> {
    AnalysisTemplateVisibility::parse_label(label)
        .ok_or_else(|| PersistenceError::UnknownAnalysisTemplateVisibility(label.to_string()))
}

fn classification_status_label(status: &ClassificationStatus) -> &'static str {
    match status {
        ClassificationStatus::PendingConfirmation => "pending_confirmation",
        ClassificationStatus::Confirmed => "confirmed",
    }
}

fn parse_classification_status(label: &str) -> Result<ClassificationStatus, PersistenceError> {
    match label {
        "pending_confirmation" => Ok(ClassificationStatus::PendingConfirmation),
        "confirmed" => Ok(ClassificationStatus::Confirmed),
        other => Err(PersistenceError::Governance(format!(
            "unknown classification status label: {other}"
        ))),
    }
}

fn sensitivity_level_label(level: &SensitivityLevel) -> &'static str {
    match level {
        SensitivityLevel::L1Public => "l1_public",
        SensitivityLevel::L2Internal => "l2_internal",
        SensitivityLevel::L3Confidential => "l3_confidential",
        SensitivityLevel::L4Sensitive => "l4_sensitive",
        SensitivityLevel::L5Restricted => "l5_restricted",
    }
}

fn data_category_label(category: &DataCategory) -> &'static str {
    match category {
        DataCategory::PublicReference => "public_reference",
        DataCategory::InternalOperational => "internal_operational",
        DataCategory::PersonalContact => "personal_contact",
        DataCategory::PersonalIdentifier => "personal_identifier",
        DataCategory::FinancialIdentifier => "financial_identifier",
        DataCategory::InvestigationSensitive => "investigation_sensitive",
        DataCategory::GeneralConfidential => "general_confidential",
    }
}

fn parse_data_category(label: &str) -> Result<DataCategory, PersistenceError> {
    match label {
        "public_reference" => Ok(DataCategory::PublicReference),
        "internal_operational" => Ok(DataCategory::InternalOperational),
        "personal_contact" => Ok(DataCategory::PersonalContact),
        "personal_identifier" => Ok(DataCategory::PersonalIdentifier),
        "financial_identifier" => Ok(DataCategory::FinancialIdentifier),
        "investigation_sensitive" => Ok(DataCategory::InvestigationSensitive),
        "general_confidential" => Ok(DataCategory::GeneralConfidential),
        other => Err(PersistenceError::Governance(format!(
            "unknown data category label: {other}"
        ))),
    }
}

fn parse_sensitivity_level(label: &str) -> Result<SensitivityLevel, PersistenceError> {
    match label {
        "l1_public" => Ok(SensitivityLevel::L1Public),
        "l2_internal" => Ok(SensitivityLevel::L2Internal),
        "l3_confidential" => Ok(SensitivityLevel::L3Confidential),
        "l4_sensitive" => Ok(SensitivityLevel::L4Sensitive),
        "l5_restricted" => Ok(SensitivityLevel::L5Restricted),
        other => Err(PersistenceError::Governance(format!(
            "unknown sensitivity level label: {other}"
        ))),
    }
}

fn masking_strategy_label(strategy: &MaskingStrategy) -> &'static str {
    match strategy {
        MaskingStrategy::None => "none",
        MaskingStrategy::PartialEmail => "partial_email",
        MaskingStrategy::PartialPhone => "partial_phone",
        MaskingStrategy::Full => "full",
    }
}

fn parse_masking_strategy(label: &str) -> Result<MaskingStrategy, PersistenceError> {
    match label {
        "none" => Ok(MaskingStrategy::None),
        "partial_email" => Ok(MaskingStrategy::PartialEmail),
        "partial_phone" => Ok(MaskingStrategy::PartialPhone),
        "full" => Ok(MaskingStrategy::Full),
        other => Err(PersistenceError::Governance(format!(
            "unknown masking strategy label: {other}"
        ))),
    }
}

fn watermark_strength_label(strength: &WatermarkStrength) -> &'static str {
    match strength {
        WatermarkStrength::Low => "low",
        WatermarkStrength::Medium => "medium",
        WatermarkStrength::High => "high",
        WatermarkStrength::Critical => "critical",
    }
}

fn parse_watermark_strength(label: &str) -> Result<WatermarkStrength, PersistenceError> {
    match label {
        "low" => Ok(WatermarkStrength::Low),
        "medium" => Ok(WatermarkStrength::Medium),
        "high" => Ok(WatermarkStrength::High),
        "critical" => Ok(WatermarkStrength::Critical),
        other => Err(PersistenceError::Governance(format!(
            "unknown watermark strength label: {other}"
        ))),
    }
}

fn policy_source_label(source: &ClassificationPolicySource) -> &'static str {
    match source {
        ClassificationPolicySource::RuleEngine => "rule_engine",
        ClassificationPolicySource::SampleDetection => "sample_detection",
        ClassificationPolicySource::ManualConfirmation => "manual_confirmation",
    }
}

fn parse_policy_source(label: &str) -> Result<ClassificationPolicySource, PersistenceError> {
    match label {
        "rule_engine" => Ok(ClassificationPolicySource::RuleEngine),
        "sample_detection" => Ok(ClassificationPolicySource::SampleDetection),
        "manual_confirmation" => Ok(ClassificationPolicySource::ManualConfirmation),
        other => Err(PersistenceError::Governance(format!(
            "unknown classification policy source label: {other}"
        ))),
    }
}

fn rule_version_status_label(status: &RuleVersionStatus) -> &'static str {
    match status {
        RuleVersionStatus::Draft => "draft",
        RuleVersionStatus::Active => "active",
        RuleVersionStatus::Retired => "retired",
    }
}

fn parse_rule_version_status(label: &str) -> Result<RuleVersionStatus, PersistenceError> {
    match label {
        "draft" => Ok(RuleVersionStatus::Draft),
        "active" => Ok(RuleVersionStatus::Active),
        "retired" => Ok(RuleVersionStatus::Retired),
        other => Err(PersistenceError::Governance(format!(
            "unknown classification rule version status label: {other}"
        ))),
    }
}

fn parse_classification_rule_version(
    row: &PgRow,
) -> Result<ClassificationRuleVersion, PersistenceError> {
    let rules = row
        .try_get::<Json<Vec<ClassificationRule>>, _>("rules_json")?
        .0;
    let catalog_entries = row
        .try_get::<Json<Vec<ClassificationCatalogEntry>>, _>("catalog_json")?
        .0;
    let version = ClassificationRuleVersion {
        rule_version_id: row.try_get("rule_version_id")?,
        project_id: row.try_get("project_id")?,
        data_source_id: row.try_get("data_source_id")?,
        version_number: row.try_get("version_number")?,
        status: parse_rule_version_status(&row.try_get::<String, _>("status")?)?,
        catalog_entries: if catalog_entries.is_empty() {
            derive_catalog_entries(&rules)
        } else {
            catalog_entries
        },
        rules,
    };
    Ok(version)
}

fn parse_field_classification_policy(
    row: &PgRow,
) -> Result<FieldClassificationPolicy, PersistenceError> {
    Ok(FieldClassificationPolicy {
        field_name: row.try_get("field_name")?,
        level: parse_sensitivity_level(&row.try_get::<String, _>("level")?)?,
        data_category: parse_data_category(&row.try_get::<String, _>("data_category")?)?,
        status: parse_classification_status(&row.try_get::<String, _>("status")?)?,
        masking_strategy: parse_masking_strategy(&row.try_get::<String, _>("masking_strategy")?)?,
        watermark_strength: parse_watermark_strength(
            &row.try_get::<String, _>("watermark_strength")?,
        )?,
        source: parse_policy_source(&row.try_get::<String, _>("source")?)?,
        pattern_hints: row
            .try_get::<Json<Vec<sdqp_data_classification::SensitivePattern>>, _>(
                "pattern_hints_json",
            )?
            .0,
        sample_value: row.try_get("sample_value")?,
        rule_version_id: row.try_get("rule_version_id")?,
        detection_run_id: row.try_get("detection_run_id")?,
        catalog_entry_id: row.try_get("catalog_entry_id")?,
        applicable_regulations: row
            .try_get::<Json<Vec<sdqp_data_classification::RegulationReference>>, _>(
                "applicable_regulations_json",
            )?
            .0,
        retention_policy: row
            .try_get::<Json<RetentionPolicy>, _>("retention_policy_json")?
            .0,
        manual_confirmation_required: row.try_get("manual_confirmation_required")?,
    })
}

fn parse_snapshot_record(row: &PgRow) -> Result<EncryptedSnapshotRecord, PersistenceError> {
    Ok(EncryptedSnapshotRecord {
        snapshot_id: row.try_get("snapshot_id")?,
        tenant_id: row.try_get("tenant_id")?,
        project_id: row.try_get("project_id")?,
        storage_key: row.try_get("storage_key")?,
        created_at: row.try_get("created_at")?,
        data_source_id: row.try_get("data_source_id")?,
        encrypted_payload: row
            .try_get::<Json<EncryptedPayload>, _>("encrypted_payload_json")?
            .0,
        row_count: row.try_get::<i64, _>("row_count")? as usize,
        payload_format: parse_snapshot_payload_format(
            &row.try_get::<String, _>("payload_format")?,
        )?,
        columns: row.try_get::<Json<Vec<String>>, _>("columns_json")?.0,
        lifecycle: SnapshotLifecycle {
            owner_user_id: row.try_get("owner_user_id")?,
            grant_id: row.try_get("grant_id")?,
            grant_expires_at: row.try_get("grant_expires_at")?,
            retention_until: row.try_get("retention_until")?,
            data_fingerprint: row.try_get("data_fingerprint")?,
            object_bucket: row.try_get("object_bucket")?,
            object_size_bytes: row.try_get::<i64, _>("object_size_bytes")? as usize,
            delete_state: parse_snapshot_delete_state(&row.try_get::<String, _>("delete_state")?)?,
            delete_reason: row.try_get("delete_reason")?,
            deleted_at: row.try_get("deleted_at")?,
            purged_at: row.try_get("purged_at")?,
            last_rewrapped_at: row.try_get("last_rewrapped_at")?,
        },
    })
}

fn encode_ueba_reason(alert: &UebaAlert) -> String {
    format!(
        "{}|{}|{}",
        ueba_rule_label(&alert.rule),
        alert.risk_score,
        alert.evidence
    )
}

fn decode_ueba_reason(reason: &str) -> Result<(UebaRule, u8, String), PersistenceError> {
    let mut parts = reason.splitn(3, '|');
    let rule = parts.next().unwrap_or_default();
    let risk_score = parts
        .next()
        .unwrap_or_default()
        .parse::<u8>()
        .map_err(|error| PersistenceError::AuditArtifact(error.to_string()))?;
    let evidence = parts.next().unwrap_or_default().to_string();
    Ok((parse_ueba_rule(rule)?, risk_score, evidence))
}

fn ueba_alert_signature(user_id: &str, reason: &str) -> String {
    format!("{user_id}|{reason}")
}

fn ueba_rule_label(rule: &UebaRule) -> &'static str {
    match rule {
        UebaRule::HighFrequencyQuery => "HighFrequencyQuery",
        UebaRule::ExportSpike => "ExportSpike",
        UebaRule::UnauthorizedQueryBurst => "UnauthorizedQueryBurst",
        UebaRule::AfterHoursAccess => "AfterHoursAccess",
        UebaRule::HiddenChannelDns => "HiddenChannelDns",
        UebaRule::HiddenChannelHttp => "HiddenChannelHttp",
    }
}

fn parse_ueba_rule(label: &str) -> Result<UebaRule, PersistenceError> {
    match label {
        "HighFrequencyQuery" => Ok(UebaRule::HighFrequencyQuery),
        "ExportSpike" => Ok(UebaRule::ExportSpike),
        "UnauthorizedQueryBurst" => Ok(UebaRule::UnauthorizedQueryBurst),
        "AfterHoursAccess" => Ok(UebaRule::AfterHoursAccess),
        "HiddenChannelDns" => Ok(UebaRule::HiddenChannelDns),
        "HiddenChannelHttp" => Ok(UebaRule::HiddenChannelHttp),
        other => Err(PersistenceError::UnknownUebaRule(other.to_string())),
    }
}

fn mitigation_action_label(action: &MitigationAction) -> &'static str {
    match action {
        MitigationAction::Observe => "Observe",
        MitigationAction::StepUpAuth => "StepUpAuth",
        MitigationAction::SuspendPermissions => "SuspendPermissions",
        MitigationAction::TerminateSession => "TerminateSession",
    }
}

fn parse_mitigation_action(label: &str) -> Result<MitigationAction, PersistenceError> {
    match label {
        "Observe" => Ok(MitigationAction::Observe),
        "StepUpAuth" => Ok(MitigationAction::StepUpAuth),
        "SuspendPermissions" => Ok(MitigationAction::SuspendPermissions),
        "TerminateSession" => Ok(MitigationAction::TerminateSession),
        other => Err(PersistenceError::UnknownUebaMitigationAction(
            other.to_string(),
        )),
    }
}

fn ueba_severity_label(risk_score: u8) -> &'static str {
    match risk_score {
        0..=39 => "low",
        40..=69 => "medium",
        70..=89 => "high",
        _ => "critical",
    }
}

fn escape_clickhouse_string(value: &str) -> String {
    value.replace('\'', "''")
}

fn clickhouse_datetime(value: chrono::DateTime<chrono::Utc>) -> String {
    value.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

fn serialize_audit_context_fields(
    fields: &AuditContextFields,
) -> Result<Option<String>, PersistenceError> {
    if fields.is_empty() {
        return Ok(None);
    }

    serde_json::to_string(fields)
        .map(Some)
        .map_err(|error| PersistenceError::AuditArtifact(error.to_string()))
}

fn deserialize_audit_context_fields(
    fields_json: Option<String>,
) -> Result<AuditContextFields, PersistenceError> {
    match fields_json {
        Some(fields_json) => serde_json::from_str(&fields_json)
            .map_err(|error| PersistenceError::AuditArtifact(error.to_string())),
        None => Ok(AuditContextFields::default()),
    }
}

fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| serde::de::Error::custom("invalid u64 value")),
        Value::String(value) => value
            .parse::<u64>()
            .map_err(|error| serde::de::Error::custom(error.to_string())),
        _ => Err(serde::de::Error::custom("unsupported u64 encoding")),
    }
}

fn deserialize_clickhouse_datetime<'de, D>(
    deserializer: D,
) -> Result<chrono::DateTime<chrono::Utc>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    chrono::DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&chrono::Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(&value, "%Y-%m-%d %H:%M:%S%.f")
                .map(|value| value.and_utc())
        })
        .map_err(|error| serde::de::Error::custom(error.to_string()))
}

fn default_audit_signature_algorithm() -> String {
    "sha256".into()
}

fn default_audit_signer_provider() -> String {
    "legacy-sha256".into()
}

fn default_audit_signer_key_id() -> String {
    "legacy-local-hash".into()
}

fn quoted_clickhouse_literals(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("'{}'", value.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(", ")
}

fn audit_replica_path(postgres_dsn: &str) -> PathBuf {
    let database_name = postgres_dsn
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("sdqp");
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("generated")
        .join("audit")
        .join(format!("{database_name}-replica.json"))
}

fn audit_archive_dir(postgres_dsn: &str, configured_dir: &str) -> PathBuf {
    if !configured_dir.trim().is_empty() {
        return PathBuf::from(configured_dir);
    }

    let database_name = postgres_dsn
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("sdqp");
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("generated")
        .join("audit")
        .join(format!("{database_name}-archives"))
}

#[cfg(test)]
mod tests {
    use super::{
        PersistenceError, audit_replica_path, auth_source_label, mfa_method_label,
        parse_auth_source, parse_mfa_method, parse_project_state, parse_query_task_state,
        parse_role, project_state_label, query_task_state_label, role_label,
    };
    use sdqp_datasource_adapter::task::QueryTaskState;
    use sdqp_system_security::{MfaMethod, Role, TrustedAuthenticationSource};
    use sdqp_tenant_isolation::ProjectState;

    #[test]
    fn labels_round_trip_for_security_and_project_enums() {
        assert_eq!(
            parse_role(role_label(&Role::Analyst)).expect("role"),
            Role::Analyst
        );
        assert_eq!(
            parse_mfa_method(mfa_method_label(&MfaMethod::WebAuthn)).expect("mfa"),
            MfaMethod::WebAuthn
        );
        assert_eq!(
            parse_auth_source(auth_source_label(&TrustedAuthenticationSource::Oidc))
                .expect("auth source"),
            TrustedAuthenticationSource::Oidc
        );
        assert_eq!(
            parse_project_state(project_state_label(ProjectState::Archived)).expect("project"),
            ProjectState::Archived
        );
        assert_eq!(
            parse_query_task_state(query_task_state_label(&QueryTaskState::Cancelled))
                .expect("task state"),
            QueryTaskState::Cancelled
        );
    }

    #[test]
    fn unknown_labels_are_rejected() {
        assert!(matches!(
            parse_role("nope"),
            Err(PersistenceError::UnknownRole(_))
        ));
        assert!(matches!(
            parse_mfa_method("unknown"),
            Err(PersistenceError::UnknownMfaMethod(_))
        ));
        assert!(matches!(
            parse_auth_source("unknown"),
            Err(PersistenceError::UnknownAuthSource(_))
        ));
    }

    #[test]
    fn audit_replica_path_uses_database_name() {
        let path = audit_replica_path("postgres://sdqp:sdqp@127.0.0.1:5432/stage5_db");
        assert!(path.ends_with("stage5_db-replica.json"));
    }
}
