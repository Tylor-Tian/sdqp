use std::{collections::HashMap, sync::Arc};

use serde_json::Value;
use sqlx::{Row, types::Json};
use sqlx_postgres::{PgPool, PgPoolOptions, PgRow};
use thiserror::Error;

use sdqp_config::AppSettings;
use sdqp_data_classification::{
    ClassificationCatalogEntry, ClassificationPolicySource, ClassificationRule,
    ClassificationRuleVersion, ClassificationStatus, DataCategory, FieldClassificationPolicy,
    MaskingStrategy, RetentionPolicy, RuleVersionStatus, SensitivityLevel, WatermarkStrength,
    derive_catalog_entries,
};
use sdqp_datasource_adapter::{
    DataSourceConfig, SourceType, StoredQueryTask, UnifiedQuery, task::QueryTaskState,
};
use sdqp_encryption::{EncryptedSnapshotRecord, SnapshotDeleteState};
use sdqp_tenant_isolation::{ProjectContext, ProjectState};

#[derive(Debug, Error)]
pub enum WorkerPersistenceError {
    #[error("postgres error: {0}")]
    Postgres(#[from] sqlx::Error),
    #[error("unknown project state label: {0}")]
    UnknownProjectState(String),
    #[error("unknown query task state label: {0}")]
    UnknownQueryTaskState(String),
    #[error("unknown source type label: {0}")]
    UnknownSourceType(String),
    #[error("unknown snapshot delete state label: {0}")]
    UnknownSnapshotDeleteState(String),
    #[error("governance persistence error: {0}")]
    Governance(String),
}

#[derive(Debug, Clone)]
pub(crate) struct WorkerPersistence {
    pool: PgPool,
}

impl WorkerPersistence {
    pub(crate) async fn initialize(
        settings: &AppSettings,
    ) -> Result<Arc<Self>, WorkerPersistenceError> {
        let pool = PgPoolOptions::new()
            .max_connections(settings.database.postgres.max_connections as u32)
            .connect(&settings.database.postgres.dsn)
            .await?;
        Ok(Arc::new(Self { pool }))
    }

    pub(crate) async fn load_projects(
        &self,
    ) -> Result<HashMap<String, ProjectContext>, WorkerPersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT project_id, tenant_id, state
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
            projects.insert(
                project_id.clone(),
                ProjectContext::new(
                    sdqp_core::TenantId::new(tenant_id).expect("seeded tenant id"),
                    sdqp_core::ProjectId::new(project_id).expect("seeded project id"),
                    parse_project_state(&state)?,
                ),
            );
        }

        Ok(projects)
    }

    pub(crate) async fn load_data_source_configs(
        &self,
    ) -> Result<Vec<DataSourceConfig>, WorkerPersistenceError> {
        let rows = sqlx::query(
            r#"
            SELECT data_source_id, source_type, connection_uri, adapter_config_json
            FROM data_sources
            ORDER BY data_source_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut configs = Vec::with_capacity(rows.len());
        for row in rows {
            configs.push(DataSourceConfig {
                data_source_id: row.try_get("data_source_id")?,
                source_type: parse_source_type(&row.try_get::<String, _>("source_type")?)?,
                connection_uri: row.try_get("connection_uri")?,
                adapter_config: row.try_get::<Json<Value>, _>("adapter_config_json")?.0,
            });
        }

        Ok(configs)
    }

    pub(crate) async fn load_classification_policies(
        &self,
        project_id: &str,
        data_source_id: &str,
        fields: &[String],
    ) -> Result<Vec<FieldClassificationPolicy>, WorkerPersistenceError> {
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

    pub(crate) async fn load_active_classification_rule_version(
        &self,
        project_id: &str,
        data_source_id: &str,
    ) -> Result<Option<ClassificationRuleVersion>, WorkerPersistenceError> {
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

    pub(crate) async fn save_classification_detection_run(
        &self,
        snapshot_id: &str,
        project_id: &str,
        data_source_id: &str,
        rule_version: &ClassificationRuleVersion,
        policies: &[FieldClassificationPolicy],
    ) -> Result<String, WorkerPersistenceError> {
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

    pub(crate) async fn claim_next_query_task(
        &self,
        worker_id: &str,
        lease_secs: u64,
    ) -> Result<Option<StoredQueryTask>, WorkerPersistenceError> {
        let row = sqlx::query(
            r#"
            WITH next_task AS (
                SELECT task_id
                FROM query_tasks
                WHERE state = 'pending'
                  AND query_payload_json IS NOT NULL
                  AND data_source_id IS NOT NULL
                  AND source_type IS NOT NULL
                  AND cache_key IS NOT NULL
                ORDER BY priority, created_at
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE query_tasks
            SET
                state = 'running',
                attempt_count = attempt_count + 1,
                lease_owner = $1,
                lease_expires_at = NOW() + make_interval(secs => $2::int),
                updated_at = NOW()
            WHERE task_id = (SELECT task_id FROM next_task)
            RETURNING
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
                max_attempts
            "#,
        )
        .bind(worker_id)
        .bind(lease_secs as i32)
        .fetch_optional(&self.pool)
        .await?;

        row.map(parse_stored_query_task).transpose()
    }

    pub(crate) async fn load_cache_entry(
        &self,
        cache_key: &str,
    ) -> Result<Option<String>, WorkerPersistenceError> {
        Ok(sqlx::query_scalar(
            "SELECT snapshot_id FROM snapshot_cache_entries WHERE cache_key = $1",
        )
        .bind(cache_key)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub(crate) async fn load_task_state(
        &self,
        task_id: &str,
    ) -> Result<Option<QueryTaskState>, WorkerPersistenceError> {
        let label =
            sqlx::query_scalar::<_, String>("SELECT state FROM query_tasks WHERE task_id = $1")
                .bind(task_id)
                .fetch_optional(&self.pool)
                .await?;
        label
            .map(|label| parse_query_task_state(&label))
            .transpose()
    }

    pub(crate) async fn complete_task(
        &self,
        task_id: &str,
        snapshot_id: &str,
        cache_hit: bool,
    ) -> Result<(), WorkerPersistenceError> {
        sqlx::query(
            r#"
            UPDATE query_tasks
            SET
                state = 'completed',
                snapshot_id = $2,
                cache_hit = $3,
                error = NULL,
                lease_owner = NULL,
                lease_expires_at = NULL,
                completion_audited = FALSE,
                updated_at = NOW()
            WHERE task_id = $1 AND state <> 'cancelled'
            "#,
        )
        .bind(task_id)
        .bind(snapshot_id)
        .bind(cache_hit)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn reset_task_for_retry(
        &self,
        task_id: &str,
        error: &str,
    ) -> Result<(), WorkerPersistenceError> {
        sqlx::query(
            r#"
            UPDATE query_tasks
            SET
                state = 'pending',
                error = $2,
                lease_owner = NULL,
                lease_expires_at = NULL,
                updated_at = NOW()
            WHERE task_id = $1 AND state <> 'cancelled'
            "#,
        )
        .bind(task_id)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn fail_task(
        &self,
        task_id: &str,
        error: &str,
    ) -> Result<(), WorkerPersistenceError> {
        sqlx::query(
            r#"
            UPDATE query_tasks
            SET
                state = 'failed',
                error = $2,
                lease_owner = NULL,
                lease_expires_at = NULL,
                completion_audited = FALSE,
                updated_at = NOW()
            WHERE task_id = $1 AND state <> 'cancelled'
            "#,
        )
        .bind(task_id)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(crate) async fn save_snapshot(
        &self,
        record: &EncryptedSnapshotRecord,
    ) -> Result<(), WorkerPersistenceError> {
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

    pub(crate) async fn save_cache_entry(
        &self,
        cache_key: &str,
        snapshot_id: &str,
    ) -> Result<(), WorkerPersistenceError> {
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
}

fn parse_stored_query_task(row: PgRow) -> Result<StoredQueryTask, WorkerPersistenceError> {
    Ok(StoredQueryTask {
        task_id: row.try_get("task_id")?,
        tenant_id: row.try_get("tenant_id")?,
        project_id: row.try_get("project_id")?,
        user_id: row.try_get("user_id")?,
        project_scope_key: row.try_get("project_scope_key")?,
        grant_id: row.try_get("grant_id")?,
        grant_valid_until: row.try_get("grant_valid_until")?,
        data_source_id: row.try_get("data_source_id")?,
        source_type: parse_source_type(&row.try_get::<String, _>("source_type")?)?,
        query: row
            .try_get::<Json<UnifiedQuery>, _>("query_payload_json")?
            .0,
        cache_key: row.try_get("cache_key")?,
        priority: row.try_get("priority")?,
        attempt_count: row.try_get::<i32, _>("attempt_count")? as u32,
        max_attempts: row.try_get::<i32, _>("max_attempts")? as u32,
    })
}

fn parse_project_state(label: &str) -> Result<ProjectState, WorkerPersistenceError> {
    match label {
        "created" => Ok(ProjectState::Created),
        "active" => Ok(ProjectState::Active),
        "frozen" => Ok(ProjectState::Frozen),
        "archived" => Ok(ProjectState::Archived),
        "deleted" => Ok(ProjectState::Deleted),
        other => Err(WorkerPersistenceError::UnknownProjectState(
            other.to_string(),
        )),
    }
}

fn parse_query_task_state(label: &str) -> Result<QueryTaskState, WorkerPersistenceError> {
    match label {
        "pending" => Ok(QueryTaskState::Pending),
        "running" => Ok(QueryTaskState::Running),
        "completed" => Ok(QueryTaskState::Completed),
        "failed" => Ok(QueryTaskState::Failed),
        "cancelled" => Ok(QueryTaskState::Cancelled),
        other => Err(WorkerPersistenceError::UnknownQueryTaskState(
            other.to_string(),
        )),
    }
}

fn parse_source_type(label: &str) -> Result<SourceType, WorkerPersistenceError> {
    match label {
        "rest" => Ok(SourceType::Rest),
        "rpc" => Ok(SourceType::Rpc),
        "hive" => Ok(SourceType::Hive),
        "rdbms" => Ok(SourceType::Rdbms),
        other => Err(WorkerPersistenceError::UnknownSourceType(other.to_string())),
    }
}

fn snapshot_delete_state_label(state: &SnapshotDeleteState) -> &'static str {
    state.as_str()
}

#[allow(dead_code)]
fn parse_snapshot_delete_state(label: &str) -> Result<SnapshotDeleteState, WorkerPersistenceError> {
    SnapshotDeleteState::parse_label(label)
        .ok_or_else(|| WorkerPersistenceError::UnknownSnapshotDeleteState(label.to_string()))
}

fn classification_status_label(status: &ClassificationStatus) -> &'static str {
    match status {
        ClassificationStatus::PendingConfirmation => "pending_confirmation",
        ClassificationStatus::Confirmed => "confirmed",
    }
}

fn parse_classification_status(
    label: &str,
) -> Result<ClassificationStatus, WorkerPersistenceError> {
    match label {
        "pending_confirmation" => Ok(ClassificationStatus::PendingConfirmation),
        "confirmed" => Ok(ClassificationStatus::Confirmed),
        other => Err(WorkerPersistenceError::Governance(format!(
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

fn parse_sensitivity_level(label: &str) -> Result<SensitivityLevel, WorkerPersistenceError> {
    match label {
        "l1_public" => Ok(SensitivityLevel::L1Public),
        "l2_internal" => Ok(SensitivityLevel::L2Internal),
        "l3_confidential" => Ok(SensitivityLevel::L3Confidential),
        "l4_sensitive" => Ok(SensitivityLevel::L4Sensitive),
        "l5_restricted" => Ok(SensitivityLevel::L5Restricted),
        other => Err(WorkerPersistenceError::Governance(format!(
            "unknown sensitivity level label: {other}"
        ))),
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

fn parse_data_category(label: &str) -> Result<DataCategory, WorkerPersistenceError> {
    match label {
        "public_reference" => Ok(DataCategory::PublicReference),
        "internal_operational" => Ok(DataCategory::InternalOperational),
        "personal_contact" => Ok(DataCategory::PersonalContact),
        "personal_identifier" => Ok(DataCategory::PersonalIdentifier),
        "financial_identifier" => Ok(DataCategory::FinancialIdentifier),
        "investigation_sensitive" => Ok(DataCategory::InvestigationSensitive),
        "general_confidential" => Ok(DataCategory::GeneralConfidential),
        other => Err(WorkerPersistenceError::Governance(format!(
            "unknown data category label: {other}"
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

fn parse_masking_strategy(label: &str) -> Result<MaskingStrategy, WorkerPersistenceError> {
    match label {
        "none" => Ok(MaskingStrategy::None),
        "partial_email" => Ok(MaskingStrategy::PartialEmail),
        "partial_phone" => Ok(MaskingStrategy::PartialPhone),
        "full" => Ok(MaskingStrategy::Full),
        other => Err(WorkerPersistenceError::Governance(format!(
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

fn parse_watermark_strength(label: &str) -> Result<WatermarkStrength, WorkerPersistenceError> {
    match label {
        "low" => Ok(WatermarkStrength::Low),
        "medium" => Ok(WatermarkStrength::Medium),
        "high" => Ok(WatermarkStrength::High),
        "critical" => Ok(WatermarkStrength::Critical),
        other => Err(WorkerPersistenceError::Governance(format!(
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

fn parse_policy_source(label: &str) -> Result<ClassificationPolicySource, WorkerPersistenceError> {
    match label {
        "rule_engine" => Ok(ClassificationPolicySource::RuleEngine),
        "sample_detection" => Ok(ClassificationPolicySource::SampleDetection),
        "manual_confirmation" => Ok(ClassificationPolicySource::ManualConfirmation),
        other => Err(WorkerPersistenceError::Governance(format!(
            "unknown classification policy source label: {other}"
        ))),
    }
}

fn parse_rule_version_status(label: &str) -> Result<RuleVersionStatus, WorkerPersistenceError> {
    match label {
        "draft" => Ok(RuleVersionStatus::Draft),
        "active" => Ok(RuleVersionStatus::Active),
        "retired" => Ok(RuleVersionStatus::Retired),
        other => Err(WorkerPersistenceError::Governance(format!(
            "unknown classification rule version status label: {other}"
        ))),
    }
}

fn parse_classification_rule_version(
    row: &PgRow,
) -> Result<ClassificationRuleVersion, WorkerPersistenceError> {
    let rules = row
        .try_get::<Json<Vec<ClassificationRule>>, _>("rules_json")?
        .0;
    let catalog_entries = row
        .try_get::<Json<Vec<ClassificationCatalogEntry>>, _>("catalog_json")?
        .0;
    Ok(ClassificationRuleVersion {
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
    })
}

fn parse_field_classification_policy(
    row: &PgRow,
) -> Result<FieldClassificationPolicy, WorkerPersistenceError> {
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

#[cfg(test)]
mod tests {
    use super::{
        WorkerPersistenceError, parse_project_state, parse_query_task_state, parse_source_type,
    };
    use sdqp_datasource_adapter::{SourceType, task::QueryTaskState};
    use sdqp_tenant_isolation::ProjectState;

    #[test]
    fn parses_project_states_from_storage_labels() {
        assert_eq!(
            parse_project_state("archived").expect("state"),
            ProjectState::Archived
        );
    }

    #[test]
    fn rejects_unknown_project_state_label() {
        assert!(matches!(
            parse_project_state("invalid"),
            Err(WorkerPersistenceError::UnknownProjectState(_))
        ));
    }

    #[test]
    fn parses_query_task_states() {
        assert_eq!(
            parse_query_task_state("running").expect("state"),
            QueryTaskState::Running
        );
    }

    #[test]
    fn parses_source_type_labels() {
        assert_eq!(parse_source_type("rpc").expect("source"), SourceType::Rpc);
    }
}
