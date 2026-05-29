use std::{collections::HashMap, sync::Arc};

use arrow::record_batch::RecordBatch;
use axum::{
    Extension, Json,
    body::Body,
    extract::{Path, Query as QueryParams, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, Utc};
use sdqp_audit::{ActionResult, AuditContextFields};
use sdqp_core::{FieldSelector, RequestContext};
use sdqp_data_classification::{
    FieldClassificationPolicy, MaskingStrategy, classify_fields, default_rule_version, mask_value,
};
use sdqp_data_view::{
    DataViewError, EncryptedSnapshotProvider, PivotMetric, SnapshotAccessProfile,
    encode_record_batches_to_arrow_ipc,
};
use sdqp_encryption::{SnapshotDeleteState, SnapshotStore};
use sdqp_permission_engine::PermissionGrant;
use serde::{Deserialize, Serialize};

use crate::{ApiErrorResponse, ApiState, AuthenticatedSession, json_error, phase2};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDisplayPolicyResponse {
    pub field_name: String,
    pub masked: bool,
    pub render_mode: String,
    pub watermark_strength: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotPageResponse {
    pub snapshot_id: String,
    pub columns: Vec<String>,
    pub rows: Vec<HashMap<String, String>>,
    pub next_cursor: Option<usize>,
    pub field_policies: Vec<FieldDisplayPolicyResponse>,
    pub watermark_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotBucketResponse {
    pub key: String,
    pub value: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisResponseFormat {
    Json,
    ArrowIpc,
}

impl AnalysisResponseFormat {
    fn label(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::ArrowIpc => "arrow_ipc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PivotMetricKind {
    RecordCount,
    CountDistinct,
    Sum,
    Avg,
    Min,
    Max,
    Median,
    Percentile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotAnalysisResponse {
    pub snapshot_id: String,
    pub dimension: String,
    pub metric: String,
    pub metric_field: Option<String>,
    pub percentile: Option<f64>,
    pub buckets: Vec<PivotBucketResponse>,
    pub watermark_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotPageArrowMetadata {
    pub snapshot_id: String,
    pub columns: Vec<String>,
    pub next_cursor: Option<usize>,
    pub field_policies: Vec<FieldDisplayPolicyResponse>,
    pub watermark_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotAnalysisArrowMetadata {
    pub snapshot_id: String,
    pub dimension: String,
    pub metric: String,
    pub metric_field: Option<String>,
    pub percentile: Option<f64>,
    pub watermark_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotPageQuery {
    pub page_size: Option<usize>,
    pub cursor: Option<usize>,
    pub response_format: Option<AnalysisResponseFormat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotAnalysisRequest {
    pub snapshot_id: String,
    pub dimension: String,
    pub metric: Option<PivotMetricKind>,
    pub metric_field: Option<String>,
    pub percentile: Option<f64>,
    pub response_format: Option<AnalysisResponseFormat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrilldownRequest {
    pub snapshot_id: String,
    pub dimension: String,
    pub value: String,
    pub fields: Vec<String>,
    pub page_size: Option<usize>,
    pub cursor: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisTemplateVisibility {
    Private,
    Published,
}

impl AnalysisTemplateVisibility {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Published => "published",
        }
    }

    pub(crate) fn parse_label(label: &str) -> Option<Self> {
        match label.trim().to_ascii_lowercase().as_str() {
            "private" => Some(Self::Private),
            "published" => Some(Self::Published),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisTemplateConfig {
    pub page_size: Option<usize>,
    pub detail_fields: Vec<String>,
    pub pivot_dimension: String,
    pub pivot_metric: PivotMetricKind,
    pub pivot_metric_field: Option<String>,
    pub pivot_percentile: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisTemplateUpsertRequest {
    pub name: String,
    pub description: Option<String>,
    pub data_source_id: String,
    pub config: AnalysisTemplateConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisTemplateResponse {
    pub template_id: String,
    pub name: String,
    pub description: Option<String>,
    pub data_source_id: String,
    pub visibility: AnalysisTemplateVisibility,
    pub owner_user_id: String,
    pub editable: bool,
    pub published_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub config: AnalysisTemplateConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisTemplateListResponse {
    pub templates: Vec<AnalysisTemplateResponse>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisTemplateDeleteResponse {
    pub template_id: String,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct AnalysisTemplateRecord {
    pub template_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub owner_user_id: String,
    pub data_source_id: String,
    pub name: String,
    pub description: Option<String>,
    pub visibility: AnalysisTemplateVisibility,
    pub config: AnalysisTemplateConfig,
    pub published_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn list_analysis_templates_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let templates = visible_analysis_templates(&state, &request_context, &session);
    let published_count = templates
        .iter()
        .filter(|template| template.visibility == AnalysisTemplateVisibility::Published)
        .count();

    phase2::append_phase2_audit_with_fields(
        &state,
        &session,
        &request_context,
        sdqp_audit::ActionType::View,
        ActionResult::Success,
        "analysis-templates",
        "analysis templates listed",
        phase2::Phase2AuditDetails::new(
            AuditContextFields::builder()
                .field("operation", "analysis_template_list")
                .field("template_count", templates.len())
                .field("published_count", published_count)
                .build(),
            None,
        ),
    )
    .await;

    Json(AnalysisTemplateListResponse {
        templates: templates
            .iter()
            .map(|template| analysis_template_response(template, &session))
            .collect(),
    })
    .into_response()
}

pub async fn create_analysis_template_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<AnalysisTemplateUpsertRequest>,
) -> Response {
    let referenced_fields = match validate_analysis_template_payload(&payload) {
        Ok(fields) => fields,
        Err(response) => return *response,
    };

    let grant = match load_active_grant(&state, &request_context, &session, &payload.data_source_id)
    {
        Ok(grant) => grant,
        Err(response) => {
            append_analysis_template_audit(
                &state,
                &session,
                &request_context,
                sdqp_audit::ActionType::ConfigChange,
                ActionResult::Denied,
                "analysis-templates",
                "analysis template save denied",
                AuditContextFields::builder()
                    .field("operation", "analysis_template_create")
                    .field("data_source_id", payload.data_source_id.clone())
                    .field("requested_fields", referenced_fields)
                    .build(),
            )
            .await;
            return *response;
        }
    };
    if let Err(response) = authorize_fields(&grant, &referenced_fields) {
        append_analysis_template_audit(
            &state,
            &session,
            &request_context,
            sdqp_audit::ActionType::ConfigChange,
            ActionResult::Denied,
            "analysis-templates",
            "analysis template save denied",
            AuditContextFields::builder()
                .field("operation", "analysis_template_create")
                .field("data_source_id", payload.data_source_id.clone())
                .field("requested_fields", referenced_fields)
                .build(),
        )
        .await;
        return *response;
    }

    let now = Utc::now();
    let record = AnalysisTemplateRecord {
        template_id: ulid::Ulid::new().to_string(),
        tenant_id: request_context.tenant_id.as_str().to_string(),
        project_id: request_context
            .project_id
            .as_ref()
            .expect("project scope")
            .as_str()
            .to_string(),
        owner_user_id: session.claims.user_id.clone(),
        data_source_id: payload.data_source_id.clone(),
        name: payload.name.trim().to_string(),
        description: payload
            .description
            .clone()
            .filter(|value| !value.trim().is_empty()),
        visibility: AnalysisTemplateVisibility::Private,
        config: normalize_analysis_template_config(payload.config),
        published_at: None,
        created_at: now,
        updated_at: now,
    };

    let record = match persist_analysis_template(&state, record).await {
        Ok(record) => record,
        Err(response) => return *response,
    };

    append_analysis_template_audit(
        &state,
        &session,
        &request_context,
        sdqp_audit::ActionType::ConfigChange,
        ActionResult::Success,
        &record.template_id,
        "analysis template saved",
        AuditContextFields::builder()
            .field("operation", "analysis_template_create")
            .field("data_source_id", record.data_source_id.clone())
            .field("visibility", record.visibility.label())
            .field(
                "requested_fields",
                analysis_template_requested_fields(&record.config),
            )
            .build(),
    )
    .await;

    (
        StatusCode::CREATED,
        Json(analysis_template_response(&record, &session)),
    )
        .into_response()
}

pub async fn get_analysis_template_handler(
    State(state): State<Arc<ApiState>>,
    Path(template_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let record = match load_accessible_analysis_template(
        &state,
        &template_id,
        &request_context,
        &session,
        "analysis template load denied",
    )
    .await
    {
        Ok(record) => record,
        Err(response) => return *response,
    };

    append_analysis_template_audit(
        &state,
        &session,
        &request_context,
        sdqp_audit::ActionType::View,
        ActionResult::Success,
        &record.template_id,
        "analysis template loaded",
        AuditContextFields::builder()
            .field("operation", "analysis_template_get")
            .field("data_source_id", record.data_source_id.clone())
            .field("visibility", record.visibility.label())
            .build(),
    )
    .await;

    Json(analysis_template_response(&record, &session)).into_response()
}

pub async fn update_analysis_template_handler(
    State(state): State<Arc<ApiState>>,
    Path(template_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<AnalysisTemplateUpsertRequest>,
) -> Response {
    let referenced_fields = match validate_analysis_template_payload(&payload) {
        Ok(fields) => fields,
        Err(response) => return *response,
    };
    let mut record = match load_owned_analysis_template(
        &state,
        &template_id,
        &request_context,
        &session,
        "analysis template update denied",
    )
    .await
    {
        Ok(record) => record,
        Err(response) => return *response,
    };

    let grant = match load_active_grant(&state, &request_context, &session, &payload.data_source_id)
    {
        Ok(grant) => grant,
        Err(response) => {
            append_analysis_template_audit(
                &state,
                &session,
                &request_context,
                sdqp_audit::ActionType::ConfigChange,
                ActionResult::Denied,
                &template_id,
                "analysis template update denied",
                AuditContextFields::builder()
                    .field("operation", "analysis_template_update")
                    .field("data_source_id", payload.data_source_id.clone())
                    .field("requested_fields", referenced_fields)
                    .build(),
            )
            .await;
            return *response;
        }
    };
    if let Err(response) = authorize_fields(&grant, &referenced_fields) {
        append_analysis_template_audit(
            &state,
            &session,
            &request_context,
            sdqp_audit::ActionType::ConfigChange,
            ActionResult::Denied,
            &template_id,
            "analysis template update denied",
            AuditContextFields::builder()
                .field("operation", "analysis_template_update")
                .field("data_source_id", payload.data_source_id.clone())
                .field("requested_fields", referenced_fields)
                .build(),
        )
        .await;
        return *response;
    }

    record.name = payload.name.trim().to_string();
    record.description = payload
        .description
        .clone()
        .filter(|value| !value.trim().is_empty());
    record.data_source_id = payload.data_source_id.clone();
    record.config = normalize_analysis_template_config(payload.config);
    record.updated_at = Utc::now();

    let record = match persist_analysis_template(&state, record).await {
        Ok(record) => record,
        Err(response) => return *response,
    };

    append_analysis_template_audit(
        &state,
        &session,
        &request_context,
        sdqp_audit::ActionType::ConfigChange,
        ActionResult::Success,
        &record.template_id,
        "analysis template updated",
        AuditContextFields::builder()
            .field("operation", "analysis_template_update")
            .field("data_source_id", record.data_source_id.clone())
            .field("visibility", record.visibility.label())
            .field(
                "requested_fields",
                analysis_template_requested_fields(&record.config),
            )
            .build(),
    )
    .await;

    Json(analysis_template_response(&record, &session)).into_response()
}

pub async fn publish_analysis_template_handler(
    State(state): State<Arc<ApiState>>,
    Path(template_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let mut record = match load_owned_analysis_template(
        &state,
        &template_id,
        &request_context,
        &session,
        "analysis template publish denied",
    )
    .await
    {
        Ok(record) => record,
        Err(response) => return *response,
    };

    let now = Utc::now();
    record.visibility = AnalysisTemplateVisibility::Published;
    record.published_at = Some(record.published_at.unwrap_or(now));
    record.updated_at = now;
    let record = match persist_analysis_template(&state, record).await {
        Ok(record) => record,
        Err(response) => return *response,
    };

    append_analysis_template_audit(
        &state,
        &session,
        &request_context,
        sdqp_audit::ActionType::ConfigChange,
        ActionResult::Success,
        &record.template_id,
        "analysis template published",
        AuditContextFields::builder()
            .field("operation", "analysis_template_publish")
            .field("data_source_id", record.data_source_id.clone())
            .field("visibility", record.visibility.label())
            .build(),
    )
    .await;

    Json(analysis_template_response(&record, &session)).into_response()
}

pub async fn unpublish_analysis_template_handler(
    State(state): State<Arc<ApiState>>,
    Path(template_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let mut record = match load_owned_analysis_template(
        &state,
        &template_id,
        &request_context,
        &session,
        "analysis template unpublish denied",
    )
    .await
    {
        Ok(record) => record,
        Err(response) => return *response,
    };

    record.visibility = AnalysisTemplateVisibility::Private;
    record.published_at = None;
    record.updated_at = Utc::now();
    let record = match persist_analysis_template(&state, record).await {
        Ok(record) => record,
        Err(response) => return *response,
    };

    append_analysis_template_audit(
        &state,
        &session,
        &request_context,
        sdqp_audit::ActionType::ConfigChange,
        ActionResult::Success,
        &record.template_id,
        "analysis template unpublished",
        AuditContextFields::builder()
            .field("operation", "analysis_template_unpublish")
            .field("data_source_id", record.data_source_id.clone())
            .field("visibility", record.visibility.label())
            .build(),
    )
    .await;

    Json(analysis_template_response(&record, &session)).into_response()
}

pub async fn delete_analysis_template_handler(
    State(state): State<Arc<ApiState>>,
    Path(template_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let record = match load_owned_analysis_template(
        &state,
        &template_id,
        &request_context,
        &session,
        "analysis template delete denied",
    )
    .await
    {
        Ok(record) => record,
        Err(response) => return *response,
    };

    if let Err(response) = delete_analysis_template(&state, &record.template_id).await {
        return *response;
    }

    append_analysis_template_audit(
        &state,
        &session,
        &request_context,
        sdqp_audit::ActionType::ConfigChange,
        ActionResult::Success,
        &record.template_id,
        "analysis template deleted",
        AuditContextFields::builder()
            .field("operation", "analysis_template_delete")
            .field("data_source_id", record.data_source_id.clone())
            .field("visibility", record.visibility.label())
            .build(),
    )
    .await;

    Json(AnalysisTemplateDeleteResponse {
        template_id: record.template_id,
        deleted: true,
    })
    .into_response()
}

pub async fn snapshot_page_handler(
    State(state): State<Arc<ApiState>>,
    Path(snapshot_id): Path<String>,
    QueryParams(params): QueryParams<SnapshotPageQuery>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let record = match load_scoped_snapshot(&state, &snapshot_id, &request_context, &session).await
    {
        Ok(record) => record,
        Err(response) => return *response,
    };

    let provider = EncryptedSnapshotProvider::new(state.cipher.clone());
    let snapshot_columns = match provider.columns(&record) {
        Ok(columns) => columns,
        Err(error) => return data_view_error_response(error, "failed to load snapshot"),
    };
    let grant = match load_active_grant(&state, &request_context, &session, &record.data_source_id)
    {
        Ok(grant) => grant,
        Err(response) => return *response,
    };
    let columns = grant_allowed_snapshot_columns(&grant, &snapshot_columns);
    if columns.is_empty() {
        return json_error(
            StatusCode::FORBIDDEN,
            "no authorized snapshot columns remain under the active grant",
        );
    }

    let policy_map =
        load_field_policies(&state, &request_context, &record.data_source_id, &columns).await;
    let access_profile = build_access_profile(&columns, &policy_map);
    let response_format = params
        .response_format
        .unwrap_or(AnalysisResponseFormat::Json);

    let page_size = params.page_size.unwrap_or(25);

    match response_format {
        AnalysisResponseFormat::Json => {
            let page = match provider
                .read_page(&record, &access_profile, &columns, page_size, params.cursor)
                .await
            {
                Ok(page) => page,
                Err(error) => return data_view_error_response(error, "invalid pagination"),
            };

            phase2::append_phase2_audit_with_fields(
                &state,
                &session,
                &request_context,
                sdqp_audit::ActionType::View,
                ActionResult::Success,
                &snapshot_id,
                "snapshot page read",
                phase2::Phase2AuditDetails::new(
                    AuditContextFields::builder()
                        .field("snapshot_id", snapshot_id.clone())
                        .field("data_source_id", record.data_source_id.clone())
                        .field("operation", "snapshot_page")
                        .field("requested_fields", columns.clone())
                        .field("field_count", columns.len())
                        .field("page_size", page_size)
                        .field("cursor_present", params.cursor.is_some())
                        .field("response_format", response_format.label())
                        .build(),
                    None,
                ),
            )
            .await;

            Json(build_snapshot_page_response(
                &snapshot_id,
                &columns,
                &page.rows,
                page.next_cursor,
                &request_context,
                &policy_map,
            ))
            .into_response()
        }
        AnalysisResponseFormat::ArrowIpc => {
            let page = match provider
                .read_page_batches(&record, &access_profile, &columns, page_size, params.cursor)
                .await
            {
                Ok(page) => page,
                Err(error) => return data_view_error_response(error, "invalid pagination"),
            };
            let payload = match encode_record_batches_to_arrow_ipc(page.schema, &page.batches) {
                Ok(payload) => payload,
                Err(error) => {
                    return data_view_error_response(
                        error,
                        "failed to encode snapshot page as arrow ipc",
                    );
                }
            };
            phase2::append_phase2_audit_with_fields(
                &state,
                &session,
                &request_context,
                sdqp_audit::ActionType::View,
                ActionResult::Success,
                &snapshot_id,
                "snapshot page read",
                phase2::Phase2AuditDetails::new(
                    AuditContextFields::builder()
                        .field("snapshot_id", snapshot_id.clone())
                        .field("data_source_id", record.data_source_id.clone())
                        .field("operation", "snapshot_page")
                        .field("requested_fields", columns.clone())
                        .field("field_count", columns.len())
                        .field("page_size", page_size)
                        .field("cursor_present", params.cursor.is_some())
                        .field("response_format", response_format.label())
                        .build(),
                    None,
                ),
            )
            .await;

            arrow_ipc_response(
                payload,
                &build_snapshot_page_arrow_metadata(
                    &snapshot_id,
                    &columns,
                    page.next_cursor,
                    &request_context,
                    &policy_map,
                ),
            )
        }
    }
}

pub async fn pivot_analysis_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<PivotAnalysisRequest>,
) -> Response {
    let record = match load_scoped_snapshot(
        &state,
        &payload.snapshot_id,
        &request_context,
        &session,
    )
    .await
    {
        Ok(record) => record,
        Err(response) => return *response,
    };

    let grant = match load_active_grant(&state, &request_context, &session, &record.data_source_id)
    {
        Ok(grant) => grant,
        Err(response) => return *response,
    };
    let metric = match resolve_pivot_metric(&payload) {
        Ok(metric) => metric,
        Err(response) => return *response,
    };
    let requested_columns = pivot_requested_fields(&payload.dimension, &metric);
    if let Err(response) = authorize_fields(&grant, &requested_columns) {
        return *response;
    }
    let policy_map = load_field_policies(
        &state,
        &request_context,
        &record.data_source_id,
        &requested_columns,
    )
    .await;
    let access_profile = build_access_profile(&requested_columns, &policy_map);
    let response_format = payload
        .response_format
        .unwrap_or(AnalysisResponseFormat::Json);

    let provider = EncryptedSnapshotProvider::new(state.cipher.clone());
    let metric_field = metric.field().map(str::to_string);
    let percentile = metric.percentile_value();

    match response_format {
        AnalysisResponseFormat::Json => {
            let buckets = match provider
                .execute_pivot(&record, &access_profile, &payload.dimension, metric.clone())
                .await
            {
                Ok(buckets) => buckets,
                Err(error) => {
                    return data_view_error_response(error, "failed to execute snapshot pivot");
                }
            };
            phase2::append_phase2_audit_with_fields(
                &state,
                &session,
                &request_context,
                sdqp_audit::ActionType::View,
                ActionResult::Success,
                &payload.snapshot_id,
                "snapshot pivot analysis executed",
                phase2::Phase2AuditDetails::new(
                    build_pivot_audit_fields(
                        &payload.snapshot_id,
                        &record.data_source_id,
                        &requested_columns,
                        &payload.dimension,
                        &metric,
                        response_format,
                        buckets.len(),
                    ),
                    None,
                ),
            )
            .await;

            Json(PivotAnalysisResponse {
                snapshot_id: payload.snapshot_id,
                dimension: payload.dimension,
                metric: metric.label().into(),
                metric_field,
                percentile,
                buckets: buckets
                    .into_iter()
                    .map(|bucket| PivotBucketResponse {
                        key: bucket.key,
                        value: bucket.value,
                    })
                    .collect(),
                watermark_text: watermark_text(&request_context),
            })
            .into_response()
        }
        AnalysisResponseFormat::ArrowIpc => {
            let batches = match provider
                .execute_pivot_batches(&record, &access_profile, &payload.dimension, metric.clone())
                .await
            {
                Ok(result) => result,
                Err(error) => {
                    return data_view_error_response(error, "failed to execute snapshot pivot");
                }
            };
            let bucket_count = total_batch_rows(&batches.batches);
            let payload_bytes =
                match encode_record_batches_to_arrow_ipc(batches.schema, &batches.batches) {
                    Ok(payload) => payload,
                    Err(error) => {
                        return data_view_error_response(
                            error,
                            "failed to encode pivot analysis as arrow ipc",
                        );
                    }
                };
            phase2::append_phase2_audit_with_fields(
                &state,
                &session,
                &request_context,
                sdqp_audit::ActionType::View,
                ActionResult::Success,
                &payload.snapshot_id,
                "snapshot pivot analysis executed",
                phase2::Phase2AuditDetails::new(
                    build_pivot_audit_fields(
                        &payload.snapshot_id,
                        &record.data_source_id,
                        &requested_columns,
                        &payload.dimension,
                        &metric,
                        response_format,
                        bucket_count,
                    ),
                    None,
                ),
            )
            .await;

            arrow_ipc_response(
                payload_bytes,
                &PivotAnalysisArrowMetadata {
                    snapshot_id: payload.snapshot_id,
                    dimension: payload.dimension,
                    metric: metric.label().into(),
                    metric_field,
                    percentile,
                    watermark_text: watermark_text(&request_context),
                },
            )
        }
    }
}

pub async fn pivot_drilldown_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<DrilldownRequest>,
) -> Response {
    let record = match load_scoped_snapshot(
        &state,
        &payload.snapshot_id,
        &request_context,
        &session,
    )
    .await
    {
        Ok(record) => record,
        Err(response) => return *response,
    };

    let mut requested_fields = payload.fields.clone();
    if !requested_fields
        .iter()
        .any(|field| field == &payload.dimension)
    {
        requested_fields.push(payload.dimension.clone());
    }
    let grant = match load_active_grant(&state, &request_context, &session, &record.data_source_id)
    {
        Ok(grant) => grant,
        Err(response) => return *response,
    };
    if let Err(response) = authorize_fields(&grant, &requested_fields) {
        return *response;
    }
    let policy_map = load_field_policies(
        &state,
        &request_context,
        &record.data_source_id,
        &requested_fields,
    )
    .await;
    let access_profile = build_access_profile(&requested_fields, &policy_map);

    let provider = EncryptedSnapshotProvider::new(state.cipher.clone());
    let page = match provider
        .execute_drilldown(
            &record,
            &access_profile,
            &payload.dimension,
            &payload.value,
            &requested_fields,
            payload.page_size.unwrap_or(25),
            payload.cursor,
        )
        .await
    {
        Ok(page) => page,
        Err(error) => {
            return data_view_error_response(error, "failed to execute drilldown query");
        }
    };

    phase2::append_phase2_audit_with_fields(
        &state,
        &session,
        &request_context,
        sdqp_audit::ActionType::View,
        ActionResult::Success,
        &payload.snapshot_id,
        "snapshot drilldown query executed",
        phase2::Phase2AuditDetails::new(
            AuditContextFields::builder()
                .field("snapshot_id", payload.snapshot_id.clone())
                .field("data_source_id", record.data_source_id.clone())
                .field("operation", "drilldown")
                .field("dimension", payload.dimension.clone())
                .field("drilldown_value", payload.value.clone())
                .field("requested_fields", requested_fields.clone())
                .field("field_count", requested_fields.len())
                .field("page_size", payload.page_size.unwrap_or(25))
                .field("cursor_present", payload.cursor.is_some())
                .build(),
            None,
        ),
    )
    .await;

    Json(build_snapshot_page_response(
        &payload.snapshot_id,
        &requested_fields,
        &page.rows,
        page.next_cursor,
        &request_context,
        &policy_map,
    ))
    .into_response()
}

pub(crate) async fn load_scoped_snapshot(
    state: &Arc<ApiState>,
    snapshot_id: &str,
    request_context: &RequestContext,
    session: &AuthenticatedSession,
) -> Result<sdqp_encryption::EncryptedSnapshotRecord, ApiErrorResponse> {
    let cached_record = {
        state
            .snapshots
            .lock()
            .expect("snapshot store")
            .get(snapshot_id)
            .ok()
    };
    let record = match cached_record {
        Some(record) => record,
        None => {
            let Some(persistence) = &state.persistence else {
                return Err(Box::new(json_error(
                    StatusCode::NOT_FOUND,
                    "snapshot not found",
                )));
            };
            match persistence.load_snapshot(snapshot_id).await {
                Ok(Some(record)) => {
                    if record.lifecycle.delete_state != SnapshotDeleteState::Active {
                        return Err(Box::new(json_error(
                            StatusCode::NOT_FOUND,
                            "snapshot not found",
                        )));
                    }
                    state
                        .snapshots
                        .lock()
                        .expect("snapshot store")
                        .restore_record(record.clone());
                    record
                }
                _ => {
                    return Err(Box::new(json_error(
                        StatusCode::NOT_FOUND,
                        "snapshot not found",
                    )));
                }
            }
        }
    };

    if record.tenant_id != request_context.tenant_id.as_str()
        || record.project_id
            != request_context
                .project_id
                .as_ref()
                .expect("project scope")
                .as_str()
    {
        phase2::append_phase2_audit(
            state,
            session,
            request_context,
            sdqp_audit::ActionType::View,
            ActionResult::Denied,
            snapshot_id,
            "snapshot scope mismatch",
            None,
        )
        .await;
        return Err(Box::new(json_error(
            StatusCode::FORBIDDEN,
            "snapshot scope mismatch",
        )));
    }

    Ok(record)
}

fn load_active_grant(
    state: &Arc<ApiState>,
    request_context: &RequestContext,
    session: &AuthenticatedSession,
    data_source_id: &str,
) -> Result<PermissionGrant, ApiErrorResponse> {
    let project_id = request_context
        .project_id
        .as_ref()
        .expect("project scope")
        .as_str();

    state
        .permissions
        .lock()
        .expect("permission registry")
        .merged_active_grant(&session.claims.user_id, project_id, data_source_id)
        .ok_or_else(|| {
            Box::new(json_error(
                StatusCode::FORBIDDEN,
                "active permission grant not found",
            ))
        })
}

fn authorize_fields(grant: &PermissionGrant, fields: &[String]) -> Result<(), ApiErrorResponse> {
    let field_selectors = fields
        .iter()
        .map(FieldSelector::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            Box::new(json_error(
                StatusCode::BAD_REQUEST,
                "invalid field selector",
            ))
        })?;

    sdqp_permission_engine::apply_grant_to_query(grant, &field_selectors)
        .map(|_| ())
        .map_err(|error| Box::new(json_error(StatusCode::FORBIDDEN, &error.to_string())))
}

fn grant_allowed_snapshot_columns(
    grant: &PermissionGrant,
    snapshot_columns: &[String],
) -> Vec<String> {
    snapshot_columns
        .iter()
        .filter(|column| {
            grant
                .fields
                .iter()
                .any(|field| field.field_name == column.as_str() && !field.denied)
        })
        .cloned()
        .collect()
}

fn build_access_profile(
    columns: &[String],
    policy_map: &HashMap<String, FieldClassificationPolicy>,
) -> SnapshotAccessProfile {
    columns.iter().fold(
        SnapshotAccessProfile::new(columns.to_vec()),
        |profile, field_name| {
            let policy = policy_map
                .get(field_name)
                .cloned()
                .unwrap_or_else(|| fallback_policy(field_name));
            profile.with_masking_rule(field_name.clone(), policy.masking_strategy)
        },
    )
}

fn resolve_pivot_metric(payload: &PivotAnalysisRequest) -> Result<PivotMetric, ApiErrorResponse> {
    match payload.metric.unwrap_or(PivotMetricKind::RecordCount) {
        PivotMetricKind::RecordCount => Ok(PivotMetric::RecordCount),
        PivotMetricKind::CountDistinct => {
            Ok(PivotMetric::count_distinct(require_metric_field(payload)?))
        }
        PivotMetricKind::Sum => Ok(PivotMetric::sum(require_metric_field(payload)?)),
        PivotMetricKind::Avg => Ok(PivotMetric::avg(require_metric_field(payload)?)),
        PivotMetricKind::Min => Ok(PivotMetric::min(require_metric_field(payload)?)),
        PivotMetricKind::Max => Ok(PivotMetric::max(require_metric_field(payload)?)),
        PivotMetricKind::Median => Ok(PivotMetric::median(require_metric_field(payload)?)),
        PivotMetricKind::Percentile => {
            let field = require_metric_field(payload)?;
            let percentile = payload.percentile.ok_or_else(|| {
                Box::new(json_error(
                    StatusCode::BAD_REQUEST,
                    "percentile is required when metric=percentile",
                ))
            })?;
            PivotMetric::percentile(field, percentile)
                .map_err(|error| Box::new(json_error(StatusCode::BAD_REQUEST, &error.to_string())))
        }
    }
}

fn require_metric_field(payload: &PivotAnalysisRequest) -> Result<String, ApiErrorResponse> {
    let Some(metric_field) = payload
        .metric_field
        .clone()
        .filter(|field| !field.is_empty())
    else {
        return Err(Box::new(json_error(
            StatusCode::BAD_REQUEST,
            "metric_field is required for the selected pivot metric",
        )));
    };

    Ok(metric_field)
}

fn pivot_requested_fields(dimension: &str, metric: &PivotMetric) -> Vec<String> {
    let mut fields = vec![dimension.to_string()];
    if let Some(metric_field) = metric.field()
        && !fields.iter().any(|field| field == metric_field)
    {
        fields.push(metric_field.to_string());
    }
    fields
}

fn build_pivot_audit_fields(
    snapshot_id: &str,
    data_source_id: &str,
    requested_columns: &[String],
    dimension: &str,
    metric: &PivotMetric,
    response_format: AnalysisResponseFormat,
    bucket_count: usize,
) -> AuditContextFields {
    let mut fields = AuditContextFields::builder()
        .field("snapshot_id", snapshot_id.to_string())
        .field("data_source_id", data_source_id.to_string())
        .field("operation", "pivot_analysis")
        .field("requested_fields", requested_columns.to_vec())
        .field("field_count", requested_columns.len())
        .field("dimension", dimension.to_string())
        .field("metric", metric.label())
        .field("response_format", response_format.label())
        .field("bucket_count", bucket_count)
        .build();
    if let Some(metric_field) = metric.field() {
        fields.insert("metric_field", metric_field.to_string());
    }
    if let Some(percentile) = metric.percentile_value() {
        fields.insert("percentile", percentile.to_string());
    }
    fields
}

fn data_view_error_response(error: DataViewError, default_message: &str) -> Response {
    match error {
        DataViewError::NoAuthorizedColumns | DataViewError::UnauthorizedColumn(_) => {
            json_error(StatusCode::FORBIDDEN, &error.to_string())
        }
        DataViewError::InvalidPageSize
        | DataViewError::MissingColumn(_)
        | DataViewError::NonNumericMetricField(_)
        | DataViewError::InvalidPercentile => {
            json_error(StatusCode::BAD_REQUEST, &error.to_string())
        }
        _ => json_error(StatusCode::INTERNAL_SERVER_ERROR, default_message),
    }
}

fn build_snapshot_page_arrow_metadata(
    snapshot_id: &str,
    columns: &[String],
    next_cursor: Option<usize>,
    request_context: &RequestContext,
    policy_map: &HashMap<String, FieldClassificationPolicy>,
) -> SnapshotPageArrowMetadata {
    SnapshotPageArrowMetadata {
        snapshot_id: snapshot_id.to_string(),
        columns: columns.to_vec(),
        next_cursor,
        field_policies: build_field_policies(columns, policy_map),
        watermark_text: watermark_text(request_context),
    }
}

fn build_field_policies(
    columns: &[String],
    policy_map: &HashMap<String, FieldClassificationPolicy>,
) -> Vec<FieldDisplayPolicyResponse> {
    columns
        .iter()
        .map(|field_name| {
            let policy = policy_map
                .get(field_name)
                .cloned()
                .unwrap_or_else(|| fallback_policy(field_name));
            FieldDisplayPolicyResponse {
                field_name: field_name.clone(),
                masked: policy.masking_strategy != MaskingStrategy::None,
                render_mode: "canvas".into(),
                watermark_strength: format!("{:?}", policy.watermark_strength).to_lowercase(),
            }
        })
        .collect::<Vec<_>>()
}

fn arrow_ipc_response<T: Serialize>(payload: Vec<u8>, metadata: &T) -> Response {
    const ARROW_STREAM_CONTENT_TYPE: &str = "application/vnd.apache.arrow.stream";
    const RESPONSE_META_HEADER: &str = "x-sdqp-response-meta";

    let metadata_json = serde_json::to_vec(metadata).expect("arrow metadata json");
    let metadata_header =
        HeaderValue::from_str(&BASE64_STANDARD.encode(metadata_json)).expect("metadata header");
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(ARROW_STREAM_CONTENT_TYPE),
    );
    headers.insert(
        HeaderName::from_static(RESPONSE_META_HEADER),
        metadata_header,
    );

    (StatusCode::OK, headers, Body::from(payload)).into_response()
}

fn total_batch_rows(batches: &[RecordBatch]) -> usize {
    batches.iter().map(|batch| batch.num_rows()).sum()
}

async fn load_field_policies(
    state: &Arc<ApiState>,
    request_context: &RequestContext,
    data_source_id: &str,
    columns: &[String],
) -> HashMap<String, FieldClassificationPolicy> {
    let Some(project_id) = request_context
        .project_id
        .as_ref()
        .map(|project_id| project_id.as_str())
    else {
        return HashMap::new();
    };
    let Some(persistence) = &state.persistence else {
        return HashMap::new();
    };

    persistence
        .load_classification_policies(project_id, data_source_id, columns)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|policy| (policy.field_name.clone(), policy))
        .collect()
}

fn build_snapshot_page_response(
    snapshot_id: &str,
    columns: &[String],
    rows: &[HashMap<String, String>],
    next_cursor: Option<usize>,
    request_context: &RequestContext,
    policy_map: &HashMap<String, FieldClassificationPolicy>,
) -> SnapshotPageResponse {
    let field_policies = build_field_policies(columns, policy_map);

    let rows = rows
        .iter()
        .map(|row| {
            columns
                .iter()
                .filter_map(|field_name| {
                    row.get(field_name).map(|value| {
                        let policy = policy_map
                            .get(field_name)
                            .cloned()
                            .unwrap_or_else(|| fallback_policy(field_name));
                        (
                            field_name.clone(),
                            mask_value(&policy.masking_strategy, value),
                        )
                    })
                })
                .collect::<HashMap<_, _>>()
        })
        .collect::<Vec<_>>();

    SnapshotPageResponse {
        snapshot_id: snapshot_id.to_string(),
        columns: columns.to_vec(),
        rows,
        next_cursor,
        field_policies,
        watermark_text: watermark_text(request_context),
    }
}

fn validate_analysis_template_payload(
    payload: &AnalysisTemplateUpsertRequest,
) -> Result<Vec<String>, ApiErrorResponse> {
    if payload.name.trim().is_empty() {
        return Err(Box::new(json_error(
            StatusCode::BAD_REQUEST,
            "analysis template name is required",
        )));
    }
    if payload.data_source_id.trim().is_empty() {
        return Err(Box::new(json_error(
            StatusCode::BAD_REQUEST,
            "data_source_id is required",
        )));
    }
    if payload.config.page_size == Some(0) {
        return Err(Box::new(json_error(
            StatusCode::BAD_REQUEST,
            "page_size must be greater than zero",
        )));
    }
    if payload.config.pivot_dimension.trim().is_empty() {
        return Err(Box::new(json_error(
            StatusCode::BAD_REQUEST,
            "pivot_dimension is required",
        )));
    }
    if payload
        .config
        .detail_fields
        .iter()
        .any(|field| field.trim().is_empty())
    {
        return Err(Box::new(json_error(
            StatusCode::BAD_REQUEST,
            "detail_fields cannot contain blank values",
        )));
    }

    resolve_template_metric(&payload.config)?;
    Ok(analysis_template_requested_fields(&payload.config))
}

fn normalize_analysis_template_config(config: AnalysisTemplateConfig) -> AnalysisTemplateConfig {
    let mut detail_fields = Vec::new();
    for field in config
        .detail_fields
        .into_iter()
        .map(|field| field.trim().to_string())
        .filter(|field| !field.is_empty())
    {
        if !detail_fields
            .iter()
            .any(|existing: &String| existing == &field)
        {
            detail_fields.push(field);
        }
    }

    AnalysisTemplateConfig {
        page_size: config.page_size,
        detail_fields,
        pivot_dimension: config.pivot_dimension.trim().to_string(),
        pivot_metric: config.pivot_metric,
        pivot_metric_field: config
            .pivot_metric_field
            .map(|field| field.trim().to_string())
            .filter(|field| !field.is_empty()),
        pivot_percentile: config.pivot_percentile,
    }
}

fn analysis_template_requested_fields(config: &AnalysisTemplateConfig) -> Vec<String> {
    let metric = resolve_template_metric(config).ok();
    let mut fields = Vec::new();

    let push_unique = |fields: &mut Vec<String>, value: &str| {
        if !fields.iter().any(|existing| existing == value) {
            fields.push(value.to_string());
        }
    };

    push_unique(&mut fields, config.pivot_dimension.trim());
    for field in config
        .detail_fields
        .iter()
        .map(|field| field.trim())
        .filter(|field| !field.is_empty())
    {
        push_unique(&mut fields, field);
    }
    if let Some(metric) = metric
        && let Some(metric_field) = metric.field()
    {
        push_unique(&mut fields, metric_field);
    }

    fields
}

fn resolve_template_metric(
    config: &AnalysisTemplateConfig,
) -> Result<PivotMetric, ApiErrorResponse> {
    resolve_pivot_metric(&PivotAnalysisRequest {
        snapshot_id: String::new(),
        dimension: config.pivot_dimension.clone(),
        metric: Some(config.pivot_metric),
        metric_field: config.pivot_metric_field.clone(),
        percentile: config.pivot_percentile,
        response_format: None,
    })
}

fn visible_analysis_templates(
    state: &Arc<ApiState>,
    request_context: &RequestContext,
    session: &AuthenticatedSession,
) -> Vec<AnalysisTemplateRecord> {
    let mut templates = state
        .analysis_templates
        .lock()
        .expect("analysis template store")
        .values()
        .filter(|template| same_scope_analysis_template(template, request_context))
        .filter(|template| {
            template.owner_user_id == session.claims.user_id
                || template.visibility == AnalysisTemplateVisibility::Published
        })
        .cloned()
        .collect::<Vec<_>>();
    templates.sort_by(|left, right| {
        right
            .updated_at
            .cmp(&left.updated_at)
            .then_with(|| left.name.cmp(&right.name))
    });
    templates
}

fn same_scope_analysis_template(
    template: &AnalysisTemplateRecord,
    request_context: &RequestContext,
) -> bool {
    template.tenant_id == request_context.tenant_id.as_str()
        && template.project_id
            == request_context
                .project_id
                .as_ref()
                .expect("project scope")
                .as_str()
}

fn analysis_template_response(
    template: &AnalysisTemplateRecord,
    session: &AuthenticatedSession,
) -> AnalysisTemplateResponse {
    AnalysisTemplateResponse {
        template_id: template.template_id.clone(),
        name: template.name.clone(),
        description: template.description.clone(),
        data_source_id: template.data_source_id.clone(),
        visibility: template.visibility,
        owner_user_id: template.owner_user_id.clone(),
        editable: template.owner_user_id == session.claims.user_id,
        published_at: template.published_at,
        created_at: template.created_at,
        updated_at: template.updated_at,
        config: template.config.clone(),
    }
}

async fn load_accessible_analysis_template(
    state: &Arc<ApiState>,
    template_id: &str,
    request_context: &RequestContext,
    session: &AuthenticatedSession,
    denied_context: &str,
) -> Result<AnalysisTemplateRecord, ApiErrorResponse> {
    let Some(template) = state
        .analysis_templates
        .lock()
        .expect("analysis template store")
        .get(template_id)
        .cloned()
    else {
        return Err(Box::new(json_error(
            StatusCode::NOT_FOUND,
            "analysis template not found",
        )));
    };

    if !same_scope_analysis_template(&template, request_context) {
        return Err(Box::new(json_error(
            StatusCode::NOT_FOUND,
            "analysis template not found",
        )));
    }
    if template.owner_user_id != session.claims.user_id
        && template.visibility != AnalysisTemplateVisibility::Published
    {
        append_analysis_template_audit(
            state,
            session,
            request_context,
            sdqp_audit::ActionType::View,
            ActionResult::Denied,
            template_id,
            denied_context,
            AuditContextFields::builder()
                .field("operation", "analysis_template_get")
                .field("visibility", template.visibility.label())
                .build(),
        )
        .await;
        return Err(Box::new(json_error(
            StatusCode::FORBIDDEN,
            "analysis template is private to its owner",
        )));
    }

    Ok(template)
}

async fn load_owned_analysis_template(
    state: &Arc<ApiState>,
    template_id: &str,
    request_context: &RequestContext,
    session: &AuthenticatedSession,
    denied_context: &str,
) -> Result<AnalysisTemplateRecord, ApiErrorResponse> {
    let template = load_accessible_analysis_template(
        state,
        template_id,
        request_context,
        session,
        denied_context,
    )
    .await?;

    if template.owner_user_id != session.claims.user_id {
        append_analysis_template_audit(
            state,
            session,
            request_context,
            sdqp_audit::ActionType::ConfigChange,
            ActionResult::Denied,
            template_id,
            denied_context,
            AuditContextFields::builder()
                .field("operation", "analysis_template_owner_check")
                .field("visibility", template.visibility.label())
                .build(),
        )
        .await;
        return Err(Box::new(json_error(
            StatusCode::FORBIDDEN,
            "analysis template can only be modified by its owner",
        )));
    }

    Ok(template)
}

async fn persist_analysis_template(
    state: &Arc<ApiState>,
    template: AnalysisTemplateRecord,
) -> Result<AnalysisTemplateRecord, ApiErrorResponse> {
    if let Some(persistence) = &state.persistence
        && let Err(error) = persistence.save_analysis_template(&template).await
    {
        return Err(Box::new(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to persist analysis template: {error}"),
        )));
    }

    state
        .analysis_templates
        .lock()
        .expect("analysis template store")
        .insert(template.template_id.clone(), template.clone());
    Ok(template)
}

async fn delete_analysis_template(
    state: &Arc<ApiState>,
    template_id: &str,
) -> Result<(), ApiErrorResponse> {
    if let Some(persistence) = &state.persistence
        && let Err(error) = persistence.delete_analysis_template(template_id).await
    {
        return Err(Box::new(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to delete analysis template: {error}"),
        )));
    }

    state
        .analysis_templates
        .lock()
        .expect("analysis template store")
        .remove(template_id);
    Ok(())
}

async fn append_analysis_template_audit(
    state: &Arc<ApiState>,
    session: &AuthenticatedSession,
    request_context: &RequestContext,
    action: sdqp_audit::ActionType,
    result: ActionResult,
    resource_id: &str,
    context: &str,
    fields: AuditContextFields,
) {
    phase2::append_phase2_audit_with_fields(
        state,
        session,
        request_context,
        action,
        result,
        resource_id,
        context,
        phase2::Phase2AuditDetails::new(fields, None),
    )
    .await;
}

fn fallback_policy(field_name: &str) -> FieldClassificationPolicy {
    let rule_version = default_rule_version("project-display-fallback", "datasource-display");
    classify_fields(&rule_version, &[], &[field_name.to_string()], None)
        .into_iter()
        .next()
        .expect("fallback policy")
}

pub(crate) fn watermark_text(request_context: &RequestContext) -> String {
    format!(
        "{} / {} / {}",
        request_context.tenant_id.as_str(),
        request_context
            .project_id
            .as_ref()
            .map(|project_id| project_id.as_str())
            .unwrap_or("-"),
        request_context.user_id.as_str()
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use axum::{
        Extension, Json,
        body::to_bytes,
        extract::{Path, Query as QueryParams, State},
    };
    use base64::Engine as _;
    use chrono::{Duration, Utc};
    use http::StatusCode;
    use sdqp_config::AppSettings;
    use sdqp_core::{ProjectId, RequestContext, TenantId, UserId};
    use sdqp_data_classification::{MaskingStrategy, recommend_field_classification};
    use sdqp_data_view::encode_rows_to_parquet;
    use sdqp_datasource_adapter::FieldQueryResult;
    use sdqp_encryption::{SnapshotPayloadFormat, SnapshotStore, SnapshotWriteRequest};
    use sdqp_permission_engine::{FieldPermission, PermissionGrant};
    use sdqp_system_security::{SessionBinding, SessionPolicy};

    use super::{
        AnalysisResponseFormat, PivotAnalysisArrowMetadata, PivotAnalysisRequest,
        PivotAnalysisResponse, PivotMetricKind, SnapshotPageArrowMetadata, SnapshotPageQuery,
        SnapshotPageResponse, build_snapshot_page_response, fallback_policy,
        pivot_analysis_handler, snapshot_page_handler, watermark_text,
    };

    fn test_request_context() -> RequestContext {
        RequestContext::new(
            TenantId::new("tenant-alpha").expect("tenant"),
            UserId::new("user-analyst").expect("user"),
        )
        .with_project(ProjectId::new("project-alpha").expect("project"))
    }

    fn test_session() -> crate::AuthenticatedSession {
        crate::AuthenticatedSession {
            claims: SessionPolicy { ttl_minutes: 15 }.issue(
                &test_request_context(),
                SessionBinding {
                    ip_address: "127.0.0.1".into(),
                    device_fingerprint: "device-phase4-test".into(),
                },
            ),
            roles: Vec::new(),
        }
    }

    fn insert_snapshot(
        state: &Arc<crate::ApiState>,
        rows: Vec<Vec<FieldQueryResult>>,
        data_source_id: &str,
    ) -> sdqp_encryption::EncryptedSnapshotRecord {
        let encoded = encode_rows_to_parquet(&rows, None).expect("encoded snapshot");
        let encrypted = state
            .cipher
            .encrypt(&encoded.payload)
            .expect("encrypted snapshot");

        state.snapshots.lock().expect("snapshot store").put(
            SnapshotWriteRequest {
                tenant_id: "tenant-alpha".into(),
                project_id: "project-alpha".into(),
                owner_user_id: "user-analyst".into(),
                grant_id: "grant-phase4".into(),
                grant_expires_at: Utc::now() + Duration::hours(8),
                retention_until: Utc::now() + Duration::hours(8),
                data_source_id: data_source_id.into(),
                object_bucket: "sdqp-snapshots".into(),
                data_fingerprint: "fingerprint-phase4".into(),
                columns: encoded.columns,
                payload_format: SnapshotPayloadFormat::Parquet,
            },
            encrypted,
            rows.len(),
        )
    }

    async fn decode_response<T: serde::de::DeserializeOwned>(
        response: axum::response::Response,
    ) -> T {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    async fn decode_arrow_rows(
        response: axum::response::Response,
    ) -> (http::HeaderMap, Vec<HashMap<String, String>>) {
        use arrow::array::Array;

        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let reader = std::io::Cursor::new(bytes.to_vec());
        let mut stream =
            arrow::ipc::reader::StreamReader::try_new(reader, None).expect("stream reader");
        let batches = stream
            .by_ref()
            .collect::<Result<Vec<_>, _>>()
            .expect("batches");
        let mut rows = Vec::new();
        for batch in batches {
            let schema = batch.schema();
            for row_index in 0..batch.num_rows() {
                let mut row = HashMap::new();
                for (column_index, field) in schema.fields().iter().enumerate() {
                    let value = batch
                        .column(column_index)
                        .as_any()
                        .downcast_ref::<arrow::array::StringArray>()
                        .map(|array| {
                            if array.is_null(row_index) {
                                String::new()
                            } else {
                                array.value(row_index).to_string()
                            }
                        })
                        .or_else(|| {
                            batch
                                .column(column_index)
                                .as_any()
                                .downcast_ref::<arrow::array::Float64Array>()
                                .map(|array| array.value(row_index).to_string())
                        })
                        .or_else(|| {
                            batch
                                .column(column_index)
                                .as_any()
                                .downcast_ref::<arrow::array::UInt64Array>()
                                .map(|array| array.value(row_index).to_string())
                        })
                        .or_else(|| {
                            batch
                                .column(column_index)
                                .as_any()
                                .downcast_ref::<arrow::array::Int64Array>()
                                .map(|array| array.value(row_index).to_string())
                        })
                        .expect("supported arrow type");
                    row.insert(field.name().to_string(), value);
                }
                rows.push(row);
            }
        }

        (headers, rows)
    }

    #[test]
    fn page_response_masks_fields_using_classification_policy() {
        let response = build_snapshot_page_response(
            "snapshot-a",
            &["employee_email".into()],
            &[HashMap::from([(
                "employee_email".into(),
                "alice@example.com".into(),
            )])],
            None,
            &RequestContext::new(
                TenantId::new("tenant-alpha").expect("tenant"),
                UserId::new("user-analyst").expect("user"),
            )
            .with_project(ProjectId::new("project-alpha").expect("project")),
            &HashMap::new(),
        );

        assert_eq!(
            response.rows[0].get("employee_email").map(String::as_str),
            Some("a***@example.com")
        );
        assert!(response.field_policies[0].masked);
    }

    #[test]
    fn fallback_policy_matches_recommendation_contract() {
        let fallback = fallback_policy("employee_id");
        assert_eq!(
            fallback.masking_strategy,
            recommend_field_classification("employee_id").masking_strategy
        );
        assert_eq!(fallback.masking_strategy, MaskingStrategy::None);
    }

    #[test]
    fn watermark_text_uses_project_scope_identity() {
        let context = RequestContext::new(
            TenantId::new("tenant-alpha").expect("tenant"),
            UserId::new("user-analyst").expect("user"),
        )
        .with_project(ProjectId::new("project-alpha").expect("project"));

        assert_eq!(
            watermark_text(&context),
            "tenant-alpha / project-alpha / user-analyst"
        );
    }

    #[tokio::test]
    async fn snapshot_page_intersects_snapshot_columns_with_current_grant() {
        let state = Arc::new(crate::ApiState::new(AppSettings::local_dev().api));
        let record = insert_snapshot(
            &state,
            vec![vec![
                FieldQueryResult {
                    field: "employee_id".into(),
                    value: "E-1".into(),
                },
                FieldQueryResult {
                    field: "department".into(),
                    value: "fraud".into(),
                },
            ]],
            "datasource-rest",
        );
        state
            .permissions
            .lock()
            .expect("permission registry")
            .register_grant(PermissionGrant::active(
                "user-analyst",
                "project-alpha",
                "datasource-rest",
                vec![FieldPermission {
                    field_name: "department".into(),
                    denied: true,
                }],
                Vec::new(),
            ));

        let response = snapshot_page_handler(
            State(state),
            Path(record.snapshot_id.clone()),
            QueryParams(SnapshotPageQuery {
                page_size: Some(10),
                cursor: None,
                response_format: None,
            }),
            Extension(test_request_context()),
            Extension(test_session()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let page: SnapshotPageResponse = decode_response(response).await;
        assert_eq!(page.columns, vec!["employee_id".to_string()]);
        assert_eq!(page.rows.len(), 1);
        assert_eq!(
            page.rows[0].get("employee_id").map(String::as_str),
            Some("E-1")
        );
        assert!(!page.rows[0].contains_key("department"));
    }

    #[tokio::test]
    async fn pivot_analysis_masks_sensitive_dimensions_before_returning_buckets() {
        let state = Arc::new(crate::ApiState::new(AppSettings::local_dev().api));
        let record = insert_snapshot(
            &state,
            vec![
                vec![FieldQueryResult {
                    field: "employee_email".into(),
                    value: "alice@example.com".into(),
                }],
                vec![FieldQueryResult {
                    field: "employee_email".into(),
                    value: "bob@example.com".into(),
                }],
            ],
            "datasource-rest",
        );
        state
            .permissions
            .lock()
            .expect("permission registry")
            .register_grant(PermissionGrant::active(
                "user-analyst",
                "project-alpha",
                "datasource-rest",
                vec![FieldPermission {
                    field_name: "employee_email".into(),
                    denied: false,
                }],
                Vec::new(),
            ));

        let response = pivot_analysis_handler(
            State(state),
            Extension(test_request_context()),
            Extension(test_session()),
            Json(PivotAnalysisRequest {
                snapshot_id: record.snapshot_id.clone(),
                dimension: "employee_email".into(),
                metric: None,
                metric_field: None,
                percentile: None,
                response_format: None,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let pivot: PivotAnalysisResponse = decode_response(response).await;
        assert!(
            pivot
                .buckets
                .iter()
                .any(|bucket| bucket.key == "a***@example.com")
        );
        assert!(
            pivot
                .buckets
                .iter()
                .any(|bucket| bucket.key == "b***@example.com")
        );
        assert!(
            !pivot
                .buckets
                .iter()
                .any(|bucket| bucket.key == "alice@example.com")
        );
    }

    #[tokio::test]
    async fn pivot_analysis_supports_numeric_metric_fields() {
        let state = Arc::new(crate::ApiState::new(AppSettings::local_dev().api));
        let record = insert_snapshot(
            &state,
            vec![
                vec![
                    FieldQueryResult {
                        field: "department".into(),
                        value: "fraud".into(),
                    },
                    FieldQueryResult {
                        field: "case_id".into(),
                        value: "10".into(),
                    },
                ],
                vec![
                    FieldQueryResult {
                        field: "department".into(),
                        value: "fraud".into(),
                    },
                    FieldQueryResult {
                        field: "case_id".into(),
                        value: "20".into(),
                    },
                ],
                vec![
                    FieldQueryResult {
                        field: "department".into(),
                        value: "risk".into(),
                    },
                    FieldQueryResult {
                        field: "case_id".into(),
                        value: "5".into(),
                    },
                ],
            ],
            "datasource-rest",
        );
        state
            .permissions
            .lock()
            .expect("permission registry")
            .register_grant(PermissionGrant::active(
                "user-analyst",
                "project-alpha",
                "datasource-rest",
                vec![
                    FieldPermission {
                        field_name: "department".into(),
                        denied: false,
                    },
                    FieldPermission {
                        field_name: "case_id".into(),
                        denied: false,
                    },
                ],
                Vec::new(),
            ));

        let response = pivot_analysis_handler(
            State(state),
            Extension(test_request_context()),
            Extension(test_session()),
            Json(PivotAnalysisRequest {
                snapshot_id: record.snapshot_id.clone(),
                dimension: "department".into(),
                metric: Some(PivotMetricKind::Sum),
                metric_field: Some("case_id".into()),
                percentile: None,
                response_format: None,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let pivot: PivotAnalysisResponse = decode_response(response).await;
        assert_eq!(pivot.metric, "sum");
        assert_eq!(pivot.metric_field.as_deref(), Some("case_id"));
        assert_eq!(pivot.percentile, None);
        assert!(
            pivot
                .buckets
                .iter()
                .any(|bucket| bucket.key == "fraud" && bucket.value == 30.0)
        );
        assert!(
            pivot
                .buckets
                .iter()
                .any(|bucket| bucket.key == "risk" && bucket.value == 5.0)
        );
    }

    #[tokio::test]
    async fn pivot_analysis_rejects_unauthorized_metric_field() {
        let state = Arc::new(crate::ApiState::new(AppSettings::local_dev().api));
        let record = insert_snapshot(
            &state,
            vec![vec![
                FieldQueryResult {
                    field: "department".into(),
                    value: "fraud".into(),
                },
                FieldQueryResult {
                    field: "case_id".into(),
                    value: "10".into(),
                },
            ]],
            "datasource-rest",
        );
        state
            .permissions
            .lock()
            .expect("permission registry")
            .register_grant(PermissionGrant::active(
                "user-analyst",
                "project-alpha",
                "datasource-rest",
                vec![FieldPermission {
                    field_name: "department".into(),
                    denied: false,
                }],
                Vec::new(),
            ));

        let response = pivot_analysis_handler(
            State(state),
            Extension(test_request_context()),
            Extension(test_session()),
            Json(PivotAnalysisRequest {
                snapshot_id: record.snapshot_id.clone(),
                dimension: "department".into(),
                metric: Some(PivotMetricKind::Sum),
                metric_field: Some("case_id".into()),
                percentile: None,
                response_format: None,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn snapshot_page_supports_arrow_ipc_response_format() {
        let state = Arc::new(crate::ApiState::new(AppSettings::local_dev().api));
        let record = insert_snapshot(
            &state,
            vec![vec![
                FieldQueryResult {
                    field: "employee_email".into(),
                    value: "alice@example.com".into(),
                },
                FieldQueryResult {
                    field: "employee_id".into(),
                    value: "E-1".into(),
                },
            ]],
            "datasource-rest",
        );
        state
            .permissions
            .lock()
            .expect("permission registry")
            .register_grant(PermissionGrant::active(
                "user-analyst",
                "project-alpha",
                "datasource-rest",
                vec![
                    FieldPermission {
                        field_name: "employee_email".into(),
                        denied: false,
                    },
                    FieldPermission {
                        field_name: "employee_id".into(),
                        denied: false,
                    },
                ],
                Vec::new(),
            ));

        let response = snapshot_page_handler(
            State(state),
            Path(record.snapshot_id.clone()),
            QueryParams(SnapshotPageQuery {
                page_size: Some(10),
                cursor: None,
                response_format: Some(AnalysisResponseFormat::ArrowIpc),
            }),
            Extension(test_request_context()),
            Extension(test_session()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/vnd.apache.arrow.stream")
        );
        let metadata = response
            .headers()
            .get("x-sdqp-response-meta")
            .and_then(|value| value.to_str().ok())
            .expect("metadata header");
        let metadata: SnapshotPageArrowMetadata = serde_json::from_slice(
            &super::BASE64_STANDARD
                .decode(metadata)
                .expect("decode metadata"),
        )
        .expect("metadata json");
        assert_eq!(metadata.snapshot_id, record.snapshot_id);
        let (_, rows) = decode_arrow_rows(response).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get("employee_email").map(String::as_str),
            Some("a***@example.com")
        );
    }

    #[tokio::test]
    async fn pivot_analysis_supports_arrow_ipc_response_format() {
        let state = Arc::new(crate::ApiState::new(AppSettings::local_dev().api));
        let record = insert_snapshot(
            &state,
            vec![
                vec![
                    FieldQueryResult {
                        field: "department".into(),
                        value: "fraud".into(),
                    },
                    FieldQueryResult {
                        field: "case_id".into(),
                        value: "10".into(),
                    },
                ],
                vec![
                    FieldQueryResult {
                        field: "department".into(),
                        value: "fraud".into(),
                    },
                    FieldQueryResult {
                        field: "case_id".into(),
                        value: "20".into(),
                    },
                ],
            ],
            "datasource-rest",
        );
        state
            .permissions
            .lock()
            .expect("permission registry")
            .register_grant(PermissionGrant::active(
                "user-analyst",
                "project-alpha",
                "datasource-rest",
                vec![
                    FieldPermission {
                        field_name: "department".into(),
                        denied: false,
                    },
                    FieldPermission {
                        field_name: "case_id".into(),
                        denied: false,
                    },
                ],
                Vec::new(),
            ));

        let response = pivot_analysis_handler(
            State(state),
            Extension(test_request_context()),
            Extension(test_session()),
            Json(PivotAnalysisRequest {
                snapshot_id: record.snapshot_id.clone(),
                dimension: "department".into(),
                metric: Some(PivotMetricKind::Sum),
                metric_field: Some("case_id".into()),
                percentile: None,
                response_format: Some(AnalysisResponseFormat::ArrowIpc),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/vnd.apache.arrow.stream")
        );
        let metadata = response
            .headers()
            .get("x-sdqp-response-meta")
            .and_then(|value| value.to_str().ok())
            .expect("metadata header");
        let metadata: PivotAnalysisArrowMetadata = serde_json::from_slice(
            &super::BASE64_STANDARD
                .decode(metadata)
                .expect("decode metadata"),
        )
        .expect("metadata json");
        assert_eq!(metadata.metric, "sum");
        let (_, rows) = decode_arrow_rows(response).await;
        assert!(rows.iter().any(|row| {
            row.get("bucket_key").map(String::as_str) == Some("fraud")
                && row.get("metric_value").map(String::as_str) == Some("30")
        }));
    }
}
