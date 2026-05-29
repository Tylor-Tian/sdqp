use std::{collections::HashMap, str::FromStr, sync::Arc};

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, Utc};
use sdqp_audit::{ActionResult, ActionType, AuditContextFields, AuditEvent};
use sdqp_contracts::proto::watermark as watermark_proto;
use sdqp_core::RequestContext;
use sdqp_evidence::{
    BlockchainAnchorConfig, EvidenceBuildRequest, EvidenceBuilder, EvidenceMetadataManifest,
    EvidencePackage, EvidenceProviderRegistry, EvidenceRecipient, EvidenceTemplate,
    EvidenceVerificationReport, EvidenceVerificationStatus, MetadataDataSource,
    MetadataFieldDescriptor, MetadataGrantCondition, MetadataGrantDetails, MetadataQueryParameter,
    TsaProviderConfig,
};
use sdqp_permission_engine::PermissionGrant;
use sdqp_tenant_isolation::ProjectContext;
use sdqp_watermark::{
    BatchByteScanInput, DetectedWatermark, WatermarkContentFormat, WatermarkImplementationTier,
    WatermarkPayload, batch_scan_bytes, detect_markers_in_bytes_with_format, overlay_text,
    verify_bytes_with_format,
};
use serde::{Deserialize, Serialize};

use crate::{ApiState, AuthenticatedSession, json_error, phase2, phase4};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkMatchResponse {
    pub token: String,
    pub verified: bool,
    pub overlay_text: Option<String>,
    pub sequence_number: Option<u64>,
    pub provider: String,
    pub algorithm: String,
    pub implementation_tier: String,
    pub content_format: String,
    pub confidence_percent: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkDetectRequest {
    pub content: Option<String>,
    pub content_base64: Option<String>,
    pub content_format: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkDetectResponse {
    pub matches: Vec<WatermarkMatchResponse>,
    pub algorithm_match_count: usize,
    pub carrier_match_count: usize,
    pub legacy_match_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkVerifyRequest {
    pub content: Option<String>,
    pub content_base64: Option<String>,
    pub content_format: Option<String>,
    pub expected_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkVerifyResponse {
    pub verified: bool,
    pub algorithm_verified: bool,
    pub matches: Vec<WatermarkMatchResponse>,
    pub algorithm_match_count: usize,
    pub carrier_match_count: usize,
    pub legacy_match_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchScanDocumentRequest {
    pub document_id: String,
    pub content: Option<String>,
    pub content_base64: Option<String>,
    pub content_format: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchScanRequest {
    pub documents: Vec<BatchScanDocumentRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchScanDocumentResponse {
    pub document_id: String,
    pub verified: bool,
    pub algorithm_verified: bool,
    pub matches: Vec<WatermarkMatchResponse>,
    pub algorithm_match_count: usize,
    pub carrier_match_count: usize,
    pub legacy_match_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchScanResponse {
    pub reports: Vec<BatchScanDocumentResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpRequestScope {
    pub tenant_id: String,
    pub project_id: String,
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpInspectionContextRequest {
    pub caller_system: String,
    pub policy_id: String,
    pub source_uri: String,
    pub correlation_id: String,
    pub scope: Option<DlpRequestScope>,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpProviderConfigRequest {
    pub provider_id: Option<String>,
    pub provider_kind: String,
    pub webhook_url: Option<String>,
    pub auth_header: Option<String>,
    pub auth_token: Option<String>,
    pub timeout_ms: Option<u32>,
    pub default_action: Option<String>,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpPolicyEvaluateRequest {
    pub document_id: String,
    pub content: Option<String>,
    pub content_base64: Option<String>,
    pub content_format: Option<String>,
    pub media_type: Option<String>,
    pub expected_token: Option<String>,
    #[serde(default)]
    pub include_payload: bool,
    pub inspection_context: DlpInspectionContextRequest,
    pub provider_config: Option<DlpProviderConfigRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpDetectionSummaryResponse {
    pub watermark_present: bool,
    pub verified: bool,
    pub algorithm_verified: bool,
    pub match_count: u32,
    pub algorithm_match_count: u32,
    pub carrier_match_count: u32,
    pub legacy_match_count: u32,
    pub expected_token_matched: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpPolicyDecisionResponse {
    pub provider_id: String,
    pub provider_kind: String,
    pub policy_id: String,
    pub policy_version: String,
    pub disposition: String,
    pub action: String,
    pub callback_delivered: bool,
    pub enforcement_required: bool,
    pub reasons: Vec<String>,
    pub attributes: HashMap<String, String>,
    pub enforcement_ttl_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpPolicyEvaluateResponse {
    pub scan_id: String,
    pub document_id: String,
    pub inspection_context: DlpInspectionContextRequest,
    pub matches: Vec<WatermarkMatchResponse>,
    pub summary: Option<DlpDetectionSummaryResponse>,
    pub disposition: String,
    pub decision: DlpPolicyDecisionResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceExportRequest {
    pub snapshot_id: String,
    pub template: String,
    pub export_body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceExportResponse {
    pub task_id: String,
    pub status: String,
    pub verified: bool,
    pub integrity_verified: bool,
    pub verification_status: String,
    pub package_id: String,
    pub snapshot_id: String,
    pub template: String,
    pub jurisdiction: String,
    pub watermark_token: String,
    pub watermark_text: String,
    pub exported_document: String,
    pub audit_event_count: usize,
    pub audit_chain_valid: bool,
    pub hash_chain_digest: String,
    pub timestamp_provider: String,
    pub timestamp_runtime_mode: String,
    pub timestamp_authority: String,
    pub timestamp_token: String,
    pub anchor_provider: String,
    pub anchor_runtime_mode: String,
    pub anchor_status: String,
    pub anchor_network: String,
    pub anchor_transaction_id: String,
    pub anchor_block_number: Option<u64>,
    pub anchor_confirmed_at: Option<DateTime<Utc>>,
    pub anchor_failure_reason: Option<String>,
    pub provider_runtime_mode: String,
    pub external_final_uat_required: bool,
    pub mock_provider_components: Vec<String>,
    pub refresh_recommended: bool,
    pub recipient_user_id: String,
    pub data_payload_kms_provider: String,
    pub data_payload_dek_id: String,
    pub data_payload_scope_binding: String,
    pub audit_extract_event_count: usize,
    pub certificate_title: String,
    pub certificate_issued_at: DateTime<Utc>,
    pub manifest_digest: String,
    pub verification_ready: bool,
    pub file_name: String,
    pub media_type: String,
    pub download_ready: bool,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub last_anchor_refresh_at: Option<DateTime<Utc>>,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportDownloadAuthorizationRequest {
    pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportDownloadAuthorizationResponse {
    pub task_id: String,
    pub download_token: String,
    pub file_name: String,
    pub media_type: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ExportTaskRecord {
    pub task_id: String,
    pub status: String,
    pub verified: bool,
    #[serde(default)]
    pub integrity_verified: bool,
    #[serde(default)]
    pub verification_status: String,
    pub package_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub user_id: String,
    pub snapshot_id: String,
    pub template: String,
    pub jurisdiction: String,
    pub watermark_token: String,
    pub watermark_text: String,
    pub exported_document: String,
    pub audit_event_count: usize,
    pub audit_chain_valid: bool,
    pub hash_chain_digest: String,
    pub timestamp_provider: String,
    #[serde(default)]
    pub timestamp_runtime_mode: String,
    pub timestamp_authority: String,
    pub timestamp_token: String,
    pub anchor_provider: String,
    #[serde(default)]
    pub anchor_runtime_mode: String,
    pub anchor_status: String,
    pub anchor_network: String,
    pub anchor_transaction_id: String,
    pub anchor_block_number: Option<u64>,
    pub anchor_confirmed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_failure_reason: Option<String>,
    #[serde(default)]
    pub provider_runtime_mode: String,
    #[serde(default)]
    pub external_final_uat_required: bool,
    #[serde(default)]
    pub mock_provider_components: Vec<String>,
    #[serde(default)]
    pub refresh_recommended: bool,
    pub recipient_user_id: String,
    pub data_payload_kms_provider: String,
    pub data_payload_dek_id: String,
    pub data_payload_scope_binding: String,
    pub audit_extract_event_count: usize,
    pub certificate_title: String,
    pub certificate_issued_at: DateTime<Utc>,
    pub manifest_digest: String,
    pub verification_ready: bool,
    pub package_json: String,
    pub file_name: String,
    pub media_type: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_anchor_refresh_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DownloadAuthorizationRecord {
    pub download_token: String,
    pub task_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub user_id: String,
    pub file_name: String,
    pub media_type: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

pub async fn watermark_detect_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<WatermarkDetectRequest>,
) -> Response {
    let format = match resolve_content_format(
        payload.content_format.as_deref(),
        payload.content_base64.is_some(),
    ) {
        Ok(format) => format,
        Err(response) => return response,
    };
    let content = match resolve_request_bytes(
        payload.content.as_deref(),
        payload.content_base64.as_deref(),
        payload.content_format.as_deref(),
    ) {
        Ok(content) => content,
        Err(response) => return response,
    };
    let matches = detect_markers_in_bytes_with_format(&content, format);
    let (algorithm_match_count, carrier_match_count, legacy_match_count) = match_counts(&matches);
    phase2::append_phase2_audit(
        &state,
        &session,
        &request_context,
        ActionType::View,
        ActionResult::Success,
        "watermark-detect",
        "watermark detection executed",
        None,
    )
    .await;

    Json(WatermarkDetectResponse {
        matches: matches.iter().map(to_match_response).collect(),
        algorithm_match_count,
        carrier_match_count,
        legacy_match_count,
    })
    .into_response()
}

pub async fn watermark_verify_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<WatermarkVerifyRequest>,
) -> Response {
    let format = match resolve_content_format(
        payload.content_format.as_deref(),
        payload.content_base64.is_some(),
    ) {
        Ok(format) => format,
        Err(response) => return response,
    };
    let content = match resolve_request_bytes(
        payload.content.as_deref(),
        payload.content_base64.as_deref(),
        payload.content_format.as_deref(),
    ) {
        Ok(content) => content,
        Err(response) => return response,
    };
    let report = verify_bytes_with_format(&content, format, payload.expected_token.as_deref());
    let (algorithm_match_count, carrier_match_count, legacy_match_count) =
        match_counts(&report.matches);
    phase2::append_phase2_audit(
        &state,
        &session,
        &request_context,
        ActionType::View,
        ActionResult::Success,
        "watermark-verify",
        "watermark verification executed",
        None,
    )
    .await;

    Json(WatermarkVerifyResponse {
        verified: report.verified,
        algorithm_verified: report.algorithm_verified,
        matches: report.matches.iter().map(to_match_response).collect(),
        algorithm_match_count,
        carrier_match_count,
        legacy_match_count,
    })
    .into_response()
}

pub async fn watermark_batch_scan_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<BatchScanRequest>,
) -> Response {
    let mut documents = Vec::with_capacity(payload.documents.len());
    for document in &payload.documents {
        let format = match resolve_content_format(
            document.content_format.as_deref(),
            document.content_base64.is_some(),
        ) {
            Ok(format) => format,
            Err(response) => return response,
        };
        let content = match resolve_request_bytes(
            document.content.as_deref(),
            document.content_base64.as_deref(),
            document.content_format.as_deref(),
        ) {
            Ok(content) => content,
            Err(response) => return response,
        };
        documents.push(BatchByteScanInput {
            document_id: document.document_id.clone(),
            format,
            content,
        });
    }

    let reports = batch_scan_bytes(&documents);
    phase2::append_phase2_audit(
        &state,
        &session,
        &request_context,
        ActionType::View,
        ActionResult::Success,
        "watermark-batch-scan",
        "watermark batch scan executed",
        None,
    )
    .await;

    Json(BatchScanResponse {
        reports: reports
            .iter()
            .map(|report| {
                let (algorithm_match_count, carrier_match_count, legacy_match_count) =
                    match_counts(&report.matches);
                BatchScanDocumentResponse {
                    document_id: report.document_id.clone(),
                    verified: report.verified,
                    algorithm_verified: report.algorithm_verified,
                    matches: report.matches.iter().map(to_match_response).collect(),
                    algorithm_match_count,
                    carrier_match_count,
                    legacy_match_count,
                }
            })
            .collect(),
    })
    .into_response()
}

pub async fn watermark_dlp_evaluate_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<DlpPolicyEvaluateRequest>,
) -> Response {
    if payload.document_id.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "document_id is required");
    }
    if payload.inspection_context.caller_system.trim().is_empty()
        || payload.inspection_context.policy_id.trim().is_empty()
        || payload.inspection_context.correlation_id.trim().is_empty()
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "inspection_context caller_system, policy_id, and correlation_id are required",
        );
    }

    let format = match resolve_content_format(
        payload.content_format.as_deref(),
        payload.content_base64.is_some(),
    ) {
        Ok(format) => format,
        Err(response) => return response,
    };
    let content = match resolve_request_bytes(
        payload.content.as_deref(),
        payload.content_base64.as_deref(),
        payload.content_format.as_deref(),
    ) {
        Ok(content) => content,
        Err(response) => return response,
    };
    let provider_config = match payload.provider_config.as_ref() {
        Some(config) => match to_proto_provider_config(config) {
            Ok(config) => Some(config),
            Err(response) => return response,
        },
        None => None,
    };
    let inspection_context = to_proto_inspection_context(
        &payload.inspection_context,
        &request_context,
        &session.claims.user_id,
    );

    let response = match crate::watermark_grpc::evaluate_dlp_policy_request(
        &state.dlp_policy,
        watermark_proto::DlpPolicyEvaluationRequest {
            document: Some(watermark_proto::WatermarkDocument {
                document_id: payload.document_id.clone(),
                content,
                content_format: proto_content_format(format) as i32,
                media_type: payload
                    .media_type
                    .clone()
                    .unwrap_or_else(|| default_media_type(format).into()),
                inspection_context: Some(inspection_context),
            }),
            include_payload: payload.include_payload,
            expected_token: payload.expected_token.clone().unwrap_or_default(),
            provider_config,
        },
    )
    .await
    {
        Ok(response) => response,
        Err(status) => return dlp_status_error(status),
    };

    let Some(decision) = response.decision.as_ref() else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "DLP decision missing");
    };
    let detection = response
        .detection
        .as_ref()
        .expect("DLP evaluation returns detection");
    phase2::append_phase2_audit_with_fields(
        &state,
        &session,
        &request_context,
        ActionType::View,
        ActionResult::Success,
        "watermark-dlp-evaluate",
        "watermark DLP policy evaluation executed",
        phase2::Phase2AuditDetails::new(
            AuditContextFields::builder()
                .field("operation", "watermark_dlp_evaluate")
                .field("scan_id", detection.scan_id.clone())
                .field("document_id", detection.document_id.clone())
                .field(
                    "caller_system",
                    payload.inspection_context.caller_system.clone(),
                )
                .field("policy_id", payload.inspection_context.policy_id.clone())
                .field(
                    "disposition",
                    dlp_disposition_label(detection.disposition).to_string(),
                )
                .field("action", dlp_action_label(decision.action).to_string())
                .field("provider_id", decision.provider_id.clone())
                .field("callback_delivered", decision.callback_delivered)
                .build(),
            Some(payload.inspection_context.correlation_id.clone()),
        ),
    )
    .await;

    Json(to_dlp_policy_evaluate_response(response)).into_response()
}

pub async fn export_evidence_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(project_context): Extension<ProjectContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<EvidenceExportRequest>,
) -> Response {
    if !project_context.state.can_export() {
        phase2::append_phase2_audit(
            &state,
            &session,
            &request_context,
            ActionType::Export,
            ActionResult::Denied,
            "exports/evidence",
            "project does not allow exports",
            None,
        )
        .await;
        return json_error(
            axum::http::StatusCode::FORBIDDEN,
            "project does not allow exports",
        );
    }

    let record = match phase4::load_scoped_snapshot(
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
    let template = match EvidenceTemplate::from_str(&payload.template) {
        Ok(template) => template,
        Err(_) => {
            return json_error(
                axum::http::StatusCode::BAD_REQUEST,
                "unknown evidence template",
            );
        }
    };

    let audit_events = scoped_project_audit_events(&state, &request_context);
    if audit_events.is_empty() {
        return json_error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "audit ledger is empty",
        );
    }

    let watermark_payload = WatermarkPayload {
        tenant_id: request_context.tenant_id.as_str().to_string(),
        project_id: request_context
            .project_id
            .as_ref()
            .map(|project_id| project_id.as_str().to_string())
            .unwrap_or_else(|| "-".into()),
        user_id: request_context.user_id.as_str().to_string(),
        sequence_number: audit_events.len() as u64 + 1,
        issued_at: Utc::now(),
        snapshot_id: Some(record.snapshot_id.clone()),
    };
    let permission_grant = state
        .permissions
        .lock()
        .expect("permission registry")
        .merged_active_grant(
            request_context.user_id.as_str(),
            request_context
                .project_id
                .as_ref()
                .expect("project scope")
                .as_str(),
            &record.data_source_id,
        );
    let metadata_manifest = build_metadata_manifest(
        &record,
        &payload,
        permission_grant.as_ref(),
        &request_context,
    );
    let export_body = payload.export_body.unwrap_or_else(|| {
        format!(
            "Snapshot Storage Key: {}\nData Source: {}\nRow Count: {}\nViewer Overlay: {}",
            record.storage_key,
            record.data_source_id,
            record.row_count,
            phase4::watermark_text(&request_context)
        )
    });

    let builder = match build_evidence_builder(&state) {
        Ok(builder) => builder,
        Err(_) => {
            return json_error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "failed to initialize evidence providers",
            );
        }
    };
    let package = match builder
        .build_package(EvidenceBuildRequest {
            snapshot_id: record.snapshot_id.clone(),
            template,
            recipient: EvidenceRecipient {
                tenant_id: request_context.tenant_id.as_str().to_string(),
                project_id: request_context
                    .project_id
                    .as_ref()
                    .expect("project scope")
                    .as_str()
                    .to_string(),
                user_id: request_context.user_id.as_str().to_string(),
                delivery_channel: "authorized-download".into(),
            },
            metadata_manifest,
            watermark_payload,
            audit_events: audit_events.clone(),
            export_body,
        })
        .await
    {
        Ok(package) => package,
        Err(_) => {
            return json_error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build evidence package",
            );
        }
    };
    let verification = builder.verify_package(&package, &audit_events).await;
    let export_task = build_export_task_record(&request_context, &package, &verification);

    cache_export_task(&state, export_task.clone());
    if let Some(persistence) = &state.persistence {
        if persistence
            .save_evidence_package(
                &package,
                request_context.tenant_id.as_str(),
                request_context
                    .project_id
                    .as_ref()
                    .expect("project scope")
                    .as_str(),
                request_context.user_id.as_str(),
                &export_task.task_id,
                &export_task.file_name,
                &export_task.media_type,
            )
            .await
            .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist evidence package",
            );
        }
        if persistence.save_export_task(&export_task).await.is_err() {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist export task",
            );
        }
    }

    phase2::append_phase2_audit_with_fields(
        &state,
        &session,
        &request_context,
        ActionType::Export,
        ActionResult::Success,
        &package.package_id,
        "evidence package exported",
        phase2::Phase2AuditDetails::new(
            AuditContextFields::builder()
                .field("operation", "evidence_export")
                .field("package_id", package.package_id.clone())
                .field("snapshot_id", package.snapshot_id.clone())
                .field("template", payload.template.clone())
                .field("task_id", export_task.task_id.clone())
                .field("audit_event_count", package.audit_event_count)
                .field("verification_ready", export_task.verification_ready)
                .field(
                    "timestamp_provider",
                    package
                        .timestamp_receipt
                        .provider
                        .clone()
                        .unwrap_or_else(|| package.timestamp_receipt.authority.clone()),
                )
                .field(
                    "timestamp_authority",
                    package.timestamp_receipt.authority.clone(),
                )
                .field(
                    "anchor_provider",
                    package
                        .anchor_receipt
                        .provider
                        .clone()
                        .unwrap_or_else(|| package.anchor_receipt.network.clone()),
                )
                .field("anchor_network", package.anchor_receipt.network.clone())
                .field(
                    "recipient_user_id",
                    package.data_payload.recipient.user_id.clone(),
                )
                .field(
                    "data_payload_kms_provider",
                    package.data_payload.encrypted_payload.kms_provider.clone(),
                )
                .field(
                    "certificate_title",
                    package.certificate_of_authenticity.title.clone(),
                )
                .build(),
            Some(package.manifest_digest.clone()),
        ),
    )
    .await;

    Json(export_task_response(&export_task)).into_response()
}

pub async fn refresh_export_anchor_handler(
    State(state): State<Arc<ApiState>>,
    Path(task_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let Some(existing_task) = load_export_task(&state, &task_id).await else {
        return json_error(StatusCode::NOT_FOUND, "export task not found");
    };
    if !task_matches_scope(&existing_task, &request_context)
        || existing_task.user_id != request_context.user_id.as_str()
    {
        phase2::append_phase2_audit(
            &state,
            &session,
            &request_context,
            ActionType::Export,
            ActionResult::Denied,
            &task_id,
            "anchor refresh denied",
            None,
        )
        .await;
        return json_error(StatusCode::FORBIDDEN, "anchor refresh denied");
    }

    let mut package: EvidencePackage = match serde_json::from_str(&existing_task.package_json) {
        Ok(package) => package,
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to load evidence package",
            );
        }
    };
    let builder = match build_evidence_builder(&state) {
        Ok(builder) => builder,
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to initialize evidence providers",
            );
        }
    };
    if let Err(error) = builder.refresh_anchor_receipt(&mut package).await {
        let failed_task = mark_export_task_anchor_refresh_failed(&existing_task, error.to_string());
        cache_export_task(&state, failed_task.clone());
        if let Some(persistence) = &state.persistence {
            let _ = persistence.save_export_task(&failed_task).await;
        }
        phase2::append_phase2_audit_with_fields(
            &state,
            &session,
            &request_context,
            ActionType::Export,
            ActionResult::Failure,
            &package.package_id,
            "evidence anchor receipt refresh failed",
            phase2::Phase2AuditDetails::new(
                AuditContextFields::builder()
                    .field("operation", "evidence_anchor_refresh")
                    .field("package_id", package.package_id.clone())
                    .field("snapshot_id", package.snapshot_id.clone())
                    .field("task_id", failed_task.task_id.clone())
                    .field("anchor_provider", failed_task.anchor_provider.clone())
                    .field("anchor_network", failed_task.anchor_network.clone())
                    .field(
                        "error",
                        failed_task.failure_reason.clone().unwrap_or_default(),
                    )
                    .build(),
                Some(failed_task.manifest_digest.clone()),
            ),
        )
        .await;
        return json_error(StatusCode::BAD_GATEWAY, "failed to refresh anchor receipt");
    }

    let audit_events = scoped_project_audit_events(&state, &request_context);
    let verification = builder.verify_package(&package, &audit_events).await;
    let updated_task = synchronize_export_task_record(&existing_task, &package, &verification);

    cache_export_task(&state, updated_task.clone());
    if let Some(persistence) = &state.persistence {
        if persistence
            .save_evidence_package(
                &package,
                request_context.tenant_id.as_str(),
                request_context
                    .project_id
                    .as_ref()
                    .expect("project scope")
                    .as_str(),
                request_context.user_id.as_str(),
                &updated_task.task_id,
                &updated_task.file_name,
                &updated_task.media_type,
            )
            .await
            .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist evidence package",
            );
        }
        if persistence.save_export_task(&updated_task).await.is_err() {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist export task",
            );
        }
    }

    phase2::append_phase2_audit_with_fields(
        &state,
        &session,
        &request_context,
        ActionType::Export,
        ActionResult::Success,
        &package.package_id,
        "evidence anchor receipt refreshed",
        phase2::Phase2AuditDetails::new(
            AuditContextFields::builder()
                .field("operation", "evidence_anchor_refresh")
                .field("package_id", package.package_id.clone())
                .field("snapshot_id", package.snapshot_id.clone())
                .field("task_id", updated_task.task_id.clone())
                .field("anchor_provider", updated_task.anchor_provider.clone())
                .field("anchor_network", updated_task.anchor_network.clone())
                .field("anchor_status", updated_task.anchor_status.clone())
                .field("verified", updated_task.verified)
                .build(),
            Some(updated_task.manifest_digest.clone()),
        ),
    )
    .await;

    Json(export_task_response(&updated_task)).into_response()
}

pub async fn export_task_status_handler(
    State(state): State<Arc<ApiState>>,
    Path(task_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let Some(task) = load_export_task(&state, &task_id).await else {
        return json_error(StatusCode::NOT_FOUND, "export task not found");
    };
    if !task_matches_scope(&task, &request_context) {
        phase2::append_phase2_audit(
            &state,
            &session,
            &request_context,
            ActionType::Export,
            ActionResult::Denied,
            &task_id,
            "export task scope mismatch",
            None,
        )
        .await;
        return json_error(StatusCode::FORBIDDEN, "export task scope mismatch");
    }

    phase2::append_phase2_audit_with_fields(
        &state,
        &session,
        &request_context,
        ActionType::View,
        ActionResult::Success,
        &task_id,
        "export task status read",
        phase2::Phase2AuditDetails::new(
            AuditContextFields::builder()
                .field("operation", "export_task_status")
                .field("package_id", task.package_id.clone())
                .field("snapshot_id", task.snapshot_id.clone())
                .field("template", task.template.clone())
                .field("task_id", task.task_id.clone())
                .field("status", task.status.clone())
                .build(),
            Some(task.manifest_digest.clone()),
        ),
    )
    .await;

    Json(export_task_response(&task)).into_response()
}

pub async fn authorize_export_download_handler(
    State(state): State<Arc<ApiState>>,
    Path(task_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<ExportDownloadAuthorizationRequest>,
) -> Response {
    let Some(task) = load_export_task(&state, &task_id).await else {
        return json_error(StatusCode::NOT_FOUND, "export task not found");
    };
    if !task_matches_scope(&task, &request_context)
        || task.user_id != request_context.user_id.as_str()
    {
        phase2::append_phase2_audit(
            &state,
            &session,
            &request_context,
            ActionType::Export,
            ActionResult::Denied,
            &task_id,
            "download authorization denied",
            None,
        )
        .await;
        return json_error(StatusCode::FORBIDDEN, "download authorization denied");
    }
    if task.status != "completed" || !task.verified {
        phase2::append_phase2_audit_with_fields(
            &state,
            &session,
            &request_context,
            ActionType::Export,
            ActionResult::Denied,
            &task_id,
            "download authorization requires completed evidence certification",
            phase2::Phase2AuditDetails::new(
                AuditContextFields::builder()
                    .field("operation", "download_authorization")
                    .field("task_id", task.task_id.clone())
                    .field("status", task.status.clone())
                    .field("verification_status", task.verification_status.clone())
                    .field("anchor_status", task.anchor_status.clone())
                    .build(),
                Some(task.manifest_digest.clone()),
            ),
        )
        .await;
        return json_error(
            StatusCode::CONFLICT,
            "evidence certification is not completed",
        );
    }

    let ttl_seconds = payload.ttl_seconds.unwrap_or(300).clamp(60, 3600);
    let auth = DownloadAuthorizationRecord {
        download_token: ulid::Ulid::new().to_string(),
        task_id: task.task_id.clone(),
        tenant_id: task.tenant_id.clone(),
        project_id: task.project_id.clone(),
        user_id: task.user_id.clone(),
        file_name: task.file_name.clone(),
        media_type: task.media_type.clone(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::seconds(ttl_seconds),
        consumed_at: None,
    };

    cache_download_authorization(&state, auth.clone());
    if let Some(persistence) = &state.persistence
        && persistence
            .save_download_authorization(&auth)
            .await
            .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist download authorization",
        );
    }

    phase2::append_phase2_audit_with_fields(
        &state,
        &session,
        &request_context,
        ActionType::Export,
        ActionResult::Success,
        &task.package_id,
        "download authorization issued",
        phase2::Phase2AuditDetails::new(
            AuditContextFields::builder()
                .field("operation", "download_authorization")
                .field("package_id", task.package_id.clone())
                .field("snapshot_id", task.snapshot_id.clone())
                .field("template", task.template.clone())
                .field("task_id", task.task_id.clone())
                .field("download_token", auth.download_token.clone())
                .field("ttl_seconds", ttl_seconds.to_string())
                .build(),
            Some(task.manifest_digest.clone()),
        ),
    )
    .await;

    Json(ExportDownloadAuthorizationResponse {
        task_id: task.task_id,
        download_token: auth.download_token,
        file_name: auth.file_name,
        media_type: auth.media_type,
        expires_at: auth.expires_at,
    })
    .into_response()
}

pub async fn download_export_handler(
    State(state): State<Arc<ApiState>>,
    Path(download_token): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let Some(mut auth) = load_download_authorization(&state, &download_token).await else {
        return json_error(StatusCode::NOT_FOUND, "download authorization not found");
    };
    if auth.tenant_id != request_context.tenant_id.as_str()
        || auth.project_id
            != request_context
                .project_id
                .as_ref()
                .expect("project scope")
                .as_str()
        || auth.user_id != request_context.user_id.as_str()
    {
        phase2::append_phase2_audit(
            &state,
            &session,
            &request_context,
            ActionType::Export,
            ActionResult::Denied,
            &download_token,
            "download authorization scope mismatch",
            None,
        )
        .await;
        return json_error(
            StatusCode::FORBIDDEN,
            "download authorization scope mismatch",
        );
    }
    if auth.expires_at < Utc::now() {
        return json_error(StatusCode::GONE, "download authorization expired");
    }
    if auth.consumed_at.is_some() {
        return json_error(
            StatusCode::CONFLICT,
            "download authorization already consumed",
        );
    }

    let Some(task) = load_export_task(&state, &auth.task_id).await else {
        return json_error(StatusCode::NOT_FOUND, "export task not found");
    };

    auth.consumed_at = Some(Utc::now());
    cache_download_authorization(&state, auth.clone());
    if let Some(persistence) = &state.persistence
        && persistence
            .consume_download_authorization(&auth)
            .await
            .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to consume download authorization",
        );
    }

    phase2::append_phase2_audit_with_fields(
        &state,
        &session,
        &request_context,
        ActionType::Export,
        ActionResult::Success,
        &task.package_id,
        "evidence package downloaded",
        phase2::Phase2AuditDetails::new(
            AuditContextFields::builder()
                .field("operation", "evidence_download")
                .field("package_id", task.package_id.clone())
                .field("snapshot_id", task.snapshot_id.clone())
                .field("template", task.template.clone())
                .field("task_id", task.task_id.clone())
                .field("download_token", auth.download_token.clone())
                .field("file_name", task.file_name.clone())
                .field("media_type", task.media_type.clone())
                .build(),
            Some(task.manifest_digest.clone()),
        ),
    )
    .await;

    let mut response = task.package_json.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&task.media_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/json; charset=utf-8")),
    );
    if let Ok(value) =
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", task.file_name))
    {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    response
}

fn scoped_project_audit_events(
    state: &Arc<ApiState>,
    request_context: &RequestContext,
) -> Vec<AuditEvent> {
    state.audit.lock().expect("audit").scoped_events(
        request_context.tenant_id.as_str(),
        request_context
            .project_id
            .as_ref()
            .map(|project_id| project_id.as_str()),
        true,
    )
}

#[allow(clippy::result_large_err)]
fn resolve_request_bytes(
    content: Option<&str>,
    content_base64: Option<&str>,
    content_format: Option<&str>,
) -> Result<Vec<u8>, Response> {
    let _ = resolve_content_format(content_format, content_base64.is_some())?;
    match (content, content_base64) {
        (_, Some(content_base64)) => STANDARD
            .decode(content_base64)
            .map_err(|_| json_error(StatusCode::BAD_REQUEST, "invalid content_base64 payload")),
        (Some(content), None) => Ok(content.as_bytes().to_vec()),
        (None, None) => Err(json_error(
            StatusCode::BAD_REQUEST,
            "content or content_base64 is required",
        )),
    }
}

#[allow(clippy::result_large_err)]
fn resolve_content_format(
    content_format: Option<&str>,
    has_binary_payload: bool,
) -> Result<WatermarkContentFormat, Response> {
    match content_format {
        Some(value) => WatermarkContentFormat::parse(value)
            .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "unsupported content_format")),
        None if has_binary_payload => Ok(WatermarkContentFormat::Binary),
        None => Ok(WatermarkContentFormat::Text),
    }
}

#[allow(clippy::result_large_err)]
fn to_proto_provider_config(
    config: &DlpProviderConfigRequest,
) -> Result<watermark_proto::DlpProviderConfig, Response> {
    let provider_kind = match config.provider_kind.trim().to_ascii_lowercase().as_str() {
        "local" | "local-policy" | "local_policy" => watermark_proto::DlpProviderKind::LocalPolicy,
        "webhook" | "http-webhook" | "http_webhook" => watermark_proto::DlpProviderKind::Webhook,
        _ => {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "unsupported DLP provider_kind",
            ));
        }
    };
    let default_action = match config.default_action.as_deref() {
        Some(action) => parse_dlp_action(action)
            .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "unsupported DLP default_action"))?,
        None => watermark_proto::DlpAction::Unspecified,
    };

    Ok(watermark_proto::DlpProviderConfig {
        provider_id: config
            .provider_id
            .clone()
            .unwrap_or_else(|| "request-provider".into()),
        provider_kind: provider_kind as i32,
        webhook_url: config.webhook_url.clone().unwrap_or_default(),
        auth_header: config.auth_header.clone().unwrap_or_default(),
        auth_token: config.auth_token.clone().unwrap_or_default(),
        timeout_ms: config.timeout_ms.unwrap_or(3_000),
        attributes: config.attributes.clone(),
        default_action: default_action as i32,
    })
}

fn to_proto_inspection_context(
    context: &DlpInspectionContextRequest,
    request_context: &RequestContext,
    session_user_id: &str,
) -> watermark_proto::DlpInspectionContext {
    let scope = context
        .scope
        .as_ref()
        .cloned()
        .unwrap_or_else(|| DlpRequestScope {
            tenant_id: request_context.tenant_id.as_str().into(),
            project_id: request_context
                .project_id
                .as_ref()
                .map(|project_id| project_id.as_str().to_string())
                .unwrap_or_default(),
            user_id: session_user_id.into(),
        });
    watermark_proto::DlpInspectionContext {
        caller_system: context.caller_system.clone(),
        policy_id: context.policy_id.clone(),
        source_uri: context.source_uri.clone(),
        correlation_id: context.correlation_id.clone(),
        scope: Some(watermark_proto::WatermarkRequestScope {
            tenant_id: scope.tenant_id,
            project_id: scope.project_id,
            user_id: scope.user_id,
        }),
        attributes: context.attributes.clone(),
    }
}

fn proto_content_format(format: WatermarkContentFormat) -> watermark_proto::WatermarkContentFormat {
    match format {
        WatermarkContentFormat::Text => watermark_proto::WatermarkContentFormat::Text,
        WatermarkContentFormat::Pdf => watermark_proto::WatermarkContentFormat::Pdf,
        WatermarkContentFormat::Office => watermark_proto::WatermarkContentFormat::Office,
        WatermarkContentFormat::Image => watermark_proto::WatermarkContentFormat::Image,
        WatermarkContentFormat::Binary => watermark_proto::WatermarkContentFormat::Binary,
    }
}

fn default_media_type(format: WatermarkContentFormat) -> &'static str {
    match format {
        WatermarkContentFormat::Text => "text/plain",
        WatermarkContentFormat::Pdf => "application/pdf",
        WatermarkContentFormat::Office => {
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        }
        WatermarkContentFormat::Image => "application/octet-stream",
        WatermarkContentFormat::Binary => "application/octet-stream",
    }
}

fn parse_dlp_action(value: &str) -> Option<watermark_proto::DlpAction> {
    match value.trim().to_ascii_lowercase().as_str() {
        "allow" => Some(watermark_proto::DlpAction::Allow),
        "alert" => Some(watermark_proto::DlpAction::Alert),
        "quarantine" => Some(watermark_proto::DlpAction::Quarantine),
        "block" | "deny" => Some(watermark_proto::DlpAction::Block),
        "escalate" => Some(watermark_proto::DlpAction::Escalate),
        "unspecified" | "" => Some(watermark_proto::DlpAction::Unspecified),
        _ => None,
    }
}

fn dlp_status_error(status: tonic::Status) -> Response {
    let http_status = match status.code() {
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    json_error(http_status, status.message())
}

fn to_dlp_policy_evaluate_response(
    response: watermark_proto::DlpPolicyEvaluationResponse,
) -> DlpPolicyEvaluateResponse {
    let detection = response.detection.expect("detection");
    let decision = response.decision.expect("decision");
    let context = detection
        .inspection_context
        .clone()
        .map(dlp_context_response)
        .unwrap_or_else(|| DlpInspectionContextRequest {
            caller_system: String::new(),
            policy_id: String::new(),
            source_uri: String::new(),
            correlation_id: String::new(),
            scope: None,
            attributes: HashMap::new(),
        });

    DlpPolicyEvaluateResponse {
        scan_id: detection.scan_id.clone(),
        document_id: detection.document_id.clone(),
        inspection_context: context,
        matches: detection
            .matches
            .iter()
            .map(to_match_response_from_proto)
            .collect(),
        summary: detection
            .summary
            .as_ref()
            .map(|summary| DlpDetectionSummaryResponse {
                watermark_present: summary.watermark_present,
                verified: summary.verified,
                algorithm_verified: summary.algorithm_verified,
                match_count: summary.match_count,
                algorithm_match_count: summary.algorithm_match_count,
                carrier_match_count: summary.carrier_match_count,
                legacy_match_count: summary.legacy_match_count,
                expected_token_matched: summary.expected_token_matched,
            }),
        disposition: dlp_disposition_label(detection.disposition).into(),
        decision: DlpPolicyDecisionResponse {
            provider_id: decision.provider_id,
            provider_kind: dlp_provider_kind_label(decision.provider_kind).into(),
            policy_id: decision.policy_id,
            policy_version: decision.policy_version,
            disposition: dlp_disposition_label(decision.disposition).into(),
            action: dlp_action_label(decision.action).into(),
            callback_delivered: decision.callback_delivered,
            enforcement_required: decision.enforcement_required,
            reasons: decision.reasons,
            attributes: decision.attributes,
            enforcement_ttl_seconds: decision.enforcement_ttl_seconds,
        },
    }
}

fn dlp_context_response(
    context: watermark_proto::DlpInspectionContext,
) -> DlpInspectionContextRequest {
    DlpInspectionContextRequest {
        caller_system: context.caller_system,
        policy_id: context.policy_id,
        source_uri: context.source_uri,
        correlation_id: context.correlation_id,
        scope: context.scope.map(|scope| DlpRequestScope {
            tenant_id: scope.tenant_id,
            project_id: scope.project_id,
            user_id: scope.user_id,
        }),
        attributes: context.attributes,
    }
}

fn to_match_response_from_proto(
    match_result: &watermark_proto::WatermarkMatch,
) -> WatermarkMatchResponse {
    WatermarkMatchResponse {
        token: match_result.token.clone(),
        verified: match_result.verified,
        overlay_text: (!match_result.overlay_text.is_empty())
            .then(|| match_result.overlay_text.clone()),
        sequence_number: match_result
            .payload
            .as_ref()
            .map(|payload| payload.sequence_number),
        provider: match_result.provider.clone(),
        algorithm: match_result.algorithm.clone(),
        implementation_tier: watermark_tier_label(match_result.implementation_tier).into(),
        content_format: watermark_content_format_label(match_result.content_format).into(),
        confidence_percent: u8::try_from(match_result.confidence_percent).unwrap_or(u8::MAX),
    }
}

fn watermark_tier_label(value: i32) -> &'static str {
    match watermark_proto::WatermarkImplementationTier::try_from(value)
        .unwrap_or(watermark_proto::WatermarkImplementationTier::Unspecified)
    {
        watermark_proto::WatermarkImplementationTier::Algorithm => "algorithm",
        watermark_proto::WatermarkImplementationTier::Carrier => "carrier",
        watermark_proto::WatermarkImplementationTier::Legacy => "legacy",
        watermark_proto::WatermarkImplementationTier::Unspecified => "unspecified",
    }
}

fn watermark_content_format_label(value: i32) -> &'static str {
    match watermark_proto::WatermarkContentFormat::try_from(value)
        .unwrap_or(watermark_proto::WatermarkContentFormat::Unspecified)
    {
        watermark_proto::WatermarkContentFormat::Text => "text",
        watermark_proto::WatermarkContentFormat::Pdf => "pdf",
        watermark_proto::WatermarkContentFormat::Office => "office",
        watermark_proto::WatermarkContentFormat::Image => "image",
        watermark_proto::WatermarkContentFormat::Binary => "binary",
        watermark_proto::WatermarkContentFormat::Unspecified => "unspecified",
    }
}

fn dlp_provider_kind_label(value: i32) -> &'static str {
    match watermark_proto::DlpProviderKind::try_from(value)
        .unwrap_or(watermark_proto::DlpProviderKind::Unspecified)
    {
        watermark_proto::DlpProviderKind::LocalPolicy => "local-policy",
        watermark_proto::DlpProviderKind::Webhook => "webhook",
        watermark_proto::DlpProviderKind::Unspecified => "unspecified",
    }
}

fn dlp_disposition_label(value: i32) -> &'static str {
    match watermark_proto::DlpDisposition::try_from(value)
        .unwrap_or(watermark_proto::DlpDisposition::Unspecified)
    {
        watermark_proto::DlpDisposition::NoWatermark => "no_watermark",
        watermark_proto::DlpDisposition::WatermarkVerified => "watermark_verified",
        watermark_proto::DlpDisposition::WatermarkUnverified => "watermark_unverified",
        watermark_proto::DlpDisposition::ExpectedTokenMismatch => "expected_token_mismatch",
        watermark_proto::DlpDisposition::Unspecified => "unspecified",
    }
}

fn dlp_action_label(value: i32) -> &'static str {
    match watermark_proto::DlpAction::try_from(value)
        .unwrap_or(watermark_proto::DlpAction::Unspecified)
    {
        watermark_proto::DlpAction::Allow => "allow",
        watermark_proto::DlpAction::Alert => "alert",
        watermark_proto::DlpAction::Quarantine => "quarantine",
        watermark_proto::DlpAction::Block => "block",
        watermark_proto::DlpAction::Escalate => "escalate",
        watermark_proto::DlpAction::Unspecified => "unspecified",
    }
}

fn build_export_task_record(
    request_context: &RequestContext,
    package: &EvidencePackage,
    verification: &EvidenceVerificationReport,
) -> ExportTaskRecord {
    let created_at = Utc::now();
    let package_json =
        serde_json::to_string_pretty(package).expect("evidence package must serialize");
    let status = export_status_from_verification(verification);
    ExportTaskRecord {
        task_id: ulid::Ulid::new().to_string(),
        status,
        verified: verification.verified,
        integrity_verified: verification.integrity_verified,
        verification_status: verification.verification_status.as_str().into(),
        package_id: package.package_id.clone(),
        tenant_id: request_context.tenant_id.as_str().to_string(),
        project_id: request_context
            .project_id
            .as_ref()
            .expect("project scope")
            .as_str()
            .to_string(),
        user_id: request_context.user_id.as_str().to_string(),
        snapshot_id: package.snapshot_id.clone(),
        template: package.template.clone(),
        jurisdiction: package.jurisdiction_marker.jurisdiction.clone(),
        watermark_token: package.watermark_token.clone(),
        watermark_text: package.watermark_text.clone(),
        exported_document: package.exported_document.clone(),
        audit_event_count: package.audit_event_count,
        audit_chain_valid: package.manifest.audit_chain_valid,
        hash_chain_digest: package.hash_chain.final_digest.clone(),
        timestamp_provider: package
            .timestamp_receipt
            .provider
            .clone()
            .unwrap_or_else(|| package.timestamp_receipt.authority.clone()),
        timestamp_runtime_mode: package.provider_runtime.timestamp_runtime_mode.clone(),
        timestamp_authority: package.timestamp_receipt.authority.clone(),
        timestamp_token: package.timestamp_receipt.token.clone(),
        anchor_provider: package
            .anchor_receipt
            .provider
            .clone()
            .unwrap_or_else(|| package.anchor_receipt.network.clone()),
        anchor_runtime_mode: package.provider_runtime.anchor_runtime_mode.clone(),
        anchor_status: package.anchor_receipt.status.as_str().into(),
        anchor_network: package.anchor_receipt.network.clone(),
        anchor_transaction_id: package.anchor_receipt.transaction_id.clone(),
        anchor_block_number: package.anchor_receipt.block_number,
        anchor_confirmed_at: package.anchor_receipt.confirmed_at,
        anchor_failure_reason: package.anchor_receipt.failure_reason.clone(),
        provider_runtime_mode: package.provider_runtime.overall_mode.clone(),
        external_final_uat_required: package.provider_runtime.external_final_uat_required,
        mock_provider_components: package.provider_runtime.mock_components.clone(),
        refresh_recommended: verification.refresh_recommended,
        recipient_user_id: package.data_payload.recipient.user_id.clone(),
        data_payload_kms_provider: package.data_payload.encrypted_payload.kms_provider.clone(),
        data_payload_dek_id: package.data_payload.encrypted_payload.dek_id.clone(),
        data_payload_scope_binding: package.data_payload.scope_binding.clone(),
        audit_extract_event_count: package.audit_extract.len(),
        certificate_title: package.certificate_of_authenticity.title.clone(),
        certificate_issued_at: package.certificate_of_authenticity.issued_at,
        manifest_digest: package.manifest_digest.clone(),
        verification_ready: verification.verified,
        package_json,
        file_name: format!("evidence-{}-{}.json", package.snapshot_id, package.template),
        media_type: "application/json; charset=utf-8".into(),
        created_at,
        completed_at: if verification.verified {
            Some(created_at)
        } else {
            None
        },
        last_anchor_refresh_at: None,
        failure_reason: package.anchor_receipt.failure_reason.clone(),
    }
}

fn synchronize_export_task_record(
    existing: &ExportTaskRecord,
    package: &EvidencePackage,
    verification: &EvidenceVerificationReport,
) -> ExportTaskRecord {
    let package_json =
        serde_json::to_string_pretty(package).expect("evidence package must serialize");
    let now = Utc::now();
    let status = export_status_from_verification(verification);
    ExportTaskRecord {
        task_id: existing.task_id.clone(),
        status,
        verified: verification.verified,
        integrity_verified: verification.integrity_verified,
        verification_status: verification.verification_status.as_str().into(),
        package_id: package.package_id.clone(),
        tenant_id: existing.tenant_id.clone(),
        project_id: existing.project_id.clone(),
        user_id: existing.user_id.clone(),
        snapshot_id: package.snapshot_id.clone(),
        template: package.template.clone(),
        jurisdiction: package.jurisdiction_marker.jurisdiction.clone(),
        watermark_token: package.watermark_token.clone(),
        watermark_text: package.watermark_text.clone(),
        exported_document: package.exported_document.clone(),
        audit_event_count: package.audit_event_count,
        audit_chain_valid: package.manifest.audit_chain_valid,
        hash_chain_digest: package.hash_chain.final_digest.clone(),
        timestamp_provider: package
            .timestamp_receipt
            .provider
            .clone()
            .unwrap_or_else(|| package.timestamp_receipt.authority.clone()),
        timestamp_runtime_mode: package.provider_runtime.timestamp_runtime_mode.clone(),
        timestamp_authority: package.timestamp_receipt.authority.clone(),
        timestamp_token: package.timestamp_receipt.token.clone(),
        anchor_provider: package
            .anchor_receipt
            .provider
            .clone()
            .unwrap_or_else(|| package.anchor_receipt.network.clone()),
        anchor_runtime_mode: package.provider_runtime.anchor_runtime_mode.clone(),
        anchor_status: package.anchor_receipt.status.as_str().into(),
        anchor_network: package.anchor_receipt.network.clone(),
        anchor_transaction_id: package.anchor_receipt.transaction_id.clone(),
        anchor_block_number: package.anchor_receipt.block_number,
        anchor_confirmed_at: package.anchor_receipt.confirmed_at,
        anchor_failure_reason: package.anchor_receipt.failure_reason.clone(),
        provider_runtime_mode: package.provider_runtime.overall_mode.clone(),
        external_final_uat_required: package.provider_runtime.external_final_uat_required,
        mock_provider_components: package.provider_runtime.mock_components.clone(),
        refresh_recommended: verification.refresh_recommended,
        recipient_user_id: package.data_payload.recipient.user_id.clone(),
        data_payload_kms_provider: package.data_payload.encrypted_payload.kms_provider.clone(),
        data_payload_dek_id: package.data_payload.encrypted_payload.dek_id.clone(),
        data_payload_scope_binding: package.data_payload.scope_binding.clone(),
        audit_extract_event_count: package.audit_extract.len(),
        certificate_title: package.certificate_of_authenticity.title.clone(),
        certificate_issued_at: package.certificate_of_authenticity.issued_at,
        manifest_digest: package.manifest_digest.clone(),
        verification_ready: verification.verified,
        package_json,
        file_name: existing.file_name.clone(),
        media_type: existing.media_type.clone(),
        created_at: existing.created_at,
        completed_at: if verification.verified {
            Some(existing.completed_at.unwrap_or(now))
        } else {
            None
        },
        last_anchor_refresh_at: Some(now),
        failure_reason: package.anchor_receipt.failure_reason.clone(),
    }
}

fn mark_export_task_anchor_refresh_failed(
    existing: &ExportTaskRecord,
    reason: String,
) -> ExportTaskRecord {
    let mut failed = existing.clone();
    failed.status = "failed_anchor".into();
    failed.verified = false;
    failed.verification_ready = false;
    failed.verification_status = EvidenceVerificationStatus::FailedAnchor.as_str().into();
    failed.refresh_recommended = true;
    failed.failure_reason = Some(reason.clone());
    failed.anchor_failure_reason = Some(reason);
    failed.last_anchor_refresh_at = Some(Utc::now());
    failed.completed_at = None;
    failed
}

fn export_status_from_verification(verification: &EvidenceVerificationReport) -> String {
    match verification.verification_status {
        EvidenceVerificationStatus::Verified if verification.verified => "completed",
        EvidenceVerificationStatus::PendingAnchor => "pending_anchor",
        EvidenceVerificationStatus::FailedAnchor => "failed_anchor",
        _ => "failed",
    }
    .into()
}

fn build_evidence_builder(
    state: &ApiState,
) -> Result<EvidenceBuilder, sdqp_evidence::EvidenceError> {
    EvidenceProviderRegistry::from_configs(
        TsaProviderConfig {
            provider: state.integrations.tsa.provider.clone(),
            base_url: state.integrations.tsa.base_url.clone(),
            api_key: state.integrations.tsa.api_key.clone(),
            authority: state.integrations.tsa.authority.clone(),
            timeout_ms: state.integrations.tsa.timeout_ms,
            require_external: state.integrations.tsa.require_external,
        },
        BlockchainAnchorConfig {
            provider: state.integrations.blockchain_anchor.provider.clone(),
            base_url: state.integrations.blockchain_anchor.base_url.clone(),
            api_key: state.integrations.blockchain_anchor.api_key.clone(),
            network: state.integrations.blockchain_anchor.network.clone(),
            timeout_ms: state.integrations.blockchain_anchor.timeout_ms,
            require_external: state.integrations.blockchain_anchor.require_external,
        },
    )
    .map(|registry| registry.builder_with_cipher(state.cipher.clone()))
}

fn export_task_response(task: &ExportTaskRecord) -> EvidenceExportResponse {
    EvidenceExportResponse {
        task_id: task.task_id.clone(),
        status: task.status.clone(),
        verified: task.verified,
        integrity_verified: task.integrity_verified,
        verification_status: task.verification_status.clone(),
        package_id: task.package_id.clone(),
        snapshot_id: task.snapshot_id.clone(),
        template: task.template.clone(),
        jurisdiction: task.jurisdiction.clone(),
        watermark_token: task.watermark_token.clone(),
        watermark_text: task.watermark_text.clone(),
        exported_document: task.exported_document.clone(),
        audit_event_count: task.audit_event_count,
        audit_chain_valid: task.audit_chain_valid,
        hash_chain_digest: task.hash_chain_digest.clone(),
        timestamp_provider: task.timestamp_provider.clone(),
        timestamp_runtime_mode: task.timestamp_runtime_mode.clone(),
        timestamp_authority: task.timestamp_authority.clone(),
        timestamp_token: task.timestamp_token.clone(),
        anchor_provider: task.anchor_provider.clone(),
        anchor_runtime_mode: task.anchor_runtime_mode.clone(),
        anchor_status: task.anchor_status.clone(),
        anchor_network: task.anchor_network.clone(),
        anchor_transaction_id: task.anchor_transaction_id.clone(),
        anchor_block_number: task.anchor_block_number,
        anchor_confirmed_at: task.anchor_confirmed_at,
        anchor_failure_reason: task.anchor_failure_reason.clone(),
        provider_runtime_mode: task.provider_runtime_mode.clone(),
        external_final_uat_required: task.external_final_uat_required,
        mock_provider_components: task.mock_provider_components.clone(),
        refresh_recommended: task.refresh_recommended,
        recipient_user_id: task.recipient_user_id.clone(),
        data_payload_kms_provider: task.data_payload_kms_provider.clone(),
        data_payload_dek_id: task.data_payload_dek_id.clone(),
        data_payload_scope_binding: task.data_payload_scope_binding.clone(),
        audit_extract_event_count: task.audit_extract_event_count,
        certificate_title: task.certificate_title.clone(),
        certificate_issued_at: task.certificate_issued_at,
        manifest_digest: task.manifest_digest.clone(),
        verification_ready: task.verification_ready,
        file_name: task.file_name.clone(),
        media_type: task.media_type.clone(),
        download_ready: task.status == "completed" && task.verified,
        created_at: task.created_at,
        completed_at: task.completed_at,
        last_anchor_refresh_at: task.last_anchor_refresh_at,
        failure_reason: task.failure_reason.clone(),
    }
}

fn build_metadata_manifest(
    record: &sdqp_encryption::EncryptedSnapshotRecord,
    payload: &EvidenceExportRequest,
    permission_grant: Option<&PermissionGrant>,
    request_context: &RequestContext,
) -> EvidenceMetadataManifest {
    EvidenceMetadataManifest {
        field_descriptors: record
            .columns
            .iter()
            .enumerate()
            .map(|(ordinal, field_name)| MetadataFieldDescriptor {
                field_name: field_name.clone(),
                ordinal,
            })
            .collect(),
        query_parameters: vec![
            MetadataQueryParameter {
                name: "snapshot_id".into(),
                value: record.snapshot_id.clone(),
            },
            MetadataQueryParameter {
                name: "template".into(),
                value: payload.template.clone(),
            },
            MetadataQueryParameter {
                name: "tenant_id".into(),
                value: request_context.tenant_id.as_str().to_string(),
            },
            MetadataQueryParameter {
                name: "project_id".into(),
                value: request_context
                    .project_id
                    .as_ref()
                    .map(|project_id| project_id.as_str().to_string())
                    .unwrap_or_default(),
            },
        ],
        permission_grant: permission_grant.map(to_metadata_grant_details),
        data_source: MetadataDataSource {
            data_source_id: record.data_source_id.clone(),
            storage_key: record.storage_key.clone(),
            row_count: record.row_count,
            columns: record.columns.clone(),
        },
    }
}

fn to_metadata_grant_details(grant: &PermissionGrant) -> MetadataGrantDetails {
    let mut allowed_fields = Vec::new();
    let mut denied_fields = Vec::new();
    for field in &grant.fields {
        if field.denied {
            denied_fields.push(field.field_name.clone());
        } else {
            allowed_fields.push(field.field_name.clone());
        }
    }

    let mut conditions = grant
        .conditions
        .iter()
        .map(|condition| MetadataGrantCondition {
            field: condition.field.clone(),
            operator: format!("{:?}", condition.operator).to_ascii_lowercase(),
            value: condition.value.clone(),
        })
        .collect::<Vec<_>>();
    for group in &grant.condition_groups {
        for condition in &group.conditions {
            conditions.push(MetadataGrantCondition {
                field: condition.field.clone(),
                operator: format!("{:?}", condition.operator).to_ascii_lowercase(),
                value: condition.value.clone(),
            });
        }
    }

    MetadataGrantDetails {
        grant_id: grant.grant_id.clone(),
        applicant_user_id: grant.applicant_user_id.clone(),
        data_source_id: grant.data_source_id.clone(),
        allowed_fields,
        denied_fields,
        conditions,
        valid_from: grant.valid_from,
        valid_until: grant.valid_until,
        status: format!("{:?}", grant.status).to_ascii_lowercase(),
    }
}

fn cache_export_task(state: &Arc<ApiState>, task: ExportTaskRecord) {
    state
        .export_tasks
        .lock()
        .expect("export tasks")
        .insert(task.task_id.clone(), task);
}

fn cache_download_authorization(state: &Arc<ApiState>, auth: DownloadAuthorizationRecord) {
    state
        .download_tokens
        .lock()
        .expect("download tokens")
        .insert(auth.download_token.clone(), auth);
}

async fn load_export_task(state: &Arc<ApiState>, task_id: &str) -> Option<ExportTaskRecord> {
    if let Some(task) = state
        .export_tasks
        .lock()
        .expect("export tasks")
        .get(task_id)
        .cloned()
    {
        return Some(task);
    }
    let persistence = state.persistence.as_ref()?;
    let task = persistence.load_export_task(task_id).await.ok().flatten()?;
    cache_export_task(state, task.clone());
    Some(task)
}

async fn load_download_authorization(
    state: &Arc<ApiState>,
    token: &str,
) -> Option<DownloadAuthorizationRecord> {
    if let Some(auth) = state
        .download_tokens
        .lock()
        .expect("download tokens")
        .get(token)
        .cloned()
    {
        return Some(auth);
    }
    let persistence = state.persistence.as_ref()?;
    let auth = persistence
        .load_download_authorization(token)
        .await
        .ok()
        .flatten()?;
    cache_download_authorization(state, auth.clone());
    Some(auth)
}

fn task_matches_scope(task: &ExportTaskRecord, request_context: &RequestContext) -> bool {
    task.tenant_id == request_context.tenant_id.as_str()
        && task.project_id
            == request_context
                .project_id
                .as_ref()
                .expect("project scope")
                .as_str()
}

fn to_match_response(match_result: &DetectedWatermark) -> WatermarkMatchResponse {
    WatermarkMatchResponse {
        token: match_result.token.clone(),
        verified: match_result.verified,
        overlay_text: match_result
            .payload
            .as_ref()
            .map(overlay_text)
            .or_else(|| match_result.overlay_text.clone()),
        sequence_number: match_result
            .payload
            .as_ref()
            .map(|payload| payload.sequence_number),
        provider: match_result.provider.clone(),
        algorithm: algorithm_label(match_result.algorithm).into(),
        implementation_tier: match match_result.implementation_tier {
            WatermarkImplementationTier::Algorithm => "algorithm",
            WatermarkImplementationTier::Carrier => "carrier",
            WatermarkImplementationTier::Legacy => "legacy",
        }
        .into(),
        content_format: match_result.content_format.as_str().into(),
        confidence_percent: match_result.confidence_percent,
    }
}

fn match_counts(matches: &[DetectedWatermark]) -> (usize, usize, usize) {
    matches.iter().fold((0, 0, 0), |mut counts, match_result| {
        match match_result.implementation_tier {
            WatermarkImplementationTier::Algorithm => counts.0 += 1,
            WatermarkImplementationTier::Carrier => counts.1 += 1,
            WatermarkImplementationTier::Legacy => counts.2 += 1,
        }
        counts
    })
}

fn algorithm_label(algorithm: sdqp_watermark::WatermarkAlgorithm) -> &'static str {
    use sdqp_watermark::WatermarkAlgorithm;

    match algorithm {
        WatermarkAlgorithm::ZeroWidthTextV1 => "zero_width_text_v1",
        WatermarkAlgorithm::PngFrequencyDctV1 => "png_frequency_dct_v1",
        WatermarkAlgorithm::JpegCoefficientDctV1 => "jpeg_coefficient_dct_v1",
        WatermarkAlgorithm::PdfMetadataObjectCarrierV1 => "pdf_metadata_object_carrier_v1",
        WatermarkAlgorithm::PdfCommentCarrierV1 => "pdf_comment_carrier_v1",
        WatermarkAlgorithm::OoxmlCustomXmlCarrierV1 => "ooxml_custom_xml_carrier_v1",
        WatermarkAlgorithm::PngChunkCarrierV1 => "png_chunk_carrier_v1",
        WatermarkAlgorithm::JpegCommentCarrierV1 => "jpeg_comment_carrier_v1",
        WatermarkAlgorithm::BinaryTrailerCarrierV1 => "binary_trailer_carrier_v1",
        WatermarkAlgorithm::LegacyTextMarkerV0 => "legacy_text_marker_v0",
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use sdqp_encryption::DevelopmentEnvelopeCipher;
    use sdqp_evidence::{
        EvidenceMetadataManifest, MetadataDataSource, MetadataFieldDescriptor,
        MetadataQueryParameter,
    };
    use sdqp_watermark::{
        WatermarkPayload, detect_markers_in_bytes_with_format, embed_marker_bytes, encode_payload,
    };

    use super::{
        BatchScanDocumentRequest, EvidenceExportRequest, ExportDownloadAuthorizationRequest,
        WatermarkDetectRequest, WatermarkVerifyRequest, build_export_task_record,
        export_task_response, resolve_content_format, resolve_request_bytes,
    };

    fn sample_metadata_manifest() -> EvidenceMetadataManifest {
        EvidenceMetadataManifest {
            field_descriptors: vec![MetadataFieldDescriptor {
                field_name: "employee_id".into(),
                ordinal: 0,
            }],
            query_parameters: vec![MetadataQueryParameter {
                name: "snapshot_id".into(),
                value: "snapshot-a".into(),
            }],
            permission_grant: None,
            data_source: MetadataDataSource {
                data_source_id: "datasource-rest".into(),
                storage_key: "tenant-alpha/project-alpha/snapshot-a.snapshot.json.enc".into(),
                row_count: 1,
                columns: vec!["employee_id".into()],
            },
        }
    }

    #[test]
    fn request_models_round_trip_through_json() {
        let detect = serde_json::to_string(&WatermarkDetectRequest {
            content: Some("document".into()),
            content_base64: None,
            content_format: Some("text".into()),
        })
        .expect("detect");
        let verify = serde_json::to_string(&WatermarkVerifyRequest {
            content: Some("document".into()),
            content_base64: None,
            content_format: Some("text".into()),
            expected_token: Some("token".into()),
        })
        .expect("verify");
        let export = serde_json::to_string(&EvidenceExportRequest {
            snapshot_id: "snapshot-a".into(),
            template: "china".into(),
            export_body: Some("body".into()),
        })
        .expect("export");
        let authorize = serde_json::to_string(&ExportDownloadAuthorizationRequest {
            ttl_seconds: Some(300),
        })
        .expect("authorize");
        let batch = serde_json::to_string(&BatchScanDocumentRequest {
            document_id: "doc-a".into(),
            content: None,
            content_base64: Some("cGRm".into()),
            content_format: Some("pdf".into()),
        })
        .expect("batch");

        assert!(detect.contains("content_format"));
        assert!(verify.contains("expected_token"));
        assert!(export.contains("snapshot-a"));
        assert!(authorize.contains("ttl_seconds"));
        assert!(batch.contains("content_base64"));
    }

    #[test]
    fn watermark_detection_response_uses_sequence_number_from_payload() {
        let token = encode_payload(&WatermarkPayload {
            tenant_id: "tenant-alpha".into(),
            project_id: "project-alpha".into(),
            user_id: "user-analyst".into(),
            sequence_number: 5,
            issued_at: Utc::now(),
            snapshot_id: Some("snapshot-a".into()),
        })
        .expect("token");
        let detected = detect_markers_in_bytes_with_format(
            &embed_marker_bytes(b"body", &token, sdqp_watermark::WatermarkContentFormat::Pdf),
            sdqp_watermark::WatermarkContentFormat::Pdf,
        );
        let response = super::to_match_response(&detected[0]);

        assert_eq!(response.sequence_number, Some(5));
        assert!(response.verified);
    }

    #[test]
    fn content_resolution_supports_text_and_binary_payloads() {
        assert_eq!(
            resolve_content_format(Some("pdf"), true).expect("format"),
            sdqp_watermark::WatermarkContentFormat::Pdf
        );
        assert_eq!(
            resolve_request_bytes(None, Some("cGRm"), Some("pdf")).expect("bytes"),
            b"pdf"
        );
        assert_eq!(
            resolve_request_bytes(Some("text"), None, None).expect("text bytes"),
            b"text"
        );
    }

    #[tokio::test]
    async fn export_task_response_exposes_download_metadata() {
        let builder = sdqp_evidence::EvidenceBuilder::new(
            sdqp_evidence::MockTimestampAuthority::default(),
            sdqp_evidence::MockBlockchainAnchor::default(),
            DevelopmentEnvelopeCipher::new("dek-evidence", 0x5A),
        );
        let audit_events = vec![sdqp_audit::AuditEvent::new(
            sdqp_audit::ActorInfo {
                user_id: "user-analyst".into(),
                session_id: "session-a".into(),
                ip_address: "127.0.0.1".into(),
            },
            sdqp_audit::ActionType::Query,
            sdqp_audit::TargetRef {
                tenant_id: "tenant-alpha".into(),
                project_id: Some("project-alpha".into()),
                resource_id: "snapshot-a".into(),
            },
            "query completed",
            sdqp_audit::ActionResult::Success,
            None,
            None,
        )];
        let package = builder
            .build_package(sdqp_evidence::EvidenceBuildRequest {
                snapshot_id: "snapshot-a".into(),
                template: sdqp_evidence::EvidenceTemplate::ChinaJudicial,
                recipient: sdqp_evidence::EvidenceRecipient {
                    tenant_id: "tenant-alpha".into(),
                    project_id: "project-alpha".into(),
                    user_id: "user-analyst".into(),
                    delivery_channel: "authorized-download".into(),
                },
                metadata_manifest: sample_metadata_manifest(),
                watermark_payload: WatermarkPayload {
                    tenant_id: "tenant-alpha".into(),
                    project_id: "project-alpha".into(),
                    user_id: "user-analyst".into(),
                    sequence_number: 3,
                    issued_at: Utc::now(),
                    snapshot_id: Some("snapshot-a".into()),
                },
                audit_events: audit_events.clone(),
                export_body: "body".into(),
            })
            .await
            .expect("package");
        let context = sdqp_core::RequestContext::new(
            sdqp_core::TenantId::new("tenant-alpha").expect("tenant"),
            sdqp_core::UserId::new("user-analyst").expect("user"),
        )
        .with_project(sdqp_core::ProjectId::new("project-alpha").expect("project"));
        let verification = builder.verify_package(&package, &audit_events).await;
        let record = build_export_task_record(&context, &package, &verification);
        let response = export_task_response(&record);

        assert_eq!(response.status, "completed");
        assert!(response.verified);
        assert!(response.download_ready);
        assert_eq!(response.jurisdiction, "China Mainland");
        assert_eq!(response.recipient_user_id, "user-analyst");
        assert_eq!(response.audit_extract_event_count, 1);
        assert_eq!(response.data_payload_kms_provider, "development");
        assert_eq!(response.anchor_status, "confirmed");
        assert!(!response.hash_chain_digest.is_empty());
        assert!(response.file_name.ends_with(".json"));
    }
}
