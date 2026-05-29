use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use sdqp_audit::{ActionResult, ActionType, AuditContextFields};
use sdqp_core::RequestContext;
use sdqp_data_classification::{
    ClassificationCatalogEntry, ClassificationRule, ClassificationRuleVersion,
    ClassificationStatus, DataCategory, FieldClassificationPolicy, MaskingStrategy,
    RegulationReference, RetentionDisposalAction, RetentionPolicy, RuleVersionStatus,
    SensitivityLevel, WatermarkStrength,
};
use serde::{Deserialize, Serialize};

use crate::{ApiState, AuthenticatedSession, json_error, phase2};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulationResponse {
    pub code: String,
    pub jurisdiction: String,
    pub title: String,
    pub retention_basis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicyResponse {
    pub policy_id: String,
    pub retain_for_days: i64,
    pub disposal_action: String,
    pub legal_hold_supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationCatalogEntryResponse {
    pub catalog_entry_id: String,
    pub data_category: String,
    pub level: String,
    pub applicable_regulations: Vec<RegulationResponse>,
    pub retention_policy: RetentionPolicyResponse,
    pub manual_confirmation_required: bool,
    pub rule_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationCatalogResponse {
    pub project_id: String,
    pub data_source_id: String,
    pub active_rule_version_id: String,
    pub entries: Vec<ClassificationCatalogEntryResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationPolicyResponse {
    pub field_name: String,
    pub level: String,
    pub data_category: String,
    pub status: String,
    pub masking_strategy: String,
    pub watermark_strength: String,
    pub source: String,
    pub sample_value: Option<String>,
    pub rule_version_id: Option<String>,
    pub detection_run_id: Option<String>,
    pub catalog_entry_id: Option<String>,
    pub applicable_regulations: Vec<RegulationResponse>,
    pub retention_policy: RetentionPolicyResponse,
    pub manual_confirmation_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationPoliciesResponse {
    pub data_source_id: String,
    pub policies: Vec<ClassificationPolicyResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationRuleVersionResponse {
    pub rule_version_id: String,
    pub project_id: String,
    pub data_source_id: String,
    pub version_number: i32,
    pub status: String,
    pub rules: Vec<ClassificationRule>,
    pub catalog_entries: Vec<ClassificationCatalogEntryResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationRuleVersionsResponse {
    pub data_source_id: String,
    pub active_rule_version_id: Option<String>,
    pub versions: Vec<ClassificationRuleVersionResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateClassificationRuleVersionRequest {
    #[serde(default)]
    pub description: Option<String>,
    pub rules: Vec<ClassificationRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmClassificationRequest {
    pub fields: Vec<String>,
    #[serde(default)]
    pub rule_version_id: Option<String>,
    #[serde(default)]
    pub reviewer_note: Option<String>,
}

pub async fn list_classification_catalog_handler(
    State(state): State<Arc<ApiState>>,
    Path(data_source_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
) -> Response {
    let Some(project_id) = project_id(&request_context) else {
        return json_error(StatusCode::BAD_REQUEST, "missing project scope");
    };
    let Some(persistence) = &state.persistence else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "classification catalog requires persistent mode",
        );
    };

    match persistence
        .load_active_classification_rule_version(project_id, &data_source_id)
        .await
    {
        Ok(Some(rule_version)) => Json(ClassificationCatalogResponse {
            project_id: project_id.to_string(),
            data_source_id,
            active_rule_version_id: rule_version.rule_version_id,
            entries: rule_version
                .catalog_entries
                .into_iter()
                .map(map_catalog_entry_response)
                .collect(),
        })
        .into_response(),
        Ok(None) => json_error(
            StatusCode::NOT_FOUND,
            "active classification rule version not found",
        ),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to load classification catalog",
        ),
    }
}

pub async fn list_classification_rule_versions_handler(
    State(state): State<Arc<ApiState>>,
    Path(data_source_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
) -> Response {
    let Some(project_id) = project_id(&request_context) else {
        return json_error(StatusCode::BAD_REQUEST, "missing project scope");
    };
    let Some(persistence) = &state.persistence else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "classification rule versions require persistent mode",
        );
    };

    match persistence
        .list_classification_rule_versions(project_id, &data_source_id)
        .await
    {
        Ok(versions) => {
            let active_rule_version_id = versions
                .iter()
                .find(|version| version.status == RuleVersionStatus::Active)
                .map(|version| version.rule_version_id.clone());
            Json(ClassificationRuleVersionsResponse {
                data_source_id,
                active_rule_version_id,
                versions: versions
                    .into_iter()
                    .map(map_rule_version_response)
                    .collect(),
            })
            .into_response()
        }
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to load classification rule versions",
        ),
    }
}

pub async fn create_classification_rule_version_handler(
    State(state): State<Arc<ApiState>>,
    Path(data_source_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<CreateClassificationRuleVersionRequest>,
) -> Response {
    let Some(project_id) = project_id(&request_context) else {
        return json_error(StatusCode::BAD_REQUEST, "missing project scope");
    };
    let Some(persistence) = &state.persistence else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "classification rule versions require persistent mode",
        );
    };
    if payload.rules.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "rules cannot be empty");
    }

    match persistence
        .create_classification_rule_version(
            project_id,
            &data_source_id,
            payload.rules,
            &session.claims.user_id,
            payload.description.as_deref(),
        )
        .await
    {
        Ok(version) => {
            append_classification_audit(
                &state,
                &session,
                &request_context,
                &version.rule_version_id,
                "classification rule version created",
                ActionResult::Success,
                AuditContextFields::builder()
                    .field("data_source_id", data_source_id)
                    .field("rule_version_id", version.rule_version_id.clone())
                    .field("status", rule_version_status_label(&version.status))
                    .field("catalog_entry_count", version.catalog_entries.len())
                    .build(),
            )
            .await;
            (
                StatusCode::CREATED,
                Json(map_rule_version_response(version)),
            )
                .into_response()
        }
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to create classification rule version",
        ),
    }
}

pub async fn activate_classification_rule_version_handler(
    State(state): State<Arc<ApiState>>,
    Path((data_source_id, rule_version_id)): Path<(String, String)>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    update_rule_version_status(
        state,
        request_context,
        session,
        data_source_id,
        rule_version_id,
        true,
    )
    .await
}

pub async fn retire_classification_rule_version_handler(
    State(state): State<Arc<ApiState>>,
    Path((data_source_id, rule_version_id)): Path<(String, String)>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    update_rule_version_status(
        state,
        request_context,
        session,
        data_source_id,
        rule_version_id,
        false,
    )
    .await
}

async fn update_rule_version_status(
    state: Arc<ApiState>,
    request_context: RequestContext,
    session: AuthenticatedSession,
    data_source_id: String,
    rule_version_id: String,
    activate: bool,
) -> Response {
    let Some(project_id) = project_id(&request_context) else {
        return json_error(StatusCode::BAD_REQUEST, "missing project scope");
    };
    let Some(persistence) = &state.persistence else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "classification rule versions require persistent mode",
        );
    };

    let result = if activate {
        persistence
            .activate_classification_rule_version(
                project_id,
                &data_source_id,
                &rule_version_id,
                &session.claims.user_id,
            )
            .await
    } else {
        persistence
            .retire_classification_rule_version(
                project_id,
                &data_source_id,
                &rule_version_id,
                &session.claims.user_id,
            )
            .await
    };

    match result {
        Ok(Some(version)) => {
            append_classification_audit(
                &state,
                &session,
                &request_context,
                &rule_version_id,
                if activate {
                    "classification rule version activated"
                } else {
                    "classification rule version retired"
                },
                ActionResult::Success,
                AuditContextFields::builder()
                    .field("data_source_id", data_source_id)
                    .field("rule_version_id", rule_version_id.clone())
                    .field("status", rule_version_status_label(&version.status))
                    .build(),
            )
            .await;
            Json(map_rule_version_response(version)).into_response()
        }
        Ok(None) => json_error(
            StatusCode::NOT_FOUND,
            "classification rule version not found",
        ),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to update classification rule version",
        ),
    }
}

pub async fn list_classification_policies_handler(
    State(state): State<Arc<ApiState>>,
    Path(data_source_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
) -> Response {
    let Some(project_id) = project_id(&request_context) else {
        return json_error(StatusCode::BAD_REQUEST, "missing project scope");
    };
    let Some(persistence) = &state.persistence else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "classification policies require persistent mode",
        );
    };

    match persistence
        .load_classification_policies(project_id, &data_source_id, &[])
        .await
    {
        Ok(policies) => Json(ClassificationPoliciesResponse {
            data_source_id,
            policies: policies.into_iter().map(map_policy_response).collect(),
        })
        .into_response(),
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to load classification policies",
        ),
    }
}

pub async fn confirm_classification_policies_handler(
    State(state): State<Arc<ApiState>>,
    Path(data_source_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<ConfirmClassificationRequest>,
) -> Response {
    let Some(project_id) = project_id(&request_context) else {
        return json_error(StatusCode::BAD_REQUEST, "missing project scope");
    };
    let Some(persistence) = &state.persistence else {
        return json_error(
            StatusCode::NOT_IMPLEMENTED,
            "classification policies require persistent mode",
        );
    };

    let rule_version = match payload.rule_version_id.as_deref() {
        Some(rule_version_id) => match persistence
            .list_classification_rule_versions(project_id, &data_source_id)
            .await
        {
            Ok(versions) => versions
                .into_iter()
                .find(|version| version.rule_version_id == rule_version_id),
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load classification rule version",
                );
            }
        },
        None => match persistence
            .load_active_classification_rule_version(project_id, &data_source_id)
            .await
        {
            Ok(version) => version,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load active classification rule version",
                );
            }
        },
    };
    let Some(rule_version) = rule_version else {
        return json_error(
            StatusCode::NOT_FOUND,
            "classification rule version not found",
        );
    };

    match persistence
        .confirm_classification_policies(
            project_id,
            &data_source_id,
            &payload.fields,
            &session.claims.user_id,
            Some(&rule_version),
            payload.reviewer_note.as_deref(),
        )
        .await
    {
        Ok(policies) => {
            append_classification_audit(
                &state,
                &session,
                &request_context,
                &data_source_id,
                "classification policies manually confirmed",
                ActionResult::Success,
                AuditContextFields::builder()
                    .field("data_source_id", data_source_id.clone())
                    .field("rule_version_id", rule_version.rule_version_id)
                    .field("field_count", payload.fields.len())
                    .field("fields", payload.fields)
                    .build(),
            )
            .await;
            Json(ClassificationPoliciesResponse {
                data_source_id,
                policies: policies.into_iter().map(map_policy_response).collect(),
            })
            .into_response()
        }
        Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to confirm classification policies",
        ),
    }
}

async fn append_classification_audit(
    state: &Arc<ApiState>,
    session: &AuthenticatedSession,
    request_context: &RequestContext,
    resource_id: &str,
    context: &str,
    result: ActionResult,
    fields: AuditContextFields,
) {
    phase2::append_phase2_audit_with_fields(
        state,
        session,
        request_context,
        ActionType::ConfigChange,
        result,
        resource_id,
        context,
        phase2::Phase2AuditDetails::new(fields, None),
    )
    .await;
}

fn project_id(request_context: &RequestContext) -> Option<&str> {
    request_context
        .project_id
        .as_ref()
        .map(|project| project.as_str())
}

fn map_rule_version_response(
    version: ClassificationRuleVersion,
) -> ClassificationRuleVersionResponse {
    ClassificationRuleVersionResponse {
        rule_version_id: version.rule_version_id,
        project_id: version.project_id,
        data_source_id: version.data_source_id,
        version_number: version.version_number,
        status: rule_version_status_label(&version.status).into(),
        rules: version.rules,
        catalog_entries: version
            .catalog_entries
            .into_iter()
            .map(map_catalog_entry_response)
            .collect(),
    }
}

fn map_catalog_entry_response(
    entry: ClassificationCatalogEntry,
) -> ClassificationCatalogEntryResponse {
    ClassificationCatalogEntryResponse {
        catalog_entry_id: entry.catalog_entry_id,
        data_category: data_category_label(&entry.data_category).into(),
        level: level_label(&entry.level).into(),
        applicable_regulations: entry
            .applicable_regulations
            .into_iter()
            .map(map_regulation_response)
            .collect(),
        retention_policy: map_retention_policy_response(entry.retention_policy),
        manual_confirmation_required: entry.manual_confirmation_required,
        rule_ids: entry.rule_ids,
    }
}

fn map_policy_response(policy: FieldClassificationPolicy) -> ClassificationPolicyResponse {
    ClassificationPolicyResponse {
        field_name: policy.field_name,
        level: level_label(&policy.level).into(),
        data_category: data_category_label(&policy.data_category).into(),
        status: status_label(&policy.status).into(),
        masking_strategy: masking_strategy_label(&policy.masking_strategy).into(),
        watermark_strength: watermark_strength_label(&policy.watermark_strength).into(),
        source: source_label(&policy.source).into(),
        sample_value: policy.sample_value,
        rule_version_id: policy.rule_version_id,
        detection_run_id: policy.detection_run_id,
        catalog_entry_id: policy.catalog_entry_id,
        applicable_regulations: policy
            .applicable_regulations
            .into_iter()
            .map(map_regulation_response)
            .collect(),
        retention_policy: map_retention_policy_response(policy.retention_policy),
        manual_confirmation_required: policy.manual_confirmation_required,
    }
}

fn map_regulation_response(regulation: RegulationReference) -> RegulationResponse {
    RegulationResponse {
        code: regulation.code,
        jurisdiction: regulation.jurisdiction,
        title: regulation.title,
        retention_basis: regulation.retention_basis,
    }
}

fn map_retention_policy_response(policy: RetentionPolicy) -> RetentionPolicyResponse {
    RetentionPolicyResponse {
        policy_id: policy.policy_id,
        retain_for_days: policy.retain_for_days,
        disposal_action: retention_disposal_action_label(&policy.disposal_action).into(),
        legal_hold_supported: policy.legal_hold_supported,
    }
}

fn level_label(level: &SensitivityLevel) -> &'static str {
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

fn status_label(status: &ClassificationStatus) -> &'static str {
    match status {
        ClassificationStatus::PendingConfirmation => "pending_confirmation",
        ClassificationStatus::Confirmed => "confirmed",
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

fn watermark_strength_label(strength: &WatermarkStrength) -> &'static str {
    match strength {
        WatermarkStrength::Low => "low",
        WatermarkStrength::Medium => "medium",
        WatermarkStrength::High => "high",
        WatermarkStrength::Critical => "critical",
    }
}

fn source_label(source: &sdqp_data_classification::ClassificationPolicySource) -> &'static str {
    match source {
        sdqp_data_classification::ClassificationPolicySource::RuleEngine => "rule_engine",
        sdqp_data_classification::ClassificationPolicySource::SampleDetection => "sample_detection",
        sdqp_data_classification::ClassificationPolicySource::ManualConfirmation => {
            "manual_confirmation"
        }
    }
}

fn rule_version_status_label(status: &RuleVersionStatus) -> &'static str {
    match status {
        RuleVersionStatus::Draft => "draft",
        RuleVersionStatus::Active => "active",
        RuleVersionStatus::Retired => "retired",
    }
}

fn retention_disposal_action_label(action: &RetentionDisposalAction) -> &'static str {
    match action {
        RetentionDisposalAction::Review => "review",
        RetentionDisposalAction::Archive => "archive",
        RetentionDisposalAction::Purge => "purge",
    }
}
