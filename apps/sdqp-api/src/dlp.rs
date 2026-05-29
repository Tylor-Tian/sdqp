use std::{collections::HashMap, time::Duration};

use reqwest::header::{HeaderName, HeaderValue};
use sdqp_config::DlpIntegrationSettings;
use sdqp_contracts::proto::watermark::{
    DetectWatermarksResponse, DlpAction, DlpDisposition, DlpInspectionContext, DlpPolicyDecision,
    DlpProviderConfig, DlpProviderKind, WatermarkDetectionSummary, WatermarkMatch,
    WatermarkPayloadView, WatermarkRequestScope,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tonic::Status;

#[derive(Debug, Error)]
pub enum DlpProviderError {
    #[error("unsupported DLP provider kind: {0}")]
    UnsupportedProvider(i32),
    #[error("webhook DLP provider requires webhook_url")]
    MissingWebhookUrl,
    #[error("invalid DLP webhook auth header")]
    InvalidAuthHeader,
    #[error("invalid DLP webhook auth token")]
    InvalidAuthToken,
    #[error("DLP provider returned invalid action: {0}")]
    InvalidAction(String),
    #[error("DLP provider returned invalid disposition: {0}")]
    InvalidDisposition(String),
    #[error("DLP provider HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("DLP provider returned HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
}

impl DlpProviderError {
    pub fn into_status(self) -> Status {
        match self {
            Self::MissingWebhookUrl
            | Self::InvalidAction(_)
            | Self::InvalidDisposition(_)
            | Self::InvalidAuthHeader
            | Self::InvalidAuthToken
            | Self::UnsupportedProvider(_) => Status::invalid_argument(self.to_string()),
            Self::Http(_) | Self::HttpStatus { .. } => Status::unavailable(self.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DlpPolicyProviderRegistry {
    client: reqwest::Client,
    default_config: DlpProviderConfig,
}

impl Default for DlpPolicyProviderRegistry {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
            default_config: DlpProviderConfig {
                provider_id: "sdqp-local-policy".into(),
                provider_kind: DlpProviderKind::LocalPolicy as i32,
                webhook_url: String::new(),
                auth_header: String::new(),
                auth_token: String::new(),
                timeout_ms: 3_000,
                attributes: HashMap::new(),
                default_action: DlpAction::Unspecified as i32,
            },
        }
    }
}

impl DlpPolicyProviderRegistry {
    pub fn from_settings(settings: &DlpIntegrationSettings) -> Self {
        Self {
            default_config: provider_config_from_settings(settings),
            ..Self::default()
        }
    }

    pub async fn evaluate(
        &self,
        provider_config: Option<DlpProviderConfig>,
        detection: &DetectWatermarksResponse,
    ) -> Result<DlpPolicyDecision, DlpProviderError> {
        let config = provider_config
            .filter(provider_config_is_present)
            .unwrap_or_else(|| self.default_config.clone());
        match resolve_provider_kind(&config)? {
            DlpProviderKind::LocalPolicy | DlpProviderKind::Unspecified => {
                Ok(local_policy_decision(&config, detection))
            }
            DlpProviderKind::Webhook => self.evaluate_webhook(&config, detection).await,
        }
    }

    async fn evaluate_webhook(
        &self,
        config: &DlpProviderConfig,
        detection: &DetectWatermarksResponse,
    ) -> Result<DlpPolicyDecision, DlpProviderError> {
        if config.webhook_url.trim().is_empty() {
            return Err(DlpProviderError::MissingWebhookUrl);
        }

        let recommended = local_policy_decision(config, detection);
        let payload = DlpPolicyWebhookRequest::from_detection(config, detection, &recommended);
        let mut request = self
            .client
            .post(config.webhook_url.trim())
            .timeout(Duration::from_millis(timeout_ms(config)))
            .json(&payload);
        if !config.auth_header.trim().is_empty() || !config.auth_token.trim().is_empty() {
            let name = HeaderName::from_bytes(config.auth_header.trim().as_bytes())
                .map_err(|_| DlpProviderError::InvalidAuthHeader)?;
            let value = HeaderValue::from_str(config.auth_token.trim())
                .map_err(|_| DlpProviderError::InvalidAuthToken)?;
            request = request.header(name, value);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(DlpProviderError::HttpStatus {
                status: status.as_u16(),
                body,
            });
        }

        let callback = response.json::<DlpPolicyWebhookResponse>().await?;
        callback.into_decision(config, detection, recommended)
    }
}

pub fn provider_config_from_settings(settings: &DlpIntegrationSettings) -> DlpProviderConfig {
    DlpProviderConfig {
        provider_id: if settings.provider_id.trim().is_empty() {
            "sdqp-local-policy".into()
        } else {
            settings.provider_id.clone()
        },
        provider_kind: provider_kind_from_label(&settings.provider) as i32,
        webhook_url: settings.webhook_url.clone(),
        auth_header: settings.auth_header.clone(),
        auth_token: settings.auth_token.clone(),
        timeout_ms: u32::try_from(settings.timeout_ms).unwrap_or(u32::MAX),
        attributes: HashMap::new(),
        default_action: parse_action_label(&settings.default_action)
            .unwrap_or(DlpAction::Unspecified) as i32,
    }
}

fn provider_config_is_present(config: &DlpProviderConfig) -> bool {
    !config.provider_id.trim().is_empty()
        || config.provider_kind != DlpProviderKind::Unspecified as i32
        || !config.webhook_url.trim().is_empty()
}

fn resolve_provider_kind(config: &DlpProviderConfig) -> Result<DlpProviderKind, DlpProviderError> {
    let kind = DlpProviderKind::try_from(config.provider_kind)
        .map_err(|_| DlpProviderError::UnsupportedProvider(config.provider_kind))?;
    if kind == DlpProviderKind::Unspecified && !config.webhook_url.trim().is_empty() {
        return Ok(DlpProviderKind::Webhook);
    }
    Ok(kind)
}

fn provider_kind_from_label(value: &str) -> DlpProviderKind {
    match normalize_label(value).as_str() {
        "webhook" | "httpwebhook" | "http" => DlpProviderKind::Webhook,
        "local" | "localpolicy" | "builtin" | "" => DlpProviderKind::LocalPolicy,
        _ => DlpProviderKind::Unspecified,
    }
}

fn local_policy_decision(
    config: &DlpProviderConfig,
    detection: &DetectWatermarksResponse,
) -> DlpPolicyDecision {
    let disposition = disposition_from_detection(detection);
    let (mapped_action, mut reasons) = action_for_disposition(disposition, detection);

    let action = detection
        .inspection_context
        .as_ref()
        .and_then(|context| context.attributes.get("dlp.policy_action"))
        .and_then(|value| parse_action_label(value))
        .or_else(|| {
            let action = DlpAction::try_from(config.default_action).ok()?;
            (action != DlpAction::Unspecified).then_some(action)
        })
        .unwrap_or(mapped_action);

    if action != mapped_action {
        reasons.push(format!(
            "policy override changed mapped action from {} to {}",
            action_label(mapped_action),
            action_label(action)
        ));
    }

    let mut attributes = HashMap::from([
        (
            "sdqp.policy.mapper".into(),
            "watermark-disposition-v1".into(),
        ),
        ("sdqp.policy.provider_mode".into(), "local-policy".into()),
    ]);
    attributes.extend(config.attributes.clone());

    DlpPolicyDecision {
        provider_id: provider_id(config),
        provider_kind: DlpProviderKind::LocalPolicy as i32,
        policy_id: detection
            .inspection_context
            .as_ref()
            .map(|context| context.policy_id.clone())
            .unwrap_or_default(),
        policy_version: "watermark-disposition-v1".into(),
        disposition: disposition as i32,
        action: action as i32,
        callback_delivered: false,
        enforcement_required: enforcement_required(action),
        reasons,
        attributes,
        enforcement_ttl_seconds: 0,
    }
}

fn action_for_disposition(
    disposition: DlpDisposition,
    detection: &DetectWatermarksResponse,
) -> (DlpAction, Vec<String>) {
    let require_watermark = detection
        .inspection_context
        .as_ref()
        .and_then(|context| context.attributes.get("dlp.require_watermark"))
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);

    match disposition {
        DlpDisposition::NoWatermark if require_watermark => (
            DlpAction::Block,
            vec!["policy requires an SDQP watermark but no watermark was detected".into()],
        ),
        DlpDisposition::NoWatermark => (
            DlpAction::Allow,
            vec!["no SDQP watermark was detected and watermark presence is not required".into()],
        ),
        DlpDisposition::WatermarkVerified => (
            DlpAction::Alert,
            vec![
                "verified SDQP watermark identified; provenance is available for DLP triage".into(),
            ],
        ),
        DlpDisposition::WatermarkUnverified => (
            DlpAction::Quarantine,
            vec!["watermark-like content was detected but could not be verified".into()],
        ),
        DlpDisposition::ExpectedTokenMismatch => (
            DlpAction::Block,
            vec!["detected watermark does not match the expected policy token".into()],
        ),
        DlpDisposition::Unspecified => (
            DlpAction::Alert,
            vec!["DLP disposition was unspecified; using conservative alert action".into()],
        ),
    }
}

fn disposition_from_detection(detection: &DetectWatermarksResponse) -> DlpDisposition {
    DlpDisposition::try_from(detection.disposition).unwrap_or(DlpDisposition::Unspecified)
}

fn provider_id(config: &DlpProviderConfig) -> String {
    if config.provider_id.trim().is_empty() {
        "sdqp-local-policy".into()
    } else {
        config.provider_id.clone()
    }
}

fn timeout_ms(config: &DlpProviderConfig) -> u64 {
    if config.timeout_ms == 0 {
        3_000
    } else {
        u64::from(config.timeout_ms)
    }
}

fn enforcement_required(action: DlpAction) -> bool {
    matches!(
        action,
        DlpAction::Quarantine | DlpAction::Block | DlpAction::Escalate
    )
}

fn parse_action_label(value: &str) -> Option<DlpAction> {
    match normalize_label(value).as_str() {
        "allow" => Some(DlpAction::Allow),
        "alert" => Some(DlpAction::Alert),
        "quarantine" => Some(DlpAction::Quarantine),
        "block" | "deny" => Some(DlpAction::Block),
        "escalate" => Some(DlpAction::Escalate),
        "unspecified" | "" => Some(DlpAction::Unspecified),
        _ => None,
    }
}

fn parse_disposition_label(value: &str) -> Option<DlpDisposition> {
    match normalize_label(value).as_str() {
        "nowatermark" => Some(DlpDisposition::NoWatermark),
        "watermarkverified" | "verified" => Some(DlpDisposition::WatermarkVerified),
        "watermarkunverified" | "unverified" => Some(DlpDisposition::WatermarkUnverified),
        "expectedtokenmismatch" | "tokenmismatch" => Some(DlpDisposition::ExpectedTokenMismatch),
        "unspecified" | "" => Some(DlpDisposition::Unspecified),
        _ => None,
    }
}

fn normalize_label(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|character| !matches!(character, '-' | '_' | '.' | ' '))
        .collect()
}

fn action_label(action: DlpAction) -> &'static str {
    match action {
        DlpAction::Unspecified => "unspecified",
        DlpAction::Allow => "allow",
        DlpAction::Alert => "alert",
        DlpAction::Quarantine => "quarantine",
        DlpAction::Block => "block",
        DlpAction::Escalate => "escalate",
    }
}

fn disposition_label(disposition: DlpDisposition) -> &'static str {
    match disposition {
        DlpDisposition::Unspecified => "unspecified",
        DlpDisposition::NoWatermark => "no_watermark",
        DlpDisposition::WatermarkVerified => "watermark_verified",
        DlpDisposition::WatermarkUnverified => "watermark_unverified",
        DlpDisposition::ExpectedTokenMismatch => "expected_token_mismatch",
    }
}

#[derive(Debug, Serialize)]
struct DlpPolicyWebhookRequest {
    provider_id: String,
    callback_type: String,
    inspection_context: Option<DlpInspectionContextJson>,
    detection: DetectionJson,
    recommended_action: String,
    recommended_disposition: String,
}

impl DlpPolicyWebhookRequest {
    fn from_detection(
        config: &DlpProviderConfig,
        detection: &DetectWatermarksResponse,
        recommended: &DlpPolicyDecision,
    ) -> Self {
        Self {
            provider_id: provider_id(config),
            callback_type: "watermark_policy_evaluation".into(),
            inspection_context: detection
                .inspection_context
                .as_ref()
                .map(DlpInspectionContextJson::from),
            detection: DetectionJson::from(detection),
            recommended_action: action_label(
                DlpAction::try_from(recommended.action).unwrap_or(DlpAction::Unspecified),
            )
            .into(),
            recommended_disposition: disposition_label(
                DlpDisposition::try_from(recommended.disposition)
                    .unwrap_or(DlpDisposition::Unspecified),
            )
            .into(),
        }
    }
}

#[derive(Debug, Serialize)]
struct DlpInspectionContextJson {
    caller_system: String,
    policy_id: String,
    source_uri: String,
    correlation_id: String,
    scope: Option<WatermarkRequestScopeJson>,
    attributes: HashMap<String, String>,
}

impl From<&DlpInspectionContext> for DlpInspectionContextJson {
    fn from(value: &DlpInspectionContext) -> Self {
        Self {
            caller_system: value.caller_system.clone(),
            policy_id: value.policy_id.clone(),
            source_uri: value.source_uri.clone(),
            correlation_id: value.correlation_id.clone(),
            scope: value.scope.as_ref().map(WatermarkRequestScopeJson::from),
            attributes: value.attributes.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct WatermarkRequestScopeJson {
    tenant_id: String,
    project_id: String,
    user_id: String,
}

impl From<&WatermarkRequestScope> for WatermarkRequestScopeJson {
    fn from(value: &WatermarkRequestScope) -> Self {
        Self {
            tenant_id: value.tenant_id.clone(),
            project_id: value.project_id.clone(),
            user_id: value.user_id.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct DetectionJson {
    scan_id: String,
    document_id: String,
    disposition: String,
    summary: Option<SummaryJson>,
    matches: Vec<MatchJson>,
}

impl From<&DetectWatermarksResponse> for DetectionJson {
    fn from(value: &DetectWatermarksResponse) -> Self {
        Self {
            scan_id: value.scan_id.clone(),
            document_id: value.document_id.clone(),
            disposition: disposition_label(disposition_from_detection(value)).into(),
            summary: value.summary.as_ref().map(SummaryJson::from),
            matches: value.matches.iter().map(MatchJson::from).collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct SummaryJson {
    watermark_present: bool,
    verified: bool,
    algorithm_verified: bool,
    match_count: u32,
    algorithm_match_count: u32,
    carrier_match_count: u32,
    legacy_match_count: u32,
    expected_token_matched: bool,
}

impl From<&WatermarkDetectionSummary> for SummaryJson {
    fn from(value: &WatermarkDetectionSummary) -> Self {
        Self {
            watermark_present: value.watermark_present,
            verified: value.verified,
            algorithm_verified: value.algorithm_verified,
            match_count: value.match_count,
            algorithm_match_count: value.algorithm_match_count,
            carrier_match_count: value.carrier_match_count,
            legacy_match_count: value.legacy_match_count,
            expected_token_matched: value.expected_token_matched,
        }
    }
}

#[derive(Debug, Serialize)]
struct MatchJson {
    token: String,
    verified: bool,
    overlay_text: String,
    provider: String,
    algorithm: String,
    implementation_tier: String,
    content_format: String,
    confidence_percent: u32,
    payload: Option<PayloadJson>,
}

impl From<&WatermarkMatch> for MatchJson {
    fn from(value: &WatermarkMatch) -> Self {
        Self {
            token: value.token.clone(),
            verified: value.verified,
            overlay_text: value.overlay_text.clone(),
            provider: value.provider.clone(),
            algorithm: value.algorithm.clone(),
            implementation_tier: value.implementation_tier.to_string(),
            content_format: value.content_format.to_string(),
            confidence_percent: value.confidence_percent,
            payload: value.payload.as_ref().map(PayloadJson::from),
        }
    }
}

#[derive(Debug, Serialize)]
struct PayloadJson {
    tenant_id: String,
    project_id: String,
    user_id: String,
    sequence_number: u64,
    issued_at: String,
    snapshot_id: String,
}

impl From<&WatermarkPayloadView> for PayloadJson {
    fn from(value: &WatermarkPayloadView) -> Self {
        Self {
            tenant_id: value.tenant_id.clone(),
            project_id: value.project_id.clone(),
            user_id: value.user_id.clone(),
            sequence_number: value.sequence_number,
            issued_at: value.issued_at.clone(),
            snapshot_id: value.snapshot_id.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct DlpPolicyWebhookResponse {
    action: Option<String>,
    disposition: Option<String>,
    policy_version: Option<String>,
    #[serde(default)]
    reasons: Vec<String>,
    #[serde(default)]
    attributes: HashMap<String, String>,
    #[serde(default)]
    enforcement_ttl_seconds: u32,
}

impl DlpPolicyWebhookResponse {
    fn into_decision(
        self,
        config: &DlpProviderConfig,
        detection: &DetectWatermarksResponse,
        recommended: DlpPolicyDecision,
    ) -> Result<DlpPolicyDecision, DlpProviderError> {
        let action = match self.action {
            Some(value) => {
                parse_action_label(&value).ok_or_else(|| DlpProviderError::InvalidAction(value))?
            }
            None => DlpAction::try_from(recommended.action).unwrap_or(DlpAction::Alert),
        };
        let disposition = match self.disposition {
            Some(value) => parse_disposition_label(&value)
                .ok_or_else(|| DlpProviderError::InvalidDisposition(value))?,
            None => disposition_from_detection(detection),
        };

        let mut attributes = self.attributes;
        attributes.insert("sdqp.policy.provider_mode".into(), "webhook".into());
        attributes.insert("sdqp.callback.url".into(), config.webhook_url.clone());

        let mut reasons = if self.reasons.is_empty() {
            recommended.reasons
        } else {
            self.reasons
        };
        reasons.push("webhook provider returned an executable DLP policy decision".into());

        Ok(DlpPolicyDecision {
            provider_id: provider_id(config),
            provider_kind: DlpProviderKind::Webhook as i32,
            policy_id: detection
                .inspection_context
                .as_ref()
                .map(|context| context.policy_id.clone())
                .unwrap_or_default(),
            policy_version: self
                .policy_version
                .unwrap_or_else(|| "external-webhook".into()),
            disposition: disposition as i32,
            action: action as i32,
            callback_delivered: true,
            enforcement_required: enforcement_required(action),
            reasons,
            attributes,
            enforcement_ttl_seconds: self.enforcement_ttl_seconds,
        })
    }
}
