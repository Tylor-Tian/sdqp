mod blockchain;
mod tsa;

use std::{str::FromStr, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sdqp_audit::{AuditContextFields, AuditEvent, verify_chain};
use sdqp_encryption::{
    DevelopmentEnvelopeCipher, EncryptedPayload, EncryptionError, EnvelopeCipher,
};
use sdqp_watermark::{
    WatermarkError, WatermarkPayload, embed_marker, encode_payload, overlay_text, verify_content,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use ulid::Ulid;

pub use blockchain::{
    AnchorParams, AnchorResult, BlockchainAnchorConfig, EthereumAnchorClient, JsonRpcError,
    JsonRpcRequest, JsonRpcResponse, ethereum_anchor_proof,
};
pub use tsa::{
    InternalHsmTimestampAuthority, Rfc3161TimestampAuthority, Rfc3161TimestampQuery,
    Rfc3161TimestampToken, TsaProviderConfig, build_rfc3161_query, build_rfc3161_reply,
    parse_rfc3161_query, parse_rfc3161_reply, rfc3161_signature,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceTemplate {
    ChinaJudicial,
    EuRegulatory,
    UsLitigation,
}

impl EvidenceTemplate {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ChinaJudicial => "china-judicial",
            Self::EuRegulatory => "eu-regulatory",
            Self::UsLitigation => "us-litigation",
        }
    }

    fn export_header(&self) -> &'static str {
        match self {
            Self::ChinaJudicial => "SDQP China Judicial Evidence Package",
            Self::EuRegulatory => "SDQP EU Regulatory Evidence Package",
            Self::UsLitigation => "SDQP US Litigation Evidence Package",
        }
    }

    fn jurisdiction(&self) -> &'static str {
        match self {
            Self::ChinaJudicial => "China Mainland",
            Self::EuRegulatory => "European Union",
            Self::UsLitigation => "United States",
        }
    }

    fn standards(&self) -> &'static [&'static str] {
        match self {
            Self::ChinaJudicial => &[
                "Supreme People's Court E-Evidence Rules (2019)",
                "Electronic Signature Law",
            ],
            Self::EuRegulatory => &["eIDAS", "GDPR"],
            Self::UsLitigation => &["FRE 901/902", "ESI Guidelines"],
        }
    }

    fn key_requirements(&self) -> &'static [&'static str] {
        match self {
            Self::ChinaJudicial => &[
                "trusted timestamp",
                "hash integrity",
                "full chain-of-custody audit log",
                "notarization-ready package",
            ],
            Self::EuRegulatory => &[
                "qualified timestamp",
                "qualified signature readiness",
                "GDPR handling traceability",
            ],
            Self::UsLitigation => &[
                "electronic record authentication",
                "chain-of-custody preservation",
                "metadata retention",
            ],
        }
    }

    fn profile_version(&self) -> &'static str {
        match self {
            Self::ChinaJudicial => "cn-judicial-v2",
            Self::EuRegulatory => "eu-eidas-gdpr-v2",
            Self::UsLitigation => "us-fre-esi-v2",
        }
    }

    fn jurisdiction_code(&self) -> &'static str {
        match self {
            Self::ChinaJudicial => "CN-MAINLAND",
            Self::EuRegulatory => "EU",
            Self::UsLitigation => "US-FEDERAL",
        }
    }

    fn submission_language(&self) -> &'static str {
        match self {
            Self::ChinaJudicial => "zh-CN/en",
            Self::EuRegulatory => "en",
            Self::UsLitigation => "en-US",
        }
    }

    fn filing_authority(&self) -> &'static str {
        match self {
            Self::ChinaJudicial => "People's court or authorized evidence review authority",
            Self::EuRegulatory => "EU supervisory or regulatory review authority",
            Self::UsLitigation => "Federal or state court discovery/authentication process",
        }
    }

    fn accepted_formats(&self) -> &'static [&'static str] {
        match self {
            Self::ChinaJudicial => &["application/json", "text/plain", "application/pdf"],
            Self::EuRegulatory => &["application/json", "application/pdf"],
            Self::UsLitigation => &["application/json", "text/plain", "application/pdf"],
        }
    }

    fn required_components(&self) -> &'static [&'static str] {
        &[
            "metadata_manifest",
            "recipient_scoped_encrypted_data_payload",
            "audit_extract",
            "hash_chain",
            "jurisdiction_marker",
            "certificate_of_authenticity",
            "trusted_timestamp_receipt",
            "blockchain_anchor_receipt",
            "traceable_watermark",
        ]
    }

    fn verification_steps(&self) -> &'static [&'static str] {
        match self {
            Self::ChinaJudicial => &[
                "verify package manifest digest",
                "verify audit hash chain continuity",
                "verify RFC3161 or accepted trusted timestamp receipt",
                "verify judicial-chain or accepted blockchain anchor receipt",
                "verify watermark token against exported document",
            ],
            Self::EuRegulatory => &[
                "verify package manifest digest",
                "verify audit chain and processing traceability",
                "verify qualified timestamp receipt where configured",
                "verify anchor receipt and receipt refresh status",
                "verify recipient-scoped payload encryption binding",
            ],
            Self::UsLitigation => &[
                "verify package manifest digest",
                "verify chain of custody and metadata retention",
                "verify timestamp receipt",
                "verify blockchain anchor receipt",
                "verify watermark token and export identity binding",
            ],
        }
    }

    fn retention_requirement(&self) -> &'static str {
        match self {
            Self::ChinaJudicial => {
                "retain package, receipts, manifest, audit extract, and verification report through judicial review and appeal period"
            }
            Self::EuRegulatory => {
                "retain package under documented regulatory purpose, minimization, and erasure-exception controls"
            }
            Self::UsLitigation => {
                "retain package and chain-of-custody materials under litigation hold until release"
            }
        }
    }

    fn certificate_issuer(&self) -> &'static str {
        match self {
            Self::ChinaJudicial => "SDQP Evidence Certification Service - CN Judicial Profile",
            Self::EuRegulatory => "SDQP Evidence Certification Service - EU Regulatory Profile",
            Self::UsLitigation => "SDQP Evidence Certification Service - US Litigation Profile",
        }
    }

    fn certificate_title(&self) -> &'static str {
        match self {
            Self::ChinaJudicial => "Electronic Evidence Authenticity Statement",
            Self::EuRegulatory => "Regulatory Authenticity Certificate",
            Self::UsLitigation => "Certificate of Authenticity",
        }
    }

    fn certificate_statement(&self) -> &'static str {
        match self {
            Self::ChinaJudicial => {
                "The enclosed export was preserved with a traceable watermark, audit chain, and trusted timestamp for judicial submission."
            }
            Self::EuRegulatory => {
                "The enclosed export preserves chain-of-custody metadata and encrypted data handling for regulatory disclosure."
            }
            Self::UsLitigation => {
                "The enclosed export preserves authenticity metadata, custody trail, and a recipient-scoped encrypted payload for litigation support."
            }
        }
    }
}

impl FromStr for EvidenceTemplate {
    type Err = EvidenceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "china" | "cn" | "china-mainland" | "china-judicial" => Ok(Self::ChinaJudicial),
            "eu" | "eidas" | "gdpr" | "eu-regulatory" => Ok(Self::EuRegulatory),
            "us" | "usa" | "fre" | "us-litigation" => Ok(Self::UsLitigation),
            _ => Err(EvidenceError::UnknownTemplate),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampReceipt {
    pub authority: String,
    pub issued_at: DateTime<Utc>,
    pub digest: String,
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorReceipt {
    pub network: String,
    pub anchored_at: DateTime<Utc>,
    pub digest: String,
    pub transaction_id: String,
    pub status: AnchorStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorStatus {
    Pending,
    Confirmed,
    Failed,
}

impl AnchorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Confirmed => "confirmed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceVerificationStatus {
    Verified,
    PendingAnchor,
    FailedAnchor,
    #[default]
    Invalid,
}

impl EvidenceVerificationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::PendingAnchor => "pending_anchor",
            Self::FailedAnchor => "failed_anchor",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceProviderRuntime {
    pub timestamp_provider: String,
    pub timestamp_runtime_mode: String,
    pub anchor_provider: String,
    pub anchor_runtime_mode: String,
    pub overall_mode: String,
    pub external_final_uat_required: bool,
    pub mock_components: Vec<String>,
}

impl Default for EvidenceProviderRuntime {
    fn default() -> Self {
        Self {
            timestamp_provider: String::new(),
            timestamp_runtime_mode: "unknown".into(),
            anchor_provider: String::new(),
            anchor_runtime_mode: "unknown".into(),
            overall_mode: "unknown".into(),
            external_final_uat_required: false,
            mock_components: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecipient {
    pub tenant_id: String,
    pub project_id: String,
    pub user_id: String,
    pub delivery_channel: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataFieldDescriptor {
    pub field_name: String,
    pub ordinal: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataQueryParameter {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataGrantCondition {
    pub field: String,
    pub operator: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataGrantDetails {
    pub grant_id: String,
    pub applicant_user_id: String,
    pub data_source_id: String,
    pub allowed_fields: Vec<String>,
    pub denied_fields: Vec<String>,
    pub conditions: Vec<MetadataGrantCondition>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataDataSource {
    pub data_source_id: String,
    pub storage_key: String,
    pub row_count: usize,
    pub columns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceMetadataManifest {
    pub field_descriptors: Vec<MetadataFieldDescriptor>,
    pub query_parameters: Vec<MetadataQueryParameter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_grant: Option<MetadataGrantDetails>,
    pub data_source: MetadataDataSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceDataPayload {
    pub recipient: EvidenceRecipient,
    pub content_format: String,
    pub plaintext_digest: String,
    pub plaintext_size_bytes: usize,
    pub scope_binding: String,
    pub encrypted_payload: EncryptedPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditExtractEntry {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub actor_user_id: String,
    pub session_id: String,
    pub action: String,
    pub result: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    pub resource_id: String,
    pub context: String,
    #[serde(default, skip_serializing_if = "AuditContextFields::is_empty")]
    pub context_fields: AuditContextFields,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_fingerprint: Option<String>,
    pub prev_hash: String,
    pub event_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashChainLink {
    pub component: String,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_digest: Option<String>,
    pub chained_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceHashChain {
    pub algorithm: String,
    pub links: Vec<HashChainLink>,
    pub final_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JurisdictionMarker {
    pub template: String,
    pub jurisdiction: String,
    pub standards: Vec<String>,
    pub key_requirements: Vec<String>,
    #[serde(default)]
    pub profile_version: String,
    #[serde(default)]
    pub jurisdiction_code: String,
    #[serde(default)]
    pub submission_language: String,
    #[serde(default)]
    pub filing_authority: String,
    #[serde(default)]
    pub accepted_formats: Vec<String>,
    #[serde(default)]
    pub required_components: Vec<String>,
    #[serde(default)]
    pub verification_steps: Vec<String>,
    #[serde(default)]
    pub retention_requirement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateOfAuthenticity {
    #[serde(default)]
    pub serial_number: String,
    pub title: String,
    pub template: String,
    pub jurisdiction: String,
    #[serde(default)]
    pub jurisdiction_code: String,
    #[serde(default)]
    pub jurisdiction_profile_version: String,
    pub statement: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub subject: String,
    pub issued_at: DateTime<Utc>,
    pub package_id: String,
    pub snapshot_id: String,
    pub recipient_user_id: String,
    pub delivery_channel: String,
    #[serde(default)]
    pub hash_algorithm: String,
    #[serde(default)]
    pub metadata_manifest_digest: String,
    pub data_payload_digest: String,
    pub audit_extract_digest: String,
    #[serde(default)]
    pub jurisdiction_marker_digest: String,
    pub exported_document_digest: String,
    #[serde(default)]
    pub scope_binding: String,
    pub timestamp_authority: String,
    pub anchor_network: String,
    pub watermark_token: String,
    #[serde(default)]
    pub required_components: Vec<String>,
    #[serde(default)]
    pub verification_steps: Vec<String>,
    pub assertions: Vec<String>,
}

#[async_trait]
pub trait TimestampAuthority: Send + Sync {
    fn authority_name(&self) -> &str;
    async fn stamp(&self, digest: &str) -> Result<TimestampReceipt, EvidenceError>;
    async fn verify(&self, receipt: &TimestampReceipt, digest: &str)
    -> Result<bool, EvidenceError>;
}

#[async_trait]
pub trait BlockchainAnchor: Send + Sync {
    fn network_name(&self) -> &str;
    async fn anchor(&self, digest: &str) -> Result<AnchorReceipt, EvidenceError>;
    async fn refresh(&self, receipt: &AnchorReceipt) -> Result<AnchorReceipt, EvidenceError>;
    async fn verify(&self, receipt: &AnchorReceipt, digest: &str) -> Result<bool, EvidenceError>;
}

#[derive(Debug, Clone)]
pub struct MockTimestampAuthority {
    authority: String,
    secret: String,
}

impl Default for MockTimestampAuthority {
    fn default() -> Self {
        Self {
            authority: "mock-tsa".into(),
            secret: "phase5-evidence-secret".into(),
        }
    }
}

impl MockTimestampAuthority {
    pub fn new(authority: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            authority: authority.into(),
            secret: secret.into(),
        }
    }
}

#[async_trait]
impl TimestampAuthority for MockTimestampAuthority {
    fn authority_name(&self) -> &str {
        &self.authority
    }

    async fn stamp(&self, digest: &str) -> Result<TimestampReceipt, EvidenceError> {
        validate_sha256_digest(digest)?;
        let issued_at = Utc::now();
        let token = hex::encode(Sha256::digest(
            format!(
                "{}|{}|{}|{}",
                self.authority,
                digest,
                issued_at.to_rfc3339(),
                self.secret
            )
            .as_bytes(),
        ));

        Ok(TimestampReceipt {
            authority: self.authority.clone(),
            issued_at,
            digest: digest.to_string(),
            token,
            provider: Some("mock".into()),
            nonce: None,
        })
    }

    async fn verify(
        &self,
        receipt: &TimestampReceipt,
        digest: &str,
    ) -> Result<bool, EvidenceError> {
        if receipt.authority != self.authority || receipt.digest != digest {
            return Ok(false);
        }
        validate_sha256_digest(digest)?;

        let expected = hex::encode(Sha256::digest(
            format!(
                "{}|{}|{}|{}",
                receipt.authority,
                digest,
                receipt.issued_at.to_rfc3339(),
                self.secret
            )
            .as_bytes(),
        ));

        Ok(expected == receipt.token)
    }
}

#[derive(Debug, Clone)]
pub struct MockBlockchainAnchor {
    network: String,
    secret: String,
}

impl Default for MockBlockchainAnchor {
    fn default() -> Self {
        Self {
            network: "mock-chain".into(),
            secret: "phase5-anchor-secret".into(),
        }
    }
}

impl MockBlockchainAnchor {
    pub fn new(network: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            network: network.into(),
            secret: secret.into(),
        }
    }
}

#[async_trait]
impl BlockchainAnchor for MockBlockchainAnchor {
    fn network_name(&self) -> &str {
        &self.network
    }

    async fn anchor(&self, digest: &str) -> Result<AnchorReceipt, EvidenceError> {
        validate_sha256_digest(digest)?;
        let anchored_at = Utc::now();
        let transaction_id = hex::encode(Sha256::digest(
            format!(
                "{}|{}|{}|{}",
                self.network,
                digest,
                anchored_at.to_rfc3339(),
                self.secret
            )
            .as_bytes(),
        ));

        Ok(AnchorReceipt {
            network: self.network.clone(),
            anchored_at,
            digest: digest.to_string(),
            transaction_id,
            status: AnchorStatus::Confirmed,
            provider: Some("mock".into()),
            block_number: None,
            proof: None,
            confirmed_at: Some(anchored_at),
            failure_reason: None,
        })
    }

    async fn refresh(&self, receipt: &AnchorReceipt) -> Result<AnchorReceipt, EvidenceError> {
        let mut refreshed = receipt.clone();
        refreshed.status = AnchorStatus::Confirmed;
        refreshed.confirmed_at = Some(receipt.anchored_at);
        Ok(refreshed)
    }

    async fn verify(&self, receipt: &AnchorReceipt, digest: &str) -> Result<bool, EvidenceError> {
        if receipt.network != self.network || receipt.digest != digest {
            return Ok(false);
        }
        validate_sha256_digest(digest)?;

        let expected = hex::encode(Sha256::digest(
            format!(
                "{}|{}|{}|{}",
                receipt.network,
                digest,
                receipt.anchored_at.to_rfc3339(),
                self.secret
            )
            .as_bytes(),
        ));

        Ok(expected == receipt.transaction_id)
    }
}

#[derive(Clone)]
pub struct EvidenceProviderRegistry {
    timestamp_authority: Arc<dyn TimestampAuthority>,
    blockchain_anchor: Arc<dyn BlockchainAnchor>,
}

impl EvidenceProviderRegistry {
    pub fn from_configs(
        tsa_config: TsaProviderConfig,
        blockchain_config: BlockchainAnchorConfig,
    ) -> Result<Self, EvidenceError> {
        let tsa_provider = tsa_config.provider.trim().to_ascii_lowercase();
        if tsa_config.require_external && tsa_provider == "mock" {
            return Err(EvidenceError::ProviderConfiguration(
                "mock TSA provider is not allowed when external TSA is required".into(),
            ));
        }
        let timestamp_authority: Arc<dyn TimestampAuthority> = match tsa_provider.as_str() {
            "mock" => Arc::new(MockTimestampAuthority::new(
                tsa_config.authority,
                default_secret(&tsa_config.api_key, "phase5-evidence-secret"),
            )),
            "rfc3161" | "ntsc" | "digicert" | "sectigo" | "eidas" => Arc::new(
                Rfc3161TimestampAuthority::from_named_provider(tsa_config, tsa_provider)?,
            ),
            "internal-hsm" | "internal_hsm" => {
                Arc::new(InternalHsmTimestampAuthority::from_config(tsa_config))
            }
            other => return Err(EvidenceError::UnknownTimestampProvider(other.into())),
        };

        let anchor_provider = blockchain_config.provider.trim().to_ascii_lowercase();
        if blockchain_config.require_external && anchor_provider == "mock" {
            return Err(EvidenceError::ProviderConfiguration(
                "mock anchor provider is not allowed when external anchor is required".into(),
            ));
        }
        let blockchain_anchor: Arc<dyn BlockchainAnchor> = match anchor_provider.as_str() {
            "mock" => Arc::new(MockBlockchainAnchor::new(
                blockchain_config.network,
                default_secret(&blockchain_config.api_key, "phase5-anchor-secret"),
            )),
            "ethereum" | "fabric" | "bsn" | "judicial" => Arc::new(
                EthereumAnchorClient::from_named_provider(blockchain_config, anchor_provider)?,
            ),
            other => return Err(EvidenceError::UnknownAnchorProvider(other.into())),
        };

        Ok(Self {
            timestamp_authority,
            blockchain_anchor,
        })
    }

    pub fn builder(&self) -> EvidenceBuilder {
        self.builder_with_cipher(Arc::new(DevelopmentEnvelopeCipher::new(
            "evidence-default-dek",
            0x5A,
        )))
    }

    pub fn builder_with_cipher(&self, envelope_cipher: Arc<dyn EnvelopeCipher>) -> EvidenceBuilder {
        EvidenceBuilder {
            timestamp_authority: self.timestamp_authority.clone(),
            blockchain_anchor: self.blockchain_anchor.clone(),
            envelope_cipher,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceManifest {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub package_id: String,
    pub snapshot_id: String,
    pub template: String,
    #[serde(default)]
    pub jurisdiction_code: String,
    pub recipient_user_id: String,
    pub watermark_token: String,
    pub watermark_text: String,
    pub audit_event_ids: Vec<String>,
    pub audit_chain_valid: bool,
    pub metadata_manifest_digest: String,
    pub data_payload_digest: String,
    pub audit_extract_digest: String,
    pub hash_chain_digest: String,
    pub jurisdiction_marker_digest: String,
    pub certificate_digest: String,
    pub exported_document_digest: String,
    #[serde(default)]
    pub timestamp_receipt_digest: String,
    #[serde(default)]
    pub anchor_receipt_digest: String,
    #[serde(default)]
    pub certificate_serial_number: String,
    #[serde(default)]
    pub provider_runtime: EvidenceProviderRuntime,
    #[serde(default)]
    pub verification_status: EvidenceVerificationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_failure_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePackage {
    pub package_id: String,
    pub snapshot_id: String,
    pub template: String,
    pub manifest: EvidenceManifest,
    pub manifest_json: String,
    pub manifest_digest: String,
    pub exported_document: String,
    pub metadata_manifest: EvidenceMetadataManifest,
    pub data_payload: EvidenceDataPayload,
    pub audit_extract: Vec<AuditExtractEntry>,
    pub hash_chain: EvidenceHashChain,
    pub jurisdiction_marker: JurisdictionMarker,
    pub certificate_of_authenticity: CertificateOfAuthenticity,
    #[serde(default)]
    pub provider_runtime: EvidenceProviderRuntime,
    pub watermark_token: String,
    pub watermark_text: String,
    pub audit_event_count: usize,
    pub timestamp_receipt: TimestampReceipt,
    pub anchor_receipt: AnchorReceipt,
}

#[derive(Debug, Clone)]
pub struct EvidenceBuildRequest {
    pub snapshot_id: String,
    pub template: EvidenceTemplate,
    pub recipient: EvidenceRecipient,
    pub metadata_manifest: EvidenceMetadataManifest,
    pub watermark_payload: WatermarkPayload,
    pub audit_events: Vec<AuditEvent>,
    pub export_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceVerificationReport {
    pub verified: bool,
    pub integrity_verified: bool,
    pub verification_status: EvidenceVerificationStatus,
    pub audit_chain_valid: bool,
    pub manifest_digest_valid: bool,
    pub metadata_manifest_valid: bool,
    pub data_payload_valid: bool,
    pub audit_extract_valid: bool,
    pub hash_chain_valid: bool,
    pub jurisdiction_marker_valid: bool,
    pub certificate_valid: bool,
    pub exported_document_digest_valid: bool,
    pub receipt_digests_valid: bool,
    pub provider_runtime_valid: bool,
    pub timestamp_valid: bool,
    pub anchor_valid: bool,
    pub anchor_confirmed: bool,
    pub refresh_recommended: bool,
    pub watermark_valid: bool,
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("audit chain is not continuous")]
    AuditChainBroken,
    #[error("evidence template is not supported")]
    UnknownTemplate,
    #[error("unknown timestamp provider: {0}")]
    UnknownTimestampProvider(String),
    #[error("unknown blockchain anchor provider: {0}")]
    UnknownAnchorProvider(String),
    #[error("provider configuration error: {0}")]
    ProviderConfiguration(String),
    #[error("provider protocol error: {0}")]
    ProviderProtocol(String),
    #[error("provider request failed: {0}")]
    ProviderRequest(String),
    #[error("evidence serialization failed")]
    Serialization,
    #[error(transparent)]
    Watermark(#[from] WatermarkError),
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
}

#[derive(Clone)]
pub struct EvidenceBuilder {
    timestamp_authority: Arc<dyn TimestampAuthority>,
    blockchain_anchor: Arc<dyn BlockchainAnchor>,
    envelope_cipher: Arc<dyn EnvelopeCipher>,
}

impl EvidenceBuilder {
    pub fn new<T, A, C>(timestamp_authority: T, blockchain_anchor: A, envelope_cipher: C) -> Self
    where
        T: TimestampAuthority + 'static,
        A: BlockchainAnchor + 'static,
        C: EnvelopeCipher + 'static,
    {
        Self {
            timestamp_authority: Arc::new(timestamp_authority),
            blockchain_anchor: Arc::new(blockchain_anchor),
            envelope_cipher: Arc::new(envelope_cipher),
        }
    }

    pub fn from_registry(registry: &EvidenceProviderRegistry) -> Self {
        registry.builder()
    }

    pub fn from_registry_with_cipher(
        registry: &EvidenceProviderRegistry,
        envelope_cipher: Arc<dyn EnvelopeCipher>,
    ) -> Self {
        registry.builder_with_cipher(envelope_cipher)
    }

    pub fn decrypt_data_payload(
        &self,
        package: &EvidencePackage,
    ) -> Result<Vec<u8>, EvidenceError> {
        self.envelope_cipher
            .decrypt(&package.data_payload.encrypted_payload)
            .map_err(EvidenceError::from)
    }

    pub async fn build_package(
        &self,
        request: EvidenceBuildRequest,
    ) -> Result<EvidencePackage, EvidenceError> {
        if !verify_chain(&request.audit_events) {
            return Err(EvidenceError::AuditChainBroken);
        }

        let EvidenceBuildRequest {
            snapshot_id,
            template,
            recipient,
            metadata_manifest,
            watermark_payload,
            audit_events,
            export_body,
        } = request;

        let package_id = Ulid::new().to_string();
        let watermark_token = encode_payload(&watermark_payload)?;
        let watermark_text = overlay_text(&watermark_payload);
        let data_payload = build_data_payload(
            &recipient,
            &snapshot_id,
            &watermark_token,
            export_body.as_bytes(),
            self.envelope_cipher.as_ref(),
        )?;
        let metadata_manifest_digest = digest_json(&metadata_manifest)?;
        let data_payload_digest = digest_json(&data_payload)?;
        let audit_extract = build_audit_extract(&audit_events);
        let audit_extract_digest = digest_json(&audit_extract)?;
        let jurisdiction_marker = build_jurisdiction_marker(&template);
        let jurisdiction_marker_digest = digest_json(&jurisdiction_marker)?;
        let created_at = Utc::now();
        let rendered_document = render_export_document(
            &template,
            &package_id,
            &snapshot_id,
            &data_payload,
            audit_events.len(),
        );
        let exported_document = embed_marker(&rendered_document, &watermark_token);
        let exported_document_digest = digest_of(&exported_document);
        let certificate_of_authenticity = build_certificate(CertificateBuildInput {
            template: &template,
            package_id: &package_id,
            snapshot_id: &snapshot_id,
            recipient: &recipient,
            watermark_token: &watermark_token,
            metadata_manifest_digest: &metadata_manifest_digest,
            data_payload_digest: &data_payload_digest,
            audit_extract_digest: &audit_extract_digest,
            jurisdiction_marker_digest: &jurisdiction_marker_digest,
            exported_document_digest: &exported_document_digest,
            scope_binding: &data_payload.scope_binding,
            timestamp_authority: self.timestamp_authority.authority_name(),
            anchor_network: self.blockchain_anchor.network_name(),
            created_at,
        });
        let hash_chain = build_hash_chain(&[
            (
                "metadata_manifest",
                digest_of_bytes(
                    serde_json::to_vec(&metadata_manifest)
                        .map_err(|_| EvidenceError::Serialization)?
                        .as_slice(),
                ),
            ),
            (
                "data_payload",
                digest_of_bytes(
                    serde_json::to_vec(&data_payload)
                        .map_err(|_| EvidenceError::Serialization)?
                        .as_slice(),
                ),
            ),
            (
                "audit_extract",
                digest_of_bytes(
                    serde_json::to_vec(&audit_extract)
                        .map_err(|_| EvidenceError::Serialization)?
                        .as_slice(),
                ),
            ),
            (
                "certificate_of_authenticity",
                digest_of_bytes(
                    serde_json::to_vec(&certificate_of_authenticity)
                        .map_err(|_| EvidenceError::Serialization)?
                        .as_slice(),
                ),
            ),
            ("exported_document", digest_of(&exported_document)),
            (
                "jurisdiction_marker",
                digest_of_bytes(
                    serde_json::to_vec(&jurisdiction_marker)
                        .map_err(|_| EvidenceError::Serialization)?
                        .as_slice(),
                ),
            ),
        ]);
        let hash_chain_digest = digest_json(&hash_chain)?;
        let certificate_digest = digest_json(&certificate_of_authenticity)?;
        let template_label = template.as_str().to_string();
        let timestamp_receipt = self
            .timestamp_authority
            .stamp(&hash_chain.final_digest)
            .await?;
        let anchor_receipt = self
            .blockchain_anchor
            .anchor(&hash_chain.final_digest)
            .await?;
        let timestamp_receipt_digest = digest_json(&timestamp_receipt)?;
        let anchor_receipt_digest = digest_json(&anchor_receipt)?;
        let provider_runtime = build_provider_runtime(&timestamp_receipt, &anchor_receipt);
        let verification_status = verification_status_from_anchor(&anchor_receipt);
        let manifest = EvidenceManifest {
            version: "evidence-manifest-v2".into(),
            package_id: package_id.clone(),
            snapshot_id: snapshot_id.clone(),
            template: template_label.clone(),
            jurisdiction_code: jurisdiction_marker.jurisdiction_code.clone(),
            recipient_user_id: recipient.user_id.clone(),
            watermark_token: watermark_token.clone(),
            watermark_text: watermark_text.clone(),
            audit_event_ids: audit_events
                .iter()
                .map(|event| event.event_id.clone())
                .collect(),
            audit_chain_valid: true,
            metadata_manifest_digest,
            data_payload_digest,
            audit_extract_digest,
            hash_chain_digest,
            jurisdiction_marker_digest,
            certificate_digest,
            exported_document_digest,
            timestamp_receipt_digest,
            anchor_receipt_digest,
            certificate_serial_number: certificate_of_authenticity.serial_number.clone(),
            provider_runtime: provider_runtime.clone(),
            verification_status,
            anchor_failure_reason: anchor_receipt.failure_reason.clone(),
            created_at: Some(created_at),
        };
        let manifest_json =
            serde_json::to_string(&manifest).map_err(|_| EvidenceError::Serialization)?;
        let manifest_digest = digest_of(&manifest_json);

        Ok(EvidencePackage {
            package_id,
            snapshot_id,
            template: template_label,
            manifest,
            manifest_json,
            manifest_digest,
            exported_document,
            metadata_manifest,
            data_payload,
            audit_extract,
            hash_chain,
            jurisdiction_marker,
            certificate_of_authenticity,
            provider_runtime,
            watermark_token,
            watermark_text,
            audit_event_count: audit_events.len(),
            timestamp_receipt,
            anchor_receipt,
        })
    }

    pub async fn refresh_anchor_receipt(
        &self,
        package: &mut EvidencePackage,
    ) -> Result<bool, EvidenceError> {
        let refreshed = self
            .blockchain_anchor
            .refresh(&package.anchor_receipt)
            .await?;
        let changed = refreshed != package.anchor_receipt;
        package.anchor_receipt = refreshed;
        package.manifest.anchor_receipt_digest = digest_json(&package.anchor_receipt)?;
        package.manifest.provider_runtime =
            build_provider_runtime(&package.timestamp_receipt, &package.anchor_receipt);
        package.provider_runtime = package.manifest.provider_runtime.clone();
        package.manifest.verification_status =
            verification_status_from_anchor(&package.anchor_receipt);
        package.manifest.anchor_failure_reason = package.anchor_receipt.failure_reason.clone();
        package.manifest_json =
            serde_json::to_string(&package.manifest).map_err(|_| EvidenceError::Serialization)?;
        package.manifest_digest = digest_of(&package.manifest_json);
        Ok(changed)
    }

    pub async fn verify_package(
        &self,
        package: &EvidencePackage,
        audit_events: &[AuditEvent],
    ) -> EvidenceVerificationReport {
        let expected_audit_event_ids = audit_events
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<Vec<_>>();
        let expected_audit_extract = build_audit_extract(audit_events);
        let expected_scope_binding = compute_scope_binding(
            &package.data_payload.recipient,
            &package.snapshot_id,
            &package.watermark_token,
        );

        let audit_chain_valid = verify_chain(audit_events)
            && package.audit_event_count == audit_events.len()
            && package.manifest.audit_event_ids == expected_audit_event_ids;
        let manifest_digest_valid = serde_json::to_string(&package.manifest)
            .map(|json| {
                digest_of(&json) == package.manifest_digest && json == package.manifest_json
            })
            .unwrap_or(false);
        let metadata_manifest_valid = serde_json::to_string(&package.metadata_manifest)
            .map(|json| digest_of(&json) == package.manifest.metadata_manifest_digest)
            .unwrap_or(false);
        let data_payload_valid = serde_json::to_string(&package.data_payload)
            .map(|json| digest_of(&json) == package.manifest.data_payload_digest)
            .unwrap_or(false)
            && self
                .decrypt_data_payload(package)
                .map(|plaintext| {
                    digest_of_bytes(&plaintext) == package.data_payload.plaintext_digest
                        && plaintext.len() == package.data_payload.plaintext_size_bytes
                        && package.data_payload.scope_binding == expected_scope_binding
                })
                .unwrap_or(false);
        let audit_extract_valid = serde_json::to_string(&package.audit_extract)
            .map(|json| digest_of(&json) == package.manifest.audit_extract_digest)
            .unwrap_or(false)
            && package.audit_extract == expected_audit_extract;
        let expected_hash_chain = expected_hash_chain(package);
        let hash_chain_valid = serde_json::to_string(&package.hash_chain)
            .map(|json| digest_of(&json) == package.manifest.hash_chain_digest)
            .unwrap_or(false)
            && package.hash_chain == expected_hash_chain;
        let jurisdiction_marker_valid = serde_json::to_string(&package.jurisdiction_marker)
            .map(|json| digest_of(&json) == package.manifest.jurisdiction_marker_digest)
            .unwrap_or(false)
            && package.jurisdiction_marker
                == build_jurisdiction_marker_for_label(&package.template);
        let expected_provider_runtime =
            build_provider_runtime(&package.timestamp_receipt, &package.anchor_receipt);
        let provider_runtime_valid = package.provider_runtime == expected_provider_runtime
            && package.manifest.provider_runtime == expected_provider_runtime;
        let certificate_valid = serde_json::to_string(&package.certificate_of_authenticity)
            .map(|json| digest_of(&json) == package.manifest.certificate_digest)
            .unwrap_or(false)
            && package.certificate_of_authenticity.package_id == package.package_id
            && package.certificate_of_authenticity.snapshot_id == package.snapshot_id
            && package.certificate_of_authenticity.recipient_user_id
                == package.data_payload.recipient.user_id
            && package.certificate_of_authenticity.watermark_token == package.watermark_token
            && package.certificate_of_authenticity.metadata_manifest_digest
                == package.manifest.metadata_manifest_digest
            && package.certificate_of_authenticity.data_payload_digest
                == package.manifest.data_payload_digest
            && package.certificate_of_authenticity.audit_extract_digest
                == package.manifest.audit_extract_digest
            && package
                .certificate_of_authenticity
                .jurisdiction_marker_digest
                == package.manifest.jurisdiction_marker_digest
            && package.certificate_of_authenticity.exported_document_digest
                == package.manifest.exported_document_digest
            && package.certificate_of_authenticity.scope_binding
                == package.data_payload.scope_binding
            && package
                .certificate_of_authenticity
                .jurisdiction_profile_version
                == package.jurisdiction_marker.profile_version
            && package.certificate_of_authenticity.serial_number
                == package.manifest.certificate_serial_number;
        let exported_document_digest_valid =
            digest_of(&package.exported_document) == package.manifest.exported_document_digest;
        let receipt_digests_valid = digest_json(&package.timestamp_receipt)
            .map(|digest| digest == package.manifest.timestamp_receipt_digest)
            .unwrap_or(false)
            && digest_json(&package.anchor_receipt)
                .map(|digest| digest == package.manifest.anchor_receipt_digest)
                .unwrap_or(false);
        let timestamp_valid = hash_chain_valid
            && self
                .timestamp_authority
                .verify(&package.timestamp_receipt, &package.hash_chain.final_digest)
                .await
                .unwrap_or(false);
        let anchor_valid = hash_chain_valid
            && match package.anchor_receipt.status {
                AnchorStatus::Pending => {
                    package.anchor_receipt.digest == package.hash_chain.final_digest
                        && !package.anchor_receipt.transaction_id.trim().is_empty()
                        && package.anchor_receipt.failure_reason.is_none()
                }
                AnchorStatus::Confirmed => self
                    .blockchain_anchor
                    .verify(&package.anchor_receipt, &package.hash_chain.final_digest)
                    .await
                    .unwrap_or(false),
                AnchorStatus::Failed => false,
            };
        let anchor_confirmed =
            package.anchor_receipt.status == AnchorStatus::Confirmed && anchor_valid;
        let watermark_valid =
            verify_content(&package.exported_document, Some(&package.watermark_token)).verified;
        let integrity_verified = audit_chain_valid
            && manifest_digest_valid
            && metadata_manifest_valid
            && data_payload_valid
            && audit_extract_valid
            && hash_chain_valid
            && jurisdiction_marker_valid
            && certificate_valid
            && exported_document_digest_valid
            && receipt_digests_valid
            && provider_runtime_valid
            && package.manifest.verification_status
                == verification_status_from_anchor(&package.anchor_receipt)
            && timestamp_valid
            && watermark_valid;
        let verification_status = if !integrity_verified {
            EvidenceVerificationStatus::Invalid
        } else if package.anchor_receipt.status == AnchorStatus::Pending && anchor_valid {
            EvidenceVerificationStatus::PendingAnchor
        } else if package.anchor_receipt.status == AnchorStatus::Confirmed && anchor_valid {
            EvidenceVerificationStatus::Verified
        } else {
            EvidenceVerificationStatus::FailedAnchor
        };
        let verified = integrity_verified && anchor_confirmed;
        let refresh_recommended = matches!(
            verification_status,
            EvidenceVerificationStatus::PendingAnchor | EvidenceVerificationStatus::FailedAnchor
        );

        EvidenceVerificationReport {
            verified,
            integrity_verified,
            verification_status,
            audit_chain_valid,
            manifest_digest_valid,
            metadata_manifest_valid,
            data_payload_valid,
            audit_extract_valid,
            hash_chain_valid,
            jurisdiction_marker_valid,
            certificate_valid,
            exported_document_digest_valid,
            receipt_digests_valid,
            provider_runtime_valid,
            timestamp_valid,
            anchor_valid,
            anchor_confirmed,
            refresh_recommended,
            watermark_valid,
        }
    }
}

fn default_secret(candidate: &str, fallback: &str) -> String {
    if candidate.trim().is_empty() {
        fallback.into()
    } else {
        candidate.to_string()
    }
}

fn build_data_payload(
    recipient: &EvidenceRecipient,
    snapshot_id: &str,
    watermark_token: &str,
    plaintext: &[u8],
    envelope_cipher: &dyn EnvelopeCipher,
) -> Result<EvidenceDataPayload, EvidenceError> {
    Ok(EvidenceDataPayload {
        recipient: recipient.clone(),
        content_format: "text/plain; charset=utf-8".into(),
        plaintext_digest: digest_of_bytes(plaintext),
        plaintext_size_bytes: plaintext.len(),
        scope_binding: compute_scope_binding(recipient, snapshot_id, watermark_token),
        encrypted_payload: envelope_cipher.encrypt(plaintext)?,
    })
}

fn build_audit_extract(audit_events: &[AuditEvent]) -> Vec<AuditExtractEntry> {
    audit_events
        .iter()
        .map(|event| AuditExtractEntry {
            event_id: event.event_id.clone(),
            timestamp: event.timestamp,
            actor_user_id: event.actor.user_id.clone(),
            session_id: event.actor.session_id.clone(),
            action: event.action.as_str().to_string(),
            result: event.result.as_str().to_string(),
            tenant_id: event.target.tenant_id.clone(),
            project_id: event.target.project_id.clone(),
            resource_id: event.target.resource_id.clone(),
            context: event.context.clone(),
            context_fields: event.context_fields.clone(),
            data_fingerprint: event.data_fingerprint.clone(),
            prev_hash: event.prev_hash.clone(),
            event_hash: event.event_hash.clone(),
        })
        .collect()
}

struct CertificateBuildInput<'a> {
    template: &'a EvidenceTemplate,
    package_id: &'a str,
    snapshot_id: &'a str,
    recipient: &'a EvidenceRecipient,
    watermark_token: &'a str,
    metadata_manifest_digest: &'a str,
    data_payload_digest: &'a str,
    audit_extract_digest: &'a str,
    jurisdiction_marker_digest: &'a str,
    exported_document_digest: &'a str,
    scope_binding: &'a str,
    timestamp_authority: &'a str,
    anchor_network: &'a str,
    created_at: DateTime<Utc>,
}

fn build_certificate(input: CertificateBuildInput<'_>) -> CertificateOfAuthenticity {
    let CertificateBuildInput {
        template,
        package_id,
        snapshot_id,
        recipient,
        watermark_token,
        metadata_manifest_digest,
        data_payload_digest,
        audit_extract_digest,
        jurisdiction_marker_digest,
        exported_document_digest,
        scope_binding,
        timestamp_authority,
        anchor_network,
        created_at,
    } = input;
    let serial_number = digest_of(&format!(
        "{}|{}|{}|{}|{}",
        template.as_str(),
        package_id,
        snapshot_id,
        recipient.user_id,
        created_at.to_rfc3339()
    ));
    CertificateOfAuthenticity {
        serial_number,
        title: template.certificate_title().into(),
        template: template.as_str().into(),
        jurisdiction: template.jurisdiction().into(),
        jurisdiction_code: template.jurisdiction_code().into(),
        jurisdiction_profile_version: template.profile_version().into(),
        statement: template.certificate_statement().into(),
        issuer: template.certificate_issuer().into(),
        subject: format!("{}:{}:{}", recipient.tenant_id, recipient.project_id, snapshot_id),
        issued_at: created_at,
        package_id: package_id.into(),
        snapshot_id: snapshot_id.into(),
        recipient_user_id: recipient.user_id.clone(),
        delivery_channel: recipient.delivery_channel.clone(),
        hash_algorithm: "sha256".into(),
        metadata_manifest_digest: metadata_manifest_digest.into(),
        data_payload_digest: data_payload_digest.into(),
        audit_extract_digest: audit_extract_digest.into(),
        jurisdiction_marker_digest: jurisdiction_marker_digest.into(),
        exported_document_digest: exported_document_digest.into(),
        scope_binding: scope_binding.into(),
        timestamp_authority: timestamp_authority.into(),
        anchor_network: anchor_network.into(),
        watermark_token: watermark_token.into(),
        required_components: template
            .required_components()
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        verification_steps: template
            .verification_steps()
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        assertions: vec![
            "Recipient-scoped encrypted data payload attached with a unique envelope key.".into(),
            "Audit extract hashes and event ordering were validated at export time.".into(),
            "Metadata manifest and jurisdiction marker were sealed into the package hash chain."
                .into(),
            "Trusted timestamp and blockchain anchor receipts are bound to the hash-chain digest."
                .into(),
            "Jurisdiction profile required components are enumerated and digest-bound in the manifest."
                .into(),
        ],
    }
}

fn render_export_document(
    template: &EvidenceTemplate,
    package_id: &str,
    snapshot_id: &str,
    data_payload: &EvidenceDataPayload,
    audit_event_count: usize,
) -> String {
    format!(
        concat!(
            "{header}\n",
            "Package ID: {package_id}\n",
            "Snapshot: {snapshot_id}\n",
            "Recipient User: {recipient_user}\n",
            "Delivery Channel: {delivery_channel}\n",
            "Audit Events: {audit_event_count}\n",
            "Jurisdiction Code: {jurisdiction_code}\n",
            "Jurisdiction Profile: {jurisdiction_profile}\n",
            "Encrypted Data Payload: attached\n",
            "Payload Digest: {payload_digest}\n",
            "Payload KMS Provider: {kms_provider}\n",
            "Payload DEK ID: {dek_id}\n",
            "Recipient Scope Binding: {scope_binding}\n",
            "Traceable Watermark: embedded\n"
        ),
        header = template.export_header(),
        package_id = package_id,
        snapshot_id = snapshot_id,
        recipient_user = data_payload.recipient.user_id,
        delivery_channel = data_payload.recipient.delivery_channel,
        audit_event_count = audit_event_count,
        jurisdiction_code = template.jurisdiction_code(),
        jurisdiction_profile = template.profile_version(),
        payload_digest = data_payload.plaintext_digest,
        kms_provider = data_payload.encrypted_payload.kms_provider,
        dek_id = data_payload.encrypted_payload.dek_id,
        scope_binding = data_payload.scope_binding,
    )
}

fn compute_scope_binding(
    recipient: &EvidenceRecipient,
    snapshot_id: &str,
    watermark_token: &str,
) -> String {
    digest_of(&format!(
        "{}|{}|{}|{}|{}|{}",
        recipient.tenant_id,
        recipient.project_id,
        recipient.user_id,
        recipient.delivery_channel,
        snapshot_id,
        watermark_token
    ))
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, EvidenceError> {
    let json = serde_json::to_string(value).map_err(|_| EvidenceError::Serialization)?;
    Ok(digest_of(&json))
}

fn build_hash_chain(entries: &[(&str, String)]) -> EvidenceHashChain {
    let mut previous = None::<String>;
    let mut links = Vec::with_capacity(entries.len());

    for (component, digest) in entries {
        let chained_digest = match previous.as_deref() {
            Some(previous_digest) => digest_of(&format!("{previous_digest}|{component}|{digest}")),
            None => digest_of(&format!("{component}|{digest}")),
        };
        links.push(HashChainLink {
            component: (*component).to_string(),
            digest: digest.clone(),
            previous_digest: previous.clone(),
            chained_digest: chained_digest.clone(),
        });
        previous = Some(chained_digest);
    }

    EvidenceHashChain {
        algorithm: "sha256-chain-v1".into(),
        final_digest: previous.unwrap_or_else(|| digest_of("empty-chain")),
        links,
    }
}

fn build_jurisdiction_marker(template: &EvidenceTemplate) -> JurisdictionMarker {
    JurisdictionMarker {
        template: template.as_str().into(),
        jurisdiction: template.jurisdiction().into(),
        standards: template
            .standards()
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        key_requirements: template
            .key_requirements()
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        profile_version: template.profile_version().into(),
        jurisdiction_code: template.jurisdiction_code().into(),
        submission_language: template.submission_language().into(),
        filing_authority: template.filing_authority().into(),
        accepted_formats: template
            .accepted_formats()
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        required_components: template
            .required_components()
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        verification_steps: template
            .verification_steps()
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        retention_requirement: template.retention_requirement().into(),
    }
}

fn build_jurisdiction_marker_for_label(template: &str) -> JurisdictionMarker {
    match EvidenceTemplate::from_str(template) {
        Ok(template) => build_jurisdiction_marker(&template),
        Err(_) => JurisdictionMarker {
            template: template.to_string(),
            jurisdiction: "Unknown".into(),
            standards: Vec::new(),
            key_requirements: Vec::new(),
            profile_version: String::new(),
            jurisdiction_code: String::new(),
            submission_language: String::new(),
            filing_authority: String::new(),
            accepted_formats: Vec::new(),
            required_components: Vec::new(),
            verification_steps: Vec::new(),
            retention_requirement: String::new(),
        },
    }
}

fn expected_hash_chain(package: &EvidencePackage) -> EvidenceHashChain {
    build_hash_chain(&[
        (
            "metadata_manifest",
            digest_json(&package.metadata_manifest).unwrap_or_default(),
        ),
        (
            "data_payload",
            digest_json(&package.data_payload).unwrap_or_default(),
        ),
        (
            "audit_extract",
            digest_json(&package.audit_extract).unwrap_or_default(),
        ),
        (
            "certificate_of_authenticity",
            digest_json(&package.certificate_of_authenticity).unwrap_or_default(),
        ),
        ("exported_document", digest_of(&package.exported_document)),
        (
            "jurisdiction_marker",
            digest_json(&package.jurisdiction_marker).unwrap_or_default(),
        ),
    ])
}

fn digest_of(value: &str) -> String {
    digest_of_bytes(value.as_bytes())
}

fn digest_of_bytes(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

pub(crate) fn validate_sha256_digest(digest: &str) -> Result<(), EvidenceError> {
    if digest.len() != 64
        || !digest
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(EvidenceError::ProviderProtocol(
            "expected lowercase or uppercase sha256 hex digest".into(),
        ));
    }
    Ok(())
}

fn build_provider_runtime(
    timestamp_receipt: &TimestampReceipt,
    anchor_receipt: &AnchorReceipt,
) -> EvidenceProviderRuntime {
    let timestamp_provider = timestamp_receipt
        .provider
        .clone()
        .unwrap_or_else(|| timestamp_receipt.authority.clone());
    let anchor_provider = anchor_receipt
        .provider
        .clone()
        .unwrap_or_else(|| anchor_receipt.network.clone());
    let timestamp_runtime_mode = provider_runtime_mode(&timestamp_provider, true);
    let anchor_runtime_mode = provider_runtime_mode(&anchor_provider, false);
    let mut mock_components = Vec::new();
    if timestamp_runtime_mode == "mock" {
        mock_components.push("timestamp_authority".into());
    }
    if anchor_runtime_mode == "mock" {
        mock_components.push("blockchain_anchor".into());
    }
    let external_final_uat_required =
        timestamp_runtime_mode == "external" || anchor_runtime_mode == "external";
    let overall_mode = if !mock_components.is_empty() {
        "mock"
    } else if external_final_uat_required {
        "external"
    } else {
        "repo_local"
    };

    EvidenceProviderRuntime {
        timestamp_provider,
        timestamp_runtime_mode,
        anchor_provider,
        anchor_runtime_mode,
        overall_mode: overall_mode.into(),
        external_final_uat_required,
        mock_components,
    }
}

fn provider_runtime_mode(provider: &str, timestamp: bool) -> String {
    match provider.trim().to_ascii_lowercase().as_str() {
        "mock" => "mock".into(),
        "internal-hsm" | "internal_hsm" => "repo_local".into(),
        "" if timestamp => "unknown".into(),
        "" => "unknown".into(),
        _ => "external".into(),
    }
}

fn verification_status_from_anchor(receipt: &AnchorReceipt) -> EvidenceVerificationStatus {
    match receipt.status {
        AnchorStatus::Pending => EvidenceVerificationStatus::PendingAnchor,
        AnchorStatus::Confirmed => EvidenceVerificationStatus::Verified,
        AnchorStatus::Failed => EvidenceVerificationStatus::FailedAnchor,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use sdqp_audit::{ActionResult, ActionType, ActorInfo, AuditEvent, TargetRef};
    use sdqp_encryption::DevelopmentEnvelopeCipher;
    use sdqp_watermark::WatermarkPayload;

    use super::{
        BlockchainAnchorConfig, EvidenceBuildRequest, EvidenceBuilder, EvidenceMetadataManifest,
        EvidenceProviderRegistry, EvidenceRecipient, EvidenceTemplate, MetadataDataSource,
        MetadataFieldDescriptor, MetadataQueryParameter, MockBlockchainAnchor,
        MockTimestampAuthority, TsaProviderConfig,
    };

    fn sample_events() -> Vec<AuditEvent> {
        let actor = ActorInfo {
            user_id: "user-analyst".into(),
            session_id: "session-a".into(),
            ip_address: "127.0.0.1".into(),
        };
        let target = TargetRef {
            tenant_id: "tenant-alpha".into(),
            project_id: Some("project-alpha".into()),
            resource_id: "snapshot-a".into(),
        };
        let first = AuditEvent::new(
            actor.clone(),
            ActionType::Query,
            target.clone(),
            "query submitted",
            ActionResult::Success,
            None,
            None,
        );
        let second = AuditEvent::new(
            actor,
            ActionType::Export,
            target,
            "evidence exported",
            ActionResult::Success,
            None,
            Some(first.event_hash.clone()),
        );

        vec![first, second]
    }

    fn sample_payload() -> WatermarkPayload {
        WatermarkPayload {
            tenant_id: "tenant-alpha".into(),
            project_id: "project-alpha".into(),
            user_id: "user-analyst".into(),
            sequence_number: 9,
            issued_at: Utc::now(),
            snapshot_id: Some("snapshot-a".into()),
        }
    }

    fn sample_recipient() -> EvidenceRecipient {
        EvidenceRecipient {
            tenant_id: "tenant-alpha".into(),
            project_id: "project-alpha".into(),
            user_id: "user-analyst".into(),
            delivery_channel: "authorized-download".into(),
        }
    }

    fn sample_metadata_manifest() -> EvidenceMetadataManifest {
        EvidenceMetadataManifest {
            field_descriptors: vec![
                MetadataFieldDescriptor {
                    field_name: "employee_id".into(),
                    ordinal: 0,
                },
                MetadataFieldDescriptor {
                    field_name: "department".into(),
                    ordinal: 1,
                },
            ],
            query_parameters: vec![
                MetadataQueryParameter {
                    name: "snapshot_id".into(),
                    value: "snapshot-a".into(),
                },
                MetadataQueryParameter {
                    name: "template".into(),
                    value: "china-judicial".into(),
                },
            ],
            permission_grant: None,
            data_source: MetadataDataSource {
                data_source_id: "datasource-rest".into(),
                storage_key: "tenant-alpha/project-alpha/snapshot-a.snapshot.json.enc".into(),
                row_count: 42,
                columns: vec!["employee_id".into(), "department".into()],
            },
        }
    }

    #[tokio::test]
    async fn evidence_package_builds_with_encrypted_payload_and_certificate() {
        let builder = EvidenceBuilder::new(
            MockTimestampAuthority::default(),
            MockBlockchainAnchor::default(),
            DevelopmentEnvelopeCipher::new("dek-evidence", 0x5A),
        );
        let package = builder
            .build_package(EvidenceBuildRequest {
                snapshot_id: "snapshot-a".into(),
                template: EvidenceTemplate::ChinaJudicial,
                recipient: sample_recipient(),
                metadata_manifest: sample_metadata_manifest(),
                watermark_payload: sample_payload(),
                audit_events: sample_events(),
                export_body: "phase5 export".into(),
            })
            .await
            .expect("package");

        let decrypted = builder.decrypt_data_payload(&package).expect("decrypted");
        assert_eq!(String::from_utf8(decrypted).expect("utf8"), "phase5 export");
        assert!(!package.exported_document.contains("phase5 export"));
        assert!(!package.exported_document.contains("[[SDQP-WM:"));
        assert!(
            package
                .exported_document
                .contains("Traceable Watermark: embedded")
        );
        assert_eq!(package.template, "china-judicial");
        assert_eq!(package.timestamp_receipt.authority, "mock-tsa");
        assert_eq!(package.anchor_receipt.network, "mock-chain");
        assert_eq!(package.hash_chain.algorithm, "sha256-chain-v1");
        assert_eq!(package.data_payload.recipient.user_id, "user-analyst");
        assert_eq!(
            package.certificate_of_authenticity.title,
            "Electronic Evidence Authenticity Statement"
        );
    }

    #[tokio::test]
    async fn verification_replays_chain_payload_and_watermark() {
        let builder = EvidenceBuilder::new(
            MockTimestampAuthority::default(),
            MockBlockchainAnchor::default(),
            DevelopmentEnvelopeCipher::new("dek-evidence", 0x5A),
        );
        let events = sample_events();
        let package = builder
            .build_package(EvidenceBuildRequest {
                snapshot_id: "snapshot-a".into(),
                template: EvidenceTemplate::EuRegulatory,
                recipient: sample_recipient(),
                metadata_manifest: sample_metadata_manifest(),
                watermark_payload: sample_payload(),
                audit_events: events.clone(),
                export_body: "phase5 export".into(),
            })
            .await
            .expect("package");

        let verification = builder.verify_package(&package, &events).await;
        assert!(verification.verified);
        assert!(verification.metadata_manifest_valid);
        assert!(verification.data_payload_valid);
        assert!(verification.audit_extract_valid);
        assert!(verification.hash_chain_valid);
        assert!(verification.jurisdiction_marker_valid);
        assert!(verification.certificate_valid);
        assert!(verification.anchor_valid);
        assert!(verification.anchor_confirmed);
    }

    #[tokio::test]
    async fn registry_keeps_mock_providers_available() {
        let registry = EvidenceProviderRegistry::from_configs(
            TsaProviderConfig::default(),
            BlockchainAnchorConfig::default(),
        )
        .expect("registry");
        let builder = registry.builder();
        let package = builder
            .build_package(EvidenceBuildRequest {
                snapshot_id: "snapshot-a".into(),
                template: EvidenceTemplate::UsLitigation,
                recipient: sample_recipient(),
                metadata_manifest: sample_metadata_manifest(),
                watermark_payload: sample_payload(),
                audit_events: sample_events(),
                export_body: "body".into(),
            })
            .await
            .expect("package");

        assert_eq!(package.timestamp_receipt.provider.as_deref(), Some("mock"));
        assert_eq!(package.anchor_receipt.provider.as_deref(), Some("mock"));
        assert_eq!(package.provider_runtime.overall_mode, "mock");
        assert_eq!(package.provider_runtime.mock_components.len(), 2);
        assert_eq!(
            package.data_payload.encrypted_payload.kms_provider,
            "development"
        );
    }

    #[test]
    fn registry_accepts_named_tsa_and_anchor_provider_aliases() {
        let registry = EvidenceProviderRegistry::from_configs(
            TsaProviderConfig {
                provider: "ntsc".into(),
                base_url: "https://tsa.example.invalid".into(),
                api_key: "key".into(),
                authority: "ntsc".into(),
                timeout_ms: 1_000,
                require_external: true,
            },
            BlockchainAnchorConfig {
                provider: "fabric".into(),
                base_url: "https://anchor.example.invalid".into(),
                api_key: "key".into(),
                network: "fabric-stage".into(),
                timeout_ms: 1_000,
                require_external: true,
            },
        );

        assert!(registry.is_ok());
    }

    #[test]
    fn registry_rejects_mock_when_external_providers_are_required() {
        let registry = EvidenceProviderRegistry::from_configs(
            TsaProviderConfig {
                require_external: true,
                ..TsaProviderConfig::default()
            },
            BlockchainAnchorConfig::default(),
        );

        assert!(registry.is_err());
    }
}
