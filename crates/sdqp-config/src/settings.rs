use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Environment {
    Dev,
    Test,
    Ci,
    LocalDocker,
    ProdSim,
}

impl Environment {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        match value.to_ascii_lowercase().as_str() {
            "dev" => Ok(Self::Dev),
            "test" => Ok(Self::Test),
            "ci" => Ok(Self::Ci),
            "local-docker" => Ok(Self::LocalDocker),
            "prod-sim" => Ok(Self::ProdSim),
            _ => Err(ConfigError::InvalidEnvironment(value.to_string())),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Test => "test",
            Self::Ci => "ci",
            Self::LocalDocker => "local-docker",
            Self::ProdSim => "prod-sim",
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("invalid environment: {0}")]
    InvalidEnvironment(String),
    #[error("invalid port value for {key}: {value}")]
    InvalidPort { key: String, value: String },
    #[error("missing config file: {path}")]
    MissingConfigFile { path: PathBuf },
    #[error("failed to read config file {path}: {message}")]
    ReadConfigFile { path: PathBuf, message: String },
    #[error("failed to parse config file {path}: {message}")]
    ParseConfigFile { path: PathBuf, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiSettings {
    pub host: String,
    pub port: u16,
    pub service_name: String,
    #[serde(default)]
    pub external_query_worker: bool,
}

impl ApiSettings {
    pub fn base_url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerSettings {
    pub host: String,
    pub port: u16,
    pub service_name: String,
    #[serde(default = "default_query_poll_interval_ms")]
    pub query_poll_interval_ms: u64,
    #[serde(default = "default_query_lease_secs")]
    pub query_lease_secs: u64,
    #[serde(default = "default_query_max_attempts")]
    pub query_max_attempts: u32,
}

impl WorkerSettings {
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

const fn default_query_poll_interval_ms() -> u64 {
    50
}

const fn default_query_lease_secs() -> u64 {
    30
}

const fn default_query_max_attempts() -> u32 {
    2
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontendSettings {
    pub title: String,
    pub port: u16,
    pub api_base_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresSettings {
    pub dsn: String,
    pub max_connections: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClickHouseSettings {
    pub http_url: String,
    pub native_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseSettings {
    pub postgres: PostgresSettings,
    pub clickhouse: ClickHouseSettings,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectStoreSettings {
    pub endpoint: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub bucket_snapshots: String,
    pub bucket_evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KafkaSettings {
    pub brokers: Vec<String>,
    pub audit_topic: String,
    pub query_topic: String,
    pub ueba_topic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityProviderSettings {
    #[serde(default = "default_oidc_provider")]
    pub oidc_provider: String,
    #[serde(default = "default_saml_provider")]
    pub saml_provider: String,
    #[serde(default = "default_scim_provider")]
    pub scim_provider: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    #[serde(default)]
    pub oidc_authorize_url: String,
    #[serde(default)]
    pub oidc_token_url: String,
    #[serde(default)]
    pub oidc_userinfo_url: String,
    #[serde(default)]
    pub saml_sso_url: String,
    #[serde(default)]
    pub saml_exchange_url: String,
    #[serde(default)]
    pub saml_entity_id: String,
    #[serde(default)]
    pub saml_audience: String,
    pub scim_base_url: String,
    pub scim_token: String,
    #[serde(default = "default_scim_tenant_id")]
    pub scim_tenant_id: String,
    #[serde(default = "default_scim_page_size")]
    pub scim_page_size: u64,
    #[serde(default = "default_integration_timeout_ms")]
    pub scim_timeout_ms: u64,
    #[serde(default = "default_scim_retry_attempts")]
    pub scim_retry_attempts: u64,
    #[serde(default = "default_notification_retry_backoff_ms")]
    pub scim_retry_backoff_ms: u64,
    #[serde(default = "default_scim_disable_missing")]
    pub scim_disable_missing_users: bool,
    #[serde(default = "default_scim_disable_missing")]
    pub scim_disable_missing_groups: bool,
    #[serde(default)]
    pub scim_delete_missing_users: bool,
    #[serde(default)]
    pub scim_delete_missing_groups: bool,
}

fn default_oidc_provider() -> String {
    "mock".into()
}

fn default_saml_provider() -> String {
    "mock".into()
}

fn default_scim_provider() -> String {
    "mock".into()
}

fn default_scim_tenant_id() -> String {
    "tenant-alpha".into()
}

const fn default_scim_page_size() -> u64 {
    100
}

const fn default_scim_retry_attempts() -> u64 {
    2
}

const fn default_scim_disable_missing() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityApiKeySettings {
    pub key_id: String,
    pub secret: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityRateLimitSettings {
    #[serde(default = "default_security_rate_limit_max_requests")]
    pub max_requests: usize,
    #[serde(default = "default_security_rate_limit_window_secs")]
    pub window_secs: u64,
}

impl Default for SecurityRateLimitSettings {
    fn default() -> Self {
        Self {
            max_requests: default_security_rate_limit_max_requests(),
            window_secs: default_security_rate_limit_window_secs(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRotationSettings {
    #[serde(default = "default_credential_rotation_enabled")]
    pub enabled: bool,
    #[serde(default = "default_credential_rotation_interval_secs")]
    pub interval_secs: i64,
    #[serde(default = "default_credential_rotation_retry_backoff_secs")]
    pub retry_backoff_secs: i64,
    #[serde(default = "default_credential_rotation_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_credential_rotation_manual_after_attempts")]
    pub manual_intervention_after_attempts: u32,
}

impl Default for CredentialRotationSettings {
    fn default() -> Self {
        Self {
            enabled: default_credential_rotation_enabled(),
            interval_secs: default_credential_rotation_interval_secs(),
            retry_backoff_secs: default_credential_rotation_retry_backoff_secs(),
            max_attempts: default_credential_rotation_max_attempts(),
            manual_intervention_after_attempts: default_credential_rotation_manual_after_attempts(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeSettings {
    #[serde(default = "default_tee_provider")]
    pub provider: String,
    #[serde(default)]
    pub attestation_url: String,
    #[serde(default)]
    pub expected_measurements: Vec<String>,
}

impl Default for TeeSettings {
    fn default() -> Self {
        Self {
            provider: default_tee_provider(),
            attestation_url: String::new(),
            expected_measurements: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecuritySettings {
    #[serde(default = "default_mfa_bootstrap_seed")]
    pub mfa_bootstrap_seed: String,
    #[serde(default = "default_mfa_challenge_ttl_secs")]
    pub mfa_challenge_ttl_secs: i64,
    #[serde(default = "default_totp_issuer")]
    pub totp_issuer: String,
    #[serde(default = "default_totp_period_secs")]
    pub totp_period_secs: u64,
    #[serde(default = "default_totp_digits")]
    pub totp_digits: u32,
    #[serde(default = "default_totp_allowed_drift_steps")]
    pub totp_allowed_drift_steps: u8,
    #[serde(default = "default_webauthn_rp_id")]
    pub webauthn_rp_id: String,
    #[serde(default = "default_webauthn_origin")]
    pub webauthn_origin: String,
    #[serde(default = "default_webauthn_timeout_ms")]
    pub webauthn_timeout_ms: u64,
    #[serde(default = "default_webauthn_require_user_verification")]
    pub webauthn_require_user_verification: bool,
    #[serde(default)]
    pub integration_api_keys: Vec<SecurityApiKeySettings>,
    #[serde(default)]
    pub integration_ip_allowlist: Vec<String>,
    #[serde(default)]
    pub integration_mtls_subjects: Vec<String>,
    #[serde(default)]
    pub integration_rate_limit: SecurityRateLimitSettings,
    #[serde(default)]
    pub credential_rotation: CredentialRotationSettings,
    #[serde(default)]
    pub tee: TeeSettings,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            mfa_bootstrap_seed: default_mfa_bootstrap_seed(),
            mfa_challenge_ttl_secs: default_mfa_challenge_ttl_secs(),
            totp_issuer: default_totp_issuer(),
            totp_period_secs: default_totp_period_secs(),
            totp_digits: default_totp_digits(),
            totp_allowed_drift_steps: default_totp_allowed_drift_steps(),
            webauthn_rp_id: default_webauthn_rp_id(),
            webauthn_origin: default_webauthn_origin(),
            webauthn_timeout_ms: default_webauthn_timeout_ms(),
            webauthn_require_user_verification: default_webauthn_require_user_verification(),
            integration_api_keys: Vec::new(),
            integration_ip_allowlist: Vec::new(),
            integration_mtls_subjects: Vec::new(),
            integration_rate_limit: SecurityRateLimitSettings::default(),
            credential_rotation: CredentialRotationSettings::default(),
            tee: TeeSettings::default(),
        }
    }
}

fn default_mfa_bootstrap_seed() -> String {
    "sdqp-dev-mfa-bootstrap".into()
}

const fn default_mfa_challenge_ttl_secs() -> i64 {
    300
}

fn default_totp_issuer() -> String {
    "SDQP".into()
}

const fn default_totp_period_secs() -> u64 {
    30
}

const fn default_totp_digits() -> u32 {
    6
}

const fn default_totp_allowed_drift_steps() -> u8 {
    1
}

fn default_webauthn_rp_id() -> String {
    "sdqp.local".into()
}

fn default_webauthn_origin() -> String {
    "https://sdqp.local".into()
}

const fn default_webauthn_timeout_ms() -> u64 {
    300_000
}

const fn default_webauthn_require_user_verification() -> bool {
    true
}

const fn default_security_rate_limit_max_requests() -> usize {
    60
}

const fn default_security_rate_limit_window_secs() -> u64 {
    60
}

const fn default_credential_rotation_enabled() -> bool {
    true
}

const fn default_credential_rotation_interval_secs() -> i64 {
    90 * 24 * 60 * 60
}

const fn default_credential_rotation_retry_backoff_secs() -> i64 {
    60 * 60
}

const fn default_credential_rotation_max_attempts() -> u32 {
    3
}

const fn default_credential_rotation_manual_after_attempts() -> u32 {
    3
}

fn default_tee_provider() -> String {
    "mock".into()
}

const fn default_kms_rotation_enabled() -> bool {
    true
}

const fn default_kms_rotation_cycle_interval_secs() -> u64 {
    60 * 60
}

const fn default_kms_rotation_batch_limit() -> u64 {
    100
}

const fn default_kms_dek_rotation_days() -> i64 {
    90
}

const fn default_kms_kek_rotation_days() -> i64 {
    365
}

const fn default_kms_allow_dek_rotation() -> bool {
    true
}

const fn default_kms_allow_kek_rewrap() -> bool {
    true
}

const fn default_classification_default_retention_days() -> i64 {
    365
}

const fn default_classification_restricted_retention_days() -> i64 {
    5 * 365
}

fn default_classification_manual_confirmation_level() -> String {
    "l4_sensitive".into()
}

fn default_classification_regulations() -> Vec<String> {
    vec!["PIPL".into(), "DSL".into(), "CSL".into()]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KmsSettings {
    pub provider: String,
    pub endpoint: String,
    pub master_key_id: String,
    pub key_ring: String,
    #[serde(default)]
    pub auth_token: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub key_version: String,
    #[serde(default)]
    pub rotation: KmsRotationSettings,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KmsRotationSettings {
    #[serde(default = "default_kms_rotation_enabled")]
    pub enabled: bool,
    #[serde(default = "default_kms_rotation_cycle_interval_secs")]
    pub cycle_interval_secs: u64,
    #[serde(default = "default_kms_rotation_batch_limit")]
    pub batch_limit: u64,
    #[serde(default = "default_kms_dek_rotation_days")]
    pub dek_rotation_days: i64,
    #[serde(default = "default_kms_kek_rotation_days")]
    pub kek_rotation_days: i64,
    #[serde(default = "default_kms_allow_dek_rotation")]
    pub allow_dek_rotation: bool,
    #[serde(default = "default_kms_allow_kek_rewrap")]
    pub allow_kek_rewrap: bool,
}

impl Default for KmsRotationSettings {
    fn default() -> Self {
        Self {
            enabled: default_kms_rotation_enabled(),
            cycle_interval_secs: default_kms_rotation_cycle_interval_secs(),
            batch_limit: default_kms_rotation_batch_limit(),
            dek_rotation_days: default_kms_dek_rotation_days(),
            kek_rotation_days: default_kms_kek_rotation_days(),
            allow_dek_rotation: default_kms_allow_dek_rotation(),
            allow_kek_rewrap: default_kms_allow_kek_rewrap(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassificationSettings {
    #[serde(default = "default_classification_default_retention_days")]
    pub default_retention_days: i64,
    #[serde(default = "default_classification_restricted_retention_days")]
    pub restricted_retention_days: i64,
    #[serde(default = "default_classification_manual_confirmation_level")]
    pub manual_confirmation_required_level: String,
    #[serde(default = "default_classification_regulations")]
    pub default_regulations: Vec<String>,
}

impl Default for ClassificationSettings {
    fn default() -> Self {
        Self {
            default_retention_days: default_classification_default_retention_days(),
            restricted_retention_days: default_classification_restricted_retention_days(),
            manual_confirmation_required_level: default_classification_manual_confirmation_level(),
            default_regulations: default_classification_regulations(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UebaGovernanceSettings {
    #[serde(default = "default_ueba_query_burst_threshold")]
    pub query_burst_threshold: u32,
    #[serde(default = "default_ueba_export_spike_threshold")]
    pub export_spike_threshold: u32,
    #[serde(default = "default_ueba_denied_query_threshold")]
    pub denied_query_threshold: u32,
    #[serde(default = "default_ueba_after_hours_start_hour")]
    pub after_hours_start_hour: u8,
    #[serde(default = "default_ueba_after_hours_end_hour")]
    pub after_hours_end_hour: u8,
    #[serde(default = "default_ueba_high_risk_score")]
    pub high_risk_score: u8,
    #[serde(default = "default_ueba_critical_risk_score")]
    pub critical_risk_score: u8,
}

impl Default for UebaGovernanceSettings {
    fn default() -> Self {
        Self {
            query_burst_threshold: default_ueba_query_burst_threshold(),
            export_spike_threshold: default_ueba_export_spike_threshold(),
            denied_query_threshold: default_ueba_denied_query_threshold(),
            after_hours_start_hour: default_ueba_after_hours_start_hour(),
            after_hours_end_hour: default_ueba_after_hours_end_hour(),
            high_risk_score: default_ueba_high_risk_score(),
            critical_risk_score: default_ueba_critical_risk_score(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UebaCalibrationSettings {
    #[serde(default = "default_ueba_calibration_enabled")]
    pub enabled: bool,
    #[serde(default = "default_ueba_calibration_min_events")]
    pub min_events: usize,
    #[serde(default = "default_ueba_calibration_model_version")]
    pub model_version: String,
    #[serde(default = "default_ueba_calibration_target_hit_rate_per_1000")]
    pub target_hit_rate_per_1000: u32,
}

impl Default for UebaCalibrationSettings {
    fn default() -> Self {
        Self {
            enabled: default_ueba_calibration_enabled(),
            min_events: default_ueba_calibration_min_events(),
            model_version: default_ueba_calibration_model_version(),
            target_hit_rate_per_1000: default_ueba_calibration_target_hit_rate_per_1000(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UebaSettings {
    #[serde(default)]
    pub governance: UebaGovernanceSettings,
    #[serde(default)]
    pub calibration: UebaCalibrationSettings,
}

const fn default_ueba_query_burst_threshold() -> u32 {
    5
}

const fn default_ueba_export_spike_threshold() -> u32 {
    3
}

const fn default_ueba_denied_query_threshold() -> u32 {
    2
}

const fn default_ueba_after_hours_start_hour() -> u8 {
    22
}

const fn default_ueba_after_hours_end_hour() -> u8 {
    6
}

const fn default_ueba_high_risk_score() -> u8 {
    70
}

const fn default_ueba_critical_risk_score() -> u8 {
    90
}

const fn default_ueba_calibration_enabled() -> bool {
    true
}

const fn default_ueba_calibration_min_events() -> usize {
    1
}

fn default_ueba_calibration_model_version() -> String {
    "ueba-governance-v1".into()
}

const fn default_ueba_calibration_target_hit_rate_per_1000() -> u32 {
    10
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HrIntegrationSettings {
    #[serde(default = "default_hr_provider")]
    pub provider: String,
    pub base_url: String,
    pub token: String,
    #[serde(default)]
    pub approver_resolution: ApproverResolutionSettings,
    #[serde(default)]
    pub feishu: FeishuIntegrationSettings,
    #[serde(default)]
    pub workday: WorkdayIntegrationSettings,
    #[serde(default)]
    pub sap_successfactors: SapSuccessFactorsIntegrationSettings,
    #[serde(default)]
    pub ldap: LdapIntegrationSettings,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverResolutionSettings {
    #[serde(default = "default_approver_system_fallback_user_id")]
    pub system_fallback_user_id: String,
    #[serde(default = "default_approver_escalation_user_ids")]
    pub escalation_user_ids: Vec<String>,
    #[serde(default = "default_approver_max_manager_hops")]
    pub max_manager_hops: u64,
    #[serde(default = "default_approver_allow_delegation")]
    pub allow_delegation: bool,
}

impl Default for ApproverResolutionSettings {
    fn default() -> Self {
        Self {
            system_fallback_user_id: default_approver_system_fallback_user_id(),
            escalation_user_ids: default_approver_escalation_user_ids(),
            max_manager_hops: default_approver_max_manager_hops(),
            allow_delegation: default_approver_allow_delegation(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeishuIntegrationSettings {
    #[serde(default = "default_feishu_provider_id")]
    pub provider_id: String,
    #[serde(default = "default_feishu_tenant_key")]
    pub tenant_key: String,
    #[serde(default)]
    pub base_url: String,
    #[serde(default = "default_feishu_auth_mode")]
    pub auth_mode: String,
    #[serde(default)]
    pub token_url: String,
    #[serde(default)]
    pub app_id: String,
    #[serde(default)]
    pub app_secret: String,
    #[serde(default)]
    pub tenant_access_token: String,
    #[serde(default = "default_feishu_users_path")]
    pub users_path: String,
    #[serde(default = "default_feishu_events_path")]
    pub events_path: String,
    #[serde(default)]
    pub webhook_verification_token: String,
    #[serde(default = "default_integration_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_feishu_page_size")]
    pub page_size: u64,
}

impl Default for FeishuIntegrationSettings {
    fn default() -> Self {
        Self {
            provider_id: default_feishu_provider_id(),
            tenant_key: default_feishu_tenant_key(),
            base_url: String::new(),
            auth_mode: default_feishu_auth_mode(),
            token_url: String::new(),
            app_id: String::new(),
            app_secret: String::new(),
            tenant_access_token: String::new(),
            users_path: default_feishu_users_path(),
            events_path: default_feishu_events_path(),
            webhook_verification_token: String::new(),
            timeout_ms: default_integration_timeout_ms(),
            page_size: default_feishu_page_size(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkdayIntegrationSettings {
    #[serde(default = "default_workday_provider_id")]
    pub provider_id: String,
    #[serde(default = "default_workday_tenant")]
    pub tenant: String,
    #[serde(default)]
    pub base_url: String,
    #[serde(default = "default_workday_auth_mode")]
    pub auth_mode: String,
    #[serde(default)]
    pub token_url: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub bearer_token: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default = "default_workday_snapshot_path")]
    pub snapshot_path: String,
    #[serde(default = "default_workday_events_path")]
    pub events_path: String,
    #[serde(default)]
    pub webhook_secret: String,
    #[serde(default = "default_integration_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_workday_page_size")]
    pub page_size: u64,
}

impl Default for WorkdayIntegrationSettings {
    fn default() -> Self {
        Self {
            provider_id: default_workday_provider_id(),
            tenant: default_workday_tenant(),
            base_url: String::new(),
            auth_mode: default_workday_auth_mode(),
            token_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            bearer_token: String::new(),
            scope: String::new(),
            snapshot_path: default_workday_snapshot_path(),
            events_path: default_workday_events_path(),
            webhook_secret: String::new(),
            timeout_ms: default_integration_timeout_ms(),
            page_size: default_workday_page_size(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SapSuccessFactorsIntegrationSettings {
    #[serde(default = "default_sap_successfactors_provider_id")]
    pub provider_id: String,
    #[serde(default = "default_sap_successfactors_company_id")]
    pub company_id: String,
    #[serde(default)]
    pub base_url: String,
    #[serde(default = "default_sap_successfactors_auth_mode")]
    pub auth_mode: String,
    #[serde(default)]
    pub token_url: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub bearer_token: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default = "default_sap_successfactors_users_path")]
    pub users_path: String,
    #[serde(default = "default_sap_successfactors_events_path")]
    pub events_path: String,
    #[serde(default)]
    pub webhook_secret: String,
    #[serde(default = "default_integration_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_sap_successfactors_page_size")]
    pub page_size: u64,
}

impl Default for SapSuccessFactorsIntegrationSettings {
    fn default() -> Self {
        Self {
            provider_id: default_sap_successfactors_provider_id(),
            company_id: default_sap_successfactors_company_id(),
            base_url: String::new(),
            auth_mode: default_sap_successfactors_auth_mode(),
            token_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            bearer_token: String::new(),
            username: String::new(),
            password: String::new(),
            scope: String::new(),
            users_path: default_sap_successfactors_users_path(),
            events_path: default_sap_successfactors_events_path(),
            webhook_secret: String::new(),
            timeout_ms: default_integration_timeout_ms(),
            page_size: default_sap_successfactors_page_size(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LdapIntegrationSettings {
    #[serde(default = "default_ldap_provider_id")]
    pub provider_id: String,
    #[serde(default)]
    pub url: String,
    #[serde(default = "default_ldap_auth_mode")]
    pub auth_mode: String,
    #[serde(default)]
    pub bind_dn: String,
    #[serde(default)]
    pub bind_password: String,
    #[serde(default = "default_ldap_tls_mode")]
    pub tls_mode: String,
    #[serde(default)]
    pub ca_cert_path: String,
    #[serde(default = "default_ldap_tls_require_valid_cert")]
    pub tls_require_valid_cert: bool,
    #[serde(default)]
    pub base_dn: String,
    #[serde(default = "default_ldap_search_filter")]
    pub search_filter: String,
    #[serde(default = "default_ldap_search_scope")]
    pub search_scope: String,
    #[serde(default = "default_ldap_user_id_attribute")]
    pub user_id_attribute: String,
    #[serde(default = "default_ldap_department_attribute")]
    pub department_attribute: String,
    #[serde(default = "default_ldap_manager_attribute")]
    pub manager_attribute: String,
    #[serde(default = "default_ldap_status_attribute")]
    pub status_attribute: String,
    #[serde(default = "default_ldap_changed_since_attribute")]
    pub changed_since_attribute: String,
    #[serde(default = "default_ldap_active_status_values")]
    pub active_status_values: Vec<String>,
    #[serde(default = "default_ldap_departed_status_values")]
    pub departed_status_values: Vec<String>,
    #[serde(default = "default_integration_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_ldap_page_size")]
    pub page_size: u64,
    #[serde(default = "default_ldapsearch_binary")]
    pub ldapsearch_binary: String,
}

impl Default for LdapIntegrationSettings {
    fn default() -> Self {
        Self {
            provider_id: default_ldap_provider_id(),
            url: String::new(),
            auth_mode: default_ldap_auth_mode(),
            bind_dn: String::new(),
            bind_password: String::new(),
            tls_mode: default_ldap_tls_mode(),
            ca_cert_path: String::new(),
            tls_require_valid_cert: default_ldap_tls_require_valid_cert(),
            base_dn: String::new(),
            search_filter: default_ldap_search_filter(),
            search_scope: default_ldap_search_scope(),
            user_id_attribute: default_ldap_user_id_attribute(),
            department_attribute: default_ldap_department_attribute(),
            manager_attribute: default_ldap_manager_attribute(),
            status_attribute: default_ldap_status_attribute(),
            changed_since_attribute: default_ldap_changed_since_attribute(),
            active_status_values: default_ldap_active_status_values(),
            departed_status_values: default_ldap_departed_status_values(),
            timeout_ms: default_integration_timeout_ms(),
            page_size: default_ldap_page_size(),
            ldapsearch_binary: default_ldapsearch_binary(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationSettings {
    pub feishu_webhook_url: String,
    pub slack_webhook_url: String,
    pub email_api_url: String,
    pub telegram_bot_api_url: String,
    pub dingtalk_webhook_url: String,
    #[serde(default = "default_notification_retry_backoff_ms")]
    pub retry_backoff_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsaSettings {
    #[serde(default = "default_tsa_provider")]
    pub provider: String,
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_tsa_authority")]
    pub authority: String,
    #[serde(default = "default_integration_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub require_external: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockchainAnchorSettings {
    #[serde(default = "default_blockchain_provider")]
    pub provider: String,
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_blockchain_network")]
    pub network: String,
    #[serde(default = "default_integration_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub require_external: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpIntegrationSettings {
    #[serde(default = "default_dlp_provider")]
    pub provider: String,
    #[serde(default = "default_dlp_provider_id")]
    pub provider_id: String,
    #[serde(default)]
    pub webhook_url: String,
    #[serde(default)]
    pub auth_header: String,
    #[serde(default)]
    pub auth_token: String,
    #[serde(default = "default_integration_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_dlp_default_action")]
    pub default_action: String,
}

impl Default for DlpIntegrationSettings {
    fn default() -> Self {
        Self {
            provider: default_dlp_provider(),
            provider_id: default_dlp_provider_id(),
            webhook_url: String::new(),
            auth_header: String::new(),
            auth_token: String::new(),
            timeout_ms: default_integration_timeout_ms(),
            default_action: default_dlp_default_action(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationSettings {
    pub im_webhook_url: String,
    pub hr: HrIntegrationSettings,
    pub notifications: NotificationSettings,
    pub tsa: TsaSettings,
    pub blockchain_anchor: BlockchainAnchorSettings,
    #[serde(default)]
    pub dlp: DlpIntegrationSettings,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheckpointSettings {
    #[serde(default = "default_audit_checkpoint_provider")]
    pub provider: String,
    #[serde(default = "default_audit_checkpoint_key_id")]
    pub key_id: String,
    #[serde(default = "default_audit_checkpoint_key_version")]
    pub key_version: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub key_ring: String,
    #[serde(default)]
    pub auth_token: String,
}

impl Default for AuditCheckpointSettings {
    fn default() -> Self {
        Self {
            provider: default_audit_checkpoint_provider(),
            key_id: default_audit_checkpoint_key_id(),
            key_version: default_audit_checkpoint_key_version(),
            endpoint: String::new(),
            region: String::new(),
            key_ring: String::new(),
            auth_token: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditForwarderSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_audit_forwarder_provider")]
    pub provider: String,
    #[serde(default = "default_integration_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub webhook_url: String,
    #[serde(default)]
    pub auth_header: String,
    #[serde(default)]
    pub auth_token: String,
    #[serde(default)]
    pub kafka_brokers: Vec<String>,
    #[serde(default = "default_audit_forwarder_topic")]
    pub kafka_topic: String,
    #[serde(default)]
    pub syslog_endpoint: String,
    #[serde(default = "default_audit_forwarder_syslog_hostname")]
    pub syslog_hostname: String,
    #[serde(default = "default_audit_forwarder_syslog_app_name")]
    pub syslog_app_name: String,
}

impl Default for AuditForwarderSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: default_audit_forwarder_provider(),
            timeout_ms: default_integration_timeout_ms(),
            webhook_url: String::new(),
            auth_header: String::new(),
            auth_token: String::new(),
            kafka_brokers: Vec::new(),
            kafka_topic: default_audit_forwarder_topic(),
            syslog_endpoint: String::new(),
            syslog_hostname: default_audit_forwarder_syslog_hostname(),
            syslog_app_name: default_audit_forwarder_syslog_app_name(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRetentionSettings {
    #[serde(default = "default_audit_retention_enabled")]
    pub enabled: bool,
    #[serde(default = "default_audit_archive_after_secs")]
    pub archive_after_secs: i64,
    #[serde(default = "default_audit_access_log_retention_secs")]
    pub access_log_retention_secs: i64,
    #[serde(default = "default_audit_permission_lifecycle_retention_secs")]
    pub permission_lifecycle_retention_secs: i64,
    #[serde(default = "default_audit_evidence_retention_secs")]
    pub evidence_retention_secs: i64,
    #[serde(default = "default_audit_system_management_retention_secs")]
    pub system_management_retention_secs: i64,
    #[serde(default)]
    pub archive_dir: String,
}

impl Default for AuditRetentionSettings {
    fn default() -> Self {
        Self {
            enabled: default_audit_retention_enabled(),
            archive_after_secs: default_audit_archive_after_secs(),
            access_log_retention_secs: default_audit_access_log_retention_secs(),
            permission_lifecycle_retention_secs: default_audit_permission_lifecycle_retention_secs(
            ),
            evidence_retention_secs: default_audit_evidence_retention_secs(),
            system_management_retention_secs: default_audit_system_management_retention_secs(),
            archive_dir: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AuditSettings {
    #[serde(default)]
    pub checkpoint: AuditCheckpointSettings,
    #[serde(default)]
    pub forwarder: AuditForwarderSettings,
    #[serde(default)]
    pub retention: AuditRetentionSettings,
}

const fn default_notification_retry_backoff_ms() -> u64 {
    250
}

fn default_tsa_provider() -> String {
    "mock".into()
}

fn default_tsa_authority() -> String {
    "mock-tsa".into()
}

fn default_blockchain_provider() -> String {
    "mock".into()
}

fn default_blockchain_network() -> String {
    "mock-chain".into()
}

fn default_dlp_provider() -> String {
    "local-policy".into()
}

fn default_dlp_provider_id() -> String {
    "sdqp-local-policy".into()
}

fn default_dlp_default_action() -> String {
    "alert".into()
}

const fn default_integration_timeout_ms() -> u64 {
    3_000
}

fn default_hr_provider() -> String {
    "mock".into()
}

fn default_approver_system_fallback_user_id() -> String {
    "user-sysadmin".into()
}

fn default_approver_escalation_user_ids() -> Vec<String> {
    vec!["user-security-a".into()]
}

const fn default_approver_max_manager_hops() -> u64 {
    16
}

const fn default_approver_allow_delegation() -> bool {
    true
}

fn default_feishu_provider_id() -> String {
    "feishu-primary".into()
}

fn default_feishu_tenant_key() -> String {
    "tenant-alpha".into()
}

fn default_feishu_auth_mode() -> String {
    "tenant_access_token".into()
}

fn default_feishu_users_path() -> String {
    "/open-apis/contact/v3/users".into()
}

fn default_feishu_events_path() -> String {
    "/open-apis/contact/v3/events".into()
}

const fn default_feishu_page_size() -> u64 {
    100
}

fn default_workday_provider_id() -> String {
    "workday-primary".into()
}

fn default_workday_tenant() -> String {
    "tenant-alpha".into()
}

fn default_workday_auth_mode() -> String {
    "bearer_token".into()
}

fn default_workday_snapshot_path() -> String {
    "/workday/workers".into()
}

fn default_workday_events_path() -> String {
    "/workday/events".into()
}

const fn default_workday_page_size() -> u64 {
    100
}

fn default_sap_successfactors_provider_id() -> String {
    "sap-successfactors-primary".into()
}

fn default_sap_successfactors_company_id() -> String {
    "company-alpha".into()
}

fn default_sap_successfactors_auth_mode() -> String {
    "bearer_token".into()
}

fn default_sap_successfactors_users_path() -> String {
    "/odata/v2/User".into()
}

fn default_sap_successfactors_events_path() -> String {
    "/odata/v2/EmpJob".into()
}

const fn default_sap_successfactors_page_size() -> u64 {
    100
}

fn default_ldap_provider_id() -> String {
    "ldap-primary".into()
}

fn default_ldap_auth_mode() -> String {
    "simple_bind".into()
}

fn default_ldap_tls_mode() -> String {
    "start_tls".into()
}

const fn default_ldap_tls_require_valid_cert() -> bool {
    true
}

fn default_ldap_search_filter() -> String {
    "(&(objectClass=person)(employeeType=employee))".into()
}

fn default_ldap_search_scope() -> String {
    "sub".into()
}

fn default_ldap_user_id_attribute() -> String {
    "uid".into()
}

fn default_ldap_department_attribute() -> String {
    "departmentNumber".into()
}

fn default_ldap_manager_attribute() -> String {
    "manager".into()
}

fn default_ldap_status_attribute() -> String {
    "employeeStatus".into()
}

fn default_ldap_changed_since_attribute() -> String {
    "modifyTimestamp".into()
}

fn default_ldap_active_status_values() -> Vec<String> {
    vec!["active".into(), "enabled".into(), "true".into()]
}

fn default_ldap_departed_status_values() -> Vec<String> {
    vec![
        "departed".into(),
        "inactive".into(),
        "disabled".into(),
        "terminated".into(),
        "false".into(),
    ]
}

const fn default_ldap_page_size() -> u64 {
    500
}

fn default_ldapsearch_binary() -> String {
    "ldapsearch".into()
}

fn default_audit_checkpoint_provider() -> String {
    "mock".into()
}

fn default_audit_checkpoint_key_id() -> String {
    "sdqp-audit-checkpoint".into()
}

fn default_audit_checkpoint_key_version() -> String {
    "1".into()
}

fn default_audit_forwarder_provider() -> String {
    "webhook".into()
}

fn default_audit_forwarder_topic() -> String {
    "sdqp.audit.siem".into()
}

fn default_audit_forwarder_syslog_hostname() -> String {
    "sdqp.local".into()
}

fn default_audit_forwarder_syslog_app_name() -> String {
    "sdqp-audit".into()
}

const fn default_audit_retention_enabled() -> bool {
    true
}

const fn default_audit_archive_after_secs() -> i64 {
    90 * 24 * 60 * 60
}

const fn default_audit_access_log_retention_secs() -> i64 {
    3 * 365 * 24 * 60 * 60
}

const fn default_audit_permission_lifecycle_retention_secs() -> i64 {
    5 * 365 * 24 * 60 * 60
}

const fn default_audit_evidence_retention_secs() -> i64 {
    10 * 365 * 24 * 60 * 60
}

const fn default_audit_system_management_retention_secs() -> i64 {
    5 * 365 * 24 * 60 * 60
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilitySettings {
    pub log_filter: String,
    pub metrics_path: String,
    pub request_id_header: String,
    pub span_id_header: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSettings {
    pub environment: Environment,
    pub api: ApiSettings,
    pub worker: WorkerSettings,
    pub frontend: FrontendSettings,
    pub database: DatabaseSettings,
    pub object_store: ObjectStoreSettings,
    pub kafka: KafkaSettings,
    pub identity_provider: IdentityProviderSettings,
    pub kms: KmsSettings,
    pub integrations: IntegrationSettings,
    #[serde(default)]
    pub audit: AuditSettings,
    #[serde(default)]
    pub security: SecuritySettings,
    #[serde(default)]
    pub classification: ClassificationSettings,
    #[serde(default)]
    pub ueba: UebaSettings,
    pub observability: ObservabilitySettings,
}

impl AppSettings {
    pub fn local_dev() -> Self {
        Self {
            environment: Environment::Dev,
            api: ApiSettings {
                host: "127.0.0.1".into(),
                port: 8080,
                service_name: "sdqp-api".into(),
                external_query_worker: false,
            },
            worker: WorkerSettings {
                host: "127.0.0.1".into(),
                port: 8081,
                service_name: "sdqp-worker".into(),
                query_poll_interval_ms: default_query_poll_interval_ms(),
                query_lease_secs: default_query_lease_secs(),
                query_max_attempts: default_query_max_attempts(),
            },
            frontend: FrontendSettings {
                title: "SDQP Phase 0".into(),
                port: 4173,
                api_base_url: "http://127.0.0.1:8080".into(),
            },
            database: DatabaseSettings {
                postgres: PostgresSettings {
                    dsn: "postgres://sdqp:sdqp@127.0.0.1:5432/sdqp".into(),
                    max_connections: 20,
                },
                clickhouse: ClickHouseSettings {
                    http_url: "http://127.0.0.1:8123".into(),
                    native_url: "tcp://127.0.0.1:9000".into(),
                },
            },
            object_store: ObjectStoreSettings {
                endpoint: "http://127.0.0.1:9002".into(),
                region: "local".into(),
                access_key: "minio".into(),
                secret_key: "minio123".into(),
                bucket_snapshots: "sdqp-snapshots".into(),
                bucket_evidence: "sdqp-evidence".into(),
            },
            kafka: KafkaSettings {
                brokers: vec!["127.0.0.1:9092".into()],
                audit_topic: "sdqp.audit.events".into(),
                query_topic: "sdqp.query.tasks".into(),
                ueba_topic: "sdqp.ueba.events".into(),
            },
            identity_provider: IdentityProviderSettings {
                oidc_provider: default_oidc_provider(),
                saml_provider: default_saml_provider(),
                scim_provider: default_scim_provider(),
                issuer_url: "https://mock-idp.local/issuer".into(),
                client_id: "sdqp-dev-client".into(),
                client_secret: "dev-client-secret".into(),
                redirect_url: "http://127.0.0.1:4173/auth/callback".into(),
                oidc_authorize_url: "https://mock-idp.local/issuer/authorize".into(),
                oidc_token_url: "https://mock-idp.local/issuer/token".into(),
                oidc_userinfo_url: "https://mock-idp.local/issuer/userinfo".into(),
                saml_sso_url: "https://mock-idp.local/issuer/saml/sso".into(),
                saml_exchange_url: "https://mock-idp.local/issuer/saml/exchange".into(),
                saml_entity_id: "sdqp-dev-client".into(),
                saml_audience: "sdqp-dev-client".into(),
                scim_base_url: "https://mock-idp.local/scim".into(),
                scim_token: "dev-scim-token".into(),
                scim_tenant_id: default_scim_tenant_id(),
                scim_page_size: default_scim_page_size(),
                scim_timeout_ms: default_integration_timeout_ms(),
                scim_retry_attempts: default_scim_retry_attempts(),
                scim_retry_backoff_ms: default_notification_retry_backoff_ms(),
                scim_disable_missing_users: default_scim_disable_missing(),
                scim_disable_missing_groups: default_scim_disable_missing(),
                scim_delete_missing_users: false,
                scim_delete_missing_groups: false,
            },
            kms: KmsSettings {
                provider: "mock".into(),
                endpoint: "http://127.0.0.1:8200".into(),
                master_key_id: "sdqp-dev-master-key".into(),
                key_ring: "sdqp-dev-ring".into(),
                auth_token: String::new(),
                region: "local".into(),
                key_version: "1".into(),
                rotation: KmsRotationSettings::default(),
            },
            integrations: IntegrationSettings {
                im_webhook_url: "http://127.0.0.1:11080/im/webhook".into(),
                hr: HrIntegrationSettings {
                    provider: default_hr_provider(),
                    base_url: "http://127.0.0.1:11080/hr".into(),
                    token: "dev-hr-token".into(),
                    approver_resolution: ApproverResolutionSettings::default(),
                    feishu: FeishuIntegrationSettings {
                        base_url: "http://127.0.0.1:11080".into(),
                        tenant_access_token: "dev-feishu-tenant-access-token".into(),
                        webhook_verification_token: "dev-feishu-webhook-token".into(),
                        ..FeishuIntegrationSettings::default()
                    },
                    workday: WorkdayIntegrationSettings {
                        base_url: "http://127.0.0.1:11080".into(),
                        bearer_token: "dev-workday-provider-token".into(),
                        webhook_secret: "dev-workday-webhook-secret".into(),
                        ..WorkdayIntegrationSettings::default()
                    },
                    sap_successfactors: SapSuccessFactorsIntegrationSettings {
                        base_url: "http://127.0.0.1:11080".into(),
                        bearer_token: "dev-sap-successfactors-token".into(),
                        webhook_secret: "dev-sap-successfactors-webhook-secret".into(),
                        ..SapSuccessFactorsIntegrationSettings::default()
                    },
                    ldap: LdapIntegrationSettings {
                        url: "ldap://127.0.0.1:1389".into(),
                        bind_dn: "cn=sdqp-sync,ou=svc,dc=example,dc=internal".into(),
                        bind_password: "dev-ldap-bind-password".into(),
                        base_dn: "ou=People,dc=example,dc=internal".into(),
                        ..LdapIntegrationSettings::default()
                    },
                },
                notifications: NotificationSettings {
                    feishu_webhook_url: "http://127.0.0.1:11080/notify/feishu".into(),
                    slack_webhook_url: "http://127.0.0.1:11080/notify/slack".into(),
                    email_api_url: "http://127.0.0.1:11080/notify/email".into(),
                    telegram_bot_api_url: "http://127.0.0.1:11080/notify/telegram".into(),
                    dingtalk_webhook_url: "http://127.0.0.1:11080/notify/dingtalk".into(),
                    retry_backoff_ms: default_notification_retry_backoff_ms(),
                },
                tsa: TsaSettings {
                    provider: default_tsa_provider(),
                    base_url: "http://127.0.0.1:11080/tsa".into(),
                    api_key: "dev-tsa-key".into(),
                    authority: default_tsa_authority(),
                    timeout_ms: default_integration_timeout_ms(),
                    require_external: false,
                },
                blockchain_anchor: BlockchainAnchorSettings {
                    provider: default_blockchain_provider(),
                    base_url: "http://127.0.0.1:11080/anchor".into(),
                    api_key: "dev-anchor-key".into(),
                    network: default_blockchain_network(),
                    timeout_ms: default_integration_timeout_ms(),
                    require_external: false,
                },
                dlp: DlpIntegrationSettings {
                    provider: default_dlp_provider(),
                    provider_id: default_dlp_provider_id(),
                    webhook_url: "http://127.0.0.1:11080/dlp/watermark/policy".into(),
                    auth_header: "x-sdqp-dlp-token".into(),
                    auth_token: "dev-dlp-token".into(),
                    timeout_ms: default_integration_timeout_ms(),
                    default_action: default_dlp_default_action(),
                },
            },
            audit: AuditSettings {
                checkpoint: AuditCheckpointSettings::default(),
                forwarder: AuditForwarderSettings {
                    enabled: false,
                    provider: default_audit_forwarder_provider(),
                    timeout_ms: default_integration_timeout_ms(),
                    webhook_url: "http://127.0.0.1:11080/audit/siem".into(),
                    auth_header: String::new(),
                    auth_token: String::new(),
                    kafka_brokers: vec!["127.0.0.1:9092".into()],
                    kafka_topic: default_audit_forwarder_topic(),
                    syslog_endpoint: "127.0.0.1:15140".into(),
                    syslog_hostname: default_audit_forwarder_syslog_hostname(),
                    syslog_app_name: default_audit_forwarder_syslog_app_name(),
                },
                retention: AuditRetentionSettings::default(),
            },
            security: SecuritySettings {
                mfa_bootstrap_seed: default_mfa_bootstrap_seed(),
                mfa_challenge_ttl_secs: default_mfa_challenge_ttl_secs(),
                totp_issuer: default_totp_issuer(),
                totp_period_secs: default_totp_period_secs(),
                totp_digits: default_totp_digits(),
                totp_allowed_drift_steps: default_totp_allowed_drift_steps(),
                webauthn_rp_id: default_webauthn_rp_id(),
                webauthn_origin: default_webauthn_origin(),
                webauthn_timeout_ms: default_webauthn_timeout_ms(),
                webauthn_require_user_verification: default_webauthn_require_user_verification(),
                integration_api_keys: vec![SecurityApiKeySettings {
                    key_id: "integration-dev".into(),
                    secret: "integration-dev-key".into(),
                    scopes: vec![
                        "scim.sync".into(),
                        "hr.events".into(),
                        "audit.permission_lifecycle".into(),
                    ],
                    allowed_ips: vec!["127.0.0.1".into()],
                }],
                integration_ip_allowlist: vec!["127.0.0.1".into()],
                integration_mtls_subjects: vec!["CN=sdqp-integration".into()],
                integration_rate_limit: SecurityRateLimitSettings {
                    max_requests: 60,
                    window_secs: 60,
                },
                credential_rotation: CredentialRotationSettings::default(),
                tee: TeeSettings::default(),
            },
            classification: ClassificationSettings::default(),
            ueba: UebaSettings::default(),
            observability: ObservabilitySettings {
                log_filter: "info,sdqp_api=info,sdqp_worker=info".into(),
                metrics_path: "/metrics".into(),
                request_id_header: "x-request-id".into(),
                span_id_header: "x-sdqp-span-id".into(),
            },
        }
    }

    pub fn from_env_map(env: &HashMap<String, String>) -> Result<Self, ConfigError> {
        let mut settings = Self::local_dev();
        settings.apply_env_overrides(env)?;
        Ok(settings)
    }

    pub fn from_profile_files(
        config_root: impl AsRef<Path>,
        environment: Environment,
        secrets_path: Option<&Path>,
    ) -> Result<Self, ConfigError> {
        let config_root = config_root.as_ref();
        let base_path = config_root.join("base").join("app.toml");
        let profile_path = config_root.join(environment.as_str()).join("app.toml");

        let mut merged = read_toml_file(&base_path)?;
        merge_toml_values(&mut merged, read_toml_file(&profile_path)?);

        if let Some(secrets_path) = secrets_path
            && secrets_path.exists()
        {
            merge_toml_values(&mut merged, read_toml_file(secrets_path)?);
        }

        let mut settings: Self =
            merged
                .try_into()
                .map_err(|error| ConfigError::ParseConfigFile {
                    path: profile_path.clone(),
                    message: error.to_string(),
                })?;
        settings.environment = environment;
        Ok(settings)
    }

    pub fn from_sources(
        config_root: impl AsRef<Path>,
        env: &HashMap<String, String>,
    ) -> Result<Self, ConfigError> {
        let environment = env
            .get("SDQP_ENVIRONMENT")
            .map(|value| Environment::parse(value))
            .transpose()?
            .unwrap_or(Environment::Dev);
        let secrets_path = env.get("SDQP_SECRETS_FILE").map(PathBuf::from);

        let mut settings =
            Self::from_profile_files(config_root, environment.clone(), secrets_path.as_deref())?;
        settings.apply_env_overrides(env)?;
        Ok(settings)
    }

    pub fn from_process_env() -> Result<Self, ConfigError> {
        let env = std::env::vars().collect::<HashMap<_, _>>();
        let config_root = env
            .get("SDQP_CONFIG_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("configs"));
        Self::from_sources(config_root, &env)
    }

    fn apply_env_overrides(&mut self, env: &HashMap<String, String>) -> Result<(), ConfigError> {
        if let Some(environment) = env.get("SDQP_ENVIRONMENT") {
            self.environment = Environment::parse(environment)?;
        }
        apply_string_override(env, "SDQP_API_HOST", &mut self.api.host);
        apply_port_override(env, "SDQP_API_PORT", &mut self.api.port)?;
        apply_string_override(env, "SDQP_API_SERVICE_NAME", &mut self.api.service_name);
        apply_bool_override(
            env,
            "SDQP_API_EXTERNAL_QUERY_WORKER",
            &mut self.api.external_query_worker,
        );
        apply_string_override(env, "SDQP_WORKER_HOST", &mut self.worker.host);
        apply_port_override(env, "SDQP_WORKER_PORT", &mut self.worker.port)?;
        apply_string_override(
            env,
            "SDQP_WORKER_SERVICE_NAME",
            &mut self.worker.service_name,
        );
        apply_u64_override(
            env,
            "SDQP_WORKER_QUERY_POLL_INTERVAL_MS",
            &mut self.worker.query_poll_interval_ms,
        );
        apply_u64_override(
            env,
            "SDQP_WORKER_QUERY_LEASE_SECS",
            &mut self.worker.query_lease_secs,
        );
        apply_u32_override(
            env,
            "SDQP_WORKER_QUERY_MAX_ATTEMPTS",
            &mut self.worker.query_max_attempts,
        );
        apply_port_override(env, "SDQP_FRONTEND_PORT", &mut self.frontend.port)?;
        apply_string_override(env, "SDQP_FRONTEND_TITLE", &mut self.frontend.title);
        apply_string_override(
            env,
            "SDQP_FRONTEND_API_BASE_URL",
            &mut self.frontend.api_base_url,
        );
        apply_string_override(env, "SDQP_POSTGRES_DSN", &mut self.database.postgres.dsn);
        apply_port_override(
            env,
            "SDQP_POSTGRES_MAX_CONNECTIONS",
            &mut self.database.postgres.max_connections,
        )?;
        apply_string_override(
            env,
            "SDQP_CLICKHOUSE_HTTP_URL",
            &mut self.database.clickhouse.http_url,
        );
        apply_string_override(
            env,
            "SDQP_CLICKHOUSE_NATIVE_URL",
            &mut self.database.clickhouse.native_url,
        );
        apply_string_override(env, "SDQP_S3_ENDPOINT", &mut self.object_store.endpoint);
        apply_string_override(env, "SDQP_S3_REGION", &mut self.object_store.region);
        apply_string_override(env, "SDQP_S3_ACCESS_KEY", &mut self.object_store.access_key);
        apply_string_override(env, "SDQP_S3_SECRET_KEY", &mut self.object_store.secret_key);
        apply_string_override(
            env,
            "SDQP_S3_BUCKET_SNAPSHOTS",
            &mut self.object_store.bucket_snapshots,
        );
        apply_string_override(
            env,
            "SDQP_S3_BUCKET_EVIDENCE",
            &mut self.object_store.bucket_evidence,
        );
        if let Some(brokers) = env.get("SDQP_KAFKA_BROKERS") {
            self.kafka.brokers = split_csv(brokers);
        }
        apply_string_override(env, "SDQP_KAFKA_AUDIT_TOPIC", &mut self.kafka.audit_topic);
        apply_string_override(env, "SDQP_KAFKA_QUERY_TOPIC", &mut self.kafka.query_topic);
        apply_string_override(env, "SDQP_KAFKA_UEBA_TOPIC", &mut self.kafka.ueba_topic);
        apply_string_override(
            env,
            "SDQP_OIDC_PROVIDER",
            &mut self.identity_provider.oidc_provider,
        );
        apply_string_override(
            env,
            "SDQP_OIDC_ISSUER_URL",
            &mut self.identity_provider.issuer_url,
        );
        apply_string_override(
            env,
            "SDQP_OIDC_CLIENT_ID",
            &mut self.identity_provider.client_id,
        );
        apply_string_override(
            env,
            "SDQP_OIDC_CLIENT_SECRET",
            &mut self.identity_provider.client_secret,
        );
        apply_string_override(
            env,
            "SDQP_OIDC_REDIRECT_URL",
            &mut self.identity_provider.redirect_url,
        );
        apply_string_override(
            env,
            "SDQP_OIDC_AUTHORIZE_URL",
            &mut self.identity_provider.oidc_authorize_url,
        );
        apply_string_override(
            env,
            "SDQP_OIDC_TOKEN_URL",
            &mut self.identity_provider.oidc_token_url,
        );
        apply_string_override(
            env,
            "SDQP_OIDC_USERINFO_URL",
            &mut self.identity_provider.oidc_userinfo_url,
        );
        apply_string_override(
            env,
            "SDQP_SAML_PROVIDER",
            &mut self.identity_provider.saml_provider,
        );
        apply_string_override(
            env,
            "SDQP_SAML_SSO_URL",
            &mut self.identity_provider.saml_sso_url,
        );
        apply_string_override(
            env,
            "SDQP_SAML_EXCHANGE_URL",
            &mut self.identity_provider.saml_exchange_url,
        );
        apply_string_override(
            env,
            "SDQP_SAML_ENTITY_ID",
            &mut self.identity_provider.saml_entity_id,
        );
        apply_string_override(
            env,
            "SDQP_SAML_AUDIENCE",
            &mut self.identity_provider.saml_audience,
        );
        apply_string_override(
            env,
            "SDQP_SCIM_PROVIDER",
            &mut self.identity_provider.scim_provider,
        );
        apply_string_override(
            env,
            "SDQP_SCIM_BASE_URL",
            &mut self.identity_provider.scim_base_url,
        );
        apply_string_override(
            env,
            "SDQP_SCIM_TOKEN",
            &mut self.identity_provider.scim_token,
        );
        apply_string_override(
            env,
            "SDQP_SCIM_TENANT_ID",
            &mut self.identity_provider.scim_tenant_id,
        );
        apply_u64_override(
            env,
            "SDQP_SCIM_PAGE_SIZE",
            &mut self.identity_provider.scim_page_size,
        );
        apply_u64_override(
            env,
            "SDQP_SCIM_TIMEOUT_MS",
            &mut self.identity_provider.scim_timeout_ms,
        );
        apply_u64_override(
            env,
            "SDQP_SCIM_RETRY_ATTEMPTS",
            &mut self.identity_provider.scim_retry_attempts,
        );
        apply_u64_override(
            env,
            "SDQP_SCIM_RETRY_BACKOFF_MS",
            &mut self.identity_provider.scim_retry_backoff_ms,
        );
        apply_bool_override(
            env,
            "SDQP_SCIM_DISABLE_MISSING_USERS",
            &mut self.identity_provider.scim_disable_missing_users,
        );
        apply_bool_override(
            env,
            "SDQP_SCIM_DISABLE_MISSING_GROUPS",
            &mut self.identity_provider.scim_disable_missing_groups,
        );
        apply_bool_override(
            env,
            "SDQP_SCIM_DELETE_MISSING_USERS",
            &mut self.identity_provider.scim_delete_missing_users,
        );
        apply_bool_override(
            env,
            "SDQP_SCIM_DELETE_MISSING_GROUPS",
            &mut self.identity_provider.scim_delete_missing_groups,
        );
        apply_string_override(env, "SDQP_KMS_PROVIDER", &mut self.kms.provider);
        apply_string_override(env, "SDQP_KMS_ENDPOINT", &mut self.kms.endpoint);
        apply_string_override(env, "SDQP_KMS_MASTER_KEY_ID", &mut self.kms.master_key_id);
        apply_string_override(env, "SDQP_KMS_KEY_RING", &mut self.kms.key_ring);
        apply_string_override(env, "SDQP_KMS_AUTH_TOKEN", &mut self.kms.auth_token);
        apply_string_override(env, "SDQP_KMS_REGION", &mut self.kms.region);
        apply_string_override(env, "SDQP_KMS_KEY_VERSION", &mut self.kms.key_version);
        apply_bool_override(
            env,
            "SDQP_KMS_ROTATION_ENABLED",
            &mut self.kms.rotation.enabled,
        );
        apply_u64_override(
            env,
            "SDQP_KMS_ROTATION_CYCLE_INTERVAL_SECS",
            &mut self.kms.rotation.cycle_interval_secs,
        );
        apply_u64_override(
            env,
            "SDQP_KMS_ROTATION_BATCH_LIMIT",
            &mut self.kms.rotation.batch_limit,
        );
        apply_i64_override(
            env,
            "SDQP_KMS_DEK_ROTATION_DAYS",
            &mut self.kms.rotation.dek_rotation_days,
        );
        apply_i64_override(
            env,
            "SDQP_KMS_KEK_ROTATION_DAYS",
            &mut self.kms.rotation.kek_rotation_days,
        );
        apply_bool_override(
            env,
            "SDQP_KMS_ALLOW_DEK_ROTATION",
            &mut self.kms.rotation.allow_dek_rotation,
        );
        apply_bool_override(
            env,
            "SDQP_KMS_ALLOW_KEK_REWRAP",
            &mut self.kms.rotation.allow_kek_rewrap,
        );
        apply_i64_override(
            env,
            "SDQP_CLASSIFICATION_DEFAULT_RETENTION_DAYS",
            &mut self.classification.default_retention_days,
        );
        apply_i64_override(
            env,
            "SDQP_CLASSIFICATION_RESTRICTED_RETENTION_DAYS",
            &mut self.classification.restricted_retention_days,
        );
        apply_string_override(
            env,
            "SDQP_CLASSIFICATION_MANUAL_CONFIRMATION_LEVEL",
            &mut self.classification.manual_confirmation_required_level,
        );
        if let Some(regulations) = env.get("SDQP_CLASSIFICATION_DEFAULT_REGULATIONS") {
            self.classification.default_regulations = split_csv(regulations);
        }
        apply_u32_override(
            env,
            "SDQP_UEBA_QUERY_BURST_THRESHOLD",
            &mut self.ueba.governance.query_burst_threshold,
        );
        apply_u32_override(
            env,
            "SDQP_UEBA_EXPORT_SPIKE_THRESHOLD",
            &mut self.ueba.governance.export_spike_threshold,
        );
        apply_u32_override(
            env,
            "SDQP_UEBA_DENIED_QUERY_THRESHOLD",
            &mut self.ueba.governance.denied_query_threshold,
        );
        apply_u8_override(
            env,
            "SDQP_UEBA_AFTER_HOURS_START_HOUR",
            &mut self.ueba.governance.after_hours_start_hour,
        );
        apply_u8_override(
            env,
            "SDQP_UEBA_AFTER_HOURS_END_HOUR",
            &mut self.ueba.governance.after_hours_end_hour,
        );
        apply_u8_override(
            env,
            "SDQP_UEBA_HIGH_RISK_SCORE",
            &mut self.ueba.governance.high_risk_score,
        );
        apply_u8_override(
            env,
            "SDQP_UEBA_CRITICAL_RISK_SCORE",
            &mut self.ueba.governance.critical_risk_score,
        );
        apply_bool_override(
            env,
            "SDQP_UEBA_CALIBRATION_ENABLED",
            &mut self.ueba.calibration.enabled,
        );
        apply_usize_override(
            env,
            "SDQP_UEBA_CALIBRATION_MIN_EVENTS",
            &mut self.ueba.calibration.min_events,
        );
        apply_string_override(
            env,
            "SDQP_UEBA_CALIBRATION_MODEL_VERSION",
            &mut self.ueba.calibration.model_version,
        );
        apply_u32_override(
            env,
            "SDQP_UEBA_CALIBRATION_TARGET_HIT_RATE_PER_1000",
            &mut self.ueba.calibration.target_hit_rate_per_1000,
        );
        apply_string_override(
            env,
            "SDQP_AUDIT_CHECKPOINT_PROVIDER",
            &mut self.audit.checkpoint.provider,
        );
        apply_string_override(
            env,
            "SDQP_AUDIT_CHECKPOINT_KEY_ID",
            &mut self.audit.checkpoint.key_id,
        );
        apply_string_override(
            env,
            "SDQP_AUDIT_CHECKPOINT_KEY_VERSION",
            &mut self.audit.checkpoint.key_version,
        );
        apply_string_override(
            env,
            "SDQP_AUDIT_CHECKPOINT_ENDPOINT",
            &mut self.audit.checkpoint.endpoint,
        );
        apply_string_override(
            env,
            "SDQP_AUDIT_CHECKPOINT_REGION",
            &mut self.audit.checkpoint.region,
        );
        apply_string_override(
            env,
            "SDQP_AUDIT_CHECKPOINT_KEY_RING",
            &mut self.audit.checkpoint.key_ring,
        );
        apply_string_override(
            env,
            "SDQP_AUDIT_CHECKPOINT_AUTH_TOKEN",
            &mut self.audit.checkpoint.auth_token,
        );
        apply_bool_override(
            env,
            "SDQP_AUDIT_FORWARDER_ENABLED",
            &mut self.audit.forwarder.enabled,
        );
        apply_string_override(
            env,
            "SDQP_AUDIT_FORWARDER_PROVIDER",
            &mut self.audit.forwarder.provider,
        );
        apply_u64_override(
            env,
            "SDQP_AUDIT_FORWARDER_TIMEOUT_MS",
            &mut self.audit.forwarder.timeout_ms,
        );
        apply_string_override(
            env,
            "SDQP_AUDIT_FORWARDER_WEBHOOK_URL",
            &mut self.audit.forwarder.webhook_url,
        );
        apply_string_override(
            env,
            "SDQP_AUDIT_FORWARDER_AUTH_HEADER",
            &mut self.audit.forwarder.auth_header,
        );
        apply_string_override(
            env,
            "SDQP_AUDIT_FORWARDER_AUTH_TOKEN",
            &mut self.audit.forwarder.auth_token,
        );
        if let Some(brokers) = env.get("SDQP_AUDIT_FORWARDER_KAFKA_BROKERS") {
            self.audit.forwarder.kafka_brokers = split_csv(brokers);
        }
        apply_string_override(
            env,
            "SDQP_AUDIT_FORWARDER_KAFKA_TOPIC",
            &mut self.audit.forwarder.kafka_topic,
        );
        apply_string_override(
            env,
            "SDQP_AUDIT_FORWARDER_SYSLOG_ENDPOINT",
            &mut self.audit.forwarder.syslog_endpoint,
        );
        apply_string_override(
            env,
            "SDQP_AUDIT_FORWARDER_SYSLOG_HOSTNAME",
            &mut self.audit.forwarder.syslog_hostname,
        );
        apply_string_override(
            env,
            "SDQP_AUDIT_FORWARDER_SYSLOG_APP_NAME",
            &mut self.audit.forwarder.syslog_app_name,
        );
        apply_bool_override(
            env,
            "SDQP_AUDIT_RETENTION_ENABLED",
            &mut self.audit.retention.enabled,
        );
        apply_i64_override(
            env,
            "SDQP_AUDIT_RETENTION_ARCHIVE_AFTER_SECS",
            &mut self.audit.retention.archive_after_secs,
        );
        apply_i64_override(
            env,
            "SDQP_AUDIT_RETENTION_ACCESS_LOG_SECS",
            &mut self.audit.retention.access_log_retention_secs,
        );
        apply_i64_override(
            env,
            "SDQP_AUDIT_RETENTION_PERMISSION_LIFECYCLE_SECS",
            &mut self.audit.retention.permission_lifecycle_retention_secs,
        );
        apply_i64_override(
            env,
            "SDQP_AUDIT_RETENTION_EVIDENCE_SECS",
            &mut self.audit.retention.evidence_retention_secs,
        );
        apply_i64_override(
            env,
            "SDQP_AUDIT_RETENTION_SYSTEM_MANAGEMENT_SECS",
            &mut self.audit.retention.system_management_retention_secs,
        );
        apply_string_override(
            env,
            "SDQP_AUDIT_RETENTION_ARCHIVE_DIR",
            &mut self.audit.retention.archive_dir,
        );
        apply_string_override(
            env,
            "SDQP_IM_WEBHOOK_URL",
            &mut self.integrations.im_webhook_url,
        );
        apply_string_override(env, "SDQP_HR_PROVIDER", &mut self.integrations.hr.provider);
        apply_string_override(env, "SDQP_HR_BASE_URL", &mut self.integrations.hr.base_url);
        apply_string_override(env, "SDQP_HR_TOKEN", &mut self.integrations.hr.token);
        apply_string_override(
            env,
            "SDQP_APPROVER_SYSTEM_FALLBACK_USER_ID",
            &mut self
                .integrations
                .hr
                .approver_resolution
                .system_fallback_user_id,
        );
        if let Some(values) = env.get("SDQP_APPROVER_ESCALATION_USER_IDS") {
            self.integrations.hr.approver_resolution.escalation_user_ids = split_csv(values);
        }
        apply_u64_override(
            env,
            "SDQP_APPROVER_MAX_MANAGER_HOPS",
            &mut self.integrations.hr.approver_resolution.max_manager_hops,
        );
        apply_bool_override(
            env,
            "SDQP_APPROVER_ALLOW_DELEGATION",
            &mut self.integrations.hr.approver_resolution.allow_delegation,
        );
        apply_string_override(
            env,
            "SDQP_FEISHU_PROVIDER_ID",
            &mut self.integrations.hr.feishu.provider_id,
        );
        apply_string_override(
            env,
            "SDQP_FEISHU_TENANT_KEY",
            &mut self.integrations.hr.feishu.tenant_key,
        );
        apply_string_override(
            env,
            "SDQP_FEISHU_BASE_URL",
            &mut self.integrations.hr.feishu.base_url,
        );
        apply_string_override(
            env,
            "SDQP_FEISHU_AUTH_MODE",
            &mut self.integrations.hr.feishu.auth_mode,
        );
        apply_string_override(
            env,
            "SDQP_FEISHU_TOKEN_URL",
            &mut self.integrations.hr.feishu.token_url,
        );
        apply_string_override(
            env,
            "SDQP_FEISHU_APP_ID",
            &mut self.integrations.hr.feishu.app_id,
        );
        apply_string_override(
            env,
            "SDQP_FEISHU_APP_SECRET",
            &mut self.integrations.hr.feishu.app_secret,
        );
        apply_string_override(
            env,
            "SDQP_FEISHU_TENANT_ACCESS_TOKEN",
            &mut self.integrations.hr.feishu.tenant_access_token,
        );
        apply_string_override(
            env,
            "SDQP_FEISHU_USERS_PATH",
            &mut self.integrations.hr.feishu.users_path,
        );
        apply_string_override(
            env,
            "SDQP_FEISHU_EVENTS_PATH",
            &mut self.integrations.hr.feishu.events_path,
        );
        apply_string_override(
            env,
            "SDQP_FEISHU_WEBHOOK_VERIFICATION_TOKEN",
            &mut self.integrations.hr.feishu.webhook_verification_token,
        );
        apply_u64_override(
            env,
            "SDQP_FEISHU_TIMEOUT_MS",
            &mut self.integrations.hr.feishu.timeout_ms,
        );
        apply_u64_override(
            env,
            "SDQP_FEISHU_PAGE_SIZE",
            &mut self.integrations.hr.feishu.page_size,
        );
        apply_string_override(
            env,
            "SDQP_WORKDAY_PROVIDER_ID",
            &mut self.integrations.hr.workday.provider_id,
        );
        apply_string_override(
            env,
            "SDQP_WORKDAY_TENANT",
            &mut self.integrations.hr.workday.tenant,
        );
        apply_string_override(
            env,
            "SDQP_WORKDAY_BASE_URL",
            &mut self.integrations.hr.workday.base_url,
        );
        apply_string_override(
            env,
            "SDQP_WORKDAY_AUTH_MODE",
            &mut self.integrations.hr.workday.auth_mode,
        );
        apply_string_override(
            env,
            "SDQP_WORKDAY_TOKEN_URL",
            &mut self.integrations.hr.workday.token_url,
        );
        apply_string_override(
            env,
            "SDQP_WORKDAY_CLIENT_ID",
            &mut self.integrations.hr.workday.client_id,
        );
        apply_string_override(
            env,
            "SDQP_WORKDAY_CLIENT_SECRET",
            &mut self.integrations.hr.workday.client_secret,
        );
        apply_string_override(
            env,
            "SDQP_WORKDAY_BEARER_TOKEN",
            &mut self.integrations.hr.workday.bearer_token,
        );
        apply_string_override(
            env,
            "SDQP_WORKDAY_SCOPE",
            &mut self.integrations.hr.workday.scope,
        );
        apply_string_override(
            env,
            "SDQP_WORKDAY_SNAPSHOT_PATH",
            &mut self.integrations.hr.workday.snapshot_path,
        );
        apply_string_override(
            env,
            "SDQP_WORKDAY_EVENTS_PATH",
            &mut self.integrations.hr.workday.events_path,
        );
        apply_string_override(
            env,
            "SDQP_WORKDAY_WEBHOOK_SECRET",
            &mut self.integrations.hr.workday.webhook_secret,
        );
        apply_u64_override(
            env,
            "SDQP_WORKDAY_TIMEOUT_MS",
            &mut self.integrations.hr.workday.timeout_ms,
        );
        apply_u64_override(
            env,
            "SDQP_WORKDAY_PAGE_SIZE",
            &mut self.integrations.hr.workday.page_size,
        );
        apply_string_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_PROVIDER_ID",
            &mut self.integrations.hr.sap_successfactors.provider_id,
        );
        apply_string_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_COMPANY_ID",
            &mut self.integrations.hr.sap_successfactors.company_id,
        );
        apply_string_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_BASE_URL",
            &mut self.integrations.hr.sap_successfactors.base_url,
        );
        apply_string_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_AUTH_MODE",
            &mut self.integrations.hr.sap_successfactors.auth_mode,
        );
        apply_string_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_TOKEN_URL",
            &mut self.integrations.hr.sap_successfactors.token_url,
        );
        apply_string_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_CLIENT_ID",
            &mut self.integrations.hr.sap_successfactors.client_id,
        );
        apply_string_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_CLIENT_SECRET",
            &mut self.integrations.hr.sap_successfactors.client_secret,
        );
        apply_string_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_BEARER_TOKEN",
            &mut self.integrations.hr.sap_successfactors.bearer_token,
        );
        apply_string_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_USERNAME",
            &mut self.integrations.hr.sap_successfactors.username,
        );
        apply_string_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_PASSWORD",
            &mut self.integrations.hr.sap_successfactors.password,
        );
        apply_string_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_SCOPE",
            &mut self.integrations.hr.sap_successfactors.scope,
        );
        apply_string_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_USERS_PATH",
            &mut self.integrations.hr.sap_successfactors.users_path,
        );
        apply_string_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_EVENTS_PATH",
            &mut self.integrations.hr.sap_successfactors.events_path,
        );
        apply_string_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_WEBHOOK_SECRET",
            &mut self.integrations.hr.sap_successfactors.webhook_secret,
        );
        apply_u64_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_TIMEOUT_MS",
            &mut self.integrations.hr.sap_successfactors.timeout_ms,
        );
        apply_u64_override(
            env,
            "SDQP_SAP_SUCCESSFACTORS_PAGE_SIZE",
            &mut self.integrations.hr.sap_successfactors.page_size,
        );
        apply_string_override(
            env,
            "SDQP_LDAP_PROVIDER_ID",
            &mut self.integrations.hr.ldap.provider_id,
        );
        apply_string_override(env, "SDQP_LDAP_URL", &mut self.integrations.hr.ldap.url);
        apply_string_override(
            env,
            "SDQP_LDAP_AUTH_MODE",
            &mut self.integrations.hr.ldap.auth_mode,
        );
        apply_string_override(
            env,
            "SDQP_LDAP_BIND_DN",
            &mut self.integrations.hr.ldap.bind_dn,
        );
        apply_string_override(
            env,
            "SDQP_LDAP_BIND_PASSWORD",
            &mut self.integrations.hr.ldap.bind_password,
        );
        apply_string_override(
            env,
            "SDQP_LDAP_TLS_MODE",
            &mut self.integrations.hr.ldap.tls_mode,
        );
        apply_string_override(
            env,
            "SDQP_LDAP_CA_CERT_PATH",
            &mut self.integrations.hr.ldap.ca_cert_path,
        );
        apply_bool_override(
            env,
            "SDQP_LDAP_TLS_REQUIRE_VALID_CERT",
            &mut self.integrations.hr.ldap.tls_require_valid_cert,
        );
        apply_string_override(
            env,
            "SDQP_LDAP_BASE_DN",
            &mut self.integrations.hr.ldap.base_dn,
        );
        apply_string_override(
            env,
            "SDQP_LDAP_SEARCH_FILTER",
            &mut self.integrations.hr.ldap.search_filter,
        );
        apply_string_override(
            env,
            "SDQP_LDAP_SEARCH_SCOPE",
            &mut self.integrations.hr.ldap.search_scope,
        );
        apply_string_override(
            env,
            "SDQP_LDAP_USER_ID_ATTRIBUTE",
            &mut self.integrations.hr.ldap.user_id_attribute,
        );
        apply_string_override(
            env,
            "SDQP_LDAP_DEPARTMENT_ATTRIBUTE",
            &mut self.integrations.hr.ldap.department_attribute,
        );
        apply_string_override(
            env,
            "SDQP_LDAP_MANAGER_ATTRIBUTE",
            &mut self.integrations.hr.ldap.manager_attribute,
        );
        apply_string_override(
            env,
            "SDQP_LDAP_STATUS_ATTRIBUTE",
            &mut self.integrations.hr.ldap.status_attribute,
        );
        apply_string_override(
            env,
            "SDQP_LDAP_CHANGED_SINCE_ATTRIBUTE",
            &mut self.integrations.hr.ldap.changed_since_attribute,
        );
        if let Some(values) = env.get("SDQP_LDAP_ACTIVE_STATUS_VALUES") {
            self.integrations.hr.ldap.active_status_values = split_csv(values);
        }
        if let Some(values) = env.get("SDQP_LDAP_DEPARTED_STATUS_VALUES") {
            self.integrations.hr.ldap.departed_status_values = split_csv(values);
        }
        apply_u64_override(
            env,
            "SDQP_LDAP_TIMEOUT_MS",
            &mut self.integrations.hr.ldap.timeout_ms,
        );
        apply_u64_override(
            env,
            "SDQP_LDAP_PAGE_SIZE",
            &mut self.integrations.hr.ldap.page_size,
        );
        apply_string_override(
            env,
            "SDQP_LDAPSEARCH_BINARY",
            &mut self.integrations.hr.ldap.ldapsearch_binary,
        );
        apply_string_override(
            env,
            "SDQP_NOTIFY_FEISHU_URL",
            &mut self.integrations.notifications.feishu_webhook_url,
        );
        apply_string_override(
            env,
            "SDQP_NOTIFY_SLACK_URL",
            &mut self.integrations.notifications.slack_webhook_url,
        );
        apply_string_override(
            env,
            "SDQP_NOTIFY_EMAIL_URL",
            &mut self.integrations.notifications.email_api_url,
        );
        apply_string_override(
            env,
            "SDQP_NOTIFY_TELEGRAM_URL",
            &mut self.integrations.notifications.telegram_bot_api_url,
        );
        apply_string_override(
            env,
            "SDQP_NOTIFY_DINGTALK_URL",
            &mut self.integrations.notifications.dingtalk_webhook_url,
        );
        apply_u64_override(
            env,
            "SDQP_NOTIFY_RETRY_BACKOFF_MS",
            &mut self.integrations.notifications.retry_backoff_ms,
        );
        apply_string_override(
            env,
            "SDQP_TSA_PROVIDER",
            &mut self.integrations.tsa.provider,
        );
        apply_string_override(
            env,
            "SDQP_TSA_BASE_URL",
            &mut self.integrations.tsa.base_url,
        );
        apply_string_override(env, "SDQP_TSA_API_KEY", &mut self.integrations.tsa.api_key);
        apply_string_override(
            env,
            "SDQP_TSA_AUTHORITY",
            &mut self.integrations.tsa.authority,
        );
        apply_u64_override(
            env,
            "SDQP_TSA_TIMEOUT_MS",
            &mut self.integrations.tsa.timeout_ms,
        );
        apply_bool_override(
            env,
            "SDQP_TSA_REQUIRE_EXTERNAL",
            &mut self.integrations.tsa.require_external,
        );
        apply_string_override(
            env,
            "SDQP_BLOCKCHAIN_PROVIDER",
            &mut self.integrations.blockchain_anchor.provider,
        );
        apply_string_override(
            env,
            "SDQP_BLOCKCHAIN_BASE_URL",
            &mut self.integrations.blockchain_anchor.base_url,
        );
        apply_string_override(
            env,
            "SDQP_BLOCKCHAIN_API_KEY",
            &mut self.integrations.blockchain_anchor.api_key,
        );
        apply_string_override(
            env,
            "SDQP_BLOCKCHAIN_NETWORK",
            &mut self.integrations.blockchain_anchor.network,
        );
        apply_u64_override(
            env,
            "SDQP_BLOCKCHAIN_TIMEOUT_MS",
            &mut self.integrations.blockchain_anchor.timeout_ms,
        );
        apply_bool_override(
            env,
            "SDQP_BLOCKCHAIN_REQUIRE_EXTERNAL",
            &mut self.integrations.blockchain_anchor.require_external,
        );
        apply_string_override(
            env,
            "SDQP_DLP_PROVIDER",
            &mut self.integrations.dlp.provider,
        );
        apply_string_override(
            env,
            "SDQP_DLP_PROVIDER_ID",
            &mut self.integrations.dlp.provider_id,
        );
        apply_string_override(
            env,
            "SDQP_DLP_WEBHOOK_URL",
            &mut self.integrations.dlp.webhook_url,
        );
        apply_string_override(
            env,
            "SDQP_DLP_AUTH_HEADER",
            &mut self.integrations.dlp.auth_header,
        );
        apply_string_override(
            env,
            "SDQP_DLP_AUTH_TOKEN",
            &mut self.integrations.dlp.auth_token,
        );
        apply_u64_override(
            env,
            "SDQP_DLP_TIMEOUT_MS",
            &mut self.integrations.dlp.timeout_ms,
        );
        apply_string_override(
            env,
            "SDQP_DLP_DEFAULT_ACTION",
            &mut self.integrations.dlp.default_action,
        );
        apply_string_override(
            env,
            "SDQP_SECURITY_MFA_BOOTSTRAP_SEED",
            &mut self.security.mfa_bootstrap_seed,
        );
        apply_i64_override(
            env,
            "SDQP_SECURITY_MFA_CHALLENGE_TTL_SECS",
            &mut self.security.mfa_challenge_ttl_secs,
        );
        apply_string_override(
            env,
            "SDQP_SECURITY_TOTP_ISSUER",
            &mut self.security.totp_issuer,
        );
        apply_u64_override(
            env,
            "SDQP_SECURITY_TOTP_PERIOD_SECS",
            &mut self.security.totp_period_secs,
        );
        apply_u32_override(
            env,
            "SDQP_SECURITY_TOTP_DIGITS",
            &mut self.security.totp_digits,
        );
        apply_u8_override(
            env,
            "SDQP_SECURITY_TOTP_DRIFT_STEPS",
            &mut self.security.totp_allowed_drift_steps,
        );
        apply_string_override(
            env,
            "SDQP_SECURITY_WEBAUTHN_RP_ID",
            &mut self.security.webauthn_rp_id,
        );
        apply_string_override(
            env,
            "SDQP_SECURITY_WEBAUTHN_ORIGIN",
            &mut self.security.webauthn_origin,
        );
        apply_u64_override(
            env,
            "SDQP_SECURITY_WEBAUTHN_TIMEOUT_MS",
            &mut self.security.webauthn_timeout_ms,
        );
        apply_bool_override(
            env,
            "SDQP_SECURITY_WEBAUTHN_REQUIRE_UV",
            &mut self.security.webauthn_require_user_verification,
        );
        if let Some(allowlist) = env.get("SDQP_SECURITY_INTEGRATION_IP_ALLOWLIST") {
            self.security.integration_ip_allowlist = split_csv(allowlist);
        }
        if let Some(subjects) = env.get("SDQP_SECURITY_INTEGRATION_MTLS_SUBJECTS") {
            self.security.integration_mtls_subjects = split_csv(subjects);
        }
        if let Some(secret) = env.get("SDQP_SECURITY_INTEGRATION_API_KEY") {
            self.security.integration_api_keys = vec![SecurityApiKeySettings {
                key_id: "env-api-key".into(),
                secret: secret.clone(),
                scopes: vec![
                    "scim.sync".into(),
                    "hr.events".into(),
                    "audit.permission_lifecycle".into(),
                ],
                allowed_ips: self.security.integration_ip_allowlist.clone(),
            }];
        }
        apply_usize_override(
            env,
            "SDQP_SECURITY_INTEGRATION_RATE_LIMIT_MAX",
            &mut self.security.integration_rate_limit.max_requests,
        );
        apply_u64_override(
            env,
            "SDQP_SECURITY_INTEGRATION_RATE_LIMIT_WINDOW_SECS",
            &mut self.security.integration_rate_limit.window_secs,
        );
        apply_bool_override(
            env,
            "SDQP_SECURITY_CREDENTIAL_ROTATION_ENABLED",
            &mut self.security.credential_rotation.enabled,
        );
        apply_i64_override(
            env,
            "SDQP_SECURITY_CREDENTIAL_ROTATION_INTERVAL_SECS",
            &mut self.security.credential_rotation.interval_secs,
        );
        apply_i64_override(
            env,
            "SDQP_SECURITY_CREDENTIAL_ROTATION_RETRY_BACKOFF_SECS",
            &mut self.security.credential_rotation.retry_backoff_secs,
        );
        apply_u32_override(
            env,
            "SDQP_SECURITY_CREDENTIAL_ROTATION_MAX_ATTEMPTS",
            &mut self.security.credential_rotation.max_attempts,
        );
        apply_u32_override(
            env,
            "SDQP_SECURITY_CREDENTIAL_ROTATION_MANUAL_AFTER_ATTEMPTS",
            &mut self
                .security
                .credential_rotation
                .manual_intervention_after_attempts,
        );
        apply_string_override(
            env,
            "SDQP_SECURITY_TEE_PROVIDER",
            &mut self.security.tee.provider,
        );
        apply_string_override(
            env,
            "SDQP_SECURITY_TEE_ATTESTATION_URL",
            &mut self.security.tee.attestation_url,
        );
        if let Some(measurements) = env.get("SDQP_SECURITY_TEE_MEASUREMENTS") {
            self.security.tee.expected_measurements = split_csv(measurements);
        }
        apply_string_override(env, "SDQP_LOG_FILTER", &mut self.observability.log_filter);
        apply_string_override(
            env,
            "SDQP_METRICS_PATH",
            &mut self.observability.metrics_path,
        );
        apply_string_override(
            env,
            "SDQP_REQUEST_ID_HEADER",
            &mut self.observability.request_id_header,
        );
        apply_string_override(
            env,
            "SDQP_SPAN_ID_HEADER",
            &mut self.observability.span_id_header,
        );

        Ok(())
    }
}

fn apply_string_override(env: &HashMap<String, String>, key: &str, target: &mut String) {
    if let Some(value) = env.get(key) {
        *target = value.clone();
    }
}

fn apply_bool_override(env: &HashMap<String, String>, key: &str, target: &mut bool) {
    if let Some(value) = env.get(key) {
        *target = matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
}

fn apply_u64_override(env: &HashMap<String, String>, key: &str, target: &mut u64) {
    if let Some(value) = env.get(key)
        && let Ok(parsed) = value.parse::<u64>()
    {
        *target = parsed;
    }
}

fn apply_u32_override(env: &HashMap<String, String>, key: &str, target: &mut u32) {
    if let Some(value) = env.get(key)
        && let Ok(parsed) = value.parse::<u32>()
    {
        *target = parsed;
    }
}

fn apply_u8_override(env: &HashMap<String, String>, key: &str, target: &mut u8) {
    if let Some(value) = env.get(key)
        && let Ok(parsed) = value.parse::<u8>()
    {
        *target = parsed;
    }
}

fn apply_i64_override(env: &HashMap<String, String>, key: &str, target: &mut i64) {
    if let Some(value) = env.get(key)
        && let Ok(parsed) = value.parse::<i64>()
    {
        *target = parsed;
    }
}

fn apply_usize_override(env: &HashMap<String, String>, key: &str, target: &mut usize) {
    if let Some(value) = env.get(key)
        && let Ok(parsed) = value.parse::<usize>()
    {
        *target = parsed;
    }
}

fn apply_port_override(
    env: &HashMap<String, String>,
    key: &str,
    target: &mut u16,
) -> Result<(), ConfigError> {
    if let Some(value) = env.get(key) {
        *target = parse_port(key, value)?;
    }
    Ok(())
}

fn parse_port(key: &str, value: &str) -> Result<u16, ConfigError> {
    value.parse::<u16>().map_err(|_| ConfigError::InvalidPort {
        key: key.to_string(),
        value: value.to_string(),
    })
}

fn read_toml_file(path: &Path) -> Result<toml::Value, ConfigError> {
    if !path.exists() {
        return Err(ConfigError::MissingConfigFile {
            path: path.to_path_buf(),
        });
    }

    let raw = fs::read_to_string(path).map_err(|error| ConfigError::ReadConfigFile {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;

    toml::from_str::<toml::Value>(&raw).map_err(|error| ConfigError::ParseConfigFile {
        path: path.to_path_buf(),
        message: error.to_string(),
    })
}

fn merge_toml_values(base: &mut toml::Value, overlay: toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base_table), toml::Value::Table(overlay_table)) => {
            for (key, value) in overlay_table {
                match base_table.get_mut(&key) {
                    Some(existing) => merge_toml_values(existing, value),
                    None => {
                        base_table.insert(key, value);
                    }
                }
            }
        }
        (base_value, overlay_value) => *base_value = overlay_value,
    }
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, path::PathBuf};

    use super::{AppSettings, ConfigError, Environment};

    fn config_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("configs")
    }

    #[test]
    fn local_dev_has_expected_defaults() {
        let settings = AppSettings::local_dev();
        assert_eq!(settings.environment, Environment::Dev);
        assert_eq!(settings.api.base_url(), "http://127.0.0.1:8080");
        assert!(!settings.api.external_query_worker);
        assert_eq!(settings.worker.socket_addr(), "127.0.0.1:8081");
        assert_eq!(settings.worker.query_poll_interval_ms, 50);
        assert_eq!(settings.worker.query_max_attempts, 2);
        assert_eq!(settings.identity_provider.oidc_provider, "mock");
        assert_eq!(settings.identity_provider.saml_provider, "mock");
        assert_eq!(settings.identity_provider.scim_provider, "mock");
        assert_eq!(settings.identity_provider.scim_tenant_id, "tenant-alpha");
        assert_eq!(settings.identity_provider.scim_page_size, 100);
        assert_eq!(settings.identity_provider.scim_timeout_ms, 3_000);
        assert_eq!(settings.identity_provider.scim_retry_attempts, 2);
        assert!(settings.identity_provider.scim_disable_missing_users);
        assert!(settings.identity_provider.scim_disable_missing_groups);
        assert_eq!(
            settings.identity_provider.oidc_authorize_url,
            "https://mock-idp.local/issuer/authorize"
        );
        assert_eq!(
            settings.identity_provider.saml_sso_url,
            "https://mock-idp.local/issuer/saml/sso"
        );
        assert_eq!(
            settings.integrations.notifications.telegram_bot_api_url,
            "http://127.0.0.1:11080/notify/telegram"
        );
        assert_eq!(
            settings.integrations.notifications.dingtalk_webhook_url,
            "http://127.0.0.1:11080/notify/dingtalk"
        );
        assert_eq!(settings.integrations.notifications.retry_backoff_ms, 250);
        assert_eq!(settings.integrations.hr.provider, "mock");
        assert_eq!(
            settings
                .integrations
                .hr
                .approver_resolution
                .system_fallback_user_id,
            "user-sysadmin"
        );
        assert_eq!(
            settings
                .integrations
                .hr
                .approver_resolution
                .escalation_user_ids,
            vec!["user-security-a"]
        );
        assert_eq!(
            settings
                .integrations
                .hr
                .approver_resolution
                .max_manager_hops,
            16
        );
        assert!(
            settings
                .integrations
                .hr
                .approver_resolution
                .allow_delegation
        );
        assert_eq!(
            settings.integrations.hr.feishu.provider_id,
            "feishu-primary"
        );
        assert_eq!(
            settings.integrations.hr.feishu.auth_mode,
            "tenant_access_token"
        );
        assert_eq!(
            settings.integrations.hr.feishu.users_path,
            "/open-apis/contact/v3/users"
        );
        assert_eq!(settings.integrations.hr.feishu.page_size, 100);
        assert_eq!(
            settings.integrations.hr.workday.provider_id,
            "workday-primary"
        );
        assert_eq!(settings.integrations.hr.workday.auth_mode, "bearer_token");
        assert_eq!(
            settings.integrations.hr.workday.snapshot_path,
            "/workday/workers"
        );
        assert_eq!(settings.integrations.hr.workday.page_size, 100);
        assert_eq!(
            settings.integrations.hr.sap_successfactors.provider_id,
            "sap-successfactors-primary"
        );
        assert_eq!(
            settings.integrations.hr.sap_successfactors.auth_mode,
            "bearer_token"
        );
        assert_eq!(
            settings.integrations.hr.sap_successfactors.users_path,
            "/odata/v2/User"
        );
        assert_eq!(settings.integrations.hr.sap_successfactors.page_size, 100);
        assert_eq!(settings.integrations.tsa.provider, "mock");
        assert_eq!(settings.integrations.tsa.authority, "mock-tsa");
        assert_eq!(settings.integrations.blockchain_anchor.provider, "mock");
        assert_eq!(settings.integrations.dlp.provider, "local-policy");
        assert_eq!(settings.integrations.dlp.provider_id, "sdqp-local-policy");
        assert_eq!(settings.integrations.dlp.default_action, "alert");
        assert_eq!(settings.audit.checkpoint.provider, "mock");
        assert_eq!(settings.audit.forwarder.provider, "webhook");
        assert!(!settings.audit.forwarder.enabled);
        assert_eq!(settings.audit.forwarder.kafka_topic, "sdqp.audit.siem");
        assert!(settings.audit.retention.enabled);
        assert_eq!(
            settings.integrations.blockchain_anchor.network,
            "mock-chain"
        );
        assert_eq!(settings.kms.provider, "mock");
        assert_eq!(settings.kms.region, "local");
        assert_eq!(settings.kms.key_version, "1");
        assert!(settings.kms.rotation.enabled);
        assert_eq!(settings.kms.rotation.dek_rotation_days, 90);
        assert_eq!(settings.kms.rotation.kek_rotation_days, 365);
        assert_eq!(settings.kms.rotation.cycle_interval_secs, 3600);
        assert_eq!(settings.kms.rotation.batch_limit, 100);
        assert_eq!(settings.classification.default_retention_days, 365);
        assert_eq!(settings.classification.restricted_retention_days, 1825);
        assert_eq!(
            settings.classification.manual_confirmation_required_level,
            "l4_sensitive"
        );
        assert_eq!(
            settings.classification.default_regulations,
            vec!["PIPL".to_string(), "DSL".to_string(), "CSL".to_string()]
        );
        assert_eq!(settings.ueba.governance.query_burst_threshold, 5);
        assert_eq!(settings.ueba.governance.export_spike_threshold, 3);
        assert_eq!(settings.ueba.governance.denied_query_threshold, 2);
        assert_eq!(settings.ueba.governance.after_hours_start_hour, 22);
        assert_eq!(settings.ueba.governance.after_hours_end_hour, 6);
        assert_eq!(settings.ueba.governance.high_risk_score, 70);
        assert_eq!(settings.ueba.governance.critical_risk_score, 90);
        assert!(settings.ueba.calibration.enabled);
        assert_eq!(settings.ueba.calibration.min_events, 1);
        assert_eq!(
            settings.ueba.calibration.model_version,
            "ueba-governance-v1"
        );
        assert_eq!(settings.ueba.calibration.target_hit_rate_per_1000, 10);
        assert!(settings.security.credential_rotation.enabled);
        assert_eq!(
            settings.security.credential_rotation.interval_secs,
            90 * 24 * 60 * 60
        );
        assert_eq!(settings.security.credential_rotation.max_attempts, 3);
        assert_eq!(settings.observability.metrics_path, "/metrics");
    }

    #[test]
    fn env_map_overrides_defaults() {
        let env = HashMap::from([
            ("SDQP_ENVIRONMENT".to_string(), "test".to_string()),
            ("SDQP_API_PORT".to_string(), "18080".to_string()),
            (
                "SDQP_API_EXTERNAL_QUERY_WORKER".to_string(),
                "true".to_string(),
            ),
            ("SDQP_WORKER_HOST".to_string(), "0.0.0.0".to_string()),
            (
                "SDQP_WORKER_QUERY_MAX_ATTEMPTS".to_string(),
                "4".to_string(),
            ),
            (
                "SDQP_KAFKA_BROKERS".to_string(),
                "broker-a:9092, broker-b:9092".to_string(),
            ),
            ("SDQP_OIDC_PROVIDER".to_string(), "oidc".to_string()),
            (
                "SDQP_OIDC_AUTHORIZE_URL".to_string(),
                "https://login.example/oidc/authorize".to_string(),
            ),
            (
                "SDQP_OIDC_TOKEN_URL".to_string(),
                "https://login.example/oidc/token".to_string(),
            ),
            (
                "SDQP_OIDC_USERINFO_URL".to_string(),
                "https://login.example/oidc/userinfo".to_string(),
            ),
            ("SDQP_SAML_PROVIDER".to_string(), "saml".to_string()),
            (
                "SDQP_SAML_SSO_URL".to_string(),
                "https://login.example/saml/sso".to_string(),
            ),
            (
                "SDQP_SAML_EXCHANGE_URL".to_string(),
                "https://login.example/saml/exchange".to_string(),
            ),
            ("SDQP_SAML_ENTITY_ID".to_string(), "sp-entity".to_string()),
            ("SDQP_SAML_AUDIENCE".to_string(), "sp-audience".to_string()),
            ("SDQP_SCIM_PROVIDER".to_string(), "bearer".to_string()),
            ("SDQP_SCIM_TENANT_ID".to_string(), "tenant-prod".to_string()),
            ("SDQP_SCIM_PAGE_SIZE".to_string(), "50".to_string()),
            ("SDQP_SCIM_TIMEOUT_MS".to_string(), "8000".to_string()),
            ("SDQP_SCIM_RETRY_ATTEMPTS".to_string(), "4".to_string()),
            ("SDQP_SCIM_RETRY_BACKOFF_MS".to_string(), "750".to_string()),
            (
                "SDQP_SCIM_DISABLE_MISSING_USERS".to_string(),
                "false".to_string(),
            ),
            (
                "SDQP_SCIM_DELETE_MISSING_GROUPS".to_string(),
                "true".to_string(),
            ),
            ("SDQP_KMS_REGION".to_string(), "cn-test-1".to_string()),
            ("SDQP_KMS_KEY_VERSION".to_string(), "4".to_string()),
            ("SDQP_KMS_ROTATION_ENABLED".to_string(), "true".to_string()),
            (
                "SDQP_KMS_ROTATION_CYCLE_INTERVAL_SECS".to_string(),
                "120".to_string(),
            ),
            ("SDQP_KMS_ROTATION_BATCH_LIMIT".to_string(), "7".to_string()),
            ("SDQP_KMS_DEK_ROTATION_DAYS".to_string(), "30".to_string()),
            ("SDQP_KMS_KEK_ROTATION_DAYS".to_string(), "180".to_string()),
            (
                "SDQP_KMS_ALLOW_DEK_ROTATION".to_string(),
                "false".to_string(),
            ),
            ("SDQP_KMS_ALLOW_KEK_REWRAP".to_string(), "true".to_string()),
            (
                "SDQP_CLASSIFICATION_DEFAULT_RETENTION_DAYS".to_string(),
                "540".to_string(),
            ),
            (
                "SDQP_CLASSIFICATION_RESTRICTED_RETENTION_DAYS".to_string(),
                "2190".to_string(),
            ),
            (
                "SDQP_CLASSIFICATION_MANUAL_CONFIRMATION_LEVEL".to_string(),
                "l5_restricted".to_string(),
            ),
            (
                "SDQP_CLASSIFICATION_DEFAULT_REGULATIONS".to_string(),
                "PIPL,DSL,SOX".to_string(),
            ),
            (
                "SDQP_UEBA_QUERY_BURST_THRESHOLD".to_string(),
                "7".to_string(),
            ),
            (
                "SDQP_UEBA_EXPORT_SPIKE_THRESHOLD".to_string(),
                "4".to_string(),
            ),
            (
                "SDQP_UEBA_DENIED_QUERY_THRESHOLD".to_string(),
                "3".to_string(),
            ),
            (
                "SDQP_UEBA_AFTER_HOURS_START_HOUR".to_string(),
                "21".to_string(),
            ),
            (
                "SDQP_UEBA_AFTER_HOURS_END_HOUR".to_string(),
                "5".to_string(),
            ),
            ("SDQP_UEBA_HIGH_RISK_SCORE".to_string(), "72".to_string()),
            (
                "SDQP_UEBA_CRITICAL_RISK_SCORE".to_string(),
                "95".to_string(),
            ),
            (
                "SDQP_UEBA_CALIBRATION_ENABLED".to_string(),
                "true".to_string(),
            ),
            (
                "SDQP_UEBA_CALIBRATION_MIN_EVENTS".to_string(),
                "12".to_string(),
            ),
            (
                "SDQP_UEBA_CALIBRATION_MODEL_VERSION".to_string(),
                "ueba-governance-v2".to_string(),
            ),
            (
                "SDQP_UEBA_CALIBRATION_TARGET_HIT_RATE_PER_1000".to_string(),
                "25".to_string(),
            ),
            (
                "SDQP_NOTIFY_RETRY_BACKOFF_MS".to_string(),
                "500".to_string(),
            ),
            ("SDQP_HR_PROVIDER".to_string(), "feishu".to_string()),
            (
                "SDQP_APPROVER_SYSTEM_FALLBACK_USER_ID".to_string(),
                "user-break-glass".to_string(),
            ),
            (
                "SDQP_APPROVER_ESCALATION_USER_IDS".to_string(),
                "user-security-a,user-security-b".to_string(),
            ),
            (
                "SDQP_APPROVER_MAX_MANAGER_HOPS".to_string(),
                "3".to_string(),
            ),
            (
                "SDQP_APPROVER_ALLOW_DELEGATION".to_string(),
                "false".to_string(),
            ),
            (
                "SDQP_FEISHU_PROVIDER_ID".to_string(),
                "feishu-cn".to_string(),
            ),
            (
                "SDQP_FEISHU_TENANT_KEY".to_string(),
                "tenant-feishu".to_string(),
            ),
            (
                "SDQP_FEISHU_BASE_URL".to_string(),
                "https://open.feishu.cn".to_string(),
            ),
            (
                "SDQP_FEISHU_AUTH_MODE".to_string(),
                "app_credentials".to_string(),
            ),
            (
                "SDQP_FEISHU_TOKEN_URL".to_string(),
                "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal".to_string(),
            ),
            ("SDQP_FEISHU_APP_ID".to_string(), "cli_a".to_string()),
            (
                "SDQP_FEISHU_APP_SECRET".to_string(),
                "feishu-secret".to_string(),
            ),
            (
                "SDQP_FEISHU_USERS_PATH".to_string(),
                "/open-apis/contact/v3/users".to_string(),
            ),
            (
                "SDQP_FEISHU_EVENTS_PATH".to_string(),
                "/open-apis/contact/v3/events".to_string(),
            ),
            (
                "SDQP_FEISHU_WEBHOOK_VERIFICATION_TOKEN".to_string(),
                "feishu-webhook-token".to_string(),
            ),
            ("SDQP_FEISHU_TIMEOUT_MS".to_string(), "6500".to_string()),
            ("SDQP_FEISHU_PAGE_SIZE".to_string(), "30".to_string()),
            (
                "SDQP_WORKDAY_PROVIDER_ID".to_string(),
                "workday-cn".to_string(),
            ),
            (
                "SDQP_WORKDAY_TENANT".to_string(),
                "tenant-workday".to_string(),
            ),
            (
                "SDQP_WORKDAY_BASE_URL".to_string(),
                "https://workday.example".to_string(),
            ),
            (
                "SDQP_WORKDAY_AUTH_MODE".to_string(),
                "oauth_client_credentials".to_string(),
            ),
            (
                "SDQP_WORKDAY_TOKEN_URL".to_string(),
                "https://workday.example/oauth2/token".to_string(),
            ),
            (
                "SDQP_WORKDAY_CLIENT_ID".to_string(),
                "wd-client".to_string(),
            ),
            (
                "SDQP_WORKDAY_CLIENT_SECRET".to_string(),
                "wd-secret".to_string(),
            ),
            (
                "SDQP_WORKDAY_SCOPE".to_string(),
                "workers events".to_string(),
            ),
            (
                "SDQP_WORKDAY_SNAPSHOT_PATH".to_string(),
                "/ccx/service/customreport2/sdqp/workers".to_string(),
            ),
            (
                "SDQP_WORKDAY_EVENTS_PATH".to_string(),
                "/ccx/api/events/v1/workers".to_string(),
            ),
            (
                "SDQP_WORKDAY_WEBHOOK_SECRET".to_string(),
                "wd-webhook-secret".to_string(),
            ),
            ("SDQP_WORKDAY_TIMEOUT_MS".to_string(), "6000".to_string()),
            ("SDQP_WORKDAY_PAGE_SIZE".to_string(), "25".to_string()),
            (
                "SDQP_SAP_SUCCESSFACTORS_PROVIDER_ID".to_string(),
                "sap-sf-cn".to_string(),
            ),
            (
                "SDQP_SAP_SUCCESSFACTORS_COMPANY_ID".to_string(),
                "company-cn".to_string(),
            ),
            (
                "SDQP_SAP_SUCCESSFACTORS_BASE_URL".to_string(),
                "https://api.successfactors.example".to_string(),
            ),
            (
                "SDQP_SAP_SUCCESSFACTORS_AUTH_MODE".to_string(),
                "oauth_client_credentials".to_string(),
            ),
            (
                "SDQP_SAP_SUCCESSFACTORS_TOKEN_URL".to_string(),
                "https://api.successfactors.example/oauth/token".to_string(),
            ),
            (
                "SDQP_SAP_SUCCESSFACTORS_CLIENT_ID".to_string(),
                "sap-client".to_string(),
            ),
            (
                "SDQP_SAP_SUCCESSFACTORS_CLIENT_SECRET".to_string(),
                "sap-secret".to_string(),
            ),
            (
                "SDQP_SAP_SUCCESSFACTORS_SCOPE".to_string(),
                "odata.read events.read".to_string(),
            ),
            (
                "SDQP_SAP_SUCCESSFACTORS_USERS_PATH".to_string(),
                "/odata/v2/User".to_string(),
            ),
            (
                "SDQP_SAP_SUCCESSFACTORS_EVENTS_PATH".to_string(),
                "/odata/v2/EmpJob".to_string(),
            ),
            (
                "SDQP_SAP_SUCCESSFACTORS_WEBHOOK_SECRET".to_string(),
                "sap-webhook-secret".to_string(),
            ),
            (
                "SDQP_SAP_SUCCESSFACTORS_TIMEOUT_MS".to_string(),
                "7000".to_string(),
            ),
            (
                "SDQP_SAP_SUCCESSFACTORS_PAGE_SIZE".to_string(),
                "35".to_string(),
            ),
            ("SDQP_LDAP_PROVIDER_ID".to_string(), "ldap-cn".to_string()),
            (
                "SDQP_LDAP_URL".to_string(),
                "ldap://ldap.example.internal:389".to_string(),
            ),
            ("SDQP_LDAP_AUTH_MODE".to_string(), "simple_bind".to_string()),
            (
                "SDQP_LDAP_BIND_DN".to_string(),
                "cn=sdqp-sync,ou=svc,dc=example,dc=internal".to_string(),
            ),
            (
                "SDQP_LDAP_BIND_PASSWORD".to_string(),
                "ldap-secret".to_string(),
            ),
            ("SDQP_LDAP_TLS_MODE".to_string(), "start_tls".to_string()),
            (
                "SDQP_LDAP_CA_CERT_PATH".to_string(),
                "/etc/sdqp/ldap-ca.pem".to_string(),
            ),
            (
                "SDQP_LDAP_TLS_REQUIRE_VALID_CERT".to_string(),
                "true".to_string(),
            ),
            (
                "SDQP_LDAP_BASE_DN".to_string(),
                "ou=People,dc=example,dc=internal".to_string(),
            ),
            (
                "SDQP_LDAP_SEARCH_FILTER".to_string(),
                "(&(objectClass=person)(employeeType=employee))".to_string(),
            ),
            ("SDQP_LDAP_SEARCH_SCOPE".to_string(), "sub".to_string()),
            ("SDQP_LDAP_USER_ID_ATTRIBUTE".to_string(), "uid".to_string()),
            (
                "SDQP_LDAP_DEPARTMENT_ATTRIBUTE".to_string(),
                "departmentNumber".to_string(),
            ),
            (
                "SDQP_LDAP_MANAGER_ATTRIBUTE".to_string(),
                "manager".to_string(),
            ),
            (
                "SDQP_LDAP_STATUS_ATTRIBUTE".to_string(),
                "employeeStatus".to_string(),
            ),
            (
                "SDQP_LDAP_CHANGED_SINCE_ATTRIBUTE".to_string(),
                "modifyTimestamp".to_string(),
            ),
            (
                "SDQP_LDAP_ACTIVE_STATUS_VALUES".to_string(),
                "active,enabled".to_string(),
            ),
            (
                "SDQP_LDAP_DEPARTED_STATUS_VALUES".to_string(),
                "departed,inactive,terminated".to_string(),
            ),
            ("SDQP_LDAP_TIMEOUT_MS".to_string(), "8000".to_string()),
            ("SDQP_LDAP_PAGE_SIZE".to_string(), "500".to_string()),
            (
                "SDQP_LDAPSEARCH_BINARY".to_string(),
                "/usr/bin/ldapsearch".to_string(),
            ),
            (
                "SDQP_NOTIFY_TELEGRAM_URL".to_string(),
                "http://notify.example/telegram".to_string(),
            ),
            (
                "SDQP_NOTIFY_DINGTALK_URL".to_string(),
                "http://notify.example/dingtalk".to_string(),
            ),
            ("SDQP_TSA_PROVIDER".to_string(), "rfc3161".to_string()),
            (
                "SDQP_TSA_AUTHORITY".to_string(),
                "tsa.example.internal".to_string(),
            ),
            ("SDQP_TSA_TIMEOUT_MS".to_string(), "4500".to_string()),
            (
                "SDQP_BLOCKCHAIN_PROVIDER".to_string(),
                "ethereum".to_string(),
            ),
            (
                "SDQP_BLOCKCHAIN_BASE_URL".to_string(),
                "https://anchor.example/internal".to_string(),
            ),
            (
                "SDQP_BLOCKCHAIN_NETWORK".to_string(),
                "ethereum-sepolia".to_string(),
            ),
            ("SDQP_BLOCKCHAIN_TIMEOUT_MS".to_string(), "9000".to_string()),
            ("SDQP_DLP_PROVIDER".to_string(), "webhook".to_string()),
            (
                "SDQP_DLP_PROVIDER_ID".to_string(),
                "enterprise-dlp".to_string(),
            ),
            (
                "SDQP_DLP_WEBHOOK_URL".to_string(),
                "https://dlp.example/policy".to_string(),
            ),
            (
                "SDQP_DLP_AUTH_HEADER".to_string(),
                "authorization".to_string(),
            ),
            (
                "SDQP_DLP_AUTH_TOKEN".to_string(),
                "Bearer dlp-token".to_string(),
            ),
            ("SDQP_DLP_TIMEOUT_MS".to_string(), "7500".to_string()),
            (
                "SDQP_DLP_DEFAULT_ACTION".to_string(),
                "quarantine".to_string(),
            ),
            (
                "SDQP_AUDIT_CHECKPOINT_PROVIDER".to_string(),
                "vault".to_string(),
            ),
            (
                "SDQP_AUDIT_CHECKPOINT_ENDPOINT".to_string(),
                "https://vault.example/v1/transit".to_string(),
            ),
            (
                "SDQP_AUDIT_CHECKPOINT_REGION".to_string(),
                "cn-test-1".to_string(),
            ),
            (
                "SDQP_AUDIT_CHECKPOINT_KEY_RING".to_string(),
                "audit-root".to_string(),
            ),
            (
                "SDQP_AUDIT_CHECKPOINT_AUTH_TOKEN".to_string(),
                "vault-token".to_string(),
            ),
            (
                "SDQP_AUDIT_FORWARDER_ENABLED".to_string(),
                "true".to_string(),
            ),
            (
                "SDQP_AUDIT_FORWARDER_PROVIDER".to_string(),
                "kafka".to_string(),
            ),
            (
                "SDQP_AUDIT_FORWARDER_KAFKA_TOPIC".to_string(),
                "siem.audit.prod".to_string(),
            ),
            (
                "SDQP_AUDIT_RETENTION_ARCHIVE_AFTER_SECS".to_string(),
                "7200".to_string(),
            ),
            (
                "SDQP_SECURITY_CREDENTIAL_ROTATION_INTERVAL_SECS".to_string(),
                "3600".to_string(),
            ),
            (
                "SDQP_SECURITY_CREDENTIAL_ROTATION_RETRY_BACKOFF_SECS".to_string(),
                "60".to_string(),
            ),
            (
                "SDQP_SECURITY_CREDENTIAL_ROTATION_MAX_ATTEMPTS".to_string(),
                "5".to_string(),
            ),
            (
                "SDQP_SECURITY_CREDENTIAL_ROTATION_MANUAL_AFTER_ATTEMPTS".to_string(),
                "4".to_string(),
            ),
        ]);

        let settings = AppSettings::from_env_map(&env).expect("valid env settings");

        assert_eq!(settings.environment, Environment::Test);
        assert_eq!(settings.api.port, 18080);
        assert!(settings.api.external_query_worker);
        assert_eq!(settings.worker.host, "0.0.0.0");
        assert_eq!(settings.worker.query_max_attempts, 4);
        assert_eq!(settings.identity_provider.oidc_provider, "oidc");
        assert_eq!(
            settings.identity_provider.oidc_token_url,
            "https://login.example/oidc/token"
        );
        assert_eq!(settings.identity_provider.saml_provider, "saml");
        assert_eq!(
            settings.identity_provider.saml_exchange_url,
            "https://login.example/saml/exchange"
        );
        assert_eq!(settings.identity_provider.saml_entity_id, "sp-entity");
        assert_eq!(settings.identity_provider.saml_audience, "sp-audience");
        assert_eq!(settings.identity_provider.scim_provider, "bearer");
        assert_eq!(settings.identity_provider.scim_tenant_id, "tenant-prod");
        assert_eq!(settings.identity_provider.scim_page_size, 50);
        assert_eq!(settings.identity_provider.scim_timeout_ms, 8000);
        assert_eq!(settings.identity_provider.scim_retry_attempts, 4);
        assert_eq!(settings.identity_provider.scim_retry_backoff_ms, 750);
        assert!(!settings.identity_provider.scim_disable_missing_users);
        assert!(settings.identity_provider.scim_disable_missing_groups);
        assert!(settings.identity_provider.scim_delete_missing_groups);
        assert_eq!(
            settings.integrations.notifications.telegram_bot_api_url,
            "http://notify.example/telegram"
        );
        assert_eq!(
            settings.integrations.notifications.dingtalk_webhook_url,
            "http://notify.example/dingtalk"
        );
        assert_eq!(settings.integrations.notifications.retry_backoff_ms, 500);
        assert_eq!(settings.integrations.hr.provider, "feishu");
        assert_eq!(
            settings
                .integrations
                .hr
                .approver_resolution
                .system_fallback_user_id,
            "user-break-glass"
        );
        assert_eq!(
            settings
                .integrations
                .hr
                .approver_resolution
                .escalation_user_ids,
            vec!["user-security-a", "user-security-b"]
        );
        assert_eq!(
            settings
                .integrations
                .hr
                .approver_resolution
                .max_manager_hops,
            3
        );
        assert!(
            !settings
                .integrations
                .hr
                .approver_resolution
                .allow_delegation
        );
        assert_eq!(settings.integrations.hr.feishu.provider_id, "feishu-cn");
        assert_eq!(settings.integrations.hr.feishu.tenant_key, "tenant-feishu");
        assert_eq!(
            settings.integrations.hr.feishu.base_url,
            "https://open.feishu.cn"
        );
        assert_eq!(settings.integrations.hr.feishu.auth_mode, "app_credentials");
        assert_eq!(
            settings.integrations.hr.feishu.token_url,
            "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
        );
        assert_eq!(settings.integrations.hr.feishu.app_id, "cli_a");
        assert_eq!(settings.integrations.hr.feishu.app_secret, "feishu-secret");
        assert_eq!(
            settings.integrations.hr.feishu.users_path,
            "/open-apis/contact/v3/users"
        );
        assert_eq!(
            settings.integrations.hr.feishu.events_path,
            "/open-apis/contact/v3/events"
        );
        assert_eq!(
            settings.integrations.hr.feishu.webhook_verification_token,
            "feishu-webhook-token"
        );
        assert_eq!(settings.integrations.hr.feishu.timeout_ms, 6500);
        assert_eq!(settings.integrations.hr.feishu.page_size, 30);
        assert_eq!(settings.integrations.hr.workday.provider_id, "workday-cn");
        assert_eq!(settings.integrations.hr.workday.tenant, "tenant-workday");
        assert_eq!(
            settings.integrations.hr.workday.base_url,
            "https://workday.example"
        );
        assert_eq!(
            settings.integrations.hr.workday.auth_mode,
            "oauth_client_credentials"
        );
        assert_eq!(
            settings.integrations.hr.workday.token_url,
            "https://workday.example/oauth2/token"
        );
        assert_eq!(settings.integrations.hr.workday.client_id, "wd-client");
        assert_eq!(settings.integrations.hr.workday.client_secret, "wd-secret");
        assert_eq!(settings.integrations.hr.workday.scope, "workers events");
        assert_eq!(
            settings.integrations.hr.workday.snapshot_path,
            "/ccx/service/customreport2/sdqp/workers"
        );
        assert_eq!(
            settings.integrations.hr.workday.events_path,
            "/ccx/api/events/v1/workers"
        );
        assert_eq!(
            settings.integrations.hr.workday.webhook_secret,
            "wd-webhook-secret"
        );
        assert_eq!(settings.integrations.hr.workday.timeout_ms, 6000);
        assert_eq!(settings.integrations.hr.workday.page_size, 25);
        assert_eq!(
            settings.integrations.hr.sap_successfactors.provider_id,
            "sap-sf-cn"
        );
        assert_eq!(
            settings.integrations.hr.sap_successfactors.company_id,
            "company-cn"
        );
        assert_eq!(
            settings.integrations.hr.sap_successfactors.base_url,
            "https://api.successfactors.example"
        );
        assert_eq!(
            settings.integrations.hr.sap_successfactors.auth_mode,
            "oauth_client_credentials"
        );
        assert_eq!(
            settings.integrations.hr.sap_successfactors.token_url,
            "https://api.successfactors.example/oauth/token"
        );
        assert_eq!(
            settings.integrations.hr.sap_successfactors.client_id,
            "sap-client"
        );
        assert_eq!(
            settings.integrations.hr.sap_successfactors.client_secret,
            "sap-secret"
        );
        assert_eq!(
            settings.integrations.hr.sap_successfactors.scope,
            "odata.read events.read"
        );
        assert_eq!(
            settings.integrations.hr.sap_successfactors.users_path,
            "/odata/v2/User"
        );
        assert_eq!(
            settings.integrations.hr.sap_successfactors.events_path,
            "/odata/v2/EmpJob"
        );
        assert_eq!(
            settings.integrations.hr.sap_successfactors.webhook_secret,
            "sap-webhook-secret"
        );
        assert_eq!(settings.integrations.hr.sap_successfactors.timeout_ms, 7000);
        assert_eq!(settings.integrations.hr.sap_successfactors.page_size, 35);
        assert_eq!(settings.integrations.hr.ldap.provider_id, "ldap-cn");
        assert_eq!(
            settings.integrations.hr.ldap.url,
            "ldap://ldap.example.internal:389"
        );
        assert_eq!(settings.integrations.hr.ldap.auth_mode, "simple_bind");
        assert_eq!(
            settings.integrations.hr.ldap.bind_dn,
            "cn=sdqp-sync,ou=svc,dc=example,dc=internal"
        );
        assert_eq!(settings.integrations.hr.ldap.bind_password, "ldap-secret");
        assert_eq!(settings.integrations.hr.ldap.tls_mode, "start_tls");
        assert_eq!(
            settings.integrations.hr.ldap.ca_cert_path,
            "/etc/sdqp/ldap-ca.pem"
        );
        assert!(settings.integrations.hr.ldap.tls_require_valid_cert);
        assert_eq!(
            settings.integrations.hr.ldap.base_dn,
            "ou=People,dc=example,dc=internal"
        );
        assert_eq!(
            settings.integrations.hr.ldap.search_filter,
            "(&(objectClass=person)(employeeType=employee))"
        );
        assert_eq!(settings.integrations.hr.ldap.search_scope, "sub");
        assert_eq!(settings.integrations.hr.ldap.user_id_attribute, "uid");
        assert_eq!(
            settings.integrations.hr.ldap.department_attribute,
            "departmentNumber"
        );
        assert_eq!(
            settings.integrations.hr.ldap.changed_since_attribute,
            "modifyTimestamp"
        );
        assert_eq!(
            settings.integrations.hr.ldap.active_status_values,
            vec!["active", "enabled"]
        );
        assert_eq!(
            settings.integrations.hr.ldap.departed_status_values,
            vec!["departed", "inactive", "terminated"]
        );
        assert_eq!(settings.integrations.hr.ldap.timeout_ms, 8000);
        assert_eq!(settings.integrations.hr.ldap.page_size, 500);
        assert_eq!(
            settings.integrations.hr.ldap.ldapsearch_binary,
            "/usr/bin/ldapsearch"
        );
        assert_eq!(settings.integrations.tsa.provider, "rfc3161");
        assert_eq!(settings.integrations.tsa.authority, "tsa.example.internal");
        assert_eq!(settings.integrations.tsa.timeout_ms, 4500);
        assert_eq!(settings.integrations.blockchain_anchor.provider, "ethereum");
        assert_eq!(
            settings.integrations.blockchain_anchor.base_url,
            "https://anchor.example/internal"
        );
        assert_eq!(
            settings.integrations.blockchain_anchor.network,
            "ethereum-sepolia"
        );
        assert_eq!(settings.integrations.blockchain_anchor.timeout_ms, 9000);
        assert_eq!(settings.integrations.dlp.provider, "webhook");
        assert_eq!(settings.integrations.dlp.provider_id, "enterprise-dlp");
        assert_eq!(
            settings.integrations.dlp.webhook_url,
            "https://dlp.example/policy"
        );
        assert_eq!(settings.integrations.dlp.auth_header, "authorization");
        assert_eq!(settings.integrations.dlp.auth_token, "Bearer dlp-token");
        assert_eq!(settings.integrations.dlp.timeout_ms, 7500);
        assert_eq!(settings.integrations.dlp.default_action, "quarantine");
        assert_eq!(settings.kms.region, "cn-test-1");
        assert_eq!(settings.kms.key_version, "4");
        assert!(settings.kms.rotation.enabled);
        assert_eq!(settings.kms.rotation.cycle_interval_secs, 120);
        assert_eq!(settings.kms.rotation.batch_limit, 7);
        assert_eq!(settings.kms.rotation.dek_rotation_days, 30);
        assert_eq!(settings.kms.rotation.kek_rotation_days, 180);
        assert!(!settings.kms.rotation.allow_dek_rotation);
        assert!(settings.kms.rotation.allow_kek_rewrap);
        assert_eq!(settings.classification.default_retention_days, 540);
        assert_eq!(settings.classification.restricted_retention_days, 2190);
        assert_eq!(
            settings.classification.manual_confirmation_required_level,
            "l5_restricted"
        );
        assert_eq!(
            settings.classification.default_regulations,
            vec!["PIPL".to_string(), "DSL".to_string(), "SOX".to_string()]
        );
        assert_eq!(settings.ueba.governance.query_burst_threshold, 7);
        assert_eq!(settings.ueba.governance.export_spike_threshold, 4);
        assert_eq!(settings.ueba.governance.denied_query_threshold, 3);
        assert_eq!(settings.ueba.governance.after_hours_start_hour, 21);
        assert_eq!(settings.ueba.governance.after_hours_end_hour, 5);
        assert_eq!(settings.ueba.governance.high_risk_score, 72);
        assert_eq!(settings.ueba.governance.critical_risk_score, 95);
        assert!(settings.ueba.calibration.enabled);
        assert_eq!(settings.ueba.calibration.min_events, 12);
        assert_eq!(
            settings.ueba.calibration.model_version,
            "ueba-governance-v2"
        );
        assert_eq!(settings.ueba.calibration.target_hit_rate_per_1000, 25);
        assert_eq!(settings.audit.checkpoint.provider, "vault");
        assert_eq!(
            settings.audit.checkpoint.endpoint,
            "https://vault.example/v1/transit"
        );
        assert_eq!(settings.audit.checkpoint.region, "cn-test-1");
        assert_eq!(settings.audit.checkpoint.key_ring, "audit-root");
        assert_eq!(settings.audit.checkpoint.auth_token, "vault-token");
        assert!(settings.audit.forwarder.enabled);
        assert_eq!(settings.audit.forwarder.provider, "kafka");
        assert_eq!(settings.audit.forwarder.kafka_topic, "siem.audit.prod");
        assert_eq!(settings.audit.retention.archive_after_secs, 7200);
        assert_eq!(settings.security.credential_rotation.interval_secs, 3600);
        assert_eq!(settings.security.credential_rotation.retry_backoff_secs, 60);
        assert_eq!(settings.security.credential_rotation.max_attempts, 5);
        assert_eq!(
            settings
                .security
                .credential_rotation
                .manual_intervention_after_attempts,
            4
        );
        assert_eq!(
            settings.kafka.brokers,
            vec!["broker-a:9092", "broker-b:9092"]
        );
    }

    #[test]
    fn invalid_port_is_rejected() {
        let env = HashMap::from([("SDQP_API_PORT".to_string(), "not-a-port".to_string())]);

        assert_eq!(
            AppSettings::from_env_map(&env),
            Err(ConfigError::InvalidPort {
                key: "SDQP_API_PORT".into(),
                value: "not-a-port".into(),
            })
        );
    }

    #[test]
    fn profile_loader_merges_base_and_local_docker_profile() {
        let settings =
            AppSettings::from_profile_files(config_root(), Environment::LocalDocker, None)
                .expect("settings");

        assert_eq!(settings.environment, Environment::LocalDocker);
        assert_eq!(settings.api.host, "0.0.0.0");
        assert!(settings.api.external_query_worker);
        assert_eq!(settings.identity_provider.oidc_provider, "mock");
        assert_eq!(settings.identity_provider.saml_provider, "mock");
        assert_eq!(
            settings.database.postgres.dsn,
            "postgres://sdqp:sdqp@postgres:5432/sdqp"
        );
        assert_eq!(
            settings.integrations.notifications.feishu_webhook_url,
            "http://mockserver:1080/notify/feishu"
        );
        assert_eq!(
            settings.integrations.notifications.telegram_bot_api_url,
            "http://mockserver:1080/notify/telegram"
        );
        assert_eq!(
            settings.integrations.notifications.dingtalk_webhook_url,
            "http://mockserver:1080/notify/dingtalk"
        );
        assert_eq!(settings.integrations.tsa.provider, "mock");
        assert_eq!(settings.integrations.blockchain_anchor.provider, "mock");
        assert_eq!(settings.kafka.brokers, vec!["redpanda:9092"]);
        assert!(settings.audit.forwarder.enabled);
        assert_eq!(settings.audit.forwarder.provider, "webhook");
        assert_eq!(
            settings.audit.forwarder.webhook_url,
            "http://mockserver:1080/audit/siem"
        );
        assert_eq!(settings.frontend.api_base_url, "");
    }

    #[test]
    fn sources_loader_applies_secrets_file_and_env_overrides() {
        let temp_dir = std::env::temp_dir().join(format!("sdqp-config-{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let secrets_path = temp_dir.join("secrets.toml");
        fs::write(
            &secrets_path,
            r#"
[identity_provider]
client_secret = "secret-from-file"
scim_token = "scim-from-file"

[object_store]
secret_key = "object-secret-from-file"
"#,
        )
        .expect("secrets file");

        let env = HashMap::from([
            ("SDQP_ENVIRONMENT".to_string(), "prod-sim".to_string()),
            (
                "SDQP_SECRETS_FILE".to_string(),
                secrets_path.to_string_lossy().to_string(),
            ),
            (
                "SDQP_OIDC_CLIENT_SECRET".to_string(),
                "secret-from-env".to_string(),
            ),
        ]);

        let settings = AppSettings::from_sources(config_root(), &env).expect("settings");

        assert_eq!(settings.environment, Environment::ProdSim);
        assert_eq!(settings.identity_provider.oidc_provider, "oidc");
        assert_eq!(settings.identity_provider.client_secret, "secret-from-env");
        assert_eq!(settings.identity_provider.scim_token, "scim-from-file");
        assert_eq!(settings.object_store.secret_key, "object-secret-from-file");

        let _ = fs::remove_file(secrets_path);
        let _ = fs::remove_dir_all(temp_dir);
    }
}
