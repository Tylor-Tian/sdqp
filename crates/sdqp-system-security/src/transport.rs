use std::{collections::HashMap, sync::Mutex};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    pub key_id: String,
    pub secret: String,
    pub scopes: Vec<String>,
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MtlsPolicy {
    pub required_subjects: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    pub max_requests: usize,
    pub window_secs: u64,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            max_requests: 60,
            window_secs: 60,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IntegrationSecurityConfig {
    pub api_keys: Vec<ApiKeyRecord>,
    pub ip_allowlist: Vec<String>,
    pub mtls: MtlsPolicy,
    pub rate_limit: RateLimitPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationRequestContext {
    pub client_ip: String,
    pub api_key: Option<String>,
    pub mtls_subject: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedIntegration {
    pub key_id: String,
    pub client_ip: String,
    pub mtls_subject: Option<String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IntegrationSecurityError {
    #[error("integration api key is missing")]
    MissingApiKey,
    #[error("integration api key is invalid")]
    InvalidApiKey,
    #[error("integration scope is not allowed")]
    ScopeDenied,
    #[error("integration client ip is not allowed")]
    IpDenied,
    #[error("mTLS client certificate subject is missing")]
    MissingMtlsSubject,
    #[error("mTLS client certificate subject is not allowed")]
    UnauthorizedMtlsSubject,
    #[error("integration rate limit exceeded")]
    RateLimited,
}

#[derive(Debug, Clone)]
pub struct IntegrationSecurityPolicy {
    config: IntegrationSecurityConfig,
}

impl IntegrationSecurityPolicy {
    pub fn new(config: IntegrationSecurityConfig) -> Self {
        Self { config }
    }

    pub fn rate_limit_policy(&self) -> RateLimitPolicy {
        self.config.rate_limit.clone()
    }

    pub fn config(&self) -> IntegrationSecurityConfig {
        self.config.clone()
    }

    pub fn api_key_record(&self, key_id: &str) -> Option<ApiKeyRecord> {
        self.config
            .api_keys
            .iter()
            .find(|record| record.key_id == key_id)
            .cloned()
    }

    pub fn upsert_api_key(&mut self, record: ApiKeyRecord) {
        if let Some(existing) = self
            .config
            .api_keys
            .iter_mut()
            .find(|candidate| candidate.key_id == record.key_id)
        {
            *existing = record;
        } else {
            self.config.api_keys.push(record);
        }
    }

    pub fn authorize(
        &self,
        scope: &str,
        require_mtls: bool,
        request: &IntegrationRequestContext,
    ) -> Result<AuthorizedIntegration, IntegrationSecurityError> {
        self.authorize_ip(&request.client_ip)?;
        let key = self.authorize_api_key(scope, &request.client_ip, request.api_key.as_deref())?;
        if require_mtls {
            self.authorize_mtls(request.mtls_subject.as_deref())?;
        }
        Ok(AuthorizedIntegration {
            key_id: key.key_id.clone(),
            client_ip: request.client_ip.clone(),
            mtls_subject: request.mtls_subject.clone(),
        })
    }

    fn authorize_ip(&self, client_ip: &str) -> Result<(), IntegrationSecurityError> {
        let in_global_allowlist = self.config.ip_allowlist.is_empty()
            || self
                .config
                .ip_allowlist
                .iter()
                .any(|candidate| candidate == client_ip);
        if in_global_allowlist {
            Ok(())
        } else {
            Err(IntegrationSecurityError::IpDenied)
        }
    }

    fn authorize_api_key(
        &self,
        scope: &str,
        client_ip: &str,
        api_key: Option<&str>,
    ) -> Result<&ApiKeyRecord, IntegrationSecurityError> {
        let api_key = api_key.ok_or(IntegrationSecurityError::MissingApiKey)?;
        let record = self
            .config
            .api_keys
            .iter()
            .find(|record| record.secret == api_key)
            .ok_or(IntegrationSecurityError::InvalidApiKey)?;
        if !record.scopes.is_empty() && !record.scopes.iter().any(|candidate| candidate == scope) {
            return Err(IntegrationSecurityError::ScopeDenied);
        }
        if !record.allowed_ips.is_empty()
            && !record
                .allowed_ips
                .iter()
                .any(|candidate| candidate == client_ip)
        {
            return Err(IntegrationSecurityError::IpDenied);
        }
        Ok(record)
    }

    fn authorize_mtls(&self, subject: Option<&str>) -> Result<(), IntegrationSecurityError> {
        let subject = subject.ok_or(IntegrationSecurityError::MissingMtlsSubject)?;
        if self.config.mtls.required_subjects.is_empty()
            || self
                .config
                .mtls
                .required_subjects
                .iter()
                .any(|candidate| candidate == subject)
        {
            Ok(())
        } else {
            Err(IntegrationSecurityError::UnauthorizedMtlsSubject)
        }
    }
}

#[derive(Debug)]
pub struct IntegrationRateLimiter {
    policy: RateLimitPolicy,
    windows: Mutex<HashMap<String, RateLimitWindow>>,
}

impl IntegrationRateLimiter {
    pub fn new(policy: RateLimitPolicy) -> Self {
        Self {
            policy,
            windows: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, identifier: &str) -> Result<(), IntegrationSecurityError> {
        let mut windows = self.windows.lock().expect("rate limiter");
        let now = Utc::now();
        let window = windows
            .entry(identifier.to_string())
            .or_insert_with(|| RateLimitWindow {
                started_at: now,
                count: 0,
            });
        if now - window.started_at >= Duration::seconds(self.policy.window_secs as i64) {
            window.started_at = now;
            window.count = 0;
        }
        if window.count >= self.policy.max_requests {
            return Err(IntegrationSecurityError::RateLimited);
        }
        window.count += 1;
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct RateLimitWindow {
    started_at: DateTime<Utc>,
    count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    IntegrationApiKey,
    ScimBearerToken,
    OidcClientSecret,
    SamlCertificate,
    MtlsCertificateMetadata,
}

impl CredentialKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IntegrationApiKey => "integration_api_key",
            Self::ScimBearerToken => "scim_bearer_token",
            Self::OidcClientSecret => "oidc_client_secret",
            Self::SamlCertificate => "saml_certificate",
            Self::MtlsCertificateMetadata => "mtls_certificate_metadata",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRotationStatus {
    Active,
    Due,
    Rotating,
    Rotated,
    FailedRetryable,
    ManualInterventionRequired,
    ExternallyManaged,
    Disabled,
}

impl CredentialRotationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Due => "due",
            Self::Rotating => "rotating",
            Self::Rotated => "rotated",
            Self::FailedRetryable => "failed_retryable",
            Self::ManualInterventionRequired => "manual_intervention_required",
            Self::ExternallyManaged => "externally_managed",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRotationPolicy {
    pub credential_id: String,
    pub kind: CredentialKind,
    pub enabled: bool,
    pub interval_secs: i64,
    pub retry_backoff_secs: i64,
    pub max_attempts: u32,
    pub manual_intervention_after_attempts: u32,
    pub repo_local_automation: bool,
}

impl CredentialRotationPolicy {
    pub fn integration_api_key(
        key_id: impl Into<String>,
        interval_secs: i64,
        retry_backoff_secs: i64,
        max_attempts: u32,
        manual_intervention_after_attempts: u32,
    ) -> Self {
        Self {
            credential_id: key_id.into(),
            kind: CredentialKind::IntegrationApiKey,
            enabled: true,
            interval_secs,
            retry_backoff_secs,
            max_attempts,
            manual_intervention_after_attempts,
            repo_local_automation: true,
        }
    }

    pub fn externally_managed(
        credential_id: impl Into<String>,
        kind: CredentialKind,
        interval_secs: i64,
        retry_backoff_secs: i64,
        max_attempts: u32,
        manual_intervention_after_attempts: u32,
    ) -> Self {
        Self {
            credential_id: credential_id.into(),
            kind,
            enabled: true,
            interval_secs,
            retry_backoff_secs,
            max_attempts,
            manual_intervention_after_attempts,
            repo_local_automation: false,
        }
    }

    pub fn next_due_after(&self, instant: DateTime<Utc>) -> DateTime<Utc> {
        instant + Duration::seconds(self.interval_secs.max(1))
    }

    pub fn retry_due_after(&self, instant: DateTime<Utc>) -> DateTime<Utc> {
        instant + Duration::seconds(self.retry_backoff_secs.max(1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRotationState {
    pub credential_id: String,
    pub kind: CredentialKind,
    pub status: CredentialRotationStatus,
    pub last_rotated_at: Option<DateTime<Utc>>,
    pub next_rotation_due_at: DateTime<Utc>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub attempts: u32,
    pub active_version: Option<String>,
    pub last_error: Option<String>,
    pub manual_intervention_reason: Option<String>,
    pub updated_at: DateTime<Utc>,
}

impl CredentialRotationState {
    pub fn new_due(policy: &CredentialRotationPolicy, now: DateTime<Utc>) -> Self {
        Self {
            credential_id: policy.credential_id.clone(),
            kind: policy.kind.clone(),
            status: if policy.enabled {
                CredentialRotationStatus::Due
            } else {
                CredentialRotationStatus::Disabled
            },
            last_rotated_at: None,
            next_rotation_due_at: now,
            last_attempt_at: None,
            attempts: 0,
            active_version: None,
            last_error: None,
            manual_intervention_reason: None,
            updated_at: now,
        }
    }

    pub fn refresh_due_status(&mut self, now: DateTime<Utc>) {
        if matches!(
            self.status,
            CredentialRotationStatus::Active | CredentialRotationStatus::Rotated
        ) && now >= self.next_rotation_due_at
        {
            self.status = CredentialRotationStatus::Due;
            self.updated_at = now;
        }
    }

    pub fn is_due(&self, policy: &CredentialRotationPolicy, now: DateTime<Utc>) -> bool {
        if !policy.enabled {
            return false;
        }
        match self.status {
            CredentialRotationStatus::Due => true,
            CredentialRotationStatus::Active | CredentialRotationStatus::Rotated => {
                now >= self.next_rotation_due_at
            }
            CredentialRotationStatus::FailedRetryable => self
                .last_attempt_at
                .map(|last_attempt| now >= policy.retry_due_after(last_attempt))
                .unwrap_or(true),
            _ => false,
        }
    }

    pub fn start_attempt(&mut self, now: DateTime<Utc>) {
        self.status = CredentialRotationStatus::Rotating;
        self.last_attempt_at = Some(now);
        self.attempts = self.attempts.saturating_add(1);
        self.updated_at = now;
    }

    pub fn mark_success(
        &mut self,
        policy: &CredentialRotationPolicy,
        now: DateTime<Utc>,
        active_version: impl Into<String>,
    ) {
        self.status = CredentialRotationStatus::Active;
        self.last_rotated_at = Some(now);
        self.next_rotation_due_at = policy.next_due_after(now);
        self.active_version = Some(active_version.into());
        self.last_error = None;
        self.manual_intervention_reason = None;
        self.attempts = 0;
        self.updated_at = now;
    }

    pub fn mark_failure(
        &mut self,
        policy: &CredentialRotationPolicy,
        now: DateTime<Utc>,
        error: impl Into<String>,
    ) {
        let error = error.into();
        self.last_error = Some(error.clone());
        self.updated_at = now;
        if self.attempts >= policy.manual_intervention_after_attempts.max(1)
            || self.attempts >= policy.max_attempts.max(1)
        {
            self.status = CredentialRotationStatus::ManualInterventionRequired;
            self.manual_intervention_reason = Some(error);
        } else {
            self.status = CredentialRotationStatus::FailedRetryable;
            self.next_rotation_due_at = policy.retry_due_after(now);
        }
    }

    pub fn mark_externally_managed(&mut self, now: DateTime<Utc>, reason: impl Into<String>) {
        let reason = reason.into();
        self.status = CredentialRotationStatus::ExternallyManaged;
        self.last_attempt_at = Some(now);
        self.last_error = Some(reason.clone());
        self.manual_intervention_reason = Some(reason);
        self.updated_at = now;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedCredentialSecret {
    pub version: String,
    pub secret: String,
}

pub fn generate_integration_api_key_secret(
    key_id: &str,
    now: DateTime<Utc>,
) -> GeneratedCredentialSecret {
    let version = Ulid::new().to_string();
    let mut hasher = Sha256::new();
    hasher.update(key_id.as_bytes());
    hasher.update(now.to_rfc3339().as_bytes());
    hasher.update(version.as_bytes());
    let digest = hasher.finalize();
    let safe_key_id = key_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();
    GeneratedCredentialSecret {
        version,
        secret: format!("sdqp_{}_{}", safe_key_id, hex::encode(&digest[..24])),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApiKeyRecord, CredentialRotationPolicy, CredentialRotationState, CredentialRotationStatus,
        IntegrationRateLimiter, IntegrationRequestContext, IntegrationSecurityConfig,
        IntegrationSecurityError, IntegrationSecurityPolicy, MtlsPolicy, RateLimitPolicy,
        generate_integration_api_key_secret,
    };
    use chrono::{Duration, Utc};

    #[test]
    fn integration_policy_requires_api_key_ip_and_mtls() {
        let policy = IntegrationSecurityPolicy::new(IntegrationSecurityConfig {
            api_keys: vec![ApiKeyRecord {
                key_id: "scim".into(),
                secret: "scim-key".into(),
                scopes: vec!["scim.sync".into()],
                allowed_ips: vec![],
            }],
            ip_allowlist: vec!["127.0.0.1".into()],
            mtls: MtlsPolicy {
                required_subjects: vec!["CN=sdqp-hr".into()],
            },
            rate_limit: RateLimitPolicy::default(),
        });

        let authorized = policy
            .authorize(
                "scim.sync",
                true,
                &IntegrationRequestContext {
                    client_ip: "127.0.0.1".into(),
                    api_key: Some("scim-key".into()),
                    mtls_subject: Some("CN=sdqp-hr".into()),
                },
            )
            .expect("authorized");
        assert_eq!(authorized.key_id, "scim");
    }

    #[test]
    fn integration_policy_rejects_invalid_ip() {
        let policy = IntegrationSecurityPolicy::new(IntegrationSecurityConfig {
            api_keys: vec![ApiKeyRecord {
                key_id: "scim".into(),
                secret: "scim-key".into(),
                scopes: vec!["scim.sync".into()],
                allowed_ips: vec![],
            }],
            ip_allowlist: vec!["127.0.0.1".into()],
            mtls: MtlsPolicy::default(),
            rate_limit: RateLimitPolicy::default(),
        });

        let error = policy
            .authorize(
                "scim.sync",
                false,
                &IntegrationRequestContext {
                    client_ip: "10.0.0.1".into(),
                    api_key: Some("scim-key".into()),
                    mtls_subject: None,
                },
            )
            .expect_err("ip denied");
        assert_eq!(error, IntegrationSecurityError::IpDenied);
    }

    #[test]
    fn integration_rate_limiter_enforces_window() {
        let limiter = IntegrationRateLimiter::new(RateLimitPolicy {
            max_requests: 2,
            window_secs: 60,
        });
        limiter.check("scim:127.0.0.1").expect("first");
        limiter.check("scim:127.0.0.1").expect("second");
        let error = limiter.check("scim:127.0.0.1").expect_err("limited");
        assert_eq!(error, IntegrationSecurityError::RateLimited);
    }

    #[test]
    fn integration_policy_accepts_rotated_api_key_material() {
        let mut policy = IntegrationSecurityPolicy::new(IntegrationSecurityConfig {
            api_keys: vec![ApiKeyRecord {
                key_id: "scim".into(),
                secret: "old-key".into(),
                scopes: vec!["scim.sync".into()],
                allowed_ips: vec![],
            }],
            ip_allowlist: vec!["127.0.0.1".into()],
            mtls: MtlsPolicy::default(),
            rate_limit: RateLimitPolicy::default(),
        });
        let mut rotated = policy.api_key_record("scim").expect("api key");
        rotated.secret = "new-key".into();
        policy.upsert_api_key(rotated);

        let error = policy
            .authorize(
                "scim.sync",
                false,
                &IntegrationRequestContext {
                    client_ip: "127.0.0.1".into(),
                    api_key: Some("old-key".into()),
                    mtls_subject: None,
                },
            )
            .expect_err("old key rejected");
        assert_eq!(error, IntegrationSecurityError::InvalidApiKey);
        assert!(
            policy
                .authorize(
                    "scim.sync",
                    false,
                    &IntegrationRequestContext {
                        client_ip: "127.0.0.1".into(),
                        api_key: Some("new-key".into()),
                        mtls_subject: None,
                    },
                )
                .is_ok()
        );
    }

    #[test]
    fn credential_rotation_state_tracks_due_success_retry_and_manual_intervention() {
        let now = Utc::now();
        let policy = CredentialRotationPolicy::integration_api_key("scim", 90, 10, 2, 2);
        let mut state = CredentialRotationState::new_due(&policy, now);
        assert!(state.is_due(&policy, now));
        state.start_attempt(now);
        state.mark_failure(&policy, now, "provider unavailable");
        assert_eq!(state.status, CredentialRotationStatus::FailedRetryable);
        assert!(!state.is_due(&policy, now + Duration::seconds(5)));
        assert!(state.is_due(&policy, now + Duration::seconds(11)));

        state.start_attempt(now + Duration::seconds(11));
        state.mark_failure(&policy, now + Duration::seconds(11), "second failure");
        assert_eq!(
            state.status,
            CredentialRotationStatus::ManualInterventionRequired
        );

        let generated = generate_integration_api_key_secret("scim", now);
        assert!(generated.secret.starts_with("sdqp_scim_"));
    }
}
