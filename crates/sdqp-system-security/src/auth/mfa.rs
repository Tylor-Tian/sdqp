use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use thiserror::Error;
use ulid::Ulid;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MfaMethod {
    Totp,
    WebAuthn,
    Biometric,
}

impl MfaMethod {
    pub fn is_phishing_resistant(&self) -> bool {
        matches!(self, Self::WebAuthn | Self::Biometric)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpProviderConfig {
    pub issuer: String,
    pub period_secs: u64,
    pub digits: u32,
    pub allowed_drift_steps: u8,
}

impl Default for TotpProviderConfig {
    fn default() -> Self {
        Self {
            issuer: "SDQP".into(),
            period_secs: 30,
            digits: 6,
            allowed_drift_steps: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnProviderConfig {
    pub rp_id: String,
    pub origin: String,
    pub timeout_ms: u64,
    pub challenge_ttl_secs: i64,
    pub require_user_verification: bool,
}

impl Default for WebAuthnProviderConfig {
    fn default() -> Self {
        Self {
            rp_id: "sdqp.local".into(),
            origin: "https://sdqp.local".into(),
            timeout_ms: 300_000,
            challenge_ttl_secs: 300,
            require_user_verification: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MfaProviderConfig {
    pub bootstrap_seed: String,
    pub challenge_ttl_secs: i64,
    pub totp: TotpProviderConfig,
    pub webauthn: WebAuthnProviderConfig,
}

impl Default for MfaProviderConfig {
    fn default() -> Self {
        Self {
            bootstrap_seed: "sdqp-mfa-bootstrap-seed".into(),
            challenge_ttl_secs: 300,
            totp: TotpProviderConfig::default(),
            webauthn: WebAuthnProviderConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpRegistration {
    pub account_name: String,
    pub secret_hex: String,
    pub digits: u32,
    pub period_secs: u64,
    pub allowed_drift_steps: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnRegistration {
    pub credential_id: String,
    pub public_key_sec1: String,
    pub rp_id: String,
    pub origin: String,
    pub require_user_verification: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MfaRegistration {
    Totp(TotpRegistration),
    WebAuthn(WebAuthnRegistration),
    Biometric(WebAuthnRegistration),
}

impl MfaRegistration {
    pub fn method(&self) -> MfaMethod {
        match self {
            Self::Totp(_) => MfaMethod::Totp,
            Self::WebAuthn(_) => MfaMethod::WebAuthn,
            Self::Biometric(_) => MfaMethod::Biometric,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnRequestOptions {
    pub challenge: String,
    pub rp_id: String,
    pub origin: String,
    pub credential_id: String,
    pub timeout_ms: u64,
    pub user_verification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MfaChallengePayload {
    Totp {
        issuer: String,
        account_name: String,
        period_secs: u64,
        digits: u32,
    },
    WebAuthn(WebAuthnRequestOptions),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MfaChallenge {
    pub challenge_id: String,
    pub method: MfaMethod,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub reason: Option<String>,
    pub challenge_payload: Option<MfaChallengePayload>,
    pub dev_only_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnAssertion {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MfaVerification {
    pub code: Option<String>,
    pub webauthn_assertion: Option<WebAuthnAssertion>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MfaError {
    #[error("mfa challenge expired")]
    ChallengeExpired,
    #[error("mfa challenge is malformed")]
    MalformedChallenge,
    #[error("mfa verification input is missing")]
    MissingVerificationInput,
    #[error("mfa verification code is invalid")]
    InvalidCode,
    #[error("webauthn assertion is invalid")]
    InvalidAssertion,
    #[error("mfa registration does not match method")]
    RegistrationMismatch,
}

#[derive(Debug, Clone)]
pub struct MfaProviderRegistry {
    config: MfaProviderConfig,
}

impl MfaProviderRegistry {
    pub fn new(config: MfaProviderConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &MfaProviderConfig {
        &self.config
    }

    pub fn bootstrap_registration(
        &self,
        tenant_id: &str,
        user_id: &str,
        account_name: &str,
        method: &MfaMethod,
    ) -> MfaRegistration {
        match method {
            MfaMethod::Totp => MfaRegistration::Totp(TotpRegistration {
                account_name: account_name.to_string(),
                secret_hex: hex::encode(self.derive_totp_secret(tenant_id, user_id, account_name)),
                digits: self.config.totp.digits,
                period_secs: self.config.totp.period_secs,
                allowed_drift_steps: self.config.totp.allowed_drift_steps,
            }),
            MfaMethod::WebAuthn => {
                let verifying_key =
                    self.derive_bootstrap_signing_key(tenant_id, user_id, account_name);
                MfaRegistration::WebAuthn(WebAuthnRegistration {
                    credential_id: self.bootstrap_credential_id(tenant_id, user_id, account_name),
                    public_key_sec1: b64_encode(
                        verifying_key
                            .verifying_key()
                            .to_encoded_point(false)
                            .as_bytes(),
                    ),
                    rp_id: self.config.webauthn.rp_id.clone(),
                    origin: self.config.webauthn.origin.clone(),
                    require_user_verification: self.config.webauthn.require_user_verification,
                })
            }
            MfaMethod::Biometric => {
                let verifying_key =
                    self.derive_bootstrap_signing_key(tenant_id, user_id, account_name);
                MfaRegistration::Biometric(WebAuthnRegistration {
                    credential_id: self.bootstrap_credential_id(tenant_id, user_id, account_name),
                    public_key_sec1: b64_encode(
                        verifying_key
                            .verifying_key()
                            .to_encoded_point(false)
                            .as_bytes(),
                    ),
                    rp_id: self.config.webauthn.rp_id.clone(),
                    origin: self.config.webauthn.origin.clone(),
                    require_user_verification: true,
                })
            }
        }
    }

    pub fn begin_challenge(
        &self,
        registration: &MfaRegistration,
        reason: Option<String>,
    ) -> Result<MfaChallenge, MfaError> {
        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::seconds(self.config.challenge_ttl_secs);
        let challenge_id = Ulid::new().to_string();
        let challenge_payload = match registration {
            MfaRegistration::Totp(registration) => Some(MfaChallengePayload::Totp {
                issuer: self.config.totp.issuer.clone(),
                account_name: registration.account_name.clone(),
                period_secs: registration.period_secs,
                digits: registration.digits,
            }),
            MfaRegistration::WebAuthn(registration) | MfaRegistration::Biometric(registration) => {
                Some(MfaChallengePayload::WebAuthn(WebAuthnRequestOptions {
                    challenge: b64_encode(
                        Sha256::digest(
                            format!(
                                "{}:{}:{}",
                                challenge_id,
                                registration.credential_id,
                                expires_at.timestamp_millis()
                            )
                            .as_bytes(),
                        )
                        .as_slice(),
                    ),
                    rp_id: registration.rp_id.clone(),
                    origin: registration.origin.clone(),
                    credential_id: registration.credential_id.clone(),
                    timeout_ms: self.config.webauthn.timeout_ms,
                    user_verification: if registration.require_user_verification {
                        "required".into()
                    } else {
                        "preferred".into()
                    },
                }))
            }
        };

        Ok(MfaChallenge {
            challenge_id,
            method: registration.method(),
            issued_at,
            expires_at,
            reason,
            challenge_payload,
            dev_only_code: None,
        })
    }

    pub fn verify_challenge(
        &self,
        registration: &MfaRegistration,
        challenge: &MfaChallenge,
        verification: &MfaVerification,
    ) -> Result<(), MfaError> {
        if Utc::now() > challenge.expires_at {
            return Err(MfaError::ChallengeExpired);
        }
        if registration.method() != challenge.method {
            return Err(MfaError::RegistrationMismatch);
        }

        match registration {
            MfaRegistration::Totp(registration) => {
                let Some(code) = verification.code.as_deref() else {
                    return Err(MfaError::MissingVerificationInput);
                };
                self.verify_totp(registration, code, challenge.issued_at)
            }
            MfaRegistration::WebAuthn(registration) | MfaRegistration::Biometric(registration) => {
                let Some(assertion) = verification.webauthn_assertion.as_ref() else {
                    return Err(MfaError::MissingVerificationInput);
                };
                self.verify_webauthn(registration, challenge, assertion)
            }
        }
    }

    pub fn bootstrap_totp_code_at(
        &self,
        tenant_id: &str,
        user_id: &str,
        account_name: &str,
        at: DateTime<Utc>,
    ) -> String {
        let secret = self.derive_totp_secret(tenant_id, user_id, account_name);
        generate_totp_code(&secret, at.timestamp(), &self.config.totp)
    }

    pub fn bootstrap_webauthn_assertion(
        &self,
        tenant_id: &str,
        user_id: &str,
        account_name: &str,
        challenge: &MfaChallenge,
    ) -> Result<WebAuthnAssertion, MfaError> {
        let Some(MfaChallengePayload::WebAuthn(options)) = challenge.challenge_payload.as_ref()
        else {
            return Err(MfaError::MalformedChallenge);
        };
        let authenticator_data =
            build_authenticator_data(&options.rp_id, options.user_verification == "required");
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": options.challenge,
            "origin": options.origin,
        });
        let client_data_json =
            serde_json::to_vec(&client_data).map_err(|_| MfaError::MalformedChallenge)?;
        let signature_message = signature_message(&authenticator_data, &client_data_json);
        let signing_key = self.derive_bootstrap_signing_key(tenant_id, user_id, account_name);
        let signature: Signature = signing_key.sign(&signature_message);

        Ok(WebAuthnAssertion {
            credential_id: self.bootstrap_credential_id(tenant_id, user_id, account_name),
            client_data_json: b64_encode(&client_data_json),
            authenticator_data: b64_encode(&authenticator_data),
            signature: b64_encode(signature.to_der().as_bytes()),
        })
    }

    fn verify_totp(
        &self,
        registration: &TotpRegistration,
        code: &str,
        issued_at: DateTime<Utc>,
    ) -> Result<(), MfaError> {
        let secret =
            hex::decode(&registration.secret_hex).map_err(|_| MfaError::MalformedChallenge)?;
        let now = Utc::now().timestamp();
        let issued_at = issued_at.timestamp();
        let lower_bound = issued_at
            - (i64::from(registration.allowed_drift_steps) * registration.period_secs as i64);
        if now < lower_bound {
            return Err(MfaError::InvalidCode);
        }
        for offset in -(i64::from(registration.allowed_drift_steps))
            ..=(i64::from(registration.allowed_drift_steps))
        {
            let timestamp = now + (offset * registration.period_secs as i64);
            let config = TotpProviderConfig {
                issuer: self.config.totp.issuer.clone(),
                period_secs: registration.period_secs,
                digits: registration.digits,
                allowed_drift_steps: registration.allowed_drift_steps,
            };
            if generate_totp_code(&secret, timestamp, &config) == code {
                return Ok(());
            }
        }
        Err(MfaError::InvalidCode)
    }

    fn verify_webauthn(
        &self,
        registration: &WebAuthnRegistration,
        challenge: &MfaChallenge,
        assertion: &WebAuthnAssertion,
    ) -> Result<(), MfaError> {
        let Some(MfaChallengePayload::WebAuthn(options)) = challenge.challenge_payload.as_ref()
        else {
            return Err(MfaError::MalformedChallenge);
        };
        if assertion.credential_id != registration.credential_id {
            return Err(MfaError::InvalidAssertion);
        }
        let client_data_json =
            b64_decode(&assertion.client_data_json).map_err(|_| MfaError::InvalidAssertion)?;
        let authenticator_data =
            b64_decode(&assertion.authenticator_data).map_err(|_| MfaError::InvalidAssertion)?;
        let signature_bytes =
            b64_decode(&assertion.signature).map_err(|_| MfaError::InvalidAssertion)?;
        let signature =
            Signature::from_der(&signature_bytes).map_err(|_| MfaError::InvalidAssertion)?;

        let client_data: WebAuthnClientData =
            serde_json::from_slice(&client_data_json).map_err(|_| MfaError::InvalidAssertion)?;
        if client_data.typ != "webauthn.get"
            || client_data.challenge != options.challenge
            || client_data.origin != registration.origin
        {
            return Err(MfaError::InvalidAssertion);
        }

        if authenticator_data.len() < 37 {
            return Err(MfaError::InvalidAssertion);
        }
        let expected_rp_hash = Sha256::digest(registration.rp_id.as_bytes());
        if authenticator_data[..32] != expected_rp_hash[..] {
            return Err(MfaError::InvalidAssertion);
        }
        let flags = authenticator_data[32];
        if flags & 0x01 == 0 {
            return Err(MfaError::InvalidAssertion);
        }
        if registration.require_user_verification && flags & 0x04 == 0 {
            return Err(MfaError::InvalidAssertion);
        }

        let public_key = VerifyingKey::from_sec1_bytes(
            &b64_decode(&registration.public_key_sec1).map_err(|_| MfaError::InvalidAssertion)?,
        )
        .map_err(|_| MfaError::InvalidAssertion)?;
        public_key
            .verify(
                &signature_message(&authenticator_data, &client_data_json),
                &signature,
            )
            .map_err(|_| MfaError::InvalidAssertion)
    }

    fn derive_totp_secret(&self, tenant_id: &str, user_id: &str, account_name: &str) -> [u8; 20] {
        let digest = Sha256::digest(
            format!(
                "totp:{}:{}:{}:{}",
                self.config.bootstrap_seed, tenant_id, user_id, account_name
            )
            .as_bytes(),
        );
        let mut secret = [0_u8; 20];
        secret.copy_from_slice(&digest[..20]);
        secret
    }

    fn bootstrap_credential_id(
        &self,
        tenant_id: &str,
        user_id: &str,
        account_name: &str,
    ) -> String {
        b64_encode(
            Sha256::digest(
                format!(
                    "credential:{}:{}:{}:{}",
                    self.config.bootstrap_seed, tenant_id, user_id, account_name
                )
                .as_bytes(),
            )
            .as_slice(),
        )
    }

    fn derive_bootstrap_signing_key(
        &self,
        tenant_id: &str,
        user_id: &str,
        account_name: &str,
    ) -> SigningKey {
        for counter in 0_u16..=u16::MAX {
            let digest = Sha256::digest(
                format!(
                    "webauthn:{}:{}:{}:{}:{}",
                    self.config.bootstrap_seed, tenant_id, user_id, account_name, counter
                )
                .as_bytes(),
            );
            if let Ok(key) = SigningKey::from_bytes(&digest) {
                return key;
            }
        }
        panic!("failed to derive bootstrap signing key");
    }
}

#[derive(Debug, Default, Clone)]
pub struct MockMfaService;

impl MockMfaService {
    pub fn begin_challenge(&self, method: MfaMethod) -> MfaChallenge {
        let issued_at = Utc::now();
        let dev_only_code = Some(match method {
            MfaMethod::Totp => "000000",
            MfaMethod::WebAuthn => "webauthn-ok",
            MfaMethod::Biometric => "biometric-ok",
        });

        MfaChallenge {
            challenge_id: Ulid::new().to_string(),
            method,
            issued_at,
            expires_at: issued_at + Duration::minutes(5),
            reason: None,
            challenge_payload: None,
            dev_only_code: dev_only_code.map(str::to_string),
        }
    }

    pub fn verify_challenge(&self, challenge: &MfaChallenge, code: &str) -> bool {
        if Utc::now() > challenge.expires_at {
            return false;
        }

        let Some(expected) = challenge.dev_only_code.as_deref() else {
            return false;
        };

        code == expected || code == "000000"
    }
}

#[derive(Debug, Deserialize)]
struct WebAuthnClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
}

fn generate_totp_code(secret: &[u8], timestamp: i64, config: &TotpProviderConfig) -> String {
    let counter = (timestamp.max(0) as u64) / config.period_secs;
    let counter_bytes = counter.to_be_bytes();
    let mut mac = HmacSha1::new_from_slice(secret).expect("hmac key");
    mac.update(&counter_bytes);
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let otp = binary % 10_u32.pow(config.digits);
    format!("{otp:0width$}", width = config.digits as usize)
}

fn build_authenticator_data(rp_id: &str, user_verification: bool) -> Vec<u8> {
    let mut data = Vec::with_capacity(37);
    data.extend_from_slice(Sha256::digest(rp_id.as_bytes()).as_slice());
    let mut flags = 0x01;
    if user_verification {
        flags |= 0x04;
    }
    data.push(flags);
    data.extend_from_slice(&0_u32.to_be_bytes());
    data
}

fn signature_message(authenticator_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
    let client_digest = Sha256::digest(client_data_json);
    authenticator_data
        .iter()
        .copied()
        .chain(client_digest)
        .collect()
}

fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn b64_decode(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(value)
}

#[cfg(test)]
mod tests {
    use super::{
        MfaMethod, MfaProviderConfig, MfaProviderRegistry, MfaVerification, MockMfaService,
    };
    use chrono::Utc;

    #[test]
    fn webauthn_is_phishing_resistant() {
        assert!(MfaMethod::WebAuthn.is_phishing_resistant());
        assert!(MfaMethod::Biometric.is_phishing_resistant());
        assert!(!MfaMethod::Totp.is_phishing_resistant());
    }

    #[test]
    fn totp_registry_accepts_rfc_style_code() {
        let registry = MfaProviderRegistry::new(MfaProviderConfig::default());
        let registration =
            registry.bootstrap_registration("tenant-a", "user-a", "analyst", &MfaMethod::Totp);
        let challenge = registry
            .begin_challenge(&registration, Some("login".into()))
            .expect("challenge");
        let code = registry.bootstrap_totp_code_at("tenant-a", "user-a", "analyst", Utc::now());
        registry
            .verify_challenge(
                &registration,
                &challenge,
                &MfaVerification {
                    code: Some(code),
                    webauthn_assertion: None,
                },
            )
            .expect("totp verification");
    }

    #[test]
    fn webauthn_registry_verifies_signed_assertion() {
        let registry = MfaProviderRegistry::new(MfaProviderConfig::default());
        let registration =
            registry.bootstrap_registration("tenant-a", "user-a", "sysadmin", &MfaMethod::WebAuthn);
        let challenge = registry
            .begin_challenge(&registration, Some("step-up".into()))
            .expect("challenge");
        let assertion = registry
            .bootstrap_webauthn_assertion("tenant-a", "user-a", "sysadmin", &challenge)
            .expect("assertion");
        registry
            .verify_challenge(
                &registration,
                &challenge,
                &MfaVerification {
                    code: None,
                    webauthn_assertion: Some(assertion),
                },
            )
            .expect("webauthn verification");
    }

    #[test]
    fn dev_mfa_service_accepts_expected_code() {
        let service = MockMfaService;
        let challenge = service.begin_challenge(MfaMethod::WebAuthn);
        assert!(service.verify_challenge(&challenge, "webauthn-ok"));
        assert!(service.verify_challenge(&challenge, "000000"));
    }
}
