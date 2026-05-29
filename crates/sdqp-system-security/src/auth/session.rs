use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use ulid::Ulid;

use sdqp_core::RequestContext;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedAuthenticationSource {
    LocalPassword,
    Oidc,
    Saml,
    Scim,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBinding {
    pub ip_address: String,
    pub device_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionClaims {
    pub session_id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub binding: SessionBinding,
}

impl SessionClaims {
    pub fn is_bound_to(&self, ip_address: &str, device_fingerprint: &str) -> bool {
        self.binding.ip_address == ip_address
            && self.binding.device_fingerprint == device_fingerprint
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPolicy {
    pub ttl_minutes: i64,
}

impl SessionPolicy {
    pub fn issue(&self, request: &RequestContext, binding: SessionBinding) -> SessionClaims {
        let issued_at = Utc::now();
        SessionClaims {
            session_id: Ulid::new().to_string(),
            user_id: request.user_id.as_str().to_string(),
            tenant_id: request.tenant_id.as_str().to_string(),
            issued_at,
            expires_at: issued_at + Duration::minutes(self.ttl_minutes),
            binding,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("token format is invalid")]
    InvalidToken,
    #[error("token signature is invalid")]
    InvalidSignature,
    #[error("token payload is invalid")]
    InvalidPayload,
    #[error("refresh token does not match active token")]
    RefreshTokenMismatch,
}

pub fn issue_access_token(claims: &SessionClaims, secret: &str) -> Result<String, AuthError> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = serde_json::to_vec(claims).map_err(|_| AuthError::InvalidPayload)?;
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{header}.{payload}");
    let signature = sign_token(&signing_input, secret);
    Ok(format!("{signing_input}.{signature}"))
}

pub fn parse_access_token(token: &str, secret: &str) -> Result<SessionClaims, AuthError> {
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(AuthError::InvalidToken);
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    if sign_token(&signing_input, secret) != parts[2] {
        return Err(AuthError::InvalidSignature);
    }

    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AuthError::InvalidPayload)?;
    serde_json::from_slice(&payload).map_err(|_| AuthError::InvalidPayload)
}

pub fn issue_refresh_token() -> String {
    Ulid::new().to_string()
}

pub fn rotate_refresh_token(current: &str, active: &str) -> Result<String, AuthError> {
    if current != active {
        return Err(AuthError::RefreshTokenMismatch);
    }

    Ok(issue_refresh_token())
}

pub fn refresh_token_fingerprint(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn sign_token(payload: &str, secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hasher.update(secret.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::{
        AuthError, SessionBinding, SessionPolicy, issue_access_token, issue_refresh_token,
        parse_access_token, refresh_token_fingerprint, rotate_refresh_token,
    };
    use sdqp_core::{RequestContext, TenantId, UserId};

    #[test]
    fn session_policy_issues_bound_claims() {
        let request = RequestContext::new(
            TenantId::new("tenant-a").expect("tenant"),
            UserId::new("user-a").expect("user"),
        );
        let claims = SessionPolicy { ttl_minutes: 15 }.issue(
            &request,
            SessionBinding {
                ip_address: "127.0.0.1".into(),
                device_fingerprint: "device-a".into(),
            },
        );

        assert!(claims.is_bound_to("127.0.0.1", "device-a"));
        assert!(!claims.is_expired_at(Utc::now()));
        assert!(!claims.session_id.is_empty());
    }

    #[test]
    fn access_token_round_trip_succeeds() {
        let request = RequestContext::new(
            TenantId::new("tenant-a").expect("tenant"),
            UserId::new("user-a").expect("user"),
        );
        let claims = SessionPolicy { ttl_minutes: 15 }.issue(
            &request,
            SessionBinding {
                ip_address: "127.0.0.1".into(),
                device_fingerprint: "device-a".into(),
            },
        );

        let token = issue_access_token(&claims, "secret").expect("token");
        let parsed = parse_access_token(&token, "secret").expect("parsed");

        assert_eq!(parsed.session_id, claims.session_id);
        assert_eq!(parsed.user_id, claims.user_id);
    }

    #[test]
    fn refresh_token_rotation_rejects_mismatch() {
        let current = issue_refresh_token();
        assert_eq!(
            rotate_refresh_token("wrong", &current),
            Err(AuthError::RefreshTokenMismatch)
        );
    }

    #[test]
    fn refresh_token_fingerprint_is_stable() {
        assert_eq!(
            refresh_token_fingerprint("refresh-a"),
            refresh_token_fingerprint("refresh-a")
        );
    }
}
