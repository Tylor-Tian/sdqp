use std::time::Duration;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use reqwest::{
    Client,
    header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use yasna::models::ObjectIdentifier;

use crate::{EvidenceError, TimestampAuthority, TimestampReceipt};

const RFC3161_QUERY_MEDIA_TYPE: &str = "application/timestamp-query";
const RFC3161_REPLY_MEDIA_TYPE: &str = "application/timestamp-reply";
const SHA256_OID: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
const DEFAULT_POLICY_OID: &str = "1.3.6.1.4.1.55555.1.1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsaProviderConfig {
    pub provider: String,
    pub base_url: String,
    pub api_key: String,
    pub authority: String,
    pub timeout_ms: u64,
    #[serde(default)]
    pub require_external: bool,
}

impl Default for TsaProviderConfig {
    fn default() -> Self {
        Self {
            provider: "mock".into(),
            base_url: String::new(),
            api_key: "phase5-evidence-secret".into(),
            authority: "mock-tsa".into(),
            timeout_ms: 3_000,
            require_external: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rfc3161TimestampQuery {
    pub digest: String,
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rfc3161TimestampToken {
    pub authority: String,
    pub digest: String,
    pub issued_at: DateTime<Utc>,
    pub nonce: u64,
    pub policy_oid: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct Rfc3161TimestampAuthority {
    authority: String,
    api_key: String,
    client: Client,
    base_url: String,
    provider_label: String,
}

impl Rfc3161TimestampAuthority {
    pub fn from_config(config: TsaProviderConfig) -> Result<Self, EvidenceError> {
        Self::from_named_provider(config, "rfc3161")
    }

    pub fn from_named_provider(
        config: TsaProviderConfig,
        provider_label: impl Into<String>,
    ) -> Result<Self, EvidenceError> {
        if config.authority.trim().is_empty() {
            return Err(EvidenceError::ProviderConfiguration(
                "rfc3161 tsa authority is required".into(),
            ));
        }
        if config.base_url.trim().is_empty() {
            return Err(EvidenceError::ProviderConfiguration(
                "rfc3161 tsa base_url is required".into(),
            ));
        }

        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms.max(1)))
            .build()
            .map_err(|error| EvidenceError::ProviderRequest(error.to_string()))?;

        Ok(Self {
            authority: config.authority,
            api_key: config.api_key,
            client,
            base_url: config.base_url,
            provider_label: provider_label.into(),
        })
    }
}

#[async_trait]
impl TimestampAuthority for Rfc3161TimestampAuthority {
    fn authority_name(&self) -> &str {
        &self.authority
    }

    async fn stamp(&self, digest: &str) -> Result<TimestampReceipt, EvidenceError> {
        crate::validate_sha256_digest(digest)?;
        let nonce = rand::random::<u64>();
        let body = build_rfc3161_query(digest, nonce)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(RFC3161_QUERY_MEDIA_TYPE),
        );
        headers.insert(ACCEPT, HeaderValue::from_static(RFC3161_REPLY_MEDIA_TYPE));
        if !self.api_key.is_empty() {
            headers.insert(
                "x-api-key",
                HeaderValue::from_str(&self.api_key)
                    .map_err(|error| EvidenceError::ProviderConfiguration(error.to_string()))?,
            );
        }

        let reply_bytes = self
            .client
            .post(&self.base_url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .and_then(|response| response.error_for_status())
            .map_err(|error| EvidenceError::ProviderRequest(error.to_string()))?
            .bytes()
            .await
            .map_err(|error| EvidenceError::ProviderRequest(error.to_string()))?
            .to_vec();
        let token = parse_rfc3161_reply(&reply_bytes)?;
        if token.digest != digest || token.nonce != nonce {
            return Err(EvidenceError::ProviderProtocol(
                "tsa reply digest/nonce mismatch".into(),
            ));
        }

        Ok(TimestampReceipt {
            authority: token.authority,
            issued_at: token.issued_at,
            digest: digest.to_string(),
            token: STANDARD.encode(reply_bytes),
            provider: Some(self.provider_label.clone()),
            nonce: Some(token.nonce.to_string()),
        })
    }

    async fn verify(
        &self,
        receipt: &TimestampReceipt,
        digest: &str,
    ) -> Result<bool, EvidenceError> {
        if receipt.digest != digest {
            return Ok(false);
        }
        crate::validate_sha256_digest(digest)?;

        let reply = STANDARD
            .decode(receipt.token.as_bytes())
            .map_err(|error| EvidenceError::ProviderProtocol(error.to_string()))?;
        let token = parse_rfc3161_reply(&reply)?;
        let receipt_nonce = receipt
            .nonce
            .as_deref()
            .ok_or_else(|| EvidenceError::ProviderProtocol("missing tsa nonce".into()))?
            .parse::<u64>()
            .map_err(|error| EvidenceError::ProviderProtocol(error.to_string()))?;
        let expected_signature = rfc3161_signature(
            &token.authority,
            &token.digest,
            token.issued_at,
            token.nonce,
            &self.api_key,
        );

        Ok(token.authority == receipt.authority
            && token.digest == digest
            && token.nonce == receipt_nonce
            && token.signature == expected_signature)
    }
}

#[derive(Debug, Clone)]
pub struct InternalHsmTimestampAuthority {
    authority: String,
    secret: String,
}

impl InternalHsmTimestampAuthority {
    pub fn from_config(config: TsaProviderConfig) -> Self {
        Self {
            authority: if config.authority.trim().is_empty() {
                "internal-hsm".into()
            } else {
                config.authority
            },
            secret: if config.api_key.trim().is_empty() {
                "phase5-evidence-secret".into()
            } else {
                config.api_key
            },
        }
    }
}

#[async_trait]
impl TimestampAuthority for InternalHsmTimestampAuthority {
    fn authority_name(&self) -> &str {
        &self.authority
    }

    async fn stamp(&self, digest: &str) -> Result<TimestampReceipt, EvidenceError> {
        crate::validate_sha256_digest(digest)?;
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
            provider: Some("internal-hsm".into()),
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
        crate::validate_sha256_digest(digest)?;

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

pub fn build_rfc3161_query(digest: &str, nonce: u64) -> Result<Vec<u8>, EvidenceError> {
    crate::validate_sha256_digest(digest)?;
    let digest_bytes =
        hex::decode(digest).map_err(|error| EvidenceError::ProviderProtocol(error.to_string()))?;
    let oid = ObjectIdentifier::from_slice(SHA256_OID);

    Ok(yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_i64(1);
            writer.next().write_sequence(|writer| {
                writer.next().write_sequence(|writer| {
                    writer.next().write_oid(&oid);
                    writer.next().write_null();
                });
                writer.next().write_bytes(&digest_bytes);
            });
            writer.next().write_u64(nonce);
            writer.next().write_bool(true);
        });
    }))
}

pub fn parse_rfc3161_query(bytes: &[u8]) -> Result<Rfc3161TimestampQuery, EvidenceError> {
    yasna::parse_der(bytes, |reader| {
        reader.read_sequence(|reader| {
            let _version = reader.next().read_i64()?;
            let digest = reader.next().read_sequence(|reader| {
                reader.next().read_sequence(|reader| {
                    let _oid = reader.next().read_oid()?;
                    reader.next().read_null()?;
                    Ok(())
                })?;
                let digest_bytes = reader.next().read_bytes()?;
                Ok(hex::encode(digest_bytes))
            })?;
            let nonce = reader.next().read_u64()?;
            let _cert_req = reader.next().read_bool()?;
            Ok(Rfc3161TimestampQuery { digest, nonce })
        })
    })
    .map_err(|error| EvidenceError::ProviderProtocol(error.to_string()))
}

pub fn build_rfc3161_reply(
    query: &Rfc3161TimestampQuery,
    authority: &str,
    api_key: &str,
) -> Result<Vec<u8>, EvidenceError> {
    let issued_at = Utc::now();
    let signature = rfc3161_signature(authority, &query.digest, issued_at, query.nonce, api_key);
    let token = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_utf8_string(authority);
            writer.next().write_utf8_string(&query.digest);
            writer.next().write_utf8_string(&issued_at.to_rfc3339());
            writer.next().write_u64(query.nonce);
            writer.next().write_utf8_string(DEFAULT_POLICY_OID);
            writer
                .next()
                .write_bytes(&hex::decode(signature).expect("signature hex"));
        });
    });

    Ok(yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                writer.next().write_i64(0);
            });
            writer.next().write_bytes(&token);
        });
    }))
}

pub fn parse_rfc3161_reply(bytes: &[u8]) -> Result<Rfc3161TimestampToken, EvidenceError> {
    yasna::parse_der(bytes, |reader| {
        reader.read_sequence(|reader| {
            reader.next().read_sequence(|reader| {
                let _status = reader.next().read_i64()?;
                Ok(())
            })?;
            let token = reader.next().read_bytes()?;
            yasna::parse_der(&token, |reader| {
                reader.read_sequence(|reader| {
                    let authority = reader.next().read_utf8string()?;
                    let digest = reader.next().read_utf8string()?;
                    let issued_at = DateTime::parse_from_rfc3339(&reader.next().read_utf8string()?)
                        .map(|value| value.with_timezone(&Utc))
                        .map_err(|_error| yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid))?;
                    let nonce = reader.next().read_u64()?;
                    let policy_oid = reader.next().read_utf8string()?;
                    let signature = hex::encode(reader.next().read_bytes()?);

                    Ok(Rfc3161TimestampToken {
                        authority,
                        digest,
                        issued_at,
                        nonce,
                        policy_oid,
                        signature,
                    })
                })
            })
        })
    })
    .map_err(|error| EvidenceError::ProviderProtocol(error.to_string()))
}

pub fn rfc3161_signature(
    authority: &str,
    digest: &str,
    issued_at: DateTime<Utc>,
    nonce: u64,
    api_key: &str,
) -> String {
    hex::encode(Sha256::digest(
        format!(
            "{authority}|{digest}|{}|{nonce}|{api_key}",
            issued_at.to_rfc3339()
        )
        .as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        build_rfc3161_query, build_rfc3161_reply, parse_rfc3161_query, parse_rfc3161_reply,
    };

    #[test]
    fn rfc3161_round_trip_keeps_digest_and_nonce() {
        let query_bytes = build_rfc3161_query(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            42,
        )
        .expect("query");
        let query = parse_rfc3161_query(&query_bytes).expect("parsed query");
        let reply_bytes = build_rfc3161_reply(&query, "tsa.local", "secret").expect("reply");
        let reply = parse_rfc3161_reply(&reply_bytes).expect("parsed reply");

        assert_eq!(
            query.digest,
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        );
        assert_eq!(reply.digest, query.digest);
        assert_eq!(reply.nonce, 42);
        assert_eq!(reply.authority, "tsa.local");
    }
}
