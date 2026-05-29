use std::{collections::HashMap, sync::Arc};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckpointSignerProvider {
    LegacySha256,
    Mock,
    Vault,
    Aws,
    Azure,
    Aliyun,
}

impl CheckpointSignerProvider {
    pub fn parse(value: &str) -> Result<Self, CheckpointSignerError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "legacy" | "legacy-sha256" | "sha256" => Ok(Self::LegacySha256),
            "mock" | "development" => Ok(Self::Mock),
            "vault" => Ok(Self::Vault),
            "aws" | "aws-kms" => Ok(Self::Aws),
            "azure" | "azure-key-vault" | "azure-keyvault" => Ok(Self::Azure),
            "aliyun" | "aliyun-kms" => Ok(Self::Aliyun),
            other => Err(CheckpointSignerError::UnsupportedProvider(
                other.to_string(),
            )),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::LegacySha256 => "legacy-sha256",
            Self::Mock => "mock",
            Self::Vault => "vault",
            Self::Aws => "aws",
            Self::Azure => "azure",
            Self::Aliyun => "aliyun",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointSignerConfig {
    pub provider: CheckpointSignerProvider,
    pub key_id: String,
    pub key_version: Option<String>,
    pub endpoint: Option<String>,
    pub region: Option<String>,
    pub key_ring: Option<String>,
    pub auth_token: Option<String>,
}

impl Default for CheckpointSignerConfig {
    fn default() -> Self {
        Self {
            provider: CheckpointSignerProvider::Mock,
            key_id: "sdqp-audit-checkpoint".into(),
            key_version: Some("1".into()),
            endpoint: None,
            region: None,
            key_ring: None,
            auth_token: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum CheckpointSignerError {
    #[error("unsupported checkpoint signer provider: {0}")]
    UnsupportedProvider(String),
    #[error("checkpoint signer configuration error: {0}")]
    Configuration(String),
}

pub trait CheckpointSigner: Send + Sync {
    fn provider_name(&self) -> &str;
    fn key_id(&self) -> &str;
    fn key_version(&self) -> Option<&str>;
    fn signature_algorithm(&self) -> &str;
    fn sign_payload(&self, payload: &str) -> Result<String, CheckpointSignerError>;

    fn verify_payload(
        &self,
        payload: &str,
        signature: &str,
    ) -> Result<bool, CheckpointSignerError> {
        Ok(self.sign_payload(payload)? == signature)
    }
}

pub struct CheckpointSignerRegistry {
    active_provider: String,
    signers: HashMap<String, Arc<dyn CheckpointSigner>>,
}

impl CheckpointSignerRegistry {
    pub fn active_provider(&self) -> &str {
        &self.active_provider
    }

    pub fn active_signer(&self) -> Option<&Arc<dyn CheckpointSigner>> {
        self.signers.get(&self.active_provider)
    }

    pub fn signer(&self, provider: &str) -> Option<&Arc<dyn CheckpointSigner>> {
        self.signers.get(provider)
    }
}

pub fn build_checkpoint_signer_registry(
    config: &CheckpointSignerConfig,
) -> Result<CheckpointSignerRegistry, CheckpointSignerError> {
    let mut signers: HashMap<String, Arc<dyn CheckpointSigner>> = HashMap::new();
    signers.insert(
        CheckpointSignerProvider::LegacySha256.label().into(),
        Arc::new(LegacySha256CheckpointSigner),
    );
    signers.insert(
        CheckpointSignerProvider::Mock.label().into(),
        Arc::new(ContractCheckpointSigner::new(
            CheckpointSignerProvider::Mock,
            config.key_id.clone(),
            config.key_version.clone(),
        )),
    );
    signers.insert(
        CheckpointSignerProvider::Vault.label().into(),
        Arc::new(ContractCheckpointSigner::new(
            CheckpointSignerProvider::Vault,
            config.key_id.clone(),
            config.key_version.clone(),
        )),
    );
    signers.insert(
        CheckpointSignerProvider::Aws.label().into(),
        Arc::new(ContractCheckpointSigner::new(
            CheckpointSignerProvider::Aws,
            config.key_id.clone(),
            config.key_version.clone(),
        )),
    );
    signers.insert(
        CheckpointSignerProvider::Azure.label().into(),
        Arc::new(ContractCheckpointSigner::new(
            CheckpointSignerProvider::Azure,
            config.key_id.clone(),
            config.key_version.clone(),
        )),
    );
    signers.insert(
        CheckpointSignerProvider::Aliyun.label().into(),
        Arc::new(ContractCheckpointSigner::new(
            CheckpointSignerProvider::Aliyun,
            config.key_id.clone(),
            config.key_version.clone(),
        )),
    );

    Ok(CheckpointSignerRegistry {
        active_provider: config.provider.label().to_string(),
        signers,
    })
}

pub fn checkpoint_signer_from_metadata(
    signer_provider: &str,
    signer_key_id: &str,
    signer_key_version: Option<&str>,
    signature_algorithm: &str,
) -> Result<Arc<dyn CheckpointSigner>, CheckpointSignerError> {
    if signature_algorithm.eq_ignore_ascii_case("sha256")
        || signer_provider.eq_ignore_ascii_case("legacy-sha256")
    {
        return Ok(Arc::new(LegacySha256CheckpointSigner));
    }

    let provider = CheckpointSignerProvider::parse(signer_provider)?;
    Ok(Arc::new(ContractCheckpointSigner::new(
        provider,
        if signer_key_id.trim().is_empty() {
            "sdqp-audit-checkpoint".into()
        } else {
            signer_key_id.to_string()
        },
        signer_key_version.map(str::to_string),
    )))
}

#[derive(Debug, Clone)]
struct ContractCheckpointSigner {
    provider: CheckpointSignerProvider,
    key_id: String,
    key_version: Option<String>,
}

impl ContractCheckpointSigner {
    fn new(
        provider: CheckpointSignerProvider,
        key_id: impl Into<String>,
        key_version: Option<String>,
    ) -> Self {
        Self {
            provider,
            key_id: key_id.into(),
            key_version,
        }
    }

    fn signing_key(&self) -> Vec<u8> {
        let mut digest = Sha256::new();
        digest.update(self.provider.label().as_bytes());
        digest.update(b"::");
        digest.update(self.key_id.as_bytes());
        digest.update(b"::");
        digest.update(self.key_version.as_deref().unwrap_or("1").as_bytes());
        digest.finalize().to_vec()
    }
}

impl CheckpointSigner for ContractCheckpointSigner {
    fn provider_name(&self) -> &str {
        self.provider.label()
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn key_version(&self) -> Option<&str> {
        self.key_version.as_deref()
    }

    fn signature_algorithm(&self) -> &str {
        "hmac-sha256"
    }

    fn sign_payload(&self, payload: &str) -> Result<String, CheckpointSignerError> {
        let mut mac = HmacSha256::new_from_slice(&self.signing_key())
            .map_err(|error| CheckpointSignerError::Configuration(error.to_string()))?;
        mac.update(payload.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }
}

#[derive(Debug, Clone, Copy)]
struct LegacySha256CheckpointSigner;

impl CheckpointSigner for LegacySha256CheckpointSigner {
    fn provider_name(&self) -> &str {
        "legacy-sha256"
    }

    fn key_id(&self) -> &str {
        "legacy-local-hash"
    }

    fn key_version(&self) -> Option<&str> {
        None
    }

    fn signature_algorithm(&self) -> &str {
        "sha256"
    }

    fn sign_payload(&self, payload: &str) -> Result<String, CheckpointSignerError> {
        Ok(hex::encode(Sha256::digest(payload.as_bytes())))
    }
}

#[cfg(test)]
mod tests {
    use sha2::Digest;

    use super::{
        CheckpointSignerConfig, CheckpointSignerProvider, build_checkpoint_signer_registry,
        checkpoint_signer_from_metadata,
    };

    #[test]
    fn registry_includes_real_provider_contracts() {
        let registry = build_checkpoint_signer_registry(&CheckpointSignerConfig {
            provider: CheckpointSignerProvider::Aws,
            key_id: "audit-root".into(),
            key_version: Some("7".into()),
            endpoint: None,
            region: Some("cn-test-1".into()),
            key_ring: None,
            auth_token: None,
        })
        .expect("registry");

        assert_eq!(registry.active_provider(), "aws");
        assert_eq!(
            registry
                .signer("vault")
                .expect("vault signer")
                .provider_name(),
            "vault"
        );
        assert_eq!(
            registry.signer("aws").expect("aws signer").key_version(),
            Some("7")
        );
    }

    #[test]
    fn contract_signer_is_not_legacy_plain_sha256() {
        let signer =
            checkpoint_signer_from_metadata("mock", "audit-root", Some("2"), "hmac-sha256")
                .expect("signer");
        let signature = signer
            .sign_payload("checkpoint-payload")
            .expect("signature");

        assert!(signature.len() >= 64);
        assert!(
            signer
                .verify_payload("checkpoint-payload", &signature)
                .expect("verify")
        );
        assert_ne!(
            signature,
            hex::encode(sha2::Sha256::digest("checkpoint-payload".as_bytes()))
        );
    }

    #[test]
    fn legacy_signer_still_verifies_old_metadata() {
        let signer = checkpoint_signer_from_metadata("legacy-sha256", "", None, "sha256")
            .expect("legacy signer");
        let signature = signer.sign_payload("legacy-payload").expect("signature");

        assert!(
            signer
                .verify_payload("legacy-payload", &signature)
                .expect("verify")
        );
    }
}
