use std::{collections::HashMap, sync::Arc};

use aes_gcm_siv::{
    Aes256GcmSiv, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::kms::{KmsError, KmsService};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub ciphertext_b64: String,
    pub dek_id: String,
    pub wrapped_dek_b64: String,
    pub kek_id: String,
    pub kms_provider: String,
    pub algorithm: String,
    pub nonce_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_version: Option<String>,
}

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("ciphertext is invalid")]
    InvalidCiphertext,
    #[error("nonce is invalid")]
    InvalidNonce,
    #[error("unknown kms provider: {0}")]
    UnknownKmsProvider(String),
    #[error("unsupported envelope algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("kms failure: {0}")]
    Kms(#[from] KmsError),
}

pub trait EnvelopeCipher: Send + Sync {
    fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedPayload, EncryptionError>;
    fn decrypt(&self, payload: &EncryptedPayload) -> Result<Vec<u8>, EncryptionError>;
    fn rewrap(&self, payload: &EncryptedPayload) -> Result<EncryptedPayload, EncryptionError> {
        Ok(payload.clone())
    }
}

impl<T> EnvelopeCipher for Arc<T>
where
    T: EnvelopeCipher + ?Sized,
{
    fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedPayload, EncryptionError> {
        self.as_ref().encrypt(plaintext)
    }

    fn decrypt(&self, payload: &EncryptedPayload) -> Result<Vec<u8>, EncryptionError> {
        self.as_ref().decrypt(payload)
    }

    fn rewrap(&self, payload: &EncryptedPayload) -> Result<EncryptedPayload, EncryptionError> {
        self.as_ref().rewrap(payload)
    }
}

#[derive(Debug, Clone)]
pub struct DevelopmentEnvelopeCipher {
    dek_id: String,
    key_byte: u8,
}

impl DevelopmentEnvelopeCipher {
    pub fn new(dek_id: impl Into<String>, key_byte: u8) -> Self {
        Self {
            dek_id: dek_id.into(),
            key_byte,
        }
    }
}

impl EnvelopeCipher for DevelopmentEnvelopeCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedPayload, EncryptionError> {
        let masked = plaintext
            .iter()
            .map(|byte| byte ^ self.key_byte)
            .collect::<Vec<_>>();

        Ok(EncryptedPayload {
            ciphertext_b64: STANDARD.encode(masked),
            dek_id: self.dek_id.clone(),
            wrapped_dek_b64: STANDARD.encode(vec![self.key_byte; 32]),
            kek_id: "development-kek".into(),
            kms_provider: "development".into(),
            algorithm: "xor-dev".into(),
            nonce_b64: String::new(),
            key_version: None,
        })
    }

    fn decrypt(&self, payload: &EncryptedPayload) -> Result<Vec<u8>, EncryptionError> {
        if !payload.algorithm.is_empty() && payload.algorithm != "xor-dev" {
            return Err(EncryptionError::UnsupportedAlgorithm(
                payload.algorithm.clone(),
            ));
        }

        let decoded = STANDARD
            .decode(payload.ciphertext_b64.as_bytes())
            .map_err(|_| EncryptionError::InvalidCiphertext)?;
        Ok(decoded
            .into_iter()
            .map(|byte| byte ^ self.key_byte)
            .collect::<Vec<_>>())
    }
}

#[derive(Debug, Clone)]
pub struct KmsEnvelopeCipher<K> {
    kms: K,
}

impl<K> KmsEnvelopeCipher<K> {
    pub fn new(kms: K) -> Self {
        Self { kms }
    }
}

pub struct ProviderEnvelopeCipher {
    active_provider: String,
    services: HashMap<String, Arc<dyn KmsService>>,
}

impl ProviderEnvelopeCipher {
    pub fn new(
        active_provider: impl Into<String>,
        services: HashMap<String, Arc<dyn KmsService>>,
    ) -> Self {
        Self {
            active_provider: active_provider.into(),
            services,
        }
    }

    fn active_service(&self) -> Result<&Arc<dyn KmsService>, EncryptionError> {
        self.service_for_provider(&self.active_provider)
    }

    fn service_for_provider(
        &self,
        provider: &str,
    ) -> Result<&Arc<dyn KmsService>, EncryptionError> {
        self.services
            .get(provider)
            .ok_or_else(|| EncryptionError::UnknownKmsProvider(provider.to_string()))
    }

    fn encrypt_with_service(
        &self,
        kms: &dyn KmsService,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, EncryptionError> {
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let material = kms.generate_data_key()?;
        let cipher = Aes256GcmSiv::new_from_slice(material.plaintext.as_slice())
            .map_err(|_| EncryptionError::InvalidCiphertext)?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| EncryptionError::InvalidCiphertext)?;

        Ok(EncryptedPayload {
            ciphertext_b64: STANDARD.encode(ciphertext),
            dek_id: material.dek_id,
            wrapped_dek_b64: material.wrapped_dek,
            kek_id: material.kek_id,
            kms_provider: kms.provider_name().into(),
            algorithm: "aes-256-gcm-siv".into(),
            nonce_b64: STANDARD.encode(nonce),
            key_version: material.key_version,
        })
    }
}

impl<K> EnvelopeCipher for KmsEnvelopeCipher<K>
where
    K: KmsService,
{
    fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedPayload, EncryptionError> {
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let material = self.kms.generate_data_key()?;
        let cipher = Aes256GcmSiv::new_from_slice(material.plaintext.as_slice())
            .map_err(|_| EncryptionError::InvalidCiphertext)?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| EncryptionError::InvalidCiphertext)?;

        Ok(EncryptedPayload {
            ciphertext_b64: STANDARD.encode(ciphertext),
            dek_id: material.dek_id,
            wrapped_dek_b64: material.wrapped_dek,
            kek_id: material.kek_id,
            kms_provider: self.kms.provider_name().into(),
            algorithm: "aes-256-gcm-siv".into(),
            nonce_b64: STANDARD.encode(nonce),
            key_version: material.key_version,
        })
    }

    fn decrypt(&self, payload: &EncryptedPayload) -> Result<Vec<u8>, EncryptionError> {
        match payload.algorithm.as_str() {
            "aes-256-gcm-siv" => {}
            other => {
                return Err(EncryptionError::UnsupportedAlgorithm(other.to_string()));
            }
        }

        let nonce = STANDARD
            .decode(payload.nonce_b64.as_bytes())
            .map_err(|_| EncryptionError::InvalidNonce)?;
        let ciphertext = STANDARD
            .decode(payload.ciphertext_b64.as_bytes())
            .map_err(|_| EncryptionError::InvalidCiphertext)?;
        let dek = self
            .kms
            .unwrap_data_key(&payload.wrapped_dek_b64, &payload.dek_id)?;
        let cipher = Aes256GcmSiv::new_from_slice(dek.as_slice())
            .map_err(|_| EncryptionError::InvalidCiphertext)?;

        cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| EncryptionError::InvalidCiphertext)
    }

    fn rewrap(&self, payload: &EncryptedPayload) -> Result<EncryptedPayload, EncryptionError> {
        let wrap = self
            .kms
            .rewrap_data_key(&payload.wrapped_dek_b64, &payload.dek_id)?;
        Ok(EncryptedPayload {
            wrapped_dek_b64: wrap.wrapped_dek,
            kek_id: wrap.kek_id,
            key_version: wrap.key_version,
            ..payload.clone()
        })
    }
}

impl EnvelopeCipher for ProviderEnvelopeCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedPayload, EncryptionError> {
        self.encrypt_with_service(self.active_service()?.as_ref(), plaintext)
    }

    fn decrypt(&self, payload: &EncryptedPayload) -> Result<Vec<u8>, EncryptionError> {
        match payload.algorithm.as_str() {
            "aes-256-gcm-siv" => {}
            other => {
                return Err(EncryptionError::UnsupportedAlgorithm(other.to_string()));
            }
        }

        let nonce = STANDARD
            .decode(payload.nonce_b64.as_bytes())
            .map_err(|_| EncryptionError::InvalidNonce)?;
        let ciphertext = STANDARD
            .decode(payload.ciphertext_b64.as_bytes())
            .map_err(|_| EncryptionError::InvalidCiphertext)?;
        let kms = self.service_for_provider(&payload.kms_provider)?;
        let dek = kms.unwrap_data_key(&payload.wrapped_dek_b64, &payload.dek_id)?;
        let cipher = Aes256GcmSiv::new_from_slice(dek.as_slice())
            .map_err(|_| EncryptionError::InvalidCiphertext)?;

        cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| EncryptionError::InvalidCiphertext)
    }

    fn rewrap(&self, payload: &EncryptedPayload) -> Result<EncryptedPayload, EncryptionError> {
        let source = self.service_for_provider(&payload.kms_provider)?;
        let target = self.active_service()?;
        let wrap = if source.provider_name() == target.provider_name() {
            target.rewrap_data_key(&payload.wrapped_dek_b64, &payload.dek_id)?
        } else {
            let dek = source.unwrap_data_key(&payload.wrapped_dek_b64, &payload.dek_id)?;
            target.wrap_data_key(dek.as_slice(), &payload.dek_id)?
        };

        Ok(EncryptedPayload {
            wrapped_dek_b64: wrap.wrapped_dek,
            kek_id: wrap.kek_id,
            kms_provider: target.provider_name().into(),
            key_version: wrap.key_version,
            ..payload.clone()
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use crate::{
        KmsEnvelopeCipher, MockKmsService, ProviderEnvelopeCipher, VaultContractKmsService,
    };

    use super::{DevelopmentEnvelopeCipher, EnvelopeCipher};

    #[test]
    fn development_cipher_round_trip_succeeds() {
        let cipher = DevelopmentEnvelopeCipher::new("dek-project-alpha", 0x5A);
        let encrypted = cipher.encrypt(b"phase2").expect("encrypted");
        let decrypted = cipher.decrypt(&encrypted).expect("decrypted");

        assert_eq!(decrypted, b"phase2");
        assert_eq!(encrypted.dek_id, "dek-project-alpha");
    }

    #[test]
    fn kms_cipher_round_trip_and_rewrap_succeeds() {
        let kms = MockKmsService::new("master-key", "ring-a", 1);
        let cipher = KmsEnvelopeCipher::new(kms.clone());
        let encrypted = cipher.encrypt(b"snapshot").expect("encrypted");
        let decrypted = cipher.decrypt(&encrypted).expect("decrypted");
        assert_eq!(decrypted, b"snapshot");
        assert_eq!(encrypted.algorithm, "aes-256-gcm-siv");

        let mut rotated_kms = kms.clone();
        rotated_kms.rotate();
        let rotated_cipher = KmsEnvelopeCipher::new(rotated_kms);
        let rewrapped = rotated_cipher.rewrap(&encrypted).expect("rewrapped");
        let decrypted = rotated_cipher.decrypt(&rewrapped).expect("decrypted");
        assert_eq!(decrypted, b"snapshot");
        assert_ne!(rewrapped.wrapped_dek_b64, encrypted.wrapped_dek_b64);
    }

    #[test]
    fn provider_cipher_can_rewrap_across_kms_providers() {
        let mock: Arc<dyn crate::KmsService> =
            Arc::new(MockKmsService::new("master-key", "ring-a", 1));
        let vault: Arc<dyn crate::KmsService> = Arc::new(VaultContractKmsService::new(
            "https://vault.example.internal",
            "transit-key",
            3,
        ));
        let services = HashMap::from([
            ("mock".to_string(), mock.clone()),
            ("vault".to_string(), vault.clone()),
        ]);

        let mock_cipher = ProviderEnvelopeCipher::new("mock", services.clone());
        let encrypted = mock_cipher.encrypt(b"snapshot").expect("encrypted");
        assert_eq!(encrypted.kms_provider, "mock");

        let vault_cipher = ProviderEnvelopeCipher::new("vault", services);
        let rewrapped = vault_cipher.rewrap(&encrypted).expect("rewrapped");
        let decrypted = vault_cipher.decrypt(&rewrapped).expect("decrypted");

        assert_eq!(rewrapped.kms_provider, "vault");
        assert_eq!(rewrapped.key_version.as_deref(), Some("3"));
        assert_ne!(rewrapped.wrapped_dek_b64, encrypted.wrapped_dek_b64);
        assert_eq!(decrypted, b"snapshot");
    }
}
