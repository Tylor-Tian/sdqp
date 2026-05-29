use std::{collections::HashMap, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::{RngCore, rngs::OsRng};
use reqwest::blocking::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use ulid::Ulid;
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct DataKeyMaterial {
    pub dek_id: String,
    pub plaintext: Zeroizing<Vec<u8>>,
    pub wrapped_dek: String,
    pub kek_id: String,
    pub key_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataKeyWrap {
    pub wrapped_dek: String,
    pub kek_id: String,
    pub key_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KmsProvider {
    Mock,
    Vault,
    Aws,
    Azure,
    Aliyun,
}

impl KmsProvider {
    pub fn parse(value: &str) -> Result<Self, KmsError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "mock" | "development" => Ok(Self::Mock),
            "vault" => Ok(Self::Vault),
            "aws" | "aws-kms" => Ok(Self::Aws),
            "azure" | "azure-key-vault" | "azure-keyvault" => Ok(Self::Azure),
            "aliyun" | "aliyun-kms" => Ok(Self::Aliyun),
            other => Err(KmsError::UnsupportedProvider(other.to_string())),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Vault => "vault",
            Self::Aws => "aws",
            Self::Azure => "azure",
            Self::Aliyun => "aliyun",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsClientConfig {
    pub provider: KmsProvider,
    pub endpoint: Option<String>,
    pub master_key_id: String,
    pub key_ring: Option<String>,
    pub auth_token: Option<String>,
    pub region: Option<String>,
    pub key_version: Option<String>,
}

impl KmsClientConfig {
    fn parsed_key_version(&self) -> u32 {
        self.key_version
            .as_deref()
            .and_then(|value| value.trim().parse::<u32>().ok())
            .filter(|version| *version >= 1)
            .unwrap_or(1)
    }
}

#[derive(Debug, Error)]
pub enum KmsError {
    #[error("wrapped data key is invalid")]
    InvalidWrappedKey,
    #[error("generated data key length is invalid")]
    InvalidDataKeyLength,
    #[error("unsupported kms provider: {0}")]
    UnsupportedProvider(String),
    #[error("vault transport failed: {0}")]
    VaultTransport(#[from] reqwest::Error),
    #[error("vault response is invalid")]
    InvalidVaultResponse,
}

pub trait KmsService: Send + Sync {
    fn provider_name(&self) -> &str;
    fn master_key_id(&self) -> &str;

    fn generate_data_key(&self) -> Result<DataKeyMaterial, KmsError> {
        let dek_id = Ulid::new().to_string();
        let mut dek = vec![0_u8; 32];
        OsRng.fill_bytes(&mut dek);
        let wrap = self.wrap_data_key(dek.as_slice(), &dek_id)?;
        Ok(DataKeyMaterial {
            dek_id,
            plaintext: Zeroizing::new(dek),
            wrapped_dek: wrap.wrapped_dek,
            kek_id: wrap.kek_id,
            key_version: wrap.key_version,
        })
    }

    fn wrap_data_key(&self, plaintext: &[u8], dek_id: &str) -> Result<DataKeyWrap, KmsError>;

    fn unwrap_data_key(
        &self,
        wrapped_dek: &str,
        dek_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, KmsError>;

    fn rewrap_data_key(&self, wrapped_dek: &str, dek_id: &str) -> Result<DataKeyWrap, KmsError> {
        let plaintext = self.unwrap_data_key(wrapped_dek, dek_id)?;
        self.wrap_data_key(plaintext.as_slice(), dek_id)
    }

    fn current_key_version(&self) -> Option<String>;
}

pub struct KmsServiceRegistry {
    active_provider: String,
    services: HashMap<String, Arc<dyn KmsService>>,
}

impl KmsServiceRegistry {
    pub fn active_provider(&self) -> &str {
        &self.active_provider
    }

    pub fn service(&self, provider: &str) -> Option<&Arc<dyn KmsService>> {
        self.services.get(provider)
    }

    pub fn into_parts(self) -> (String, HashMap<String, Arc<dyn KmsService>>) {
        (self.active_provider, self.services)
    }
}

pub fn build_kms_service_registry(
    config: &KmsClientConfig,
) -> Result<KmsServiceRegistry, KmsError> {
    let mut services: HashMap<String, Arc<dyn KmsService>> = HashMap::new();

    let mock: Arc<dyn KmsService> = Arc::new(MockKmsService::new(
        config.master_key_id.clone(),
        config
            .key_ring
            .clone()
            .unwrap_or_else(|| "sdqp-default-ring".into()),
        config.parsed_key_version(),
    ));
    services.insert("mock".into(), mock.clone());
    services.insert("development".into(), mock);

    let vault: Arc<dyn KmsService> =
        if config.provider == KmsProvider::Vault && has_value(config.auth_token.as_deref()) {
            Arc::new(VaultTransitKmsService::new(
                config.endpoint.clone().unwrap_or_default(),
                config.auth_token.clone().unwrap_or_default(),
                config.master_key_id.clone(),
            ))
        } else {
            Arc::new(VaultContractKmsService::new(
                config.endpoint.clone().unwrap_or_default(),
                config.master_key_id.clone(),
                config.parsed_key_version(),
            ))
        };
    services.insert("vault".into(), vault);

    let aws: Arc<dyn KmsService> = Arc::new(AwsKmsService::new(
        config.region.clone().unwrap_or_else(|| "local".into()),
        config.endpoint.clone().unwrap_or_default(),
        config.master_key_id.clone(),
        config.parsed_key_version(),
    ));
    services.insert("aws".into(), aws);

    let azure: Arc<dyn KmsService> = Arc::new(AzureKeyVaultKmsService::new(
        config.endpoint.clone().unwrap_or_default(),
        config.master_key_id.clone(),
        config.parsed_key_version(),
    ));
    services.insert("azure".into(), azure);

    let aliyun: Arc<dyn KmsService> = Arc::new(AliyunKmsService::new(
        config
            .region
            .clone()
            .unwrap_or_else(|| "cn-hangzhou".into()),
        config.endpoint.clone().unwrap_or_default(),
        config.master_key_id.clone(),
        config.key_ring.clone().unwrap_or_else(|| "default".into()),
        config.parsed_key_version(),
    ));
    services.insert("aliyun".into(), aliyun);

    Ok(KmsServiceRegistry {
        active_provider: config.provider.label().to_string(),
        services,
    })
}

#[derive(Debug, Clone)]
struct ContractKmsCore {
    provider_name: &'static str,
    wrap_prefix: &'static str,
    master_key_id: String,
    entropy_parts: Vec<String>,
    version: u32,
}

impl ContractKmsCore {
    fn new(
        provider_name: &'static str,
        wrap_prefix: &'static str,
        master_key_id: impl Into<String>,
        entropy_parts: Vec<String>,
        version: u32,
    ) -> Self {
        Self {
            provider_name,
            wrap_prefix,
            master_key_id: master_key_id.into(),
            entropy_parts,
            version: version.max(1),
        }
    }

    fn wrap_data_key(&self, plaintext: &[u8]) -> DataKeyWrap {
        DataKeyWrap {
            wrapped_dek: self.wrap_bytes(self.version, plaintext),
            kek_id: self.master_key_id.clone(),
            key_version: Some(self.version.to_string()),
        }
    }

    fn unwrap_data_key(&self, wrapped_dek: &str) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        let (_, plaintext) = unwrap_bytes(wrapped_dek, &[self.wrap_prefix], |version| {
            self.wrap_mask(version)
        })?;
        if plaintext.len() != 32 {
            return Err(KmsError::InvalidDataKeyLength);
        }
        Ok(plaintext)
    }

    fn provider_name(&self) -> &str {
        self.provider_name
    }

    fn master_key_id(&self) -> &str {
        &self.master_key_id
    }

    fn current_key_version(&self) -> Option<String> {
        Some(self.version.to_string())
    }

    fn wrap_bytes(&self, version: u32, bytes: &[u8]) -> String {
        let mask = self.wrap_mask(version);
        wrap_bytes(self.wrap_prefix, version, &mask, bytes)
    }

    fn wrap_mask(&self, version: u32) -> Vec<u8> {
        let mut digest = Sha256::new();
        digest.update(self.provider_name.as_bytes());
        digest.update(b"::");
        digest.update(self.master_key_id.as_bytes());
        digest.update(b"::");
        for part in &self.entropy_parts {
            digest.update(part.as_bytes());
            digest.update(b"::");
        }
        digest.update(version.to_string().as_bytes());
        digest.finalize().to_vec()
    }
}

#[derive(Debug, Clone)]
pub struct MockKmsService {
    core: ContractKmsCore,
}

impl MockKmsService {
    pub fn new(
        master_key_id: impl Into<String>,
        key_ring: impl Into<String>,
        version: u32,
    ) -> Self {
        Self {
            core: ContractKmsCore::new(
                "mock",
                "mockkms",
                master_key_id,
                vec![key_ring.into()],
                version,
            ),
        }
    }

    pub fn rotate(&mut self) {
        self.core.version += 1;
    }
}

impl KmsService for MockKmsService {
    fn provider_name(&self) -> &str {
        self.core.provider_name()
    }

    fn master_key_id(&self) -> &str {
        self.core.master_key_id()
    }

    fn wrap_data_key(&self, plaintext: &[u8], _dek_id: &str) -> Result<DataKeyWrap, KmsError> {
        Ok(self.core.wrap_data_key(plaintext))
    }

    fn unwrap_data_key(
        &self,
        wrapped_dek: &str,
        _dek_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        self.core.unwrap_data_key(wrapped_dek)
    }

    fn current_key_version(&self) -> Option<String> {
        self.core.current_key_version()
    }
}

#[derive(Debug, Clone)]
pub struct VaultContractKmsService {
    core: ContractKmsCore,
}

impl VaultContractKmsService {
    pub fn new(base_url: impl Into<String>, key_name: impl Into<String>, version: u32) -> Self {
        let base_url = base_url.into();
        let key_name = key_name.into();
        Self {
            core: ContractKmsCore::new("vault", "vaultcontract", key_name, vec![base_url], version),
        }
    }
}

impl KmsService for VaultContractKmsService {
    fn provider_name(&self) -> &str {
        self.core.provider_name()
    }

    fn master_key_id(&self) -> &str {
        self.core.master_key_id()
    }

    fn wrap_data_key(&self, plaintext: &[u8], _dek_id: &str) -> Result<DataKeyWrap, KmsError> {
        Ok(self.core.wrap_data_key(plaintext))
    }

    fn unwrap_data_key(
        &self,
        wrapped_dek: &str,
        _dek_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        self.core.unwrap_data_key(wrapped_dek)
    }

    fn current_key_version(&self) -> Option<String> {
        self.core.current_key_version()
    }
}

#[derive(Debug, Clone)]
pub struct AwsKmsService {
    core: ContractKmsCore,
}

impl AwsKmsService {
    pub fn new(
        region: impl Into<String>,
        endpoint: impl Into<String>,
        master_key_id: impl Into<String>,
        version: u32,
    ) -> Self {
        Self {
            core: ContractKmsCore::new(
                "aws",
                "awskms",
                master_key_id,
                vec![region.into(), endpoint.into()],
                version,
            ),
        }
    }
}

impl KmsService for AwsKmsService {
    fn provider_name(&self) -> &str {
        self.core.provider_name()
    }

    fn master_key_id(&self) -> &str {
        self.core.master_key_id()
    }

    fn wrap_data_key(&self, plaintext: &[u8], _dek_id: &str) -> Result<DataKeyWrap, KmsError> {
        Ok(self.core.wrap_data_key(plaintext))
    }

    fn unwrap_data_key(
        &self,
        wrapped_dek: &str,
        _dek_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        self.core.unwrap_data_key(wrapped_dek)
    }

    fn current_key_version(&self) -> Option<String> {
        self.core.current_key_version()
    }
}

#[derive(Debug, Clone)]
pub struct AzureKeyVaultKmsService {
    core: ContractKmsCore,
}

impl AzureKeyVaultKmsService {
    pub fn new(vault_url: impl Into<String>, key_name: impl Into<String>, version: u32) -> Self {
        Self {
            core: ContractKmsCore::new(
                "azure",
                "azurekms",
                key_name,
                vec![vault_url.into()],
                version,
            ),
        }
    }
}

impl KmsService for AzureKeyVaultKmsService {
    fn provider_name(&self) -> &str {
        self.core.provider_name()
    }

    fn master_key_id(&self) -> &str {
        self.core.master_key_id()
    }

    fn wrap_data_key(&self, plaintext: &[u8], _dek_id: &str) -> Result<DataKeyWrap, KmsError> {
        Ok(self.core.wrap_data_key(plaintext))
    }

    fn unwrap_data_key(
        &self,
        wrapped_dek: &str,
        _dek_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        self.core.unwrap_data_key(wrapped_dek)
    }

    fn current_key_version(&self) -> Option<String> {
        self.core.current_key_version()
    }
}

#[derive(Debug, Clone)]
pub struct AliyunKmsService {
    core: ContractKmsCore,
}

impl AliyunKmsService {
    pub fn new(
        region: impl Into<String>,
        endpoint: impl Into<String>,
        master_key_id: impl Into<String>,
        key_ring: impl Into<String>,
        version: u32,
    ) -> Self {
        Self {
            core: ContractKmsCore::new(
                "aliyun",
                "aliyunkms",
                master_key_id,
                vec![region.into(), endpoint.into(), key_ring.into()],
                version,
            ),
        }
    }
}

impl KmsService for AliyunKmsService {
    fn provider_name(&self) -> &str {
        self.core.provider_name()
    }

    fn master_key_id(&self) -> &str {
        self.core.master_key_id()
    }

    fn wrap_data_key(&self, plaintext: &[u8], _dek_id: &str) -> Result<DataKeyWrap, KmsError> {
        Ok(self.core.wrap_data_key(plaintext))
    }

    fn unwrap_data_key(
        &self,
        wrapped_dek: &str,
        _dek_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        self.core.unwrap_data_key(wrapped_dek)
    }

    fn current_key_version(&self) -> Option<String> {
        self.core.current_key_version()
    }
}

#[derive(Debug, Clone)]
pub struct VaultTransitKmsService {
    base_url: String,
    token: String,
    key_name: String,
    client: Client,
}

impl VaultTransitKmsService {
    pub fn new(
        base_url: impl Into<String>,
        token: impl Into<String>,
        key_name: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            key_name: key_name.into(),
            client: Client::new(),
        }
    }

    fn request(&self, path: &str) -> reqwest::blocking::RequestBuilder {
        self.client
            .post(format!(
                "{}/{}",
                self.base_url,
                path.trim_start_matches('/')
            ))
            .header("X-Vault-Token", self.token.clone())
    }

    fn get(&self, path: &str) -> reqwest::blocking::RequestBuilder {
        self.client
            .get(format!(
                "{}/{}",
                self.base_url,
                path.trim_start_matches('/')
            ))
            .header("X-Vault-Token", self.token.clone())
    }
}

impl KmsService for VaultTransitKmsService {
    fn provider_name(&self) -> &str {
        "vault"
    }

    fn master_key_id(&self) -> &str {
        &self.key_name
    }

    fn generate_data_key(&self) -> Result<DataKeyMaterial, KmsError> {
        let response = self
            .request(&format!("v1/transit/datakey/plaintext/{}", self.key_name))
            .json(&serde_json::json!({ "bits": 256 }))
            .send()?
            .error_for_status()?
            .json::<VaultTransitDataKeyResponse>()?;

        let plaintext = STANDARD
            .decode(response.data.plaintext.as_bytes())
            .map_err(|_| KmsError::InvalidVaultResponse)?;
        if plaintext.len() != 32 {
            return Err(KmsError::InvalidDataKeyLength);
        }

        Ok(DataKeyMaterial {
            dek_id: Ulid::new().to_string(),
            plaintext: Zeroizing::new(plaintext),
            wrapped_dek: response.data.ciphertext,
            kek_id: self.key_name.clone(),
            key_version: response.data.key_version.map(|version| version.to_string()),
        })
    }

    fn wrap_data_key(&self, plaintext: &[u8], _dek_id: &str) -> Result<DataKeyWrap, KmsError> {
        let response = self
            .request(&format!("v1/transit/encrypt/{}", self.key_name))
            .json(&serde_json::json!({
                "plaintext": STANDARD.encode(plaintext),
            }))
            .send()?
            .error_for_status()?
            .json::<VaultTransitEncryptResponse>()?;

        Ok(DataKeyWrap {
            wrapped_dek: response.data.ciphertext,
            kek_id: self.key_name.clone(),
            key_version: response.data.key_version.map(|version| version.to_string()),
        })
    }

    fn unwrap_data_key(
        &self,
        wrapped_dek: &str,
        _dek_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, KmsError> {
        let response = self
            .request(&format!("v1/transit/decrypt/{}", self.key_name))
            .json(&serde_json::json!({ "ciphertext": wrapped_dek }))
            .send()?
            .error_for_status()?
            .json::<VaultTransitDecryptResponse>()?;

        let plaintext = STANDARD
            .decode(response.data.plaintext.as_bytes())
            .map_err(|_| KmsError::InvalidVaultResponse)?;
        if plaintext.len() != 32 {
            return Err(KmsError::InvalidDataKeyLength);
        }

        Ok(Zeroizing::new(plaintext))
    }

    fn rewrap_data_key(&self, wrapped_dek: &str, _dek_id: &str) -> Result<DataKeyWrap, KmsError> {
        let response = self
            .request(&format!("v1/transit/rewrap/{}", self.key_name))
            .json(&serde_json::json!({ "ciphertext": wrapped_dek }))
            .send()?
            .error_for_status()?
            .json::<VaultTransitRewrapResponse>()?;
        Ok(DataKeyWrap {
            wrapped_dek: response.data.ciphertext,
            kek_id: self.key_name.clone(),
            key_version: response.data.key_version.map(|version| version.to_string()),
        })
    }

    fn current_key_version(&self) -> Option<String> {
        let response = self
            .get(&format!("v1/transit/keys/{}", self.key_name))
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .ok()?
            .json::<VaultTransitReadKeyResponse>()
            .ok()?;
        response
            .data
            .latest_version
            .map(|version| version.to_string())
    }
}

#[derive(Debug, Deserialize)]
struct VaultTransitDataKeyResponse {
    data: VaultTransitDataKeyResponseData,
}

#[derive(Debug, Deserialize)]
struct VaultTransitDataKeyResponseData {
    plaintext: String,
    ciphertext: String,
    #[serde(default)]
    key_version: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct VaultTransitEncryptResponse {
    data: VaultTransitEncryptResponseData,
}

#[derive(Debug, Deserialize)]
struct VaultTransitEncryptResponseData {
    ciphertext: String,
    #[serde(default)]
    key_version: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct VaultTransitDecryptResponse {
    data: VaultTransitDecryptResponseData,
}

#[derive(Debug, Deserialize)]
struct VaultTransitDecryptResponseData {
    plaintext: String,
}

#[derive(Debug, Deserialize)]
struct VaultTransitRewrapResponse {
    data: VaultTransitRewrapResponseData,
}

#[derive(Debug, Deserialize)]
struct VaultTransitRewrapResponseData {
    ciphertext: String,
    #[serde(default)]
    key_version: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct VaultTransitReadKeyResponse {
    data: VaultTransitReadKeyResponseData,
}

#[derive(Debug, Deserialize)]
struct VaultTransitReadKeyResponseData {
    #[serde(default)]
    latest_version: Option<u32>,
}

fn has_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

fn wrap_bytes(prefix: &str, version: u32, mask: &[u8], bytes: &[u8]) -> String {
    let wrapped = bytes
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ mask[index % mask.len()])
        .collect::<Vec<_>>();
    format!("{prefix}:v{version}:{}", STANDARD.encode(wrapped))
}

fn unwrap_bytes<F>(
    wrapped_dek: &str,
    accepted_prefixes: &[&str],
    wrap_mask: F,
) -> Result<(u32, Zeroizing<Vec<u8>>), KmsError>
where
    F: Fn(u32) -> Vec<u8>,
{
    let Some((prefix, ciphertext_b64)) = wrapped_dek.rsplit_once(':') else {
        return Err(KmsError::InvalidWrappedKey);
    };
    let version = accepted_prefixes
        .iter()
        .find_map(|accepted| {
            prefix
                .strip_prefix(&format!("{accepted}:v"))
                .and_then(|version| version.parse::<u32>().ok())
        })
        .ok_or(KmsError::InvalidWrappedKey)?;
    let wrapped = STANDARD
        .decode(ciphertext_b64.as_bytes())
        .map_err(|_| KmsError::InvalidWrappedKey)?;
    let mask = wrap_mask(version);
    let plaintext = wrapped
        .into_iter()
        .enumerate()
        .map(|(index, byte)| byte ^ mask[index % mask.len()])
        .collect::<Vec<_>>();
    Ok((version, Zeroizing::new(plaintext)))
}

#[cfg(test)]
mod tests {
    use super::{
        AwsKmsService, AzureKeyVaultKmsService, KmsClientConfig, KmsProvider, KmsService,
        MockKmsService, VaultContractKmsService, build_kms_service_registry,
    };

    #[test]
    fn mock_kms_generates_unwraps_and_rewraps_data_keys() {
        let mut kms = MockKmsService::new("master-key", "ring-a", 1);
        let material = kms.generate_data_key().expect("data key");
        let first_version = material.key_version.clone();
        let unwrapped = kms
            .unwrap_data_key(&material.wrapped_dek, &material.dek_id)
            .expect("unwrap");
        assert_eq!(unwrapped.as_slice(), material.plaintext.as_slice());
        assert_eq!(first_version.as_deref(), Some("1"));

        kms.rotate();
        let rewrapped = kms
            .rewrap_data_key(&material.wrapped_dek, &material.dek_id)
            .expect("rewrap");
        assert_eq!(rewrapped.key_version.as_deref(), Some("2"));
        let rewrapped_plaintext = kms
            .unwrap_data_key(&rewrapped.wrapped_dek, &material.dek_id)
            .expect("rewrapped plaintext");
        assert_eq!(
            rewrapped_plaintext.as_slice(),
            material.plaintext.as_slice()
        );
    }

    #[test]
    fn provider_registry_includes_explicit_provider_contracts() {
        let registry = build_kms_service_registry(&KmsClientConfig {
            provider: KmsProvider::Aws,
            endpoint: Some("https://kms.example.internal".into()),
            master_key_id: "master-key".into(),
            key_ring: Some("ring-a".into()),
            auth_token: None,
            region: Some("cn-test-1".into()),
            key_version: Some("3".into()),
        })
        .expect("registry");

        assert_eq!(registry.active_provider(), "aws");
        assert_eq!(
            registry
                .service("mock")
                .expect("mock service")
                .provider_name(),
            "mock"
        );
        assert_eq!(
            registry
                .service("vault")
                .expect("vault service")
                .provider_name(),
            "vault"
        );
        assert_eq!(
            registry
                .service("aws")
                .expect("aws service")
                .provider_name(),
            "aws"
        );
        assert_eq!(
            registry
                .service("azure")
                .expect("azure service")
                .provider_name(),
            "azure"
        );
        assert_eq!(
            registry
                .service("aliyun")
                .expect("aliyun service")
                .provider_name(),
            "aliyun"
        );
    }

    #[test]
    fn provider_contract_services_round_trip_data_keys() {
        let providers: Vec<Box<dyn KmsService>> = vec![
            Box::new(VaultContractKmsService::new(
                "https://vault.example.internal",
                "transit-key",
                2,
            )),
            Box::new(AwsKmsService::new(
                "cn-test-1",
                "https://kms.cn-test-1.amazonaws.com",
                "arn:aws:kms:cn-test-1:123:key/test",
                2,
            )),
            Box::new(AzureKeyVaultKmsService::new(
                "https://vault.example.vault.azure.net",
                "sdqp-prod-key",
                2,
            )),
        ];

        for provider in providers {
            let material = provider.generate_data_key().expect("data key");
            let plaintext = provider
                .unwrap_data_key(&material.wrapped_dek, &material.dek_id)
                .expect("unwrap");
            assert_eq!(plaintext.as_slice(), material.plaintext.as_slice());
            assert_eq!(material.key_version.as_deref(), Some("2"));
        }
    }

    #[test]
    fn legacy_development_alias_resolves_to_mock_provider() {
        let provider = KmsProvider::parse("development").expect("provider");
        assert_eq!(provider, KmsProvider::Mock);
        assert_eq!(provider.label(), "mock");
    }
}
