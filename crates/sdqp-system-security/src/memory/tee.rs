use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeAttestation {
    pub provider: String,
    pub workload: String,
    pub measurement: String,
    pub secure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeProviderConfig {
    pub provider: String,
    pub attestation_url: String,
    pub expected_measurements: Vec<String>,
}

impl Default for TeeProviderConfig {
    fn default() -> Self {
        Self {
            provider: "mock".into(),
            attestation_url: String::new(),
            expected_measurements: Vec::new(),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TeeError {
    #[error("unknown tee provider: {0}")]
    UnknownProvider(String),
    #[error("tee provider configuration error: {0}")]
    ProviderConfiguration(String),
    #[error("tee provider request failed: {0}")]
    ProviderRequest(String),
    #[error("tee attestation is not secure")]
    InsecureAttestation,
    #[error("tee attestation measurement is not allowed")]
    MeasurementMismatch,
}

#[async_trait]
pub trait TeeProvider: Send + Sync {
    async fn attest(&self, workload: &str) -> Result<TeeAttestation, TeeError>;
}

#[derive(Debug, Clone)]
pub struct MockTeeProvider {
    provider: String,
}

impl Default for MockTeeProvider {
    fn default() -> Self {
        Self {
            provider: "mock-tee".into(),
        }
    }
}

#[async_trait]
impl TeeProvider for MockTeeProvider {
    async fn attest(&self, workload: &str) -> Result<TeeAttestation, TeeError> {
        let mut hasher = Sha256::new();
        hasher.update(workload.as_bytes());
        Ok(TeeAttestation {
            provider: self.provider.clone(),
            workload: workload.to_string(),
            measurement: hex::encode(hasher.finalize()),
            secure: true,
        })
    }
}

#[derive(Clone)]
pub struct TeeProviderRegistry {
    provider: TeeProviderEntry,
    expected_measurements: Vec<String>,
}

impl TeeProviderRegistry {
    pub fn from_config(config: TeeProviderConfig) -> Result<Self, TeeError> {
        let provider = match config.provider.trim().to_ascii_lowercase().as_str() {
            "" | "mock" => TeeProviderEntry::Mock(MockTeeProvider::default()),
            "http-attestation" => {
                TeeProviderEntry::Http(HttpAttestationTeeProvider::from_config(&config)?)
            }
            other => return Err(TeeError::UnknownProvider(other.into())),
        };

        Ok(Self {
            provider,
            expected_measurements: config.expected_measurements,
        })
    }

    pub async fn attest(&self, workload: &str) -> Result<TeeAttestation, TeeError> {
        self.provider.attest(workload).await
    }

    pub async fn enforce_secure_workload(
        &self,
        workload: &str,
    ) -> Result<TeeAttestation, TeeError> {
        let attestation = self.attest(workload).await?;
        if !attestation.secure {
            return Err(TeeError::InsecureAttestation);
        }
        if !self.expected_measurements.is_empty()
            && !self
                .expected_measurements
                .iter()
                .any(|value| value == &attestation.measurement)
        {
            return Err(TeeError::MeasurementMismatch);
        }
        Ok(attestation)
    }
}

#[derive(Clone)]
enum TeeProviderEntry {
    Mock(MockTeeProvider),
    Http(HttpAttestationTeeProvider),
}

impl TeeProviderEntry {
    async fn attest(&self, workload: &str) -> Result<TeeAttestation, TeeError> {
        match self {
            Self::Mock(provider) => provider.attest(workload).await,
            Self::Http(provider) => provider.attest(workload).await,
        }
    }
}

#[derive(Clone)]
struct HttpAttestationTeeProvider {
    attestation_url: String,
    client: Client,
}

impl HttpAttestationTeeProvider {
    fn from_config(config: &TeeProviderConfig) -> Result<Self, TeeError> {
        if config.attestation_url.trim().is_empty() {
            return Err(TeeError::ProviderConfiguration(
                "tee.attestation_url must not be empty".into(),
            ));
        }
        Ok(Self {
            attestation_url: config.attestation_url.clone(),
            client: Client::new(),
        })
    }
}

#[async_trait]
impl TeeProvider for HttpAttestationTeeProvider {
    async fn attest(&self, workload: &str) -> Result<TeeAttestation, TeeError> {
        let response = self
            .client
            .post(&self.attestation_url)
            .json(&serde_json::json!({ "workload": workload }))
            .send()
            .await
            .map_err(|error| TeeError::ProviderRequest(error.to_string()))?;
        if !response.status().is_success() {
            return Err(TeeError::ProviderRequest(format!(
                "attestation endpoint returned status {}",
                response.status()
            )));
        }
        response
            .json::<TeeAttestation>()
            .await
            .map_err(|error| TeeError::ProviderRequest(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use axum::{Json, Router, routing::post};

    use super::{
        MockTeeProvider, TeeAttestation, TeeProvider, TeeProviderConfig, TeeProviderRegistry,
    };

    #[tokio::test]
    async fn mock_tee_provider_returns_attestation() {
        let provider = MockTeeProvider::default();
        let attestation = provider.attest("decrypt-pipeline").await.expect("attest");
        assert!(attestation.secure);
        assert_eq!(attestation.provider, "mock-tee");
    }

    #[tokio::test]
    async fn http_tee_provider_enforces_expected_measurement() {
        async fn attest(Json(payload): Json<serde_json::Value>) -> Json<TeeAttestation> {
            let workload = payload["workload"].as_str().expect("workload");
            Json(TeeAttestation {
                provider: "http-attestation".into(),
                workload: workload.into(),
                measurement: format!("measurement:{workload}"),
                secure: true,
            })
        }

        let app = Router::new().route("/tee/attest", post(attest));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("tee server");
        });

        let registry = TeeProviderRegistry::from_config(TeeProviderConfig {
            provider: "http-attestation".into(),
            attestation_url: format!("http://{addr}/tee/attest"),
            expected_measurements: vec!["measurement:decrypt-pipeline".into()],
        })
        .expect("registry");
        let attestation = registry
            .enforce_secure_workload("decrypt-pipeline")
            .await
            .expect("attestation");
        assert_eq!(attestation.provider, "http-attestation");
    }
}
