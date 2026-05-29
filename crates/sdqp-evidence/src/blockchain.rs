use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AnchorReceipt, AnchorStatus, BlockchainAnchor, EvidenceError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockchainAnchorConfig {
    pub provider: String,
    pub base_url: String,
    pub api_key: String,
    pub network: String,
    pub timeout_ms: u64,
    #[serde(default)]
    pub require_external: bool,
}

impl Default for BlockchainAnchorConfig {
    fn default() -> Self {
        Self {
            provider: "mock".into(),
            base_url: String::new(),
            api_key: "phase5-anchor-secret".into(),
            network: "mock-chain".into(),
            timeout_ms: 3_000,
            require_external: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EthereumAnchorClient {
    client: Client,
    base_url: String,
    api_key: String,
    network: String,
    provider_label: String,
    anchor_method: String,
    receipt_method: String,
}

impl EthereumAnchorClient {
    pub fn from_config(config: BlockchainAnchorConfig) -> Result<Self, EvidenceError> {
        Self::from_named_provider(config, "ethereum")
    }

    pub fn from_named_provider(
        config: BlockchainAnchorConfig,
        provider_label: impl Into<String>,
    ) -> Result<Self, EvidenceError> {
        if config.network.trim().is_empty() {
            return Err(EvidenceError::ProviderConfiguration(
                "anchor network is required".into(),
            ));
        }
        if config.base_url.trim().is_empty() {
            return Err(EvidenceError::ProviderConfiguration(
                "ethereum anchor base_url is required".into(),
            ));
        }

        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms.max(1)))
            .build()
            .map_err(|error| EvidenceError::ProviderRequest(error.to_string()))?;

        let provider_label = provider_label.into();
        let (anchor_method, receipt_method) = match provider_label.as_str() {
            "fabric" => ("sdqp_fabricAnchorDigest", "sdqp_fabricGetReceipt"),
            "bsn" => ("sdqp_bsnAnchorDigest", "sdqp_bsnGetReceipt"),
            "judicial" => ("sdqp_judicialAnchorDigest", "sdqp_judicialGetReceipt"),
            _ => ("sdqp_anchorDigest", "sdqp_getAnchorReceipt"),
        };

        Ok(Self {
            client,
            base_url: config.base_url,
            api_key: config.api_key,
            network: config.network,
            provider_label,
            anchor_method: anchor_method.into(),
            receipt_method: receipt_method.into(),
        })
    }
}

#[async_trait]
impl BlockchainAnchor for EthereumAnchorClient {
    fn network_name(&self) -> &str {
        &self.network
    }

    async fn anchor(&self, digest: &str) -> Result<AnchorReceipt, EvidenceError> {
        crate::validate_sha256_digest(digest)?;
        let request = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: "sdqp-anchor".into(),
            method: self.anchor_method.clone(),
            params: AnchorParams {
                network: self.network.clone(),
                digest: digest.to_string(),
                transaction_id: None,
            },
        };
        let response: JsonRpcResponse<AnchorResult> = self
            .client
            .post(&self.base_url)
            .header("x-api-key", &self.api_key)
            .json(&request)
            .send()
            .await
            .and_then(|response| response.error_for_status())
            .map_err(|error| EvidenceError::ProviderRequest(error.to_string()))?
            .json()
            .await
            .map_err(|error| EvidenceError::ProviderRequest(error.to_string()))?;
        validate_json_rpc_envelope(&response, &request.id)?;
        let result = response
            .result
            .ok_or_else(|| EvidenceError::ProviderProtocol("missing anchor result".into()))?;
        validate_anchor_result(&result, &self.network, digest, false)?;

        Ok(AnchorReceipt {
            network: result.network,
            anchored_at: result.anchored_at,
            digest: result.digest,
            transaction_id: result.transaction_id,
            status: parse_anchor_status(&result.status)?,
            provider: Some(self.provider_label.clone()),
            block_number: result.block_number,
            proof: result.proof,
            confirmed_at: result.confirmed_at,
            failure_reason: result.failure_reason,
        })
    }

    async fn refresh(&self, receipt: &AnchorReceipt) -> Result<AnchorReceipt, EvidenceError> {
        crate::validate_sha256_digest(&receipt.digest)?;
        let request = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: "sdqp-anchor-refresh".into(),
            method: self.receipt_method.clone(),
            params: AnchorParams {
                network: receipt.network.clone(),
                digest: receipt.digest.clone(),
                transaction_id: Some(receipt.transaction_id.clone()),
            },
        };
        let response: JsonRpcResponse<AnchorResult> = self
            .client
            .post(&self.base_url)
            .header("x-api-key", &self.api_key)
            .json(&request)
            .send()
            .await
            .and_then(|response| response.error_for_status())
            .map_err(|error| EvidenceError::ProviderRequest(error.to_string()))?
            .json()
            .await
            .map_err(|error| EvidenceError::ProviderRequest(error.to_string()))?;
        validate_json_rpc_envelope(&response, &request.id)?;
        let result = response
            .result
            .ok_or_else(|| EvidenceError::ProviderProtocol("missing anchor result".into()))?;
        validate_anchor_result(&result, &receipt.network, &receipt.digest, true)?;

        Ok(AnchorReceipt {
            network: result.network,
            anchored_at: result.anchored_at,
            digest: result.digest,
            transaction_id: result.transaction_id,
            status: parse_anchor_status(&result.status)?,
            provider: Some(self.provider_label.clone()),
            block_number: result.block_number,
            proof: result.proof,
            confirmed_at: result.confirmed_at,
            failure_reason: result.failure_reason,
        })
    }

    async fn verify(&self, receipt: &AnchorReceipt, digest: &str) -> Result<bool, EvidenceError> {
        if receipt.digest != digest || receipt.status != AnchorStatus::Confirmed {
            return Ok(false);
        }
        crate::validate_sha256_digest(digest)?;

        let Some(proof) = &receipt.proof else {
            return Ok(false);
        };
        let expected = ethereum_anchor_proof(
            &receipt.network,
            digest,
            &receipt.transaction_id,
            receipt.confirmed_at.unwrap_or(receipt.anchored_at),
            &self.api_key,
        );

        Ok(proof == &expected)
    }
}

pub fn ethereum_anchor_proof(
    network: &str,
    digest: &str,
    transaction_id: &str,
    anchored_at: DateTime<Utc>,
    api_key: &str,
) -> String {
    hex::encode(Sha256::digest(
        format!(
            "{network}|{digest}|{transaction_id}|{}|{api_key}",
            anchored_at.to_rfc3339()
        )
        .as_bytes(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorParams {
    pub network: String,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorResult {
    pub network: String,
    pub digest: String,
    pub transaction_id: String,
    pub anchored_at: DateTime<Utc>,
    pub status: String,
    pub block_number: Option<u64>,
    pub proof: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcRequest<T> {
    pub jsonrpc: String,
    pub id: String,
    pub method: String,
    pub params: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcResponse<T> {
    pub jsonrpc: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub result: Option<T>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

fn parse_anchor_status(value: &str) -> Result<AnchorStatus, EvidenceError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "pending" => Ok(AnchorStatus::Pending),
        "confirmed" => Ok(AnchorStatus::Confirmed),
        "failed" => Ok(AnchorStatus::Failed),
        other => Err(EvidenceError::ProviderProtocol(format!(
            "unknown anchor status {other}"
        ))),
    }
}

fn validate_json_rpc_envelope<T>(
    response: &JsonRpcResponse<T>,
    expected_id: &str,
) -> Result<(), EvidenceError> {
    if response.jsonrpc != "2.0" {
        return Err(EvidenceError::ProviderProtocol(
            "invalid json-rpc version".into(),
        ));
    }
    if response.id != expected_id {
        return Err(EvidenceError::ProviderProtocol(
            "json-rpc response id mismatch".into(),
        ));
    }
    if let Some(error) = &response.error {
        return Err(EvidenceError::ProviderProtocol(format!(
            "json-rpc error {}: {}",
            error.code, error.message
        )));
    }
    Ok(())
}

fn validate_anchor_result(
    result: &AnchorResult,
    expected_network: &str,
    expected_digest: &str,
    refresh: bool,
) -> Result<(), EvidenceError> {
    if result.network != expected_network {
        return Err(EvidenceError::ProviderProtocol(
            "anchor receipt network mismatch".into(),
        ));
    }
    if result.digest != expected_digest {
        return Err(EvidenceError::ProviderProtocol(
            "anchor receipt digest mismatch".into(),
        ));
    }
    if result.transaction_id.trim().is_empty() {
        return Err(EvidenceError::ProviderProtocol(
            "anchor receipt transaction_id is required".into(),
        ));
    }

    match parse_anchor_status(&result.status)? {
        AnchorStatus::Confirmed => {
            if refresh && result.confirmed_at.is_none() {
                return Err(EvidenceError::ProviderProtocol(
                    "confirmed anchor receipt requires confirmed_at".into(),
                ));
            }
            if result
                .proof
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                return Err(EvidenceError::ProviderProtocol(
                    "confirmed anchor receipt requires proof".into(),
                ));
            }
        }
        AnchorStatus::Pending => {
            if result.failure_reason.is_some() {
                return Err(EvidenceError::ProviderProtocol(
                    "pending anchor receipt must not include failure_reason".into(),
                ));
            }
        }
        AnchorStatus::Failed => {
            if result
                .failure_reason
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                return Err(EvidenceError::ProviderProtocol(
                    "failed anchor receipt requires failure_reason".into(),
                ));
            }
        }
    }

    Ok(())
}
