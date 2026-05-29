use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{McpGatewayError, McpResult, registry::McpToolName};

/// MCP-specific watermark payload containing the standard SDQP payload plus agent fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpWatermarkPayload {
    /// Tenant ID from the standard SDQP watermark payload.
    pub tenant_id: String,
    /// Project ID from the standard SDQP watermark payload.
    pub project_id: String,
    /// Delegated user ID from the standard SDQP watermark payload.
    pub user_id: String,
    /// Sequence number from the standard SDQP watermark payload.
    pub sequence_number: u64,
    /// Issue timestamp from the standard SDQP watermark payload.
    pub issued_at: DateTime<Utc>,
    /// Optional snapshot or task ID from the standard SDQP watermark payload.
    pub snapshot_id: Option<String>,
    /// MCP agent ID.
    pub agent_id: String,
    /// MCP tool name.
    pub tool_name: String,
    /// MCP session ID.
    pub mcp_session_id: String,
}

impl McpWatermarkPayload {
    /// Returns the standard SDQP watermark payload view.
    pub fn standard_payload(&self) -> sdqp_watermark::WatermarkPayload {
        sdqp_watermark::WatermarkPayload {
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            user_id: self.user_id.clone(),
            sequence_number: self.sequence_number,
            issued_at: self.issued_at,
            snapshot_id: self.snapshot_id.clone(),
        }
    }
}

/// Encoded MCP watermark envelope returned by Gateway tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpWatermarkEnvelope {
    /// Structured watermark payload.
    pub payload: McpWatermarkPayload,
    /// Signed compact token.
    pub token: String,
    /// Human-readable overlay text.
    pub overlay_text: String,
}

/// Builds and signs an MCP-specific watermark payload.
pub fn build_mcp_watermark(
    tenant_id: &str,
    project_id: &str,
    user_id: &str,
    sequence_number: u64,
    snapshot_id: Option<String>,
    agent_id: &str,
    tool_name: McpToolName,
    mcp_session_id: &str,
) -> McpResult<McpWatermarkEnvelope> {
    let payload = McpWatermarkPayload {
        tenant_id: tenant_id.into(),
        project_id: project_id.into(),
        user_id: user_id.into(),
        sequence_number,
        issued_at: Utc::now(),
        snapshot_id,
        agent_id: agent_id.into(),
        tool_name: tool_name.as_str().into(),
        mcp_session_id: mcp_session_id.into(),
    };
    let token = encode_mcp_payload(&payload)?;
    let overlay_text = format!(
        "{} / {} / {} / {} / {} #{}",
        payload.tenant_id,
        payload.project_id,
        payload.user_id,
        payload.agent_id,
        payload.tool_name,
        payload.sequence_number
    );
    Ok(McpWatermarkEnvelope {
        payload,
        token,
        overlay_text,
    })
}

/// Encodes an MCP watermark payload using the SDQP token format.
pub fn encode_mcp_payload(payload: &McpWatermarkPayload) -> McpResult<String> {
    let bytes = serde_json::to_vec(payload)
        .map_err(|error| McpGatewayError::Serialization(error.to_string()))?;
    let digest = hex_string(Sha256::digest(&bytes).as_slice());
    Ok(format!("{}.{}", URL_SAFE_NO_PAD.encode(bytes), digest))
}

/// Decodes and verifies an MCP watermark payload.
pub fn decode_mcp_payload(token: &str) -> McpResult<McpWatermarkPayload> {
    let (encoded, expected_digest) = token
        .split_once('.')
        .ok_or_else(|| McpGatewayError::InvalidRequest("invalid watermark token".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| McpGatewayError::Serialization(error.to_string()))?;
    let actual_digest = hex_string(Sha256::digest(&bytes).as_slice());
    if actual_digest != expected_digest {
        return Err(McpGatewayError::InvalidRequest(
            "watermark digest mismatch".into(),
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| McpGatewayError::Serialization(error.to_string()))
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
