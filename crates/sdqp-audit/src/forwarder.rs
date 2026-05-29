use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use rskafka::{
    client::{
        ClientBuilder,
        partition::{Compression, UnknownTopicHandling},
    },
    record::Record,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::UdpSocket;
use ulid::Ulid;

use crate::{AuditCheckpoint, AuditEvent};

const DEFAULT_FORWARD_TOPIC_PARTITION: i32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditForwarderProvider {
    Disabled,
    Webhook,
    Kafka,
    Syslog,
}

impl AuditForwarderProvider {
    pub fn parse(value: &str) -> Result<Self, AuditForwardError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "disabled" | "off" | "none" => Ok(Self::Disabled),
            "webhook" | "http" | "https" => Ok(Self::Webhook),
            "kafka" => Ok(Self::Kafka),
            "syslog" | "udp-syslog" => Ok(Self::Syslog),
            other => Err(AuditForwardError::UnsupportedProvider(other.to_string())),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Webhook => "webhook",
            Self::Kafka => "kafka",
            Self::Syslog => "syslog",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WebhookAuditForwarderConfig {
    pub endpoint: String,
    pub auth_header: Option<String>,
    pub auth_token: Option<String>,
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KafkaAuditForwarderConfig {
    pub brokers: Vec<String>,
    pub topic: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogAuditForwarderConfig {
    pub endpoint: String,
    pub hostname: String,
    pub app_name: String,
}

impl Default for SyslogAuditForwarderConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            hostname: "sdqp.local".into(),
            app_name: "sdqp-audit".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditForwarderConfig {
    pub enabled: bool,
    pub provider: AuditForwarderProvider,
    pub timeout_ms: u64,
    pub webhook: WebhookAuditForwarderConfig,
    pub kafka: KafkaAuditForwarderConfig,
    pub syslog: SyslogAuditForwarderConfig,
}

impl Default for AuditForwarderConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: AuditForwarderProvider::Disabled,
            timeout_ms: 3_000,
            webhook: WebhookAuditForwarderConfig::default(),
            kafka: KafkaAuditForwarderConfig::default(),
            syslog: SyslogAuditForwarderConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditForwardRequest {
    pub forwarded_at: DateTime<Utc>,
    pub event: AuditEvent,
    pub checkpoint: AuditCheckpoint,
}

impl AuditForwardRequest {
    pub fn new(event: AuditEvent, checkpoint: AuditCheckpoint) -> Self {
        Self {
            forwarded_at: Utc::now(),
            event,
            checkpoint,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditForwardEnvelope {
    pub forwarded_at: DateTime<Utc>,
    pub event: AuditEvent,
    pub checkpoint: AuditCheckpoint,
}

impl From<&AuditForwardRequest> for AuditForwardEnvelope {
    fn from(value: &AuditForwardRequest) -> Self {
        Self {
            forwarded_at: value.forwarded_at,
            event: value.event.clone(),
            checkpoint: value.checkpoint.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditForwardReceipt {
    pub delivery_id: String,
    pub provider: String,
    pub destination: String,
    pub payload_bytes: usize,
    pub delivered_at: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum AuditForwardError {
    #[error("unsupported audit forwarder provider: {0}")]
    UnsupportedProvider(String),
    #[error("audit forwarder is disabled")]
    Disabled,
    #[error("audit forwarder configuration error: {0}")]
    Configuration(String),
    #[error("audit forward request failed: {0}")]
    Request(String),
    #[error("audit forward delivery rejected by remote status {0}")]
    DeliveryRejected(u16),
}

#[async_trait]
pub trait AuditForwarder: Send + Sync {
    fn provider_name(&self) -> &str;
    fn destination(&self) -> String;
    async fn forward(
        &self,
        request: &AuditForwardRequest,
    ) -> Result<AuditForwardReceipt, AuditForwardError>;
}

pub struct AuditForwarderRegistry {
    enabled: bool,
    active_provider: String,
    forwarders: BTreeMap<String, Arc<dyn AuditForwarder>>,
}

impl AuditForwarderRegistry {
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn active_provider(&self) -> &str {
        &self.active_provider
    }

    pub fn active_destination(&self) -> String {
        self.forwarders
            .get(&self.active_provider)
            .map(|forwarder| forwarder.destination())
            .unwrap_or_else(|| self.active_provider.clone())
    }

    pub async fn forward_active(
        &self,
        request: &AuditForwardRequest,
    ) -> Result<Option<AuditForwardReceipt>, AuditForwardError> {
        if !self.enabled || self.active_provider == AuditForwarderProvider::Disabled.label() {
            return Ok(None);
        }

        let Some(forwarder) = self.forwarders.get(&self.active_provider) else {
            return Err(AuditForwardError::Configuration(format!(
                "missing active forwarder {}",
                self.active_provider
            )));
        };
        forwarder.forward(request).await.map(Some)
    }
}

pub fn build_audit_forwarder_registry(
    config: &AuditForwarderConfig,
) -> Result<AuditForwarderRegistry, AuditForwardError> {
    let mut forwarders: BTreeMap<String, Arc<dyn AuditForwarder>> = BTreeMap::new();
    forwarders.insert(
        AuditForwarderProvider::Webhook.label().into(),
        Arc::new(WebhookAuditForwarder::new(
            config.timeout_ms,
            config.webhook.clone(),
        )?),
    );
    forwarders.insert(
        AuditForwarderProvider::Kafka.label().into(),
        Arc::new(KafkaAuditForwarder::new(config.kafka.clone())?),
    );
    forwarders.insert(
        AuditForwarderProvider::Syslog.label().into(),
        Arc::new(SyslogAuditForwarder::new(config.syslog.clone())?),
    );

    Ok(AuditForwarderRegistry {
        enabled: config.enabled,
        active_provider: config.provider.label().to_string(),
        forwarders,
    })
}

#[derive(Debug, Clone)]
struct WebhookAuditForwarder {
    client: Client,
    config: WebhookAuditForwarderConfig,
}

impl WebhookAuditForwarder {
    fn new(
        timeout_ms: u64,
        config: WebhookAuditForwarderConfig,
    ) -> Result<Self, AuditForwardError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms.max(1)))
            .build()
            .map_err(|error| AuditForwardError::Configuration(error.to_string()))?;
        Ok(Self { client, config })
    }
}

#[async_trait]
impl AuditForwarder for WebhookAuditForwarder {
    fn provider_name(&self) -> &str {
        AuditForwarderProvider::Webhook.label()
    }

    fn destination(&self) -> String {
        self.config.endpoint.clone()
    }

    async fn forward(
        &self,
        request: &AuditForwardRequest,
    ) -> Result<AuditForwardReceipt, AuditForwardError> {
        if self.config.endpoint.trim().is_empty() {
            return Err(AuditForwardError::Configuration(
                "webhook endpoint is empty".into(),
            ));
        }

        let envelope = AuditForwardEnvelope::from(request);
        let payload = serde_json::to_vec(&envelope)
            .map_err(|error| AuditForwardError::Request(error.to_string()))?;
        let mut builder = self
            .client
            .post(&self.config.endpoint)
            .body(payload.clone());
        for (key, value) in &self.config.headers {
            builder = builder.header(key, value);
        }
        if let Some(header_name) = &self.config.auth_header
            && let Some(token) = &self.config.auth_token
        {
            builder = builder.header(header_name, token);
        }

        let response = builder
            .header("content-type", "application/json")
            .send()
            .await
            .map_err(|error| AuditForwardError::Request(error.to_string()))?;
        if !response.status().is_success() {
            return Err(AuditForwardError::DeliveryRejected(
                response.status().as_u16(),
            ));
        }

        Ok(AuditForwardReceipt {
            delivery_id: Ulid::new().to_string(),
            provider: self.provider_name().into(),
            destination: self.destination(),
            payload_bytes: payload.len(),
            delivered_at: Utc::now(),
        })
    }
}

#[derive(Debug, Clone)]
struct KafkaAuditForwarder {
    config: KafkaAuditForwarderConfig,
}

impl KafkaAuditForwarder {
    fn new(config: KafkaAuditForwarderConfig) -> Result<Self, AuditForwardError> {
        Ok(Self { config })
    }
}

#[async_trait]
impl AuditForwarder for KafkaAuditForwarder {
    fn provider_name(&self) -> &str {
        AuditForwarderProvider::Kafka.label()
    }

    fn destination(&self) -> String {
        self.config.topic.clone()
    }

    async fn forward(
        &self,
        request: &AuditForwardRequest,
    ) -> Result<AuditForwardReceipt, AuditForwardError> {
        if self.config.brokers.is_empty() {
            return Err(AuditForwardError::Configuration(
                "kafka brokers are empty".into(),
            ));
        }
        if self.config.topic.trim().is_empty() {
            return Err(AuditForwardError::Configuration(
                "kafka topic is empty".into(),
            ));
        }

        let envelope = AuditForwardEnvelope::from(request);
        let payload = serde_json::to_vec(&envelope)
            .map_err(|error| AuditForwardError::Request(error.to_string()))?;
        let client = ClientBuilder::new(self.config.brokers.clone())
            .build()
            .await
            .map_err(|error| AuditForwardError::Request(error.to_string()))?;
        if let Ok(controller) = client.controller_client() {
            let _ = controller
                .create_topic(&self.config.topic, 1, 1, 5_000)
                .await;
        }
        let partition_client = client
            .partition_client(
                self.config.topic.clone(),
                DEFAULT_FORWARD_TOPIC_PARTITION,
                UnknownTopicHandling::Retry,
            )
            .await
            .map_err(|error| AuditForwardError::Request(error.to_string()))?;
        partition_client
            .produce(
                vec![Record {
                    key: Some(request.event.event_id.as_bytes().to_vec()),
                    value: Some(payload.clone()),
                    headers: BTreeMap::new(),
                    timestamp: request.event.timestamp,
                }],
                Compression::default(),
            )
            .await
            .map_err(|error| AuditForwardError::Request(error.to_string()))?;

        Ok(AuditForwardReceipt {
            delivery_id: Ulid::new().to_string(),
            provider: self.provider_name().into(),
            destination: self.destination(),
            payload_bytes: payload.len(),
            delivered_at: Utc::now(),
        })
    }
}

#[derive(Debug, Clone)]
struct SyslogAuditForwarder {
    config: SyslogAuditForwarderConfig,
}

impl SyslogAuditForwarder {
    fn new(config: SyslogAuditForwarderConfig) -> Result<Self, AuditForwardError> {
        Ok(Self { config })
    }
}

#[async_trait]
impl AuditForwarder for SyslogAuditForwarder {
    fn provider_name(&self) -> &str {
        AuditForwarderProvider::Syslog.label()
    }

    fn destination(&self) -> String {
        self.config.endpoint.clone()
    }

    async fn forward(
        &self,
        request: &AuditForwardRequest,
    ) -> Result<AuditForwardReceipt, AuditForwardError> {
        if self.config.endpoint.trim().is_empty() {
            return Err(AuditForwardError::Configuration(
                "syslog endpoint is empty".into(),
            ));
        }

        let message = format!(
            "<134>1 {} {} {} - - [sdqp@32473 event_id=\"{}\" checkpoint_id=\"{}\" tenant_id=\"{}\" resource_id=\"{}\"] {}",
            request.forwarded_at.to_rfc3339(),
            self.config.hostname,
            self.config.app_name,
            request.event.event_id,
            request.checkpoint.checkpoint_id,
            request.event.target.tenant_id,
            request.event.target.resource_id,
            request.event.context
        );
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|error| AuditForwardError::Request(error.to_string()))?;
        socket
            .send_to(message.as_bytes(), &self.config.endpoint)
            .await
            .map_err(|error| AuditForwardError::Request(error.to_string()))?;

        Ok(AuditForwardReceipt {
            delivery_id: Ulid::new().to_string(),
            provider: self.provider_name().into(),
            destination: self.destination(),
            payload_bytes: message.len(),
            delivered_at: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::{ActionResult, ActionType, ActorInfo, AuditEvent, TargetRef, create_checkpoint};
    use axum::{Json, Router, routing::post};

    use super::{
        AuditForwardRequest, AuditForwarderConfig, AuditForwarderProvider,
        WebhookAuditForwarderConfig, build_audit_forwarder_registry,
    };

    fn sample_request() -> AuditForwardRequest {
        let event = AuditEvent::new(
            ActorInfo {
                user_id: "user-a".into(),
                session_id: "session-a".into(),
                ip_address: "127.0.0.1".into(),
            },
            ActionType::Query,
            TargetRef {
                tenant_id: "tenant-a".into(),
                project_id: Some("project-a".into()),
                resource_id: "snapshot-a".into(),
            },
            "forward audit event",
            ActionResult::Success,
            None,
            None,
        );
        let checkpoint = create_checkpoint(std::slice::from_ref(&event)).expect("checkpoint");
        AuditForwardRequest::new(event, checkpoint)
    }

    #[tokio::test]
    async fn webhook_forwarder_posts_structured_envelope() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let app = {
            let captured = captured.clone();
            Router::new().route(
                "/audit/siem",
                post(move |Json(body): Json<serde_json::Value>| {
                    let captured = captured.clone();
                    async move {
                        captured.lock().expect("captured").push(body);
                        axum::http::StatusCode::ACCEPTED
                    }
                }),
            )
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let address = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let registry = build_audit_forwarder_registry(&AuditForwarderConfig {
            enabled: true,
            provider: AuditForwarderProvider::Webhook,
            timeout_ms: 3_000,
            webhook: WebhookAuditForwarderConfig {
                endpoint: format!("http://{address}/audit/siem"),
                ..WebhookAuditForwarderConfig::default()
            },
            ..AuditForwarderConfig::default()
        })
        .expect("registry");

        let receipt = registry
            .forward_active(&sample_request())
            .await
            .expect("forward")
            .expect("enabled receipt");

        assert_eq!(receipt.provider, "webhook");
        let bodies = captured.lock().expect("captured");
        assert_eq!(bodies.len(), 1);
        assert_eq!(
            bodies[0]["event"]["target"]["resource_id"],
            serde_json::Value::String("snapshot-a".into())
        );
    }

    #[tokio::test]
    async fn disabled_registry_skips_delivery() {
        let registry =
            build_audit_forwarder_registry(&AuditForwarderConfig::default()).expect("registry");

        assert!(
            registry
                .forward_active(&sample_request())
                .await
                .expect("disabled")
                .is_none()
        );
    }
}
