use axum::{Json, extract::State, routing::post};
use chrono::Utc;
use futures_util::stream;
use http::HeaderMap;
use sdqp_api::watermark_grpc::watermark_detection_service_server;
use sdqp_contracts::proto::watermark::{
    BatchScanRequest, DetectWatermarksRequest, DlpAction, DlpDisposition, DlpInspectionContext,
    DlpPolicyEvaluationRequest, DlpProviderConfig, DlpProviderKind, VerifyWatermarkRequest,
    WatermarkContentFormat, WatermarkRequestScope,
    watermark_detection_service_client::WatermarkDetectionServiceClient,
};
use sdqp_watermark::{
    WatermarkContentFormat as DomainContentFormat, WatermarkPayload, embed_marker,
    embed_marker_bytes, encode_payload,
};
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tonic::transport::Server;

struct GrpcServerHandle {
    endpoint: String,
    shutdown: Option<oneshot::Sender<()>>,
}

impl Drop for GrpcServerHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

async fn spawn_watermark_grpc_server() -> GrpcServerHandle {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind grpc listener");
    let addr = listener.local_addr().expect("listener addr");
    let incoming = stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    tokio::spawn(async move {
        Server::builder()
            .add_service(watermark_detection_service_server())
            .serve_with_incoming_shutdown(incoming, async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("watermark grpc server");
    });

    GrpcServerHandle {
        endpoint: format!("http://{addr}"),
        shutdown: Some(shutdown_tx),
    }
}

async fn spawn_dlp_webhook() -> (String, mpsc::Receiver<serde_json::Value>) {
    #[derive(Clone)]
    struct WebhookState {
        sender: mpsc::Sender<serde_json::Value>,
    }

    async fn handler(
        State(state): State<WebhookState>,
        headers: HeaderMap,
        Json(payload): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        assert_eq!(
            headers
                .get("x-dlp-token")
                .and_then(|value| value.to_str().ok()),
            Some("dlp-secret")
        );
        state.sender.send(payload).await.expect("capture payload");
        Json(serde_json::json!({
            "action": "quarantine",
            "policy_version": "enterprise-dlp-2026.04",
            "reasons": ["external DLP policy requires quarantine for verified SDQP watermark"],
            "attributes": {
                "provider.ticket": "DLP-42",
                "provider.rule": "sensitive-export-watermark"
            },
            "enforcement_ttl_seconds": 900
        }))
    }

    let (sender, receiver) = mpsc::channel(1);
    let app = axum::Router::new()
        .route("/dlp/policy", post(handler))
        .with_state(WebhookState { sender });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("dlp bind");
    let addr = listener.local_addr().expect("dlp addr");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("dlp webhook server");
    });
    (format!("http://{addr}/dlp/policy"), receiver)
}

fn sample_payload(sequence_number: u64) -> WatermarkPayload {
    WatermarkPayload {
        tenant_id: "tenant-alpha".into(),
        project_id: "project-alpha".into(),
        user_id: "user-analyst".into(),
        sequence_number,
        issued_at: Utc::now(),
        snapshot_id: Some("snapshot-grpc".into()),
    }
}

fn minimal_pdf() -> Vec<u8> {
    b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000068 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n117\n%%EOF\n"
        .to_vec()
}

fn dlp_context(correlation_id: &str) -> DlpInspectionContext {
    DlpInspectionContext {
        caller_system: "external-dlp-gateway".into(),
        policy_id: "policy-sensitive-export".into(),
        source_uri: "dlp://mail-gateway/message-42/attachment-1".into(),
        correlation_id: correlation_id.into(),
        scope: Some(WatermarkRequestScope {
            tenant_id: "tenant-alpha".into(),
            project_id: "project-alpha".into(),
            user_id: "user-analyst".into(),
        }),
        attributes: [
            ("dlp.channel".into(), "email".into()),
            ("dlp.policy_action".into(), "quarantine".into()),
        ]
        .into_iter()
        .collect(),
    }
}

#[tokio::test]
async fn uat_standalone_watermark_grpc_detects_verifies_and_batch_scans_for_dlp() {
    let server = spawn_watermark_grpc_server().await;
    let mut client = WatermarkDetectionServiceClient::connect(server.endpoint.clone())
        .await
        .expect("grpc client");

    let token = encode_payload(&sample_payload(51)).expect("token");
    let pdf = embed_marker_bytes(&minimal_pdf(), &token, DomainContentFormat::Pdf);
    let detect = client
        .detect_watermarks(DetectWatermarksRequest {
            document: Some(sdqp_contracts::proto::watermark::WatermarkDocument {
                document_id: "pdf-export-1".into(),
                content: pdf.clone(),
                content_format: WatermarkContentFormat::Pdf as i32,
                media_type: "application/pdf".into(),
                inspection_context: Some(dlp_context("corr-detect-1")),
            }),
            include_payload: true,
        })
        .await
        .expect("detect response")
        .into_inner();

    assert!(detect.scan_id.starts_with("wm-scan-"));
    assert_eq!(detect.document_id, "pdf-export-1");
    assert_eq!(
        detect
            .inspection_context
            .as_ref()
            .expect("dlp context")
            .caller_system,
        "external-dlp-gateway"
    );
    assert_eq!(detect.disposition, DlpDisposition::WatermarkVerified as i32);
    assert_eq!(detect.matches.len(), 1);
    assert_eq!(
        detect.matches[0].algorithm,
        "pdf_metadata_object_carrier_v1"
    );
    assert_eq!(
        detect.matches[0]
            .payload
            .as_ref()
            .expect("payload view")
            .tenant_id,
        "tenant-alpha"
    );
    assert_eq!(
        detect
            .summary
            .as_ref()
            .expect("summary")
            .carrier_match_count,
        1
    );

    let verify = client
        .verify_watermark(VerifyWatermarkRequest {
            document: Some(sdqp_contracts::proto::watermark::WatermarkDocument {
                document_id: "pdf-export-1".into(),
                content: pdf,
                content_format: WatermarkContentFormat::Pdf as i32,
                media_type: "application/pdf".into(),
                inspection_context: Some(dlp_context("corr-verify-1")),
            }),
            expected_token: token.clone(),
            include_payload: false,
        })
        .await
        .expect("verify response")
        .into_inner();

    let verify_summary = verify.summary.as_ref().expect("verify summary");
    assert!(verify_summary.verified);
    assert!(verify_summary.expected_token_matched);
    assert_eq!(verify.disposition, DlpDisposition::WatermarkVerified as i32);
    assert!(verify.matches[0].payload.is_none());

    let text_token = encode_payload(&sample_payload(52)).expect("text token");
    let batch = client
        .batch_scan(BatchScanRequest {
            documents: vec![
                sdqp_contracts::proto::watermark::WatermarkDocument {
                    document_id: "marked-text".into(),
                    content: embed_marker("marked body", &text_token).into_bytes(),
                    content_format: WatermarkContentFormat::Text as i32,
                    media_type: "text/plain".into(),
                    inspection_context: Some(dlp_context("corr-batch-1")),
                },
                sdqp_contracts::proto::watermark::WatermarkDocument {
                    document_id: "plain-text".into(),
                    content: b"plain body".to_vec(),
                    content_format: WatermarkContentFormat::Text as i32,
                    media_type: "text/plain".into(),
                    inspection_context: Some(dlp_context("corr-batch-2")),
                },
            ],
            include_payload: false,
        })
        .await
        .expect("batch response")
        .into_inner();

    assert_eq!(batch.reports.len(), 2);
    assert_eq!(
        batch.reports[0].disposition,
        DlpDisposition::WatermarkVerified as i32
    );
    assert_eq!(
        batch.reports[1].disposition,
        DlpDisposition::NoWatermark as i32
    );
    assert_eq!(
        batch
            .aggregate_summary
            .as_ref()
            .expect("aggregate")
            .match_count,
        1
    );

    let (dlp_url, mut dlp_payloads) = spawn_dlp_webhook().await;
    let dlp_pdf = embed_marker_bytes(&minimal_pdf(), &token, DomainContentFormat::Pdf);
    let dlp = client
        .evaluate_dlp_policy(DlpPolicyEvaluationRequest {
            document: Some(sdqp_contracts::proto::watermark::WatermarkDocument {
                document_id: "pdf-export-1".into(),
                content: dlp_pdf,
                content_format: WatermarkContentFormat::Pdf as i32,
                media_type: "application/pdf".into(),
                inspection_context: Some(dlp_context("corr-dlp-1")),
            }),
            include_payload: true,
            expected_token: token.clone(),
            provider_config: Some(DlpProviderConfig {
                provider_id: "enterprise-dlp".into(),
                provider_kind: DlpProviderKind::Webhook as i32,
                webhook_url: dlp_url,
                auth_header: "x-dlp-token".into(),
                auth_token: "dlp-secret".into(),
                timeout_ms: 3_000,
                attributes: [("deployment".into(), "uat".into())].into_iter().collect(),
                default_action: DlpAction::Alert as i32,
            }),
        })
        .await
        .expect("dlp policy response")
        .into_inner();

    let dlp_detection = dlp.detection.as_ref().expect("dlp detection");
    let dlp_decision = dlp.decision.as_ref().expect("dlp decision");
    assert_eq!(
        dlp_detection.disposition,
        DlpDisposition::WatermarkVerified as i32
    );
    assert_eq!(dlp_decision.provider_id, "enterprise-dlp");
    assert_eq!(dlp_decision.provider_kind, DlpProviderKind::Webhook as i32);
    assert_eq!(dlp_decision.action, DlpAction::Quarantine as i32);
    assert!(dlp_decision.callback_delivered);
    assert!(dlp_decision.enforcement_required);
    assert_eq!(dlp_decision.enforcement_ttl_seconds, 900);
    assert_eq!(
        dlp_decision.attributes.get("provider.ticket"),
        Some(&"DLP-42".to_string())
    );

    let observed = dlp_payloads.recv().await.expect("webhook payload");
    assert_eq!(
        observed["inspection_context"]["caller_system"].as_str(),
        Some("external-dlp-gateway")
    );
    assert_eq!(
        observed["inspection_context"]["policy_id"].as_str(),
        Some("policy-sensitive-export")
    );
    assert_eq!(
        observed["inspection_context"]["correlation_id"].as_str(),
        Some("corr-dlp-1")
    );
    assert_eq!(
        observed["detection"]["disposition"].as_str(),
        Some("watermark_verified")
    );
    assert_eq!(observed["recommended_action"].as_str(), Some("quarantine"));
}
