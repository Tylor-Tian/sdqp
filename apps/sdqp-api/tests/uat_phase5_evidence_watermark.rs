use std::{io::Write, time::Duration};

use axum::body::{Body, to_bytes};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use http::{Method, Request, StatusCode, header};
use sdqp_api::{
    BatchScanResponse, EvidenceExportResponse, ExportDownloadAuthorizationResponse, LoginResponse,
    QuerySubmitResponse, QueryTaskStatusResponse, TokenPairResponse, WatermarkDetectResponse,
    WatermarkVerifyResponse, build_router,
};
use sdqp_system_security::{
    MfaProviderConfig, MfaProviderRegistry, TotpProviderConfig, WebAuthnProviderConfig,
};
use sdqp_test_kit::sample_settings;
use sdqp_watermark::{WatermarkContentFormat, embed_marker_bytes};
use tower::ServiceExt;

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1A\n";

fn png_chunk(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
    use crc32fast::hash as crc32;

    let mut output = Vec::with_capacity(12 + data.len());
    output.extend_from_slice(&(data.len() as u32).to_be_bytes());
    output.extend_from_slice(chunk_type);
    output.extend_from_slice(data);

    let mut crc_input = Vec::with_capacity(chunk_type.len() + data.len());
    crc_input.extend_from_slice(chunk_type);
    crc_input.extend_from_slice(data);
    output.extend_from_slice(&crc32(&crc_input).to_be_bytes());
    output
}

fn zip_local_file(name: &str, data: &[u8]) -> Vec<u8> {
    use crc32fast::hash as crc32;

    let name_bytes = name.as_bytes();
    let data_len = u32::try_from(data.len()).expect("zip data len");
    let mut output = Vec::with_capacity(30 + name_bytes.len() + data.len());
    output.extend_from_slice(&0x0403_4B50_u32.to_le_bytes());
    output.extend_from_slice(&20_u16.to_le_bytes());
    output.extend_from_slice(&(1_u16 << 11).to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&crc32(data).to_le_bytes());
    output.extend_from_slice(&data_len.to_le_bytes());
    output.extend_from_slice(&data_len.to_le_bytes());
    output.extend_from_slice(
        &u16::try_from(name_bytes.len())
            .expect("zip name len")
            .to_le_bytes(),
    );
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(name_bytes);
    output.extend_from_slice(data);
    output
}

fn zip_central_directory(name: &str, data: &[u8], local_offset: u32) -> Vec<u8> {
    use crc32fast::hash as crc32;

    let name_bytes = name.as_bytes();
    let data_len = u32::try_from(data.len()).expect("zip data len");
    let mut output = Vec::with_capacity(46 + name_bytes.len());
    output.extend_from_slice(&0x0201_4B50_u32.to_le_bytes());
    output.extend_from_slice(&20_u16.to_le_bytes());
    output.extend_from_slice(&20_u16.to_le_bytes());
    output.extend_from_slice(&(1_u16 << 11).to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&crc32(data).to_le_bytes());
    output.extend_from_slice(&data_len.to_le_bytes());
    output.extend_from_slice(&data_len.to_le_bytes());
    output.extend_from_slice(
        &u16::try_from(name_bytes.len())
            .expect("zip name len")
            .to_le_bytes(),
    );
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&0_u32.to_le_bytes());
    output.extend_from_slice(&local_offset.to_le_bytes());
    output.extend_from_slice(name_bytes);
    output
}

fn minimal_ooxml_workbook() -> Vec<u8> {
    let entries = [
        (
            "[Content_Types].xml",
            br#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>"#
                .as_slice(),
        ),
        (
            "xl/workbook.xml",
            br#"<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>"#
                .as_slice(),
        ),
    ];

    let mut local_records = Vec::new();
    let mut central_records = Vec::new();
    let mut cursor = 0_u32;
    for (name, data) in entries {
        let local = zip_local_file(name, data);
        central_records.push(zip_central_directory(name, data, cursor));
        cursor += u32::try_from(local.len()).expect("local len");
        local_records.push(local);
    }

    let central_directory_offset = cursor;
    let mut output = Vec::new();
    for local in local_records {
        output.extend_from_slice(&local);
    }
    let mut central_directory = Vec::new();
    for record in central_records {
        central_directory.extend_from_slice(&record);
    }
    let central_directory_size = u32::try_from(central_directory.len()).expect("central dir size");
    output.extend_from_slice(&central_directory);
    output.extend_from_slice(&0x0605_4B50_u32.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(
        &u16::try_from(entries.len())
            .expect("entry count")
            .to_le_bytes(),
    );
    output.extend_from_slice(
        &u16::try_from(entries.len())
            .expect("entry count")
            .to_le_bytes(),
    );
    output.extend_from_slice(&central_directory_size.to_le_bytes());
    output.extend_from_slice(&central_directory_offset.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output
}

fn medium_png(width: u32, height: u32) -> Vec<u8> {
    use flate2::{Compression, write::ZlibEncoder};

    let mut scanlines = Vec::new();
    for y in 0..height {
        scanlines.push(0);
        for x in 0..width {
            let red = ((x * 255) / width.max(1)) as u8;
            let green = ((y * 255) / height.max(1)) as u8;
            let blue = red.wrapping_add(green / 2).wrapping_add(24);
            scanlines.extend_from_slice(&[red, green, blue, 255]);
        }
    }

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&scanlines).expect("scanlines");
    let compressed = encoder.finish().expect("compressed");

    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);

    let mut output = Vec::from(PNG_SIGNATURE.as_slice());
    output.extend_from_slice(&png_chunk(b"IHDR", &ihdr));
    output.extend_from_slice(&png_chunk(b"IDAT", &compressed));
    output.extend_from_slice(&png_chunk(b"IEND", &[]));
    output
}

fn minimal_pdf() -> Vec<u8> {
    b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000068 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n117\n%%EOF\n"
        .to_vec()
}

async fn json_request(
    app: axum::Router,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
    headers: &[(&str, &str)],
) -> http::Response<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }

    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
        None => builder.body(Body::empty()).expect("request"),
    };

    app.oneshot(request).await.expect("response")
}

async fn decode_json<T: serde::de::DeserializeOwned>(response: http::Response<Body>) -> T {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

async fn analyst_tokens(app: axum::Router) -> TokenPairResponse {
    let settings = sample_settings();
    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            Some(serde_json::json!({
                "username": "analyst",
                "password": "password123",
                "device_fingerprint": "device-phase5"
            })),
            &[("x-forwarded-for", "127.0.0.1")],
        )
        .await,
    )
    .await;

    let registry = MfaProviderRegistry::new(MfaProviderConfig {
        bootstrap_seed: settings.security.mfa_bootstrap_seed.clone(),
        challenge_ttl_secs: settings.security.mfa_challenge_ttl_secs,
        totp: TotpProviderConfig {
            issuer: settings.security.totp_issuer.clone(),
            period_secs: settings.security.totp_period_secs,
            digits: settings.security.totp_digits,
            allowed_drift_steps: settings.security.totp_allowed_drift_steps,
        },
        webauthn: WebAuthnProviderConfig {
            rp_id: settings.security.webauthn_rp_id.clone(),
            origin: settings.security.webauthn_origin.clone(),
            timeout_ms: settings.security.webauthn_timeout_ms,
            challenge_ttl_secs: settings.security.mfa_challenge_ttl_secs,
            require_user_verification: settings.security.webauthn_require_user_verification,
        },
    });
    let mfa_code =
        registry.bootstrap_totp_code_at("tenant-alpha", "user-analyst", "analyst", Utc::now());

    decode_json(
        json_request(
            app,
            Method::POST,
            "/auth/mfa/verify",
            Some(serde_json::json!({
                "pending_session_id": login.pending_session_id,
                "code": mfa_code
            })),
            &[],
        )
        .await,
    )
    .await
}

fn scoped_headers(token: &str) -> [(&str, &str); 3] {
    [
        ("authorization", token),
        ("x-tenant-id", "tenant-alpha"),
        ("x-project-id", "project-alpha"),
    ]
}

async fn wait_for_completed_snapshot(app: axum::Router, token: &str, fields: &[&str]) -> String {
    let submit: QuerySubmitResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "source_type": "rest",
                "fields": fields
            })),
            &scoped_headers(token),
        )
        .await,
    )
    .await;

    for _ in 0..40 {
        let status: QueryTaskStatusResponse = decode_json(
            json_request(
                app.clone(),
                Method::GET,
                &format!("/v1/tasks/{}/status", submit.task_id),
                None,
                &scoped_headers(token),
            )
            .await,
        )
        .await;

        if status.state == "completed" {
            return status.snapshot_id.expect("snapshot id");
        }

        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    panic!("query did not complete")
}

#[tokio::test]
async fn uat_evidence_export_contains_verifiable_watermark_and_timestamp() {
    let app = build_router(sample_settings().api);
    let tokens = analyst_tokens(app.clone()).await;
    let bearer = format!("Bearer {}", tokens.access_token);
    let snapshot_id = wait_for_completed_snapshot(app.clone(), &bearer, &["employee_id"]).await;

    let export = json_request(
        app.clone(),
        Method::POST,
        "/v1/exports/evidence",
        Some(serde_json::json!({
            "snapshot_id": snapshot_id,
            "template": "china"
        })),
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(export.status(), StatusCode::OK);
    let export: EvidenceExportResponse = decode_json(export).await;

    assert!(!export.exported_document.contains("[[SDQP-WM:"));
    assert!(export.audit_chain_valid);
    assert!(export.verification_ready);
    assert!(export.download_ready);
    assert_eq!(export.status, "completed");
    assert_eq!(export.timestamp_authority, "mock-tsa");
    assert_eq!(export.anchor_network, "mock-chain");
    assert_eq!(export.recipient_user_id, "user-analyst");
    assert_eq!(export.audit_extract_event_count, export.audit_event_count);
    assert!(!export.anchor_transaction_id.is_empty());

    let task_status: EvidenceExportResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/exports/tasks/{}", export.task_id),
            None,
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert_eq!(task_status.package_id, export.package_id);

    let download_auth: ExportDownloadAuthorizationResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            &format!("/v1/exports/tasks/{}/authorize-download", export.task_id),
            Some(serde_json::json!({
                "ttl_seconds": 300
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;

    let download_response = json_request(
        app.clone(),
        Method::GET,
        &format!("/v1/exports/download/{}", download_auth.download_token),
        None,
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(download_response.status(), StatusCode::OK);
    let downloaded_package = String::from_utf8(
        to_bytes(download_response.into_body(), usize::MAX)
            .await
            .expect("download body")
            .to_vec(),
    )
    .expect("downloaded text");
    let downloaded_package: serde_json::Value =
        serde_json::from_str(&downloaded_package).expect("downloaded package json");
    assert_eq!(
        downloaded_package["package_id"].as_str(),
        Some(export.package_id.as_str())
    );
    assert_eq!(
        downloaded_package["data_payload"]["recipient"]["user_id"].as_str(),
        Some("user-analyst")
    );

    let detect: WatermarkDetectResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/watermarks/detect",
            Some(serde_json::json!({
                "content": export.exported_document
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert_eq!(detect.matches.len(), 1);
    assert!(detect.matches[0].verified);
    assert_eq!(detect.algorithm_match_count, 1);
    assert_eq!(detect.carrier_match_count, 0);

    let verify: WatermarkVerifyResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/watermarks/verify",
            Some(serde_json::json!({
                "content": export.exported_document,
                "expected_token": export.watermark_token
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert!(verify.verified);
    assert!(verify.algorithm_verified);
    assert_eq!(verify.algorithm_match_count, 1);
    assert!(
        verify.matches[0]
            .overlay_text
            .as_deref()
            .is_some_and(|value| value.contains("tenant-alpha / project-alpha / user-analyst"))
    );
    assert_eq!(verify.matches[0].implementation_tier, "algorithm");

    let pdf_payload = STANDARD.encode(format!("%PDF-1.7\n{}", export.exported_document));
    let pdf_detect: WatermarkDetectResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/watermarks/detect",
            Some(serde_json::json!({
                "content_base64": pdf_payload,
                "content_format": "pdf"
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert_eq!(pdf_detect.matches.len(), 1);
    assert_eq!(pdf_detect.algorithm_match_count, 1);

    let native_pdf_bytes = embed_marker_bytes(
        &minimal_pdf(),
        &export.watermark_token,
        WatermarkContentFormat::Pdf,
    );
    let native_pdf_detect: WatermarkDetectResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/watermarks/detect",
            Some(serde_json::json!({
                "content_base64": STANDARD.encode(native_pdf_bytes.clone()),
                "content_format": "pdf"
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert_eq!(native_pdf_detect.matches.len(), 1);
    assert_eq!(native_pdf_detect.algorithm_match_count, 0);
    assert_eq!(native_pdf_detect.carrier_match_count, 1);
    assert_eq!(
        native_pdf_detect.matches[0].algorithm,
        "pdf_metadata_object_carrier_v1"
    );

    let native_pdf_verify: WatermarkVerifyResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/watermarks/verify",
            Some(serde_json::json!({
                "content_base64": STANDARD.encode(native_pdf_bytes),
                "content_format": "pdf",
                "expected_token": export.watermark_token.clone()
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert!(native_pdf_verify.verified);
    assert!(!native_pdf_verify.algorithm_verified);

    let png_bytes = embed_marker_bytes(
        &medium_png(256, 256),
        &export.watermark_token,
        WatermarkContentFormat::Image,
    );
    let png_detect: WatermarkDetectResponse = decode_json(
        json_request(
            app,
            Method::POST,
            "/v1/watermarks/detect",
            Some(serde_json::json!({
                "content_base64": STANDARD.encode(png_bytes),
                "content_format": "image"
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert_eq!(png_detect.matches.len(), 1);
    assert_eq!(png_detect.algorithm_match_count, 1);
    assert_eq!(png_detect.matches[0].algorithm, "png_frequency_dct_v1");
}

#[tokio::test]
async fn uat_batch_scan_distinguishes_marked_and_plain_documents() {
    let app = build_router(sample_settings().api);
    let tokens = analyst_tokens(app.clone()).await;
    let bearer = format!("Bearer {}", tokens.access_token);
    let snapshot_id = wait_for_completed_snapshot(app.clone(), &bearer, &["employee_id"]).await;

    let export: EvidenceExportResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/exports/evidence",
            Some(serde_json::json!({
                "snapshot_id": snapshot_id,
                "template": "us"
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;

    let response = json_request(
        app.clone(),
        Method::POST,
        "/v1/watermarks/batch_scan",
        Some(serde_json::json!({
            "documents": [
                {
                    "document_id": "marked",
                    "content": export.exported_document
                },
                {
                    "document_id": "plain",
                    "content": "no watermark in this document"
                }
            ]
        })),
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let batch: BatchScanResponse = decode_json(response).await;

    assert_eq!(batch.reports.len(), 2);
    assert!(batch.reports[0].verified);
    assert!(batch.reports[0].algorithm_verified);
    assert!(!batch.reports[1].verified);

    let binary_batch = json_request(
        app,
        Method::POST,
        "/v1/watermarks/batch_scan",
        Some(serde_json::json!({
            "documents": [
                {
                    "document_id": "pdf",
                    "content_base64": STANDARD.encode(format!("%PDF-1.7\n{}", export.exported_document)),
                    "content_format": "pdf"
                },
                {
                    "document_id": "image",
                    "content_base64": STANDARD.encode(vec![0x89u8, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]),
                    "content_format": "image"
                }
            ]
        })),
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(binary_batch.status(), StatusCode::OK);
    let binary_batch: BatchScanResponse = decode_json(binary_batch).await;
    assert!(binary_batch.reports[0].verified);
    assert!(!binary_batch.reports[1].verified);
    assert_eq!(binary_batch.reports[0].algorithm_match_count, 1);
}

#[tokio::test]
async fn uat_detects_ooxml_watermarks_via_phase5_api() {
    let app = build_router(sample_settings().api);
    let tokens = analyst_tokens(app.clone()).await;
    let bearer = format!("Bearer {}", tokens.access_token);
    let snapshot_id = wait_for_completed_snapshot(app.clone(), &bearer, &["employee_id"]).await;

    let export: EvidenceExportResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/exports/evidence",
            Some(serde_json::json!({
                "snapshot_id": snapshot_id,
                "template": "us"
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;

    let office_bytes = embed_marker_bytes(
        &minimal_ooxml_workbook(),
        &export.watermark_token,
        WatermarkContentFormat::Office,
    );
    let office_base64 = STANDARD.encode(office_bytes);

    let detect: WatermarkDetectResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/watermarks/detect",
            Some(serde_json::json!({
                "content_base64": office_base64.clone(),
                "content_format": "office"
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert_eq!(detect.matches.len(), 1);
    assert_eq!(detect.matches[0].content_format, "office");
    assert_eq!(detect.matches[0].algorithm, "ooxml_custom_xml_carrier_v1");
    assert_eq!(detect.algorithm_match_count, 0);
    assert_eq!(detect.carrier_match_count, 1);

    let verify: WatermarkVerifyResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/watermarks/verify",
            Some(serde_json::json!({
                "content_base64": office_base64.clone(),
                "content_format": "office",
                "expected_token": export.watermark_token.clone()
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert!(verify.verified);
    assert!(!verify.algorithm_verified);
    assert_eq!(verify.matches[0].implementation_tier, "carrier");

    let batch: BatchScanResponse = decode_json(
        json_request(
            app,
            Method::POST,
            "/v1/watermarks/batch_scan",
            Some(serde_json::json!({
                "documents": [
                    {
                        "document_id": "office",
                        "content_base64": office_base64,
                        "content_format": "office"
                    }
                ]
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert!(batch.reports[0].verified);
    assert_eq!(batch.reports[0].carrier_match_count, 1);
}
