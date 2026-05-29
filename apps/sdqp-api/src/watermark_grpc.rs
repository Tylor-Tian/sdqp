use std::{net::SocketAddr, str::FromStr};

use sdqp_contracts::proto::watermark::{
    BatchScanRequest, BatchScanResponse, DetectWatermarksRequest, DetectWatermarksResponse,
    DlpDisposition, DlpPolicyEvaluationRequest, DlpPolicyEvaluationResponse,
    VerifyWatermarkRequest, VerifyWatermarkResponse, WatermarkContentFormat as ProtoContentFormat,
    WatermarkDetectionSummary, WatermarkDocument,
    WatermarkImplementationTier as ProtoImplementationTier, WatermarkMatch, WatermarkPayloadView,
    watermark_detection_service_server::{
        WatermarkDetectionService, WatermarkDetectionServiceServer,
    },
};
use sdqp_watermark::{
    BatchByteScanInput, BatchScanReport, DetectedWatermark, WatermarkAlgorithm as DomainAlgorithm,
    WatermarkContentFormat as DomainContentFormat,
    WatermarkImplementationTier as DomainImplementationTier, batch_scan_bytes,
    detect_markers_in_bytes_with_format, verify_bytes_with_format,
};
use tonic::{Request, Response, Status, transport::Server};

use crate::dlp::DlpPolicyProviderRegistry;

#[derive(Debug, Clone, Default)]
pub struct WatermarkDetectionGrpcService {
    dlp_provider_registry: DlpPolicyProviderRegistry,
}

pub type StandaloneWatermarkDetectionServer =
    WatermarkDetectionServiceServer<WatermarkDetectionGrpcService>;

pub fn watermark_detection_service_server() -> StandaloneWatermarkDetectionServer {
    WatermarkDetectionServiceServer::new(WatermarkDetectionGrpcService::default())
}

pub fn watermark_detection_service_server_with_dlp_registry(
    dlp_provider_registry: DlpPolicyProviderRegistry,
) -> StandaloneWatermarkDetectionServer {
    WatermarkDetectionServiceServer::new(WatermarkDetectionGrpcService {
        dlp_provider_registry,
    })
}

pub async fn run_standalone_watermark_grpc(
    addr: SocketAddr,
) -> Result<(), tonic::transport::Error> {
    tracing::info!("sdqp-watermark-grpc listening on {}", addr);
    Server::builder()
        .add_service(watermark_detection_service_server())
        .serve(addr)
        .await
}

#[tonic::async_trait]
impl WatermarkDetectionService for WatermarkDetectionGrpcService {
    async fn detect_watermarks(
        &self,
        request: Request<DetectWatermarksRequest>,
    ) -> Result<Response<DetectWatermarksResponse>, Status> {
        let request = request.into_inner();
        let document = request
            .document
            .ok_or_else(|| Status::invalid_argument("document is required"))?;
        let response = detect_document(&document, request.include_payload)?;
        Ok(Response::new(response))
    }

    async fn verify_watermark(
        &self,
        request: Request<VerifyWatermarkRequest>,
    ) -> Result<Response<VerifyWatermarkResponse>, Status> {
        let request = request.into_inner();
        let document = request
            .document
            .ok_or_else(|| Status::invalid_argument("document is required"))?;
        if request.expected_token.trim().is_empty() {
            return Err(Status::invalid_argument("expected_token is required"));
        }

        let domain_format = resolve_document_format(&document)?;
        let report = verify_bytes_with_format(
            &document.content,
            domain_format,
            Some(request.expected_token.as_str()),
        );
        let expected_token_matched = report.matches.iter().any(|match_result| {
            match_result.verified && match_result.token == request.expected_token
        });
        let summary = summarize_matches(
            &report.matches,
            report.algorithm_verified,
            Some(expected_token_matched),
        );
        let disposition = disposition_for_summary(&summary);
        let response = VerifyWatermarkResponse {
            scan_id: new_scan_id(),
            document_id: document.document_id.clone(),
            inspection_context: document.inspection_context.clone(),
            matches: report
                .matches
                .iter()
                .map(|match_result| to_proto_match(match_result, request.include_payload))
                .collect(),
            summary: Some(summary),
            disposition: disposition as i32,
        };

        Ok(Response::new(response))
    }

    async fn batch_scan(
        &self,
        request: Request<BatchScanRequest>,
    ) -> Result<Response<BatchScanResponse>, Status> {
        let request = request.into_inner();
        if request.documents.is_empty() {
            return Err(Status::invalid_argument("documents must not be empty"));
        }

        let mut scan_inputs = Vec::with_capacity(request.documents.len());
        for document in &request.documents {
            ensure_document_has_content(document)?;
            scan_inputs.push(BatchByteScanInput {
                document_id: document.document_id.clone(),
                format: resolve_document_format(document)?,
                content: document.content.clone(),
            });
        }

        let batch_reports = batch_scan_bytes(&scan_inputs);
        let reports = batch_reports
            .iter()
            .zip(request.documents.iter())
            .map(|(report, document)| {
                batch_report_to_detection_response(report, document, request.include_payload)
            })
            .collect::<Vec<_>>();
        let aggregate_summary = aggregate_report_summaries(&reports);

        Ok(Response::new(BatchScanResponse {
            reports,
            aggregate_summary: Some(aggregate_summary),
        }))
    }

    async fn evaluate_dlp_policy(
        &self,
        request: Request<DlpPolicyEvaluationRequest>,
    ) -> Result<Response<DlpPolicyEvaluationResponse>, Status> {
        let response =
            evaluate_dlp_policy_request(&self.dlp_provider_registry, request.into_inner()).await?;
        Ok(Response::new(response))
    }
}

fn detect_document(
    document: &WatermarkDocument,
    include_payload: bool,
) -> Result<DetectWatermarksResponse, Status> {
    ensure_document_has_content(document)?;
    let domain_format = resolve_document_format(document)?;
    let matches = detect_markers_in_bytes_with_format(&document.content, domain_format);
    let summary = summarize_matches(&matches, algorithm_verified(&matches), None);
    let disposition = disposition_for_summary(&summary);

    Ok(DetectWatermarksResponse {
        scan_id: new_scan_id(),
        document_id: document.document_id.clone(),
        inspection_context: document.inspection_context.clone(),
        matches: matches
            .iter()
            .map(|match_result| to_proto_match(match_result, include_payload))
            .collect(),
        summary: Some(summary),
        disposition: disposition as i32,
    })
}

pub async fn evaluate_dlp_policy_request(
    dlp_provider_registry: &DlpPolicyProviderRegistry,
    request: DlpPolicyEvaluationRequest,
) -> Result<DlpPolicyEvaluationResponse, Status> {
    let document = request
        .document
        .ok_or_else(|| Status::invalid_argument("document is required"))?;
    let detection = detect_document_for_policy(
        &document,
        request.include_payload,
        non_empty_token(request.expected_token.as_str()),
    )?;
    let decision = dlp_provider_registry
        .evaluate(request.provider_config, &detection)
        .await
        .map_err(|error| error.into_status())?;

    Ok(DlpPolicyEvaluationResponse {
        detection: Some(detection),
        decision: Some(decision),
    })
}

pub fn detect_document_for_policy(
    document: &WatermarkDocument,
    include_payload: bool,
    expected_token: Option<&str>,
) -> Result<DetectWatermarksResponse, Status> {
    ensure_document_has_content(document)?;
    let domain_format = resolve_document_format(document)?;
    let (matches, algorithm_verified, expected_token_matched) =
        if let Some(expected_token) = expected_token {
            let report =
                verify_bytes_with_format(&document.content, domain_format, Some(expected_token));
            let expected_token_matched = report
                .matches
                .iter()
                .any(|match_result| match_result.verified && match_result.token == expected_token);
            let algorithm_verified = report.algorithm_verified;
            (
                report.matches,
                algorithm_verified,
                Some(expected_token_matched),
            )
        } else {
            let matches = detect_markers_in_bytes_with_format(&document.content, domain_format);
            let algorithm_verified = algorithm_verified(&matches);
            (matches, algorithm_verified, None)
        };
    let summary = summarize_matches(&matches, algorithm_verified, expected_token_matched);
    let disposition = disposition_for_summary(&summary);

    Ok(DetectWatermarksResponse {
        scan_id: new_scan_id(),
        document_id: document.document_id.clone(),
        inspection_context: document.inspection_context.clone(),
        matches: matches
            .iter()
            .map(|match_result| to_proto_match(match_result, include_payload))
            .collect(),
        summary: Some(summary),
        disposition: disposition as i32,
    })
}

fn non_empty_token(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn batch_report_to_detection_response(
    report: &BatchScanReport,
    document: &WatermarkDocument,
    include_payload: bool,
) -> DetectWatermarksResponse {
    let summary = summarize_matches(&report.matches, report.algorithm_verified, None);
    let disposition = disposition_for_summary(&summary);
    DetectWatermarksResponse {
        scan_id: new_scan_id(),
        document_id: report.document_id.clone(),
        inspection_context: document.inspection_context.clone(),
        matches: report
            .matches
            .iter()
            .map(|match_result| to_proto_match(match_result, include_payload))
            .collect(),
        summary: Some(summary),
        disposition: disposition as i32,
    }
}

fn ensure_document_has_content(document: &WatermarkDocument) -> Result<(), Status> {
    if document.content.is_empty() {
        return Err(Status::invalid_argument(
            "document content must not be empty",
        ));
    }
    Ok(())
}

fn resolve_document_format(document: &WatermarkDocument) -> Result<DomainContentFormat, Status> {
    let proto_format = ProtoContentFormat::try_from(document.content_format)
        .map_err(|_| Status::invalid_argument("unknown content_format"))?;
    match proto_format {
        ProtoContentFormat::Unspecified => Ok(infer_document_format(
            &document.content,
            document.media_type.as_str(),
        )),
        ProtoContentFormat::Text => Ok(DomainContentFormat::Text),
        ProtoContentFormat::Pdf => Ok(DomainContentFormat::Pdf),
        ProtoContentFormat::Office => Ok(DomainContentFormat::Office),
        ProtoContentFormat::Image => Ok(DomainContentFormat::Image),
        ProtoContentFormat::Binary => Ok(DomainContentFormat::Binary),
    }
}

fn infer_document_format(content: &[u8], media_type: &str) -> DomainContentFormat {
    if let Some(format) = DomainContentFormat::parse(media_type) {
        return format;
    }
    if content.starts_with(b"%PDF") {
        DomainContentFormat::Pdf
    } else if content.starts_with(b"\x89PNG\r\n\x1A\n") || content.starts_with(&[0xFF, 0xD8]) {
        DomainContentFormat::Image
    } else if looks_like_ooxml(content) {
        DomainContentFormat::Office
    } else if std::str::from_utf8(content).is_ok() {
        DomainContentFormat::Text
    } else {
        DomainContentFormat::Binary
    }
}

fn looks_like_ooxml(content: &[u8]) -> bool {
    content.starts_with(b"PK\x03\x04")
        && find_bytes(content, b"[Content_Types].xml").is_some()
        && (find_bytes(content, b"xl/").is_some()
            || find_bytes(content, b"word/").is_some()
            || find_bytes(content, b"ppt/").is_some())
}

fn find_bytes(content: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || content.len() < needle.len() {
        return None;
    }
    content
        .windows(needle.len())
        .position(|window| window == needle)
}

fn summarize_matches(
    matches: &[DetectedWatermark],
    algorithm_verified: bool,
    expected_token_matched: Option<bool>,
) -> WatermarkDetectionSummary {
    let mut algorithm_match_count = 0_u32;
    let mut carrier_match_count = 0_u32;
    let mut legacy_match_count = 0_u32;
    for match_result in matches {
        match match_result.implementation_tier {
            DomainImplementationTier::Algorithm => algorithm_match_count += 1,
            DomainImplementationTier::Carrier => carrier_match_count += 1,
            DomainImplementationTier::Legacy => legacy_match_count += 1,
        }
    }

    let watermark_present = !matches.is_empty();
    let all_matches_verified =
        watermark_present && matches.iter().all(|match_result| match_result.verified);
    let expected_token_matched = expected_token_matched.unwrap_or(true);

    WatermarkDetectionSummary {
        watermark_present,
        verified: all_matches_verified && expected_token_matched,
        algorithm_verified,
        match_count: matches.len() as u32,
        algorithm_match_count,
        carrier_match_count,
        legacy_match_count,
        expected_token_matched,
    }
}

fn aggregate_report_summaries(reports: &[DetectWatermarksResponse]) -> WatermarkDetectionSummary {
    let mut aggregate = WatermarkDetectionSummary {
        expected_token_matched: true,
        ..WatermarkDetectionSummary::default()
    };

    for report in reports {
        let Some(summary) = report.summary.as_ref() else {
            continue;
        };
        aggregate.watermark_present |= summary.watermark_present;
        aggregate.algorithm_verified |= summary.algorithm_verified;
        aggregate.match_count += summary.match_count;
        aggregate.algorithm_match_count += summary.algorithm_match_count;
        aggregate.carrier_match_count += summary.carrier_match_count;
        aggregate.legacy_match_count += summary.legacy_match_count;
        aggregate.expected_token_matched &= summary.expected_token_matched;
    }
    aggregate.verified = aggregate.watermark_present
        && reports.iter().all(|report| {
            report
                .summary
                .as_ref()
                .is_some_and(|summary| !summary.watermark_present || summary.verified)
        });
    aggregate
}

fn disposition_for_summary(summary: &WatermarkDetectionSummary) -> DlpDisposition {
    if !summary.watermark_present {
        DlpDisposition::NoWatermark
    } else if !summary.expected_token_matched {
        DlpDisposition::ExpectedTokenMismatch
    } else if summary.verified {
        DlpDisposition::WatermarkVerified
    } else {
        DlpDisposition::WatermarkUnverified
    }
}

fn algorithm_verified(matches: &[DetectedWatermark]) -> bool {
    matches.iter().any(|match_result| {
        match_result.verified
            && match_result.implementation_tier == DomainImplementationTier::Algorithm
    })
}

fn to_proto_match(match_result: &DetectedWatermark, include_payload: bool) -> WatermarkMatch {
    WatermarkMatch {
        token: match_result.token.clone(),
        verified: match_result.verified,
        overlay_text: match_result.overlay_text.clone().unwrap_or_default(),
        provider: match_result.provider.clone(),
        algorithm: algorithm_label(match_result.algorithm).into(),
        implementation_tier: proto_tier(match_result.implementation_tier) as i32,
        content_format: proto_content_format(match_result.content_format) as i32,
        confidence_percent: u32::from(match_result.confidence_percent),
        payload: include_payload
            .then(|| match_result.payload.as_ref().map(to_proto_payload))
            .flatten(),
    }
}

fn to_proto_payload(payload: &sdqp_watermark::WatermarkPayload) -> WatermarkPayloadView {
    WatermarkPayloadView {
        tenant_id: payload.tenant_id.clone(),
        project_id: payload.project_id.clone(),
        user_id: payload.user_id.clone(),
        sequence_number: payload.sequence_number,
        issued_at: payload.issued_at.to_rfc3339(),
        snapshot_id: payload.snapshot_id.clone().unwrap_or_default(),
    }
}

fn proto_tier(tier: DomainImplementationTier) -> ProtoImplementationTier {
    match tier {
        DomainImplementationTier::Algorithm => ProtoImplementationTier::Algorithm,
        DomainImplementationTier::Carrier => ProtoImplementationTier::Carrier,
        DomainImplementationTier::Legacy => ProtoImplementationTier::Legacy,
    }
}

fn proto_content_format(format: DomainContentFormat) -> ProtoContentFormat {
    match format {
        DomainContentFormat::Text => ProtoContentFormat::Text,
        DomainContentFormat::Pdf => ProtoContentFormat::Pdf,
        DomainContentFormat::Office => ProtoContentFormat::Office,
        DomainContentFormat::Image => ProtoContentFormat::Image,
        DomainContentFormat::Binary => ProtoContentFormat::Binary,
    }
}

fn algorithm_label(algorithm: DomainAlgorithm) -> &'static str {
    match algorithm {
        DomainAlgorithm::ZeroWidthTextV1 => "zero_width_text_v1",
        DomainAlgorithm::PngFrequencyDctV1 => "png_frequency_dct_v1",
        DomainAlgorithm::JpegCoefficientDctV1 => "jpeg_coefficient_dct_v1",
        DomainAlgorithm::PdfMetadataObjectCarrierV1 => "pdf_metadata_object_carrier_v1",
        DomainAlgorithm::PdfCommentCarrierV1 => "pdf_comment_carrier_v1",
        DomainAlgorithm::OoxmlCustomXmlCarrierV1 => "ooxml_custom_xml_carrier_v1",
        DomainAlgorithm::PngChunkCarrierV1 => "png_chunk_carrier_v1",
        DomainAlgorithm::JpegCommentCarrierV1 => "jpeg_comment_carrier_v1",
        DomainAlgorithm::BinaryTrailerCarrierV1 => "binary_trailer_carrier_v1",
        DomainAlgorithm::LegacyTextMarkerV0 => "legacy_text_marker_v0",
    }
}

fn new_scan_id() -> String {
    format!("wm-scan-{}", ulid::Ulid::new())
}

pub fn parse_grpc_addr(value: &str) -> Result<SocketAddr, std::net::AddrParseError> {
    SocketAddr::from_str(value)
}
