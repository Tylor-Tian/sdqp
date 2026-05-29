use std::{
    f64::consts::PI,
    io::{Read, Write},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use crc32fast::hash as crc32;
use flate2::{
    Compression,
    read::{DeflateDecoder, ZlibDecoder},
    write::ZlibEncoder,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const LEGACY_MARKER_PREFIX: &str = "[[SDQP-WM:";
const LEGACY_MARKER_SUFFIX: &str = "]]";
const TEXT_START_SENTINEL: &str = "\u{2060}\u{2063}\u{2060}";
const TEXT_END_SENTINEL: &str = "\u{2060}\u{2062}\u{2060}";
const ZERO_BIT: char = '\u{200B}';
const ONE_BIT: char = '\u{200C}';
const PDF_METADATA_TOKEN_ATTRIBUTE: &[u8] = b"sdqp:token=\"";
const PDF_COMMENT_PREFIX: &[u8] = b"%SDQPWM-B64:";
const BINARY_TRAILER_PREFIX: &[u8] = b"\nSDQPWM-B64:";
const JPEG_SOI: &[u8; 2] = &[0xFF, 0xD8];
const JPEG_COMMENT_MARKER: u8 = 0xFE;
const JPEG_COMMENT_PREFIX: &[u8] = b"SDQPWM:";
const JPEG_DCT_FRAME_MAGIC: &[u8; 4] = b"SDQJ";
const JPEG_DCT_FRAME_VERSION: u8 = 1;
const JPEG_DCT_FRAME_HEADER_SIZE: usize = 7;
const JPEG_DCT_BLOCK_SIZE: usize = 8;
const JPEG_DCT_SPREAD_FACTOR: usize = 3;
const JPEG_DCT_STRENGTH: i16 = 18;
const JPEG_DCT_COEFF_A_INDEX: usize = 10;
const JPEG_DCT_COEFF_B_INDEX: usize = 11;
const ZIP_LOCAL_HEADER_SIGNATURE: u32 = 0x0403_4B50;
const ZIP_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0201_4B50;
const ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4B50;
const ZIP_STORED_METHOD: u16 = 0;
const ZIP_DEFLATE_METHOD: u16 = 8;
const ZIP_UTF8_FLAG: u16 = 1 << 11;
const OOXML_WATERMARK_ENTRY_PATH: &str = "customXml/sdqp-watermark.xml";
const OOXML_TOKEN_ATTRIBUTE: &str = "token=\"";
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1A\n";
const PNG_WATERMARK_CHUNK_TYPE: &[u8; 4] = b"sDWP";
const PNG_DCT_FRAME_MAGIC: &[u8; 4] = b"SDQW";
const PNG_DCT_FRAME_VERSION: u8 = 1;
const PNG_DCT_BLOCK_SIZE: usize = 4;
const PNG_DCT_SPREAD_FACTOR: usize = 2;
const PNG_DCT_STRENGTH: f64 = 18.0;
const PNG_DCT_COEFF_A: (usize, usize) = (1, 2);
const PNG_DCT_COEFF_B: (usize, usize) = (2, 1);
const PNG_DCT_HEADER_SIZE: usize = 7;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatermarkPayload {
    pub tenant_id: String,
    pub project_id: String,
    pub user_id: String,
    pub sequence_number: u64,
    pub issued_at: DateTime<Utc>,
    pub snapshot_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatermarkImplementationTier {
    Algorithm,
    Carrier,
    Legacy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatermarkAlgorithm {
    ZeroWidthTextV1,
    PngFrequencyDctV1,
    JpegCoefficientDctV1,
    PdfMetadataObjectCarrierV1,
    PdfCommentCarrierV1,
    OoxmlCustomXmlCarrierV1,
    PngChunkCarrierV1,
    JpegCommentCarrierV1,
    BinaryTrailerCarrierV1,
    LegacyTextMarkerV0,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedWatermark {
    pub token: String,
    pub verified: bool,
    pub overlay_text: Option<String>,
    pub payload: Option<WatermarkPayload>,
    pub provider: String,
    pub algorithm: WatermarkAlgorithm,
    pub implementation_tier: WatermarkImplementationTier,
    pub content_format: WatermarkContentFormat,
    pub confidence_percent: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatermarkVerificationReport {
    pub verified: bool,
    pub algorithm_verified: bool,
    pub matches: Vec<DetectedWatermark>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatermarkContentFormat {
    Text,
    Pdf,
    Office,
    Image,
    Binary,
}

impl WatermarkContentFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Pdf => "pdf",
            Self::Office => "office",
            Self::Image => "image",
            Self::Binary => "binary",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "text" | "plain" | "txt" => Some(Self::Text),
            "pdf" | "application/pdf" => Some(Self::Pdf),
            "office"
            | "xlsx"
            | "xlsm"
            | "xlsb"
            | "docx"
            | "pptx"
            | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            | "application/vnd.ms-excel.sheet.macroenabled.12"
            | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            | "application/vnd.openxmlformats-officedocument.presentationml.presentation" => {
                Some(Self::Office)
            }
            "image" | "png" | "jpeg" | "jpg" | "image/png" | "image/jpeg" => Some(Self::Image),
            "binary" | "file" | "bytes" | "application/octet-stream" => Some(Self::Binary),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchScanInput {
    pub document_id: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchByteScanInput {
    pub document_id: String,
    pub format: WatermarkContentFormat,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchScanReport {
    pub document_id: String,
    pub verified: bool,
    pub algorithm_verified: bool,
    pub matches: Vec<DetectedWatermark>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WatermarkError {
    #[error("invalid watermark token format")]
    InvalidTokenFormat,
    #[error("watermark digest mismatch")]
    DigestMismatch,
    #[error("watermark payload encoding is invalid")]
    InvalidEncoding,
    #[error("watermark payload is invalid")]
    InvalidPayload,
    #[error("png watermark capacity exceeded")]
    CarrierCapacityExceeded,
    #[error("unsupported png image format")]
    UnsupportedImageCarrier,
    #[error("png image decode failed")]
    PngDecodeFailed,
    #[error("png image encode failed")]
    PngEncodeFailed,
    #[error("office package decode failed")]
    ZipDecodeFailed,
    #[error("watermark payload compression failed")]
    CompressionFailed,
    #[error("watermark payload decompression failed")]
    DecompressionFailed,
}

#[derive(Clone, Copy)]
struct ProviderDescriptor {
    id: &'static str,
    algorithm: WatermarkAlgorithm,
    implementation_tier: WatermarkImplementationTier,
}

#[derive(Debug, Clone)]
struct ExtractedToken {
    token: String,
    confidence_percent: u8,
}

trait WatermarkProvider {
    fn descriptor(&self) -> ProviderDescriptor;

    fn supports_format(&self, format: WatermarkContentFormat, content: &[u8]) -> bool;

    fn embed(
        &self,
        _content: &[u8],
        _token: &str,
        _format: WatermarkContentFormat,
    ) -> Result<Option<Vec<u8>>, WatermarkError> {
        Ok(None)
    }

    fn extract(&self, content: &[u8], format: WatermarkContentFormat) -> Vec<ExtractedToken>;
}

struct ZeroWidthTextProvider;
struct LegacyTextMarkerProvider;
struct PdfMetadataObjectProvider;
struct PdfCommentProvider;
struct OfficeOpenXmlProvider;
struct BinaryTrailerProvider;
struct PngChunkProvider;
struct JpegCommentProvider;
struct PngFrequencyDctProvider;
struct JpegCoefficientDctProvider;

static ZERO_WIDTH_TEXT_PROVIDER: ZeroWidthTextProvider = ZeroWidthTextProvider;
static LEGACY_TEXT_MARKER_PROVIDER: LegacyTextMarkerProvider = LegacyTextMarkerProvider;
static PDF_METADATA_OBJECT_PROVIDER: PdfMetadataObjectProvider = PdfMetadataObjectProvider;
static PDF_COMMENT_PROVIDER: PdfCommentProvider = PdfCommentProvider;
static OFFICE_OPEN_XML_PROVIDER: OfficeOpenXmlProvider = OfficeOpenXmlProvider;
static BINARY_TRAILER_PROVIDER: BinaryTrailerProvider = BinaryTrailerProvider;
static PNG_CHUNK_PROVIDER: PngChunkProvider = PngChunkProvider;
static JPEG_COMMENT_PROVIDER: JpegCommentProvider = JpegCommentProvider;
static PNG_FREQUENCY_DCT_PROVIDER: PngFrequencyDctProvider = PngFrequencyDctProvider;
static JPEG_COEFFICIENT_DCT_PROVIDER: JpegCoefficientDctProvider = JpegCoefficientDctProvider;

pub fn encode_payload(payload: &WatermarkPayload) -> Result<String, WatermarkError> {
    let bytes = serde_json::to_vec(payload).map_err(|_| WatermarkError::InvalidPayload)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    Ok(format!("{}.{}", URL_SAFE_NO_PAD.encode(bytes), digest))
}

pub fn decode_payload(token: &str) -> Result<WatermarkPayload, WatermarkError> {
    let (encoded, digest) = token
        .split_once('.')
        .ok_or(WatermarkError::InvalidTokenFormat)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| WatermarkError::InvalidEncoding)?;
    let actual_digest = hex::encode(Sha256::digest(&decoded));
    if actual_digest != digest {
        return Err(WatermarkError::DigestMismatch);
    }

    serde_json::from_slice(&decoded).map_err(|_| WatermarkError::InvalidPayload)
}

pub fn overlay_text(payload: &WatermarkPayload) -> String {
    format!(
        "{} / {} / {} #{}",
        payload.tenant_id, payload.project_id, payload.user_id, payload.sequence_number
    )
}

pub fn embed_marker(content: &str, token: &str) -> String {
    String::from_utf8(embed_marker_bytes(
        content.as_bytes(),
        token,
        WatermarkContentFormat::Text,
    ))
    .expect("zero-width watermark embedding must preserve utf-8")
}

pub fn embed_marker_bytes(content: &[u8], token: &str, format: WatermarkContentFormat) -> Vec<u8> {
    for provider in provider_registry() {
        if !provider.supports_format(format, content) {
            continue;
        }
        if let Ok(Some(output)) = provider.embed(content, token, format) {
            return output;
        }
    }
    content.to_vec()
}

pub fn detect_markers(content: &str) -> Vec<DetectedWatermark> {
    detect_markers_in_bytes_with_format(content.as_bytes(), WatermarkContentFormat::Text)
}

pub fn detect_markers_in_bytes(content: &[u8]) -> Vec<DetectedWatermark> {
    detect_markers_in_bytes_with_format(content, infer_content_format(content))
}

pub fn detect_markers_in_bytes_with_format(
    content: &[u8],
    format: WatermarkContentFormat,
) -> Vec<DetectedWatermark> {
    let mut matches = Vec::new();
    for provider in provider_registry() {
        if !provider.supports_format(format, content) {
            continue;
        }
        let descriptor = provider.descriptor();
        for extraction in provider.extract(content, format) {
            push_detected_token(
                &mut matches,
                extraction.token,
                descriptor,
                format,
                extraction.confidence_percent,
            );
        }
    }
    matches
}

pub fn verify_content(content: &str, expected_token: Option<&str>) -> WatermarkVerificationReport {
    build_verification_report(detect_markers(content), expected_token)
}

pub fn verify_bytes(content: &[u8], expected_token: Option<&str>) -> WatermarkVerificationReport {
    verify_bytes_with_format(content, infer_content_format(content), expected_token)
}

pub fn verify_bytes_with_format(
    content: &[u8],
    format: WatermarkContentFormat,
    expected_token: Option<&str>,
) -> WatermarkVerificationReport {
    build_verification_report(
        detect_markers_in_bytes_with_format(content, format),
        expected_token,
    )
}

pub fn batch_scan(documents: &[BatchScanInput]) -> Vec<BatchScanReport> {
    documents
        .iter()
        .map(|document| {
            let verification = verify_content(&document.content, None);
            BatchScanReport {
                document_id: document.document_id.clone(),
                verified: verification.verified,
                algorithm_verified: verification.algorithm_verified,
                matches: verification.matches,
            }
        })
        .collect()
}

pub fn batch_scan_bytes(documents: &[BatchByteScanInput]) -> Vec<BatchScanReport> {
    documents
        .iter()
        .map(|document| {
            let verification = verify_bytes_with_format(&document.content, document.format, None);
            BatchScanReport {
                document_id: document.document_id.clone(),
                verified: verification.verified,
                algorithm_verified: verification.algorithm_verified,
                matches: verification.matches,
            }
        })
        .collect()
}

impl WatermarkProvider for ZeroWidthTextProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: "zero_width_text",
            algorithm: WatermarkAlgorithm::ZeroWidthTextV1,
            implementation_tier: WatermarkImplementationTier::Algorithm,
        }
    }

    fn supports_format(&self, format: WatermarkContentFormat, content: &[u8]) -> bool {
        matches!(
            format,
            WatermarkContentFormat::Text | WatermarkContentFormat::Pdf
        ) && std::str::from_utf8(content).is_ok()
    }

    fn embed(
        &self,
        content: &[u8],
        token: &str,
        format: WatermarkContentFormat,
    ) -> Result<Option<Vec<u8>>, WatermarkError> {
        if format != WatermarkContentFormat::Text {
            return Ok(None);
        }
        let text = std::str::from_utf8(content).map_err(|_| WatermarkError::InvalidEncoding)?;
        let mut output = String::with_capacity(text.len() + token.len() * 10);
        output.push_str(text);
        output.push_str(&encode_hidden_text_token(token));
        Ok(Some(output.into_bytes()))
    }

    fn extract(&self, content: &[u8], _format: WatermarkContentFormat) -> Vec<ExtractedToken> {
        let Ok(text) = std::str::from_utf8(content) else {
            return Vec::new();
        };
        extract_hidden_text_tokens(text)
            .into_iter()
            .map(|token| ExtractedToken {
                token,
                confidence_percent: 100,
            })
            .collect()
    }
}

impl WatermarkProvider for LegacyTextMarkerProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: "legacy_text_marker",
            algorithm: WatermarkAlgorithm::LegacyTextMarkerV0,
            implementation_tier: WatermarkImplementationTier::Legacy,
        }
    }

    fn supports_format(&self, format: WatermarkContentFormat, content: &[u8]) -> bool {
        matches!(
            format,
            WatermarkContentFormat::Text | WatermarkContentFormat::Pdf
        ) && std::str::from_utf8(content).is_ok()
    }

    fn extract(&self, content: &[u8], _format: WatermarkContentFormat) -> Vec<ExtractedToken> {
        let Ok(text) = std::str::from_utf8(content) else {
            return Vec::new();
        };
        extract_legacy_text_tokens(text)
            .into_iter()
            .map(|token| ExtractedToken {
                token,
                confidence_percent: 100,
            })
            .collect()
    }
}

impl WatermarkProvider for PdfMetadataObjectProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: "pdf_metadata_object_carrier",
            algorithm: WatermarkAlgorithm::PdfMetadataObjectCarrierV1,
            implementation_tier: WatermarkImplementationTier::Carrier,
        }
    }

    fn supports_format(&self, format: WatermarkContentFormat, content: &[u8]) -> bool {
        format == WatermarkContentFormat::Pdf && content.starts_with(b"%PDF")
    }

    fn embed(
        &self,
        content: &[u8],
        token: &str,
        _format: WatermarkContentFormat,
    ) -> Result<Option<Vec<u8>>, WatermarkError> {
        Ok(Some(embed_pdf_metadata_object_watermark(content, token)))
    }

    fn extract(&self, content: &[u8], _format: WatermarkContentFormat) -> Vec<ExtractedToken> {
        extract_pdf_metadata_object_tokens(content)
            .into_iter()
            .map(|token| ExtractedToken {
                token,
                confidence_percent: 100,
            })
            .collect()
    }
}

impl WatermarkProvider for PdfCommentProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: "pdf_comment_carrier",
            algorithm: WatermarkAlgorithm::PdfCommentCarrierV1,
            implementation_tier: WatermarkImplementationTier::Carrier,
        }
    }

    fn supports_format(&self, format: WatermarkContentFormat, _content: &[u8]) -> bool {
        format == WatermarkContentFormat::Pdf
    }

    fn embed(
        &self,
        content: &[u8],
        token: &str,
        _format: WatermarkContentFormat,
    ) -> Result<Option<Vec<u8>>, WatermarkError> {
        Ok(Some(embed_pdf_comment_watermark(content, token)))
    }

    fn extract(&self, content: &[u8], _format: WatermarkContentFormat) -> Vec<ExtractedToken> {
        extract_base64_tokens_with_prefix(content, PDF_COMMENT_PREFIX)
            .into_iter()
            .map(|token| ExtractedToken {
                token,
                confidence_percent: 100,
            })
            .collect()
    }
}

impl WatermarkProvider for OfficeOpenXmlProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: "ooxml_custom_xml_carrier",
            algorithm: WatermarkAlgorithm::OoxmlCustomXmlCarrierV1,
            implementation_tier: WatermarkImplementationTier::Carrier,
        }
    }

    fn supports_format(&self, format: WatermarkContentFormat, content: &[u8]) -> bool {
        format == WatermarkContentFormat::Office && is_ooxml_package(content)
    }

    fn embed(
        &self,
        content: &[u8],
        token: &str,
        _format: WatermarkContentFormat,
    ) -> Result<Option<Vec<u8>>, WatermarkError> {
        match embed_ooxml_custom_xml_watermark(content, token) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(WatermarkError::ZipDecodeFailed) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn extract(&self, content: &[u8], _format: WatermarkContentFormat) -> Vec<ExtractedToken> {
        extract_ooxml_custom_xml_tokens(content)
            .into_iter()
            .map(|token| ExtractedToken {
                token,
                confidence_percent: 100,
            })
            .collect()
    }
}

impl WatermarkProvider for BinaryTrailerProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: "binary_trailer_carrier",
            algorithm: WatermarkAlgorithm::BinaryTrailerCarrierV1,
            implementation_tier: WatermarkImplementationTier::Carrier,
        }
    }

    fn supports_format(&self, format: WatermarkContentFormat, _content: &[u8]) -> bool {
        matches!(
            format,
            WatermarkContentFormat::Binary | WatermarkContentFormat::Image
        )
    }

    fn embed(
        &self,
        content: &[u8],
        token: &str,
        _format: WatermarkContentFormat,
    ) -> Result<Option<Vec<u8>>, WatermarkError> {
        Ok(Some(embed_binary_trailer_watermark(content, token)))
    }

    fn extract(&self, content: &[u8], _format: WatermarkContentFormat) -> Vec<ExtractedToken> {
        extract_base64_tokens_with_prefix(content, BINARY_TRAILER_PREFIX)
            .into_iter()
            .map(|token| ExtractedToken {
                token,
                confidence_percent: 100,
            })
            .collect()
    }
}

impl WatermarkProvider for PngChunkProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: "png_chunk_carrier",
            algorithm: WatermarkAlgorithm::PngChunkCarrierV1,
            implementation_tier: WatermarkImplementationTier::Carrier,
        }
    }

    fn supports_format(&self, format: WatermarkContentFormat, content: &[u8]) -> bool {
        format == WatermarkContentFormat::Image && content.starts_with(PNG_SIGNATURE)
    }

    fn embed(
        &self,
        content: &[u8],
        token: &str,
        _format: WatermarkContentFormat,
    ) -> Result<Option<Vec<u8>>, WatermarkError> {
        Ok(Some(embed_png_chunk_watermark(content, token)))
    }

    fn extract(&self, content: &[u8], _format: WatermarkContentFormat) -> Vec<ExtractedToken> {
        extract_png_chunk_tokens(content)
            .into_iter()
            .map(|token| ExtractedToken {
                token,
                confidence_percent: 100,
            })
            .collect()
    }
}

impl WatermarkProvider for JpegCommentProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: "jpeg_comment_carrier",
            algorithm: WatermarkAlgorithm::JpegCommentCarrierV1,
            implementation_tier: WatermarkImplementationTier::Carrier,
        }
    }

    fn supports_format(&self, format: WatermarkContentFormat, content: &[u8]) -> bool {
        format == WatermarkContentFormat::Image && content.starts_with(JPEG_SOI)
    }

    fn embed(
        &self,
        content: &[u8],
        token: &str,
        _format: WatermarkContentFormat,
    ) -> Result<Option<Vec<u8>>, WatermarkError> {
        Ok(Some(embed_jpeg_comment_watermark(content, token)))
    }

    fn extract(&self, content: &[u8], _format: WatermarkContentFormat) -> Vec<ExtractedToken> {
        extract_jpeg_comment_tokens(content)
            .into_iter()
            .map(|token| ExtractedToken {
                token,
                confidence_percent: 100,
            })
            .collect()
    }
}

impl WatermarkProvider for PngFrequencyDctProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: "png_frequency_dct",
            algorithm: WatermarkAlgorithm::PngFrequencyDctV1,
            implementation_tier: WatermarkImplementationTier::Algorithm,
        }
    }

    fn supports_format(&self, format: WatermarkContentFormat, content: &[u8]) -> bool {
        format == WatermarkContentFormat::Image && content.starts_with(PNG_SIGNATURE)
    }

    fn embed(
        &self,
        content: &[u8],
        token: &str,
        _format: WatermarkContentFormat,
    ) -> Result<Option<Vec<u8>>, WatermarkError> {
        match embed_png_frequency_watermark(content, token) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(
                WatermarkError::CarrierCapacityExceeded | WatermarkError::UnsupportedImageCarrier,
            ) => Ok(None),
            Err(_) => Ok(None),
        }
    }

    fn extract(&self, content: &[u8], _format: WatermarkContentFormat) -> Vec<ExtractedToken> {
        extract_png_frequency_watermark(content)
            .into_iter()
            .collect()
    }
}

impl WatermarkProvider for JpegCoefficientDctProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: "jpeg_coefficient_dct",
            algorithm: WatermarkAlgorithm::JpegCoefficientDctV1,
            implementation_tier: WatermarkImplementationTier::Algorithm,
        }
    }

    fn supports_format(&self, format: WatermarkContentFormat, content: &[u8]) -> bool {
        format == WatermarkContentFormat::Image && content.starts_with(JPEG_SOI)
    }

    fn embed(
        &self,
        content: &[u8],
        token: &str,
        _format: WatermarkContentFormat,
    ) -> Result<Option<Vec<u8>>, WatermarkError> {
        match embed_jpeg_dct_watermark(content, token) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(
                WatermarkError::CarrierCapacityExceeded | WatermarkError::UnsupportedImageCarrier,
            ) => Ok(None),
            Err(_) => Ok(None),
        }
    }

    fn extract(&self, content: &[u8], _format: WatermarkContentFormat) -> Vec<ExtractedToken> {
        extract_jpeg_dct_watermark(content).into_iter().collect()
    }
}

fn provider_registry() -> [&'static dyn WatermarkProvider; 10] {
    [
        &JPEG_COEFFICIENT_DCT_PROVIDER,
        &PNG_FREQUENCY_DCT_PROVIDER,
        &ZERO_WIDTH_TEXT_PROVIDER,
        &PDF_METADATA_OBJECT_PROVIDER,
        &PDF_COMMENT_PROVIDER,
        &OFFICE_OPEN_XML_PROVIDER,
        &PNG_CHUNK_PROVIDER,
        &JPEG_COMMENT_PROVIDER,
        &BINARY_TRAILER_PROVIDER,
        &LEGACY_TEXT_MARKER_PROVIDER,
    ]
}

fn build_verification_report(
    matches: Vec<DetectedWatermark>,
    expected_token: Option<&str>,
) -> WatermarkVerificationReport {
    let expected_match = expected_token.is_none_or(|token| {
        matches
            .iter()
            .any(|detected| detected.token == token && detected.verified)
    });
    let verified =
        !matches.is_empty() && matches.iter().all(|detected| detected.verified) && expected_match;
    let algorithm_verified = matches.iter().any(|detected| {
        detected.verified
            && detected.implementation_tier == WatermarkImplementationTier::Algorithm
            && expected_token.is_none_or(|token| detected.token == token)
    });

    WatermarkVerificationReport {
        verified,
        algorithm_verified,
        matches,
    }
}

fn infer_content_format(content: &[u8]) -> WatermarkContentFormat {
    if content.starts_with(PNG_SIGNATURE) || content.starts_with(JPEG_SOI) {
        WatermarkContentFormat::Image
    } else if content.starts_with(b"%PDF") {
        WatermarkContentFormat::Pdf
    } else if is_ooxml_package(content) {
        WatermarkContentFormat::Office
    } else if std::str::from_utf8(content).is_ok() {
        WatermarkContentFormat::Text
    } else {
        WatermarkContentFormat::Binary
    }
}

fn push_detected_token(
    matches: &mut Vec<DetectedWatermark>,
    token: String,
    descriptor: ProviderDescriptor,
    content_format: WatermarkContentFormat,
    confidence_percent: u8,
) {
    let candidate = match decode_payload(&token) {
        Ok(payload) => DetectedWatermark {
            token,
            verified: true,
            overlay_text: Some(overlay_text(&payload)),
            payload: Some(payload),
            provider: descriptor.id.into(),
            algorithm: descriptor.algorithm,
            implementation_tier: descriptor.implementation_tier,
            content_format,
            confidence_percent,
        },
        Err(_) => DetectedWatermark {
            token,
            verified: false,
            overlay_text: None,
            payload: None,
            provider: descriptor.id.into(),
            algorithm: descriptor.algorithm,
            implementation_tier: descriptor.implementation_tier,
            content_format,
            confidence_percent,
        },
    };

    if let Some(existing) = matches
        .iter_mut()
        .find(|existing| existing.token == candidate.token)
    {
        if candidate_priority(&candidate) > candidate_priority(existing) {
            *existing = candidate;
        }
        return;
    }

    matches.push(candidate);
}

fn candidate_priority(candidate: &DetectedWatermark) -> (u8, u8, u8) {
    (
        candidate.verified as u8,
        match candidate.implementation_tier {
            WatermarkImplementationTier::Algorithm => 3,
            WatermarkImplementationTier::Carrier => 2,
            WatermarkImplementationTier::Legacy => 1,
        },
        candidate.confidence_percent,
    )
}

fn encode_hidden_text_token(token: &str) -> String {
    let mut output = String::with_capacity(TEXT_START_SENTINEL.len() + token.len() * 8 * 3);
    output.push_str(TEXT_START_SENTINEL);
    for byte in token.as_bytes() {
        for shift in (0..8).rev() {
            let bit = (byte >> shift) & 1;
            output.push(if bit == 0 { ZERO_BIT } else { ONE_BIT });
        }
    }
    output.push_str(TEXT_END_SENTINEL);
    output
}

fn extract_hidden_text_tokens(content: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut search_from = 0;

    while let Some(relative_start) = content[search_from..].find(TEXT_START_SENTINEL) {
        let start = search_from + relative_start + TEXT_START_SENTINEL.len();
        let Some(relative_end) = content[start..].find(TEXT_END_SENTINEL) else {
            break;
        };
        let end = start + relative_end;
        if let Some(token) = decode_hidden_text_token(&content[start..end]) {
            tokens.push(token);
        }
        search_from = end + TEXT_END_SENTINEL.len();
    }

    tokens
}

fn decode_hidden_text_token(bits: &str) -> Option<String> {
    if bits.is_empty() || !bits.chars().count().is_multiple_of(8) {
        return None;
    }

    let mut bytes = Vec::with_capacity(bits.len() / 8);
    let mut value = 0_u8;
    for (index, bit) in bits.chars().enumerate() {
        value <<= 1;
        match bit {
            ZERO_BIT => {}
            ONE_BIT => value |= 1,
            _ => return None,
        }
        if index % 8 == 7 {
            bytes.push(value);
            value = 0;
        }
    }

    String::from_utf8(bytes).ok()
}

fn extract_legacy_text_tokens(content: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut remainder = content;

    while let Some(start) = remainder.find(LEGACY_MARKER_PREFIX) {
        let after_prefix = &remainder[start + LEGACY_MARKER_PREFIX.len()..];
        let Some(end) = after_prefix.find(LEGACY_MARKER_SUFFIX) else {
            break;
        };
        tokens.push(after_prefix[..end].to_string());
        remainder = &after_prefix[end + LEGACY_MARKER_SUFFIX.len()..];
    }

    tokens
}

#[derive(Debug, Clone, Copy)]
struct PdfIndirectObject {
    number: u32,
    generation: u16,
    body_start: usize,
    body_end: usize,
}

fn embed_pdf_metadata_object_watermark(content: &[u8], token: &str) -> Vec<u8> {
    let objects = parse_pdf_indirect_objects(content);
    let highest_object = objects
        .iter()
        .map(|object| object.number)
        .max()
        .unwrap_or(0);
    let metadata_object_number = highest_object + 1;
    let previous_startxref = parse_last_pdf_startxref(content);
    let metadata_xml = build_pdf_metadata_xml(token);
    let catalog_update = find_pdf_catalog_object(content, &objects)
        .and_then(|catalog| build_pdf_catalog_update(content, catalog, metadata_object_number));

    let mut output = content.to_vec();
    if !output.ends_with(b"\n") {
        output.push(b'\n');
    }

    let metadata_offset = output.len();
    write_pdf_metadata_object(&mut output, metadata_object_number, &metadata_xml);

    let mut xref_entries = vec![(metadata_object_number, metadata_offset)];
    if let Some((catalog_object, updated_catalog_body)) = catalog_update {
        let catalog_offset = output.len();
        write_pdf_object(
            &mut output,
            catalog_object.number,
            catalog_object.generation,
            &updated_catalog_body,
        );
        xref_entries.push((catalog_object.number, catalog_offset));
    }
    xref_entries.sort_by_key(|(object_number, _)| *object_number);

    let startxref = output.len();
    output.extend_from_slice(b"xref\n");
    for (object_number, offset) in &xref_entries {
        output.extend_from_slice(format!("{object_number} 1\n{offset:010} 00000 n \n").as_bytes());
    }

    output.extend_from_slice(b"trailer\n<< ");
    output.extend_from_slice(format!("/Size {} ", metadata_object_number + 1).as_bytes());
    if let Some(previous_startxref) = previous_startxref {
        output.extend_from_slice(format!("/Prev {previous_startxref} ").as_bytes());
    }
    output.extend_from_slice(b">>\nstartxref\n");
    output.extend_from_slice(startxref.to_string().as_bytes());
    output.extend_from_slice(b"\n%%EOF\n");
    output
}

fn build_pdf_metadata_xml(token: &str) -> Vec<u8> {
    format!(
        "<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n\
<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n\
<rdf:Description xmlns:sdqp=\"urn:sdqp:watermark:v1\" sdqp:token=\"{}\" sdqp:carrier=\"pdf_metadata_object_v1\"/>\n\
</rdf:RDF>\n\
</x:xmpmeta>\n\
<?xpacket end=\"w\"?>\n",
        token
    )
    .into_bytes()
}

fn write_pdf_metadata_object(output: &mut Vec<u8>, object_number: u32, metadata_xml: &[u8]) {
    output.extend_from_slice(format!("{object_number} 0 obj\n").as_bytes());
    output.extend_from_slice(
        format!(
            "<< /Type /Metadata /Subtype /XML /Length {} >>\nstream\n",
            metadata_xml.len()
        )
        .as_bytes(),
    );
    output.extend_from_slice(metadata_xml);
    output.extend_from_slice(b"endstream\nendobj\n");
}

fn write_pdf_object(output: &mut Vec<u8>, object_number: u32, generation: u16, body: &[u8]) {
    output.extend_from_slice(format!("{object_number} {generation} obj\n").as_bytes());
    output.extend_from_slice(body);
    if !body.ends_with(b"\n") {
        output.push(b'\n');
    }
    output.extend_from_slice(b"endobj\n");
}

fn parse_pdf_indirect_objects(content: &[u8]) -> Vec<PdfIndirectObject> {
    let mut objects = Vec::new();
    let mut cursor = 0;
    while let Some(relative_obj) = find_bytes(&content[cursor..], b" obj") {
        let header_end = cursor + relative_obj;
        let object_start = content[..header_end]
            .iter()
            .rposition(|byte| matches!(byte, b'\n' | b'\r'))
            .map_or(0, |position| position + 1);
        let header = &content[object_start..header_end];
        let Some((number, generation)) = parse_pdf_object_header(header) else {
            cursor = header_end + 4;
            continue;
        };

        let body_start = header_end + 4;
        let Some(relative_end) = find_bytes(&content[body_start..], b"endobj") else {
            break;
        };
        let body_end = body_start + relative_end;
        objects.push(PdfIndirectObject {
            number,
            generation,
            body_start,
            body_end,
        });
        cursor = body_end + b"endobj".len();
    }
    objects
}

fn parse_pdf_object_header(header: &[u8]) -> Option<(u32, u16)> {
    let header = std::str::from_utf8(header).ok()?;
    let mut parts = header.split_whitespace();
    let number = parts.next()?.parse::<u32>().ok()?;
    let generation = parts.next()?.parse::<u16>().ok()?;
    parts.next().is_none().then_some((number, generation))
}

fn parse_last_pdf_startxref(content: &[u8]) -> Option<usize> {
    let start = rfind_bytes(content, b"startxref")? + b"startxref".len();
    let tail = std::str::from_utf8(&content[start..]).ok()?;
    tail.split_whitespace()
        .next()
        .and_then(|value| value.parse::<usize>().ok())
}

fn find_pdf_catalog_object(
    content: &[u8],
    objects: &[PdfIndirectObject],
) -> Option<PdfIndirectObject> {
    objects.iter().copied().find(|object| {
        let body = &content[object.body_start..object.body_end];
        find_bytes(body, b"/Type").is_some() && find_bytes(body, b"/Catalog").is_some()
    })
}

fn build_pdf_catalog_update(
    content: &[u8],
    catalog: PdfIndirectObject,
    metadata_object_number: u32,
) -> Option<(PdfIndirectObject, Vec<u8>)> {
    let body = &content[catalog.body_start..catalog.body_end];
    let dict_start = find_bytes(body, b"<<")?;
    let dict_end = rfind_bytes(body, b">>")?;
    if dict_end <= dict_start {
        return None;
    }

    let mut cleaned_dict = remove_pdf_metadata_reference(&body[dict_start..dict_end]);
    cleaned_dict.extend_from_slice(format!(" /Metadata {metadata_object_number} 0 R ").as_bytes());

    let mut updated = Vec::with_capacity(body.len() + 32);
    updated.extend_from_slice(&body[..dict_start]);
    updated.extend_from_slice(&cleaned_dict);
    updated.extend_from_slice(&body[dict_end..]);
    Some((catalog, updated))
}

fn remove_pdf_metadata_reference(dict_prefix: &[u8]) -> Vec<u8> {
    let Some(relative_start) = find_bytes(dict_prefix, b"/Metadata") else {
        return dict_prefix.to_vec();
    };
    let mut end = relative_start + b"/Metadata".len();
    end = skip_ascii_whitespace(dict_prefix, end);
    end = skip_ascii_digits(dict_prefix, end);
    end = skip_ascii_whitespace(dict_prefix, end);
    end = skip_ascii_digits(dict_prefix, end);
    end = skip_ascii_whitespace(dict_prefix, end);
    if dict_prefix.get(end) == Some(&b'R') {
        end += 1;
    } else {
        while end < dict_prefix.len()
            && dict_prefix[end] != b'/'
            && !matches!(dict_prefix[end], b'>' | b'\r' | b'\n')
        {
            end += 1;
        }
    }

    let mut output = Vec::with_capacity(dict_prefix.len());
    output.extend_from_slice(&dict_prefix[..relative_start]);
    output.extend_from_slice(&dict_prefix[end..]);
    output
}

fn skip_ascii_whitespace(content: &[u8], mut cursor: usize) -> usize {
    while cursor < content.len() && content[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    cursor
}

fn skip_ascii_digits(content: &[u8], mut cursor: usize) -> usize {
    while cursor < content.len() && content[cursor].is_ascii_digit() {
        cursor += 1;
    }
    cursor
}

fn extract_pdf_metadata_object_tokens(content: &[u8]) -> Vec<String> {
    extract_xml_attribute_tokens(content, PDF_METADATA_TOKEN_ATTRIBUTE)
}

fn extract_xml_attribute_tokens(content: &[u8], attribute: &[u8]) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cursor = 0;
    while let Some(relative_start) = find_bytes(&content[cursor..], attribute) {
        let start = cursor + relative_start + attribute.len();
        let mut end = start;
        while end < content.len() && content[end] != b'"' {
            end += 1;
        }
        if end < content.len()
            && let Ok(token) = std::str::from_utf8(&content[start..end])
        {
            tokens.push(token.to_string());
        }
        cursor = end.saturating_add(1);
    }
    tokens
}

fn embed_pdf_comment_watermark(content: &[u8], token: &str) -> Vec<u8> {
    let mut output = content.to_vec();
    if !output.ends_with(b"\n") {
        output.push(b'\n');
    }
    output.extend_from_slice(PDF_COMMENT_PREFIX);
    output.extend_from_slice(STANDARD.encode(token.as_bytes()).as_bytes());
    output.push(b'\n');
    output
}

fn embed_binary_trailer_watermark(content: &[u8], token: &str) -> Vec<u8> {
    let mut output = content.to_vec();
    output.extend_from_slice(BINARY_TRAILER_PREFIX);
    output.extend_from_slice(STANDARD.encode(token.as_bytes()).as_bytes());
    output
}

fn embed_png_chunk_watermark(content: &[u8], token: &str) -> Vec<u8> {
    let encoded = STANDARD.encode(token.as_bytes());
    let chunk = build_png_chunk(PNG_WATERMARK_CHUNK_TYPE, encoded.as_bytes());
    let insert_at = first_png_chunk_end(content).unwrap_or(PNG_SIGNATURE.len());

    let mut output = Vec::with_capacity(content.len() + chunk.len());
    output.extend_from_slice(&content[..insert_at]);
    output.extend_from_slice(&chunk);
    output.extend_from_slice(&content[insert_at..]);
    output
}

fn first_png_chunk_end(content: &[u8]) -> Option<usize> {
    if !content.starts_with(PNG_SIGNATURE) || content.len() < 8 + 12 {
        return None;
    }

    let length = u32::from_be_bytes(content.get(8..12)?.try_into().ok()?) as usize;
    let end = 8 + 12 + length;
    (end <= content.len()).then_some(end)
}

fn build_png_chunk(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut chunk = Vec::with_capacity(12 + data.len());
    chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
    chunk.extend_from_slice(chunk_type);
    chunk.extend_from_slice(data);

    let mut crc_input = Vec::with_capacity(chunk_type.len() + data.len());
    crc_input.extend_from_slice(chunk_type);
    crc_input.extend_from_slice(data);
    chunk.extend_from_slice(&crc32(&crc_input).to_be_bytes());
    chunk
}

fn extract_png_chunk_tokens(content: &[u8]) -> Vec<String> {
    if !content.starts_with(PNG_SIGNATURE) {
        return Vec::new();
    }

    let mut tokens = Vec::new();
    let mut cursor = PNG_SIGNATURE.len();
    while cursor + 12 <= content.len() {
        let Some(length_bytes) = content.get(cursor..cursor + 4) else {
            break;
        };
        let length = u32::from_be_bytes(length_bytes.try_into().expect("slice len")) as usize;
        let chunk_type_start = cursor + 4;
        let data_start = chunk_type_start + 4;
        let data_end = data_start + length;
        let chunk_end = data_end + 4;
        if chunk_end > content.len() {
            break;
        }

        if content[chunk_type_start..data_start] == PNG_WATERMARK_CHUNK_TYPE[..]
            && let Ok(decoded) = STANDARD.decode(&content[data_start..data_end])
            && let Ok(token) = String::from_utf8(decoded)
        {
            tokens.push(token);
        }

        cursor = chunk_end;
    }
    tokens
}

fn embed_jpeg_comment_watermark(content: &[u8], token: &str) -> Vec<u8> {
    let encoded = STANDARD.encode(token.as_bytes());
    let mut comment = Vec::with_capacity(JPEG_COMMENT_PREFIX.len() + encoded.len());
    comment.extend_from_slice(JPEG_COMMENT_PREFIX);
    comment.extend_from_slice(encoded.as_bytes());

    let length = (comment.len() + 2) as u16;
    let mut output = Vec::with_capacity(content.len() + comment.len() + 4);
    output.extend_from_slice(&content[..2]);
    output.extend_from_slice(&[0xFF, JPEG_COMMENT_MARKER]);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&comment);
    output.extend_from_slice(&content[2..]);
    output
}

fn extract_jpeg_comment_tokens(content: &[u8]) -> Vec<String> {
    if !content.starts_with(JPEG_SOI) {
        return Vec::new();
    }

    let mut tokens = Vec::new();
    let mut cursor = 2;
    while cursor + 4 <= content.len() {
        if content[cursor] != 0xFF {
            break;
        }
        let marker = content[cursor + 1];
        if marker == 0xD9 || marker == 0xDA {
            break;
        }

        let length = u16::from_be_bytes([content[cursor + 2], content[cursor + 3]]) as usize;
        if length < 2 || cursor + 2 + length > content.len() {
            break;
        }

        let data_start = cursor + 4;
        let data_end = cursor + 2 + length;
        if marker == JPEG_COMMENT_MARKER
            && content[data_start..data_end].starts_with(JPEG_COMMENT_PREFIX)
            && let Ok(decoded) =
                STANDARD.decode(&content[data_start + JPEG_COMMENT_PREFIX.len()..data_end])
            && let Ok(token) = String::from_utf8(decoded)
        {
            tokens.push(token);
        }

        cursor = data_end;
    }
    tokens
}

fn extract_base64_tokens_with_prefix(content: &[u8], prefix: &[u8]) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cursor = 0;

    while let Some(relative_start) = find_bytes(&content[cursor..], prefix) {
        let start = cursor + relative_start + prefix.len();
        let mut end = start;
        while end < content.len() && !matches!(content[end], b'\r' | b'\n' | 0) {
            end += 1;
        }
        if let Ok(decoded) = STANDARD.decode(&content[start..end])
            && let Ok(token) = String::from_utf8(decoded)
        {
            tokens.push(token);
        }
        cursor = end;
    }

    tokens
}

fn find_bytes(content: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || content.len() < needle.len() {
        return None;
    }

    content
        .windows(needle.len())
        .position(|window| window == needle)
}

fn rfind_bytes(content: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || content.len() < needle.len() {
        return None;
    }

    content
        .windows(needle.len())
        .rposition(|window| window == needle)
}

fn is_ooxml_package(content: &[u8]) -> bool {
    content.starts_with(b"PK\x03\x04")
        && find_bytes(content, b"[Content_Types].xml").is_some()
        && (find_bytes(content, b"xl/").is_some()
            || find_bytes(content, b"word/").is_some()
            || find_bytes(content, b"ppt/").is_some())
}

fn embed_ooxml_custom_xml_watermark(
    content: &[u8],
    token: &str,
) -> Result<Vec<u8>, WatermarkError> {
    let package = ZipPackage::parse(content)?;
    if !package.is_ooxml() {
        return Err(WatermarkError::ZipDecodeFailed);
    }
    let watermark_xml = build_ooxml_watermark_part(token);
    package.with_replaced_entry(OOXML_WATERMARK_ENTRY_PATH, &watermark_xml)
}

fn extract_ooxml_custom_xml_tokens(content: &[u8]) -> Vec<String> {
    let Ok(package) = ZipPackage::parse(content) else {
        return Vec::new();
    };
    package
        .entries
        .iter()
        .filter(|entry| {
            entry
                .name()
                .eq_ignore_ascii_case(OOXML_WATERMARK_ENTRY_PATH)
        })
        .filter_map(|entry| entry.read_data().ok())
        .filter_map(|xml| String::from_utf8(xml).ok())
        .filter_map(|xml| extract_xml_token_attribute(&xml))
        .collect()
}

fn build_ooxml_watermark_part(token: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<sdqp-watermark xmlns=\"urn:sdqp:watermark:v1\" token=\"{token}\"/>"
    )
    .into_bytes()
}

fn extract_xml_token_attribute(xml: &str) -> Option<String> {
    let start = xml.find(OOXML_TOKEN_ATTRIBUTE)? + OOXML_TOKEN_ATTRIBUTE.len();
    let end = xml[start..].find('"')? + start;
    Some(xml[start..end].to_string())
}

#[derive(Clone)]
struct ZipEntryRecord {
    version_made_by: u16,
    version_needed: u16,
    flags: u16,
    compression_method: u16,
    last_mod_time: u16,
    last_mod_date: u16,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    disk_number_start: u16,
    internal_attributes: u16,
    external_attributes: u32,
    file_name: Vec<u8>,
    extra: Vec<u8>,
    file_comment: Vec<u8>,
    local_header_offset: u32,
    raw_local_record: Vec<u8>,
}

impl ZipEntryRecord {
    fn name(&self) -> String {
        String::from_utf8_lossy(&self.file_name).replace('\\', "/")
    }

    fn read_data(&self) -> Result<Vec<u8>, WatermarkError> {
        if self.raw_local_record.len() < 30 {
            return Err(WatermarkError::ZipDecodeFailed);
        }
        let signature = read_u32_le(&self.raw_local_record, 0)?;
        if signature != ZIP_LOCAL_HEADER_SIGNATURE {
            return Err(WatermarkError::ZipDecodeFailed);
        }
        let file_name_len = usize::from(read_u16_le(&self.raw_local_record, 26)?);
        let extra_len = usize::from(read_u16_le(&self.raw_local_record, 28)?);
        let data_start = 30 + file_name_len + extra_len;
        let compressed_size =
            usize::try_from(self.compressed_size).map_err(|_| WatermarkError::ZipDecodeFailed)?;
        let data_end = data_start + compressed_size;
        if data_end > self.raw_local_record.len() {
            return Err(WatermarkError::ZipDecodeFailed);
        }
        let data = &self.raw_local_record[data_start..data_end];
        match self.compression_method {
            ZIP_STORED_METHOD => Ok(data.to_vec()),
            ZIP_DEFLATE_METHOD => {
                let mut decoder = DeflateDecoder::new(data);
                let mut output = Vec::new();
                decoder
                    .read_to_end(&mut output)
                    .map_err(|_| WatermarkError::ZipDecodeFailed)?;
                Ok(output)
            }
            _ => Err(WatermarkError::ZipDecodeFailed),
        }
    }
}

struct ZipPackage {
    entries: Vec<ZipEntryRecord>,
}

impl ZipPackage {
    fn parse(content: &[u8]) -> Result<Self, WatermarkError> {
        let eocd_offset = find_zip_end_of_central_directory(content)?;
        let disk_number = read_u16_le(content, eocd_offset + 4)?;
        let disk_with_central_directory = read_u16_le(content, eocd_offset + 6)?;
        if disk_number != 0 || disk_with_central_directory != 0 {
            return Err(WatermarkError::ZipDecodeFailed);
        }

        let entry_count = usize::from(read_u16_le(content, eocd_offset + 10)?);
        let central_directory_size = usize::try_from(read_u32_le(content, eocd_offset + 12)?)
            .map_err(|_| WatermarkError::ZipDecodeFailed)?;
        let central_directory_offset = usize::try_from(read_u32_le(content, eocd_offset + 16)?)
            .map_err(|_| WatermarkError::ZipDecodeFailed)?;
        if central_directory_offset + central_directory_size > content.len() {
            return Err(WatermarkError::ZipDecodeFailed);
        }

        let mut entries = Vec::with_capacity(entry_count);
        let mut cursor = central_directory_offset;
        for _ in 0..entry_count {
            if cursor + 46 > content.len() {
                return Err(WatermarkError::ZipDecodeFailed);
            }
            if read_u32_le(content, cursor)? != ZIP_CENTRAL_DIRECTORY_SIGNATURE {
                return Err(WatermarkError::ZipDecodeFailed);
            }

            let file_name_len = usize::from(read_u16_le(content, cursor + 28)?);
            let extra_len = usize::from(read_u16_le(content, cursor + 30)?);
            let comment_len = usize::from(read_u16_le(content, cursor + 32)?);
            let header_end = cursor + 46 + file_name_len + extra_len + comment_len;
            if header_end > content.len() {
                return Err(WatermarkError::ZipDecodeFailed);
            }

            let file_name_start = cursor + 46;
            let extra_start = file_name_start + file_name_len;
            let comment_start = extra_start + extra_len;

            entries.push(ZipEntryRecord {
                version_made_by: read_u16_le(content, cursor + 4)?,
                version_needed: read_u16_le(content, cursor + 6)?,
                flags: read_u16_le(content, cursor + 8)?,
                compression_method: read_u16_le(content, cursor + 10)?,
                last_mod_time: read_u16_le(content, cursor + 12)?,
                last_mod_date: read_u16_le(content, cursor + 14)?,
                crc32: read_u32_le(content, cursor + 16)?,
                compressed_size: read_u32_le(content, cursor + 20)?,
                uncompressed_size: read_u32_le(content, cursor + 24)?,
                disk_number_start: read_u16_le(content, cursor + 34)?,
                internal_attributes: read_u16_le(content, cursor + 36)?,
                external_attributes: read_u32_le(content, cursor + 38)?,
                file_name: content[file_name_start..extra_start].to_vec(),
                extra: content[extra_start..comment_start].to_vec(),
                file_comment: content[comment_start..header_end].to_vec(),
                local_header_offset: read_u32_le(content, cursor + 42)?,
                raw_local_record: Vec::new(),
            });
            cursor = header_end;
        }

        entries.sort_by_key(|entry| entry.local_header_offset);
        for index in 0..entries.len() {
            let start = usize::try_from(entries[index].local_header_offset)
                .map_err(|_| WatermarkError::ZipDecodeFailed)?;
            let end = if let Some(next_entry) = entries.get(index + 1) {
                usize::try_from(next_entry.local_header_offset)
                    .map_err(|_| WatermarkError::ZipDecodeFailed)?
            } else {
                central_directory_offset
            };
            if start >= end || end > content.len() {
                return Err(WatermarkError::ZipDecodeFailed);
            }
            entries[index].raw_local_record = content[start..end].to_vec();
        }

        Ok(Self { entries })
    }

    fn is_ooxml(&self) -> bool {
        let mut has_content_types = false;
        let mut has_document_root = false;
        for entry in &self.entries {
            let name = entry.name();
            if name.eq_ignore_ascii_case("[Content_Types].xml") {
                has_content_types = true;
            }
            if name.starts_with("xl/") || name.starts_with("word/") || name.starts_with("ppt/") {
                has_document_root = true;
            }
        }
        has_content_types && has_document_root
    }

    fn with_replaced_entry(&self, path: &str, data: &[u8]) -> Result<Vec<u8>, WatermarkError> {
        let mut entries = self
            .entries
            .iter()
            .filter(|entry| !entry.name().eq_ignore_ascii_case(path))
            .cloned()
            .collect::<Vec<_>>();
        let mut watermark_entry = build_stored_zip_entry(path, data)?;
        watermark_entry.local_header_offset = self
            .entries
            .iter()
            .map(|entry| entry.local_header_offset)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        entries.push(watermark_entry);
        entries.sort_by_key(|entry| entry.local_header_offset);
        rebuild_zip_archive(&entries)
    }
}

fn find_zip_end_of_central_directory(content: &[u8]) -> Result<usize, WatermarkError> {
    if content.len() < 22 {
        return Err(WatermarkError::ZipDecodeFailed);
    }
    let min_offset = content.len().saturating_sub(22 + usize::from(u16::MAX));
    for offset in (min_offset..=content.len() - 22).rev() {
        if read_u32_le(content, offset)? != ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE {
            continue;
        }
        let comment_len = usize::from(read_u16_le(content, offset + 20)?);
        if offset + 22 + comment_len == content.len() {
            return Ok(offset);
        }
    }
    Err(WatermarkError::ZipDecodeFailed)
}

fn build_stored_zip_entry(path: &str, data: &[u8]) -> Result<ZipEntryRecord, WatermarkError> {
    let file_name = path.as_bytes().to_vec();
    let crc = crc32(data);
    let compressed_size = u32::try_from(data.len()).map_err(|_| WatermarkError::ZipDecodeFailed)?;

    let mut raw_local_record = Vec::with_capacity(30 + file_name.len() + data.len());
    raw_local_record.extend_from_slice(&ZIP_LOCAL_HEADER_SIGNATURE.to_le_bytes());
    raw_local_record.extend_from_slice(&20_u16.to_le_bytes());
    raw_local_record.extend_from_slice(&ZIP_UTF8_FLAG.to_le_bytes());
    raw_local_record.extend_from_slice(&ZIP_STORED_METHOD.to_le_bytes());
    raw_local_record.extend_from_slice(&0_u16.to_le_bytes());
    raw_local_record.extend_from_slice(&0_u16.to_le_bytes());
    raw_local_record.extend_from_slice(&crc.to_le_bytes());
    raw_local_record.extend_from_slice(&compressed_size.to_le_bytes());
    raw_local_record.extend_from_slice(&compressed_size.to_le_bytes());
    raw_local_record.extend_from_slice(
        &u16::try_from(file_name.len())
            .map_err(|_| WatermarkError::ZipDecodeFailed)?
            .to_le_bytes(),
    );
    raw_local_record.extend_from_slice(&0_u16.to_le_bytes());
    raw_local_record.extend_from_slice(&file_name);
    raw_local_record.extend_from_slice(data);

    Ok(ZipEntryRecord {
        version_made_by: 20,
        version_needed: 20,
        flags: ZIP_UTF8_FLAG,
        compression_method: ZIP_STORED_METHOD,
        last_mod_time: 0,
        last_mod_date: 0,
        crc32: crc,
        compressed_size,
        uncompressed_size: compressed_size,
        disk_number_start: 0,
        internal_attributes: 0,
        external_attributes: 0,
        file_name,
        extra: Vec::new(),
        file_comment: Vec::new(),
        local_header_offset: 0,
        raw_local_record,
    })
}

fn rebuild_zip_archive(entries: &[ZipEntryRecord]) -> Result<Vec<u8>, WatermarkError> {
    let mut output = Vec::new();
    let mut central_directory = Vec::new();
    let mut local_offsets = Vec::with_capacity(entries.len());

    for entry in entries {
        let offset = u32::try_from(output.len()).map_err(|_| WatermarkError::ZipDecodeFailed)?;
        local_offsets.push(offset);
        output.extend_from_slice(&entry.raw_local_record);
    }

    let central_directory_offset =
        u32::try_from(output.len()).map_err(|_| WatermarkError::ZipDecodeFailed)?;
    for (entry, local_offset) in entries.iter().zip(local_offsets.iter()) {
        central_directory.extend_from_slice(&ZIP_CENTRAL_DIRECTORY_SIGNATURE.to_le_bytes());
        central_directory.extend_from_slice(&entry.version_made_by.to_le_bytes());
        central_directory.extend_from_slice(&entry.version_needed.to_le_bytes());
        central_directory.extend_from_slice(&entry.flags.to_le_bytes());
        central_directory.extend_from_slice(&entry.compression_method.to_le_bytes());
        central_directory.extend_from_slice(&entry.last_mod_time.to_le_bytes());
        central_directory.extend_from_slice(&entry.last_mod_date.to_le_bytes());
        central_directory.extend_from_slice(&entry.crc32.to_le_bytes());
        central_directory.extend_from_slice(&entry.compressed_size.to_le_bytes());
        central_directory.extend_from_slice(&entry.uncompressed_size.to_le_bytes());
        central_directory.extend_from_slice(
            &u16::try_from(entry.file_name.len())
                .map_err(|_| WatermarkError::ZipDecodeFailed)?
                .to_le_bytes(),
        );
        central_directory.extend_from_slice(
            &u16::try_from(entry.extra.len())
                .map_err(|_| WatermarkError::ZipDecodeFailed)?
                .to_le_bytes(),
        );
        central_directory.extend_from_slice(
            &u16::try_from(entry.file_comment.len())
                .map_err(|_| WatermarkError::ZipDecodeFailed)?
                .to_le_bytes(),
        );
        central_directory.extend_from_slice(&entry.disk_number_start.to_le_bytes());
        central_directory.extend_from_slice(&entry.internal_attributes.to_le_bytes());
        central_directory.extend_from_slice(&entry.external_attributes.to_le_bytes());
        central_directory.extend_from_slice(&local_offset.to_le_bytes());
        central_directory.extend_from_slice(&entry.file_name);
        central_directory.extend_from_slice(&entry.extra);
        central_directory.extend_from_slice(&entry.file_comment);
    }

    output.extend_from_slice(&central_directory);
    let central_directory_size =
        u32::try_from(central_directory.len()).map_err(|_| WatermarkError::ZipDecodeFailed)?;
    let entry_count = u16::try_from(entries.len()).map_err(|_| WatermarkError::ZipDecodeFailed)?;

    output.extend_from_slice(&ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&entry_count.to_le_bytes());
    output.extend_from_slice(&entry_count.to_le_bytes());
    output.extend_from_slice(&central_directory_size.to_le_bytes());
    output.extend_from_slice(&central_directory_offset.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());

    Ok(output)
}

fn read_u16_le(content: &[u8], offset: usize) -> Result<u16, WatermarkError> {
    let bytes = content
        .get(offset..offset + 2)
        .ok_or(WatermarkError::ZipDecodeFailed)?;
    Ok(u16::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| WatermarkError::ZipDecodeFailed)?,
    ))
}

fn read_u32_le(content: &[u8], offset: usize) -> Result<u32, WatermarkError> {
    let bytes = content
        .get(offset..offset + 4)
        .ok_or(WatermarkError::ZipDecodeFailed)?;
    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| WatermarkError::ZipDecodeFailed)?,
    ))
}

fn embed_png_frequency_watermark(content: &[u8], token: &str) -> Result<Vec<u8>, WatermarkError> {
    let frame = build_png_dct_frame(token)?;
    let bits = bytes_to_bits(&frame);
    let mut png = PngRaster::decode(content)?;
    let block_capacity = png.block_capacity();
    if bits.len() * PNG_DCT_SPREAD_FACTOR > block_capacity {
        return Err(WatermarkError::CarrierCapacityExceeded);
    }

    for (bit_index, bit) in bits.iter().enumerate() {
        for repeat_index in 0..PNG_DCT_SPREAD_FACTOR {
            png.embed_bit(bit_index * PNG_DCT_SPREAD_FACTOR + repeat_index, *bit);
        }
    }

    png.encode()
}

fn extract_png_frequency_watermark(content: &[u8]) -> Option<ExtractedToken> {
    let png = PngRaster::decode(content).ok()?;
    let logical_capacity_bits = png.block_capacity() / PNG_DCT_SPREAD_FACTOR;
    if logical_capacity_bits < PNG_DCT_HEADER_SIZE * 8 {
        return None;
    }

    let (header_bits, _) = png.extract_bits(PNG_DCT_HEADER_SIZE * 8)?;
    let header = bits_to_bytes(&header_bits)?;
    if header.get(0..4) != Some(PNG_DCT_FRAME_MAGIC)
        || header.get(4).copied() != Some(PNG_DCT_FRAME_VERSION)
    {
        return None;
    }

    let compressed_len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let total_frame_bytes = PNG_DCT_HEADER_SIZE + compressed_len + 4;
    if total_frame_bytes * 8 > logical_capacity_bits {
        return None;
    }

    let (frame_bits, confidences) = png.extract_bits(total_frame_bytes * 8)?;
    let frame = bits_to_bytes(&frame_bits)?;
    let payload = parse_png_dct_frame(&frame).ok()?;
    let token = encode_payload(&payload).ok()?;
    let average_confidence = if confidences.is_empty() {
        0
    } else {
        (confidences
            .iter()
            .map(|value| u32::from(*value))
            .sum::<u32>()
            / confidences.len() as u32) as u8
    };

    Some(ExtractedToken {
        token,
        confidence_percent: average_confidence,
    })
}

fn build_png_dct_frame(token: &str) -> Result<Vec<u8>, WatermarkError> {
    let payload = decode_payload(token)?;
    let payload_bytes = serde_json::to_vec(&payload).map_err(|_| WatermarkError::InvalidPayload)?;
    let compressed = compress_bytes(&payload_bytes)?;
    let compressed_len: u16 = compressed
        .len()
        .try_into()
        .map_err(|_| WatermarkError::CarrierCapacityExceeded)?;

    let mut frame = Vec::with_capacity(PNG_DCT_HEADER_SIZE + compressed.len() + 4);
    frame.extend_from_slice(PNG_DCT_FRAME_MAGIC);
    frame.push(PNG_DCT_FRAME_VERSION);
    frame.extend_from_slice(&compressed_len.to_be_bytes());
    frame.extend_from_slice(&compressed);
    frame.extend_from_slice(&crc32(&payload_bytes).to_be_bytes());
    Ok(frame)
}

fn parse_png_dct_frame(frame: &[u8]) -> Result<WatermarkPayload, WatermarkError> {
    if frame.len() < PNG_DCT_HEADER_SIZE + 4 || frame.get(0..4) != Some(PNG_DCT_FRAME_MAGIC) {
        return Err(WatermarkError::InvalidEncoding);
    }
    if frame[4] != PNG_DCT_FRAME_VERSION {
        return Err(WatermarkError::InvalidEncoding);
    }

    let compressed_len = u16::from_be_bytes([frame[5], frame[6]]) as usize;
    let expected_len = PNG_DCT_HEADER_SIZE + compressed_len + 4;
    if frame.len() != expected_len {
        return Err(WatermarkError::InvalidEncoding);
    }

    let compressed = &frame[PNG_DCT_HEADER_SIZE..PNG_DCT_HEADER_SIZE + compressed_len];
    let expected_crc = u32::from_be_bytes(
        frame[PNG_DCT_HEADER_SIZE + compressed_len..expected_len]
            .try_into()
            .map_err(|_| WatermarkError::InvalidEncoding)?,
    );
    let payload_bytes = decompress_bytes(compressed)?;
    if crc32(&payload_bytes) != expected_crc {
        return Err(WatermarkError::DigestMismatch);
    }

    serde_json::from_slice(&payload_bytes).map_err(|_| WatermarkError::InvalidPayload)
}

fn compress_bytes(bytes: &[u8]) -> Result<Vec<u8>, WatermarkError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(bytes)
        .map_err(|_| WatermarkError::CompressionFailed)?;
    encoder
        .finish()
        .map_err(|_| WatermarkError::CompressionFailed)
}

fn decompress_bytes(bytes: &[u8]) -> Result<Vec<u8>, WatermarkError> {
    let mut decoder = ZlibDecoder::new(bytes);
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .map_err(|_| WatermarkError::DecompressionFailed)?;
    Ok(output)
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for shift in (0..8).rev() {
            bits.push((byte >> shift) & 1);
        }
    }
    bits
}

fn bits_to_bytes(bits: &[u8]) -> Option<Vec<u8>> {
    if !bits.len().is_multiple_of(8) {
        return None;
    }

    let mut bytes = Vec::with_capacity(bits.len() / 8);
    for chunk in bits.chunks_exact(8) {
        let mut value = 0_u8;
        for bit in chunk {
            value = (value << 1) | (*bit & 1);
        }
        bytes.push(value);
    }
    Some(bytes)
}

fn embed_jpeg_dct_watermark(content: &[u8], token: &str) -> Result<Vec<u8>, WatermarkError> {
    let frame = build_jpeg_dct_frame(token)?;
    let bits = bytes_to_bits(&frame);
    let mut jpeg = JpegCoefficientImage::parse(content)?;
    let carrier_blocks = jpeg.primary_component_block_indices();
    if bits.len() * JPEG_DCT_SPREAD_FACTOR > carrier_blocks.len() {
        return Err(WatermarkError::CarrierCapacityExceeded);
    }

    for (bit_index, bit) in bits.iter().enumerate() {
        for repeat_index in 0..JPEG_DCT_SPREAD_FACTOR {
            let block_index = carrier_blocks[bit_index * JPEG_DCT_SPREAD_FACTOR + repeat_index];
            jpeg.embed_bit(block_index, *bit);
        }
    }

    jpeg.encode()
}

fn extract_jpeg_dct_watermark(content: &[u8]) -> Option<ExtractedToken> {
    let jpeg = JpegCoefficientImage::parse(content).ok()?;
    let carrier_blocks = jpeg.primary_component_block_indices();
    let logical_capacity_bits = carrier_blocks.len() / JPEG_DCT_SPREAD_FACTOR;
    if logical_capacity_bits < JPEG_DCT_FRAME_HEADER_SIZE * 8 {
        return None;
    }

    let (header_bits, _) = jpeg.extract_bits(&carrier_blocks, JPEG_DCT_FRAME_HEADER_SIZE * 8)?;
    let header = bits_to_bytes(&header_bits)?;
    if header.get(0..4) != Some(JPEG_DCT_FRAME_MAGIC)
        || header.get(4).copied() != Some(JPEG_DCT_FRAME_VERSION)
    {
        return None;
    }

    let compressed_len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let total_frame_bytes = JPEG_DCT_FRAME_HEADER_SIZE + compressed_len + 4;
    if total_frame_bytes * 8 > logical_capacity_bits {
        return None;
    }

    let (frame_bits, confidences) = jpeg.extract_bits(&carrier_blocks, total_frame_bytes * 8)?;
    let frame = bits_to_bytes(&frame_bits)?;
    let payload = parse_jpeg_dct_frame(&frame).ok()?;
    let token = encode_payload(&payload).ok()?;
    let average_confidence = if confidences.is_empty() {
        0
    } else {
        (confidences
            .iter()
            .map(|value| u32::from(*value))
            .sum::<u32>()
            / confidences.len() as u32) as u8
    };

    Some(ExtractedToken {
        token,
        confidence_percent: average_confidence,
    })
}

fn build_jpeg_dct_frame(token: &str) -> Result<Vec<u8>, WatermarkError> {
    let payload = decode_payload(token)?;
    let payload_bytes = serde_json::to_vec(&payload).map_err(|_| WatermarkError::InvalidPayload)?;
    let compressed = compress_bytes(&payload_bytes)?;
    let compressed_len: u16 = compressed
        .len()
        .try_into()
        .map_err(|_| WatermarkError::CarrierCapacityExceeded)?;

    let mut frame = Vec::with_capacity(JPEG_DCT_FRAME_HEADER_SIZE + compressed.len() + 4);
    frame.extend_from_slice(JPEG_DCT_FRAME_MAGIC);
    frame.push(JPEG_DCT_FRAME_VERSION);
    frame.extend_from_slice(&compressed_len.to_be_bytes());
    frame.extend_from_slice(&compressed);
    frame.extend_from_slice(&crc32(&payload_bytes).to_be_bytes());
    Ok(frame)
}

fn parse_jpeg_dct_frame(frame: &[u8]) -> Result<WatermarkPayload, WatermarkError> {
    if frame.len() < JPEG_DCT_FRAME_HEADER_SIZE + 4 || frame.get(0..4) != Some(JPEG_DCT_FRAME_MAGIC)
    {
        return Err(WatermarkError::InvalidEncoding);
    }
    if frame[4] != JPEG_DCT_FRAME_VERSION {
        return Err(WatermarkError::InvalidEncoding);
    }

    let compressed_len = u16::from_be_bytes([frame[5], frame[6]]) as usize;
    let expected_len = JPEG_DCT_FRAME_HEADER_SIZE + compressed_len + 4;
    if frame.len() != expected_len {
        return Err(WatermarkError::InvalidEncoding);
    }

    let compressed =
        &frame[JPEG_DCT_FRAME_HEADER_SIZE..JPEG_DCT_FRAME_HEADER_SIZE + compressed_len];
    let expected_crc = u32::from_be_bytes(
        frame[JPEG_DCT_FRAME_HEADER_SIZE + compressed_len..expected_len]
            .try_into()
            .map_err(|_| WatermarkError::InvalidEncoding)?,
    );
    let payload_bytes = decompress_bytes(compressed)?;
    if crc32(&payload_bytes) != expected_crc {
        return Err(WatermarkError::DigestMismatch);
    }

    serde_json::from_slice(&payload_bytes).map_err(|_| WatermarkError::InvalidPayload)
}

#[derive(Clone)]
struct JpegHuffmanEntry {
    code: u16,
    len: u8,
    symbol: u8,
}

#[derive(Clone)]
struct JpegHuffmanTable {
    entries: Vec<JpegHuffmanEntry>,
    encodings: [Option<(u16, u8)>; 256],
}

impl JpegHuffmanTable {
    fn from_counts(counts: &[u8], values: &[u8]) -> Result<Self, WatermarkError> {
        if counts.len() != 16
            || values.len()
                != counts
                    .iter()
                    .map(|value| usize::from(*value))
                    .sum::<usize>()
        {
            return Err(WatermarkError::UnsupportedImageCarrier);
        }

        let mut entries = Vec::with_capacity(values.len());
        let mut encodings = [None; 256];
        let mut code = 0_u16;
        let mut value_index = 0_usize;
        for (length_index, count) in counts.iter().enumerate() {
            let len = (length_index + 1) as u8;
            for _ in 0..*count {
                let symbol = values[value_index];
                entries.push(JpegHuffmanEntry { code, len, symbol });
                encodings[usize::from(symbol)] = Some((code, len));
                code = code.saturating_add(1);
                value_index += 1;
            }
            code <<= 1;
        }

        Ok(Self { entries, encodings })
    }

    fn decode_symbol(&self, reader: &mut JpegBitReader<'_>) -> Option<u8> {
        let mut code = 0_u16;
        for len in 1..=16 {
            code = (code << 1) | u16::from(reader.read_bit()?);
            if let Some(entry) = self
                .entries
                .iter()
                .find(|entry| entry.len == len && entry.code == code)
            {
                return Some(entry.symbol);
            }
        }
        None
    }

    fn encoding(&self, symbol: u8) -> Option<(u16, u8)> {
        self.encodings[usize::from(symbol)]
    }
}

#[derive(Clone)]
#[allow(dead_code)]
struct JpegFrameComponent {
    id: u8,
    horizontal_factor: u8,
    vertical_factor: u8,
    quant_table_id: u8,
}

#[derive(Clone)]
struct JpegScanComponent {
    component_index: usize,
    dc_table_id: u8,
    ac_table_id: u8,
}

#[derive(Clone)]
struct JpegBlock {
    component_index: usize,
    coefficients: [i16; 64],
}

#[allow(dead_code)]
struct JpegCoefficientImage {
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    width: usize,
    height: usize,
    frame_components: Vec<JpegFrameComponent>,
    scan_components: Vec<JpegScanComponent>,
    dc_tables: Vec<Option<JpegHuffmanTable>>,
    ac_tables: Vec<Option<JpegHuffmanTable>>,
    quant_tables: Vec<Option<[u16; 64]>>,
    blocks: Vec<JpegBlock>,
}

impl JpegCoefficientImage {
    fn parse(content: &[u8]) -> Result<Self, WatermarkError> {
        if !content.starts_with(JPEG_SOI) {
            return Err(WatermarkError::UnsupportedImageCarrier);
        }

        let mut cursor = JPEG_SOI.len();
        let mut width = 0_usize;
        let mut height = 0_usize;
        let mut frame_components = Vec::new();
        let mut quant_tables = vec![None; 4];
        let mut dc_tables = (0..4).map(|_| None).collect::<Vec<_>>();
        let mut ac_tables = (0..4).map(|_| None).collect::<Vec<_>>();

        while cursor + 4 <= content.len() {
            let marker_offset = next_jpeg_marker(content, cursor)?;
            cursor = marker_offset + 2;
            let marker = content[marker_offset + 1];
            if marker == 0xD9 {
                return Err(WatermarkError::UnsupportedImageCarrier);
            }
            if is_jpeg_standalone_marker(marker) {
                continue;
            }
            if cursor + 2 > content.len() {
                return Err(WatermarkError::UnsupportedImageCarrier);
            }

            let segment_len = u16::from_be_bytes([content[cursor], content[cursor + 1]]) as usize;
            if segment_len < 2 || cursor + segment_len > content.len() {
                return Err(WatermarkError::UnsupportedImageCarrier);
            }
            let data_start = cursor + 2;
            let data_end = cursor + segment_len;
            let segment_data = &content[data_start..data_end];

            match marker {
                0xDB => parse_jpeg_dqt_segment(segment_data, &mut quant_tables)?,
                0xC4 => parse_jpeg_dht_segment(segment_data, &mut dc_tables, &mut ac_tables)?,
                0xC0 => {
                    let frame = parse_jpeg_sof0_segment(segment_data)?;
                    width = frame.0;
                    height = frame.1;
                    frame_components = frame.2;
                }
                0xC2 => return Err(WatermarkError::UnsupportedImageCarrier),
                0xDD => {
                    if segment_data.len() >= 2
                        && u16::from_be_bytes([segment_data[0], segment_data[1]]) != 0
                    {
                        return Err(WatermarkError::UnsupportedImageCarrier);
                    }
                }
                0xDA => {
                    if width == 0 || height == 0 || frame_components.is_empty() {
                        return Err(WatermarkError::UnsupportedImageCarrier);
                    }
                    let scan_components = parse_jpeg_sos_segment(segment_data, &frame_components)?;
                    let scan_data_start = data_end;
                    let scan_data_end = find_jpeg_entropy_end(content, scan_data_start)?;
                    let entropy_data =
                        destuff_jpeg_entropy(&content[scan_data_start..scan_data_end])?;
                    let blocks = decode_jpeg_scan_blocks(
                        width,
                        height,
                        &frame_components,
                        &scan_components,
                        &dc_tables,
                        &ac_tables,
                        &entropy_data,
                    )?;
                    return Ok(Self {
                        prefix: content[..scan_data_start].to_vec(),
                        suffix: content[scan_data_end..].to_vec(),
                        width,
                        height,
                        frame_components,
                        scan_components,
                        dc_tables,
                        ac_tables,
                        quant_tables,
                        blocks,
                    });
                }
                _ => {}
            }

            cursor = data_end;
        }

        Err(WatermarkError::UnsupportedImageCarrier)
    }

    fn encode(&self) -> Result<Vec<u8>, WatermarkError> {
        let entropy_data = self.encode_entropy_data()?;
        let mut output =
            Vec::with_capacity(self.prefix.len() + entropy_data.len() + self.suffix.len());
        output.extend_from_slice(&self.prefix);
        output.extend_from_slice(&entropy_data);
        output.extend_from_slice(&self.suffix);
        Ok(output)
    }

    fn encode_entropy_data(&self) -> Result<Vec<u8>, WatermarkError> {
        let mut writer = JpegBitWriter::default();
        let mut previous_dc = vec![0_i16; self.frame_components.len()];

        for block in &self.blocks {
            let scan_component = self
                .scan_components
                .iter()
                .find(|component| component.component_index == block.component_index)
                .ok_or(WatermarkError::UnsupportedImageCarrier)?;
            let dc_table = self
                .dc_tables
                .get(usize::from(scan_component.dc_table_id))
                .and_then(|table| table.as_ref())
                .ok_or(WatermarkError::UnsupportedImageCarrier)?;
            let ac_table = self
                .ac_tables
                .get(usize::from(scan_component.ac_table_id))
                .and_then(|table| table.as_ref())
                .ok_or(WatermarkError::UnsupportedImageCarrier)?;
            encode_jpeg_block(
                &mut writer,
                dc_table,
                ac_table,
                &block.coefficients,
                &mut previous_dc[block.component_index],
            )?;
        }

        Ok(writer.finish())
    }

    fn primary_component_block_indices(&self) -> Vec<usize> {
        let Some(primary_component) = self
            .scan_components
            .first()
            .map(|component| component.component_index)
        else {
            return Vec::new();
        };
        self.blocks
            .iter()
            .enumerate()
            .filter_map(|(index, block)| {
                (block.component_index == primary_component).then_some(index)
            })
            .collect()
    }

    fn embed_bit(&mut self, block_index: usize, bit: u8) {
        let block = &mut self.blocks[block_index];
        let mut a = block.coefficients[JPEG_DCT_COEFF_A_INDEX];
        let mut b = block.coefficients[JPEG_DCT_COEFF_B_INDEX];
        force_jpeg_dct_bit(&mut a, &mut b, bit);
        block.coefficients[JPEG_DCT_COEFF_A_INDEX] = a;
        block.coefficients[JPEG_DCT_COEFF_B_INDEX] = b;
    }

    fn extract_bits(
        &self,
        carrier_blocks: &[usize],
        logical_bits: usize,
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        if logical_bits * JPEG_DCT_SPREAD_FACTOR > carrier_blocks.len() {
            return None;
        }

        let mut bits = Vec::with_capacity(logical_bits);
        let mut confidences = Vec::with_capacity(logical_bits);
        for logical_index in 0..logical_bits {
            let mut ones = 0_usize;
            let mut confidence_sum = 0_u16;
            for repeat_index in 0..JPEG_DCT_SPREAD_FACTOR {
                let block_index =
                    carrier_blocks[logical_index * JPEG_DCT_SPREAD_FACTOR + repeat_index];
                let (bit, confidence) = self.extract_bit(block_index)?;
                ones += usize::from(bit);
                confidence_sum += u16::from(confidence);
            }
            bits.push((ones * 2 >= JPEG_DCT_SPREAD_FACTOR) as u8);
            confidences.push((confidence_sum / JPEG_DCT_SPREAD_FACTOR as u16) as u8);
        }

        Some((bits, confidences))
    }

    fn extract_bit(&self, block_index: usize) -> Option<(u8, u8)> {
        let block = self.blocks.get(block_index)?;
        let difference =
            block.coefficients[JPEG_DCT_COEFF_A_INDEX] - block.coefficients[JPEG_DCT_COEFF_B_INDEX];
        let confidence = ((f64::from(difference.abs()) / f64::from(JPEG_DCT_STRENGTH)).min(1.0)
            * 100.0)
            .round() as u8;
        Some(((difference >= 0) as u8, confidence))
    }
}

fn parse_jpeg_dqt_segment(
    segment: &[u8],
    quant_tables: &mut [Option<[u16; 64]>],
) -> Result<(), WatermarkError> {
    let mut cursor = 0_usize;
    while cursor < segment.len() {
        let table_info = segment[cursor];
        cursor += 1;
        let precision = table_info >> 4;
        let table_id = usize::from(table_info & 0x0F);
        if table_id >= quant_tables.len() {
            return Err(WatermarkError::UnsupportedImageCarrier);
        }
        let value_size = match precision {
            0 => 1,
            1 => 2,
            _ => return Err(WatermarkError::UnsupportedImageCarrier),
        };
        if cursor + 64 * value_size > segment.len() {
            return Err(WatermarkError::UnsupportedImageCarrier);
        }
        let mut table = [0_u16; 64];
        for slot in &mut table {
            *slot = if value_size == 1 {
                let value = u16::from(segment[cursor]);
                cursor += 1;
                value
            } else {
                let value = u16::from_be_bytes([segment[cursor], segment[cursor + 1]]);
                cursor += 2;
                value
            };
        }
        quant_tables[table_id] = Some(table);
    }
    Ok(())
}

fn parse_jpeg_dht_segment(
    segment: &[u8],
    dc_tables: &mut [Option<JpegHuffmanTable>],
    ac_tables: &mut [Option<JpegHuffmanTable>],
) -> Result<(), WatermarkError> {
    let mut cursor = 0_usize;
    while cursor < segment.len() {
        if cursor + 17 > segment.len() {
            return Err(WatermarkError::UnsupportedImageCarrier);
        }
        let table_info = segment[cursor];
        cursor += 1;
        let table_class = table_info >> 4;
        let table_id = usize::from(table_info & 0x0F);
        let counts = &segment[cursor..cursor + 16];
        cursor += 16;
        let value_count = counts
            .iter()
            .map(|value| usize::from(*value))
            .sum::<usize>();
        if cursor + value_count > segment.len() {
            return Err(WatermarkError::UnsupportedImageCarrier);
        }
        let values = &segment[cursor..cursor + value_count];
        cursor += value_count;
        let table = JpegHuffmanTable::from_counts(counts, values)?;
        match table_class {
            0 if table_id < dc_tables.len() => dc_tables[table_id] = Some(table),
            1 if table_id < ac_tables.len() => ac_tables[table_id] = Some(table),
            _ => return Err(WatermarkError::UnsupportedImageCarrier),
        }
    }
    Ok(())
}

fn parse_jpeg_sof0_segment(
    segment: &[u8],
) -> Result<(usize, usize, Vec<JpegFrameComponent>), WatermarkError> {
    if segment.len() < 6 || segment[0] != 8 {
        return Err(WatermarkError::UnsupportedImageCarrier);
    }
    let height = u16::from_be_bytes([segment[1], segment[2]]) as usize;
    let width = u16::from_be_bytes([segment[3], segment[4]]) as usize;
    let component_count = usize::from(segment[5]);
    if height == 0 || width == 0 || component_count == 0 || segment.len() < 6 + component_count * 3
    {
        return Err(WatermarkError::UnsupportedImageCarrier);
    }

    let mut components = Vec::with_capacity(component_count);
    let mut cursor = 6;
    for _ in 0..component_count {
        let id = segment[cursor];
        let sampling = segment[cursor + 1];
        let horizontal_factor = sampling >> 4;
        let vertical_factor = sampling & 0x0F;
        let quant_table_id = segment[cursor + 2];
        if horizontal_factor == 0 || vertical_factor == 0 {
            return Err(WatermarkError::UnsupportedImageCarrier);
        }
        components.push(JpegFrameComponent {
            id,
            horizontal_factor,
            vertical_factor,
            quant_table_id,
        });
        cursor += 3;
    }

    Ok((width, height, components))
}

fn parse_jpeg_sos_segment(
    segment: &[u8],
    frame_components: &[JpegFrameComponent],
) -> Result<Vec<JpegScanComponent>, WatermarkError> {
    if segment.len() < 4 {
        return Err(WatermarkError::UnsupportedImageCarrier);
    }
    let component_count = usize::from(segment[0]);
    if component_count == 0 || segment.len() < 1 + component_count * 2 + 3 {
        return Err(WatermarkError::UnsupportedImageCarrier);
    }

    let mut scan_components = Vec::with_capacity(component_count);
    let mut cursor = 1;
    for _ in 0..component_count {
        let component_id = segment[cursor];
        let table_selector = segment[cursor + 1];
        let component_index = frame_components
            .iter()
            .position(|component| component.id == component_id)
            .ok_or(WatermarkError::UnsupportedImageCarrier)?;
        scan_components.push(JpegScanComponent {
            component_index,
            dc_table_id: table_selector >> 4,
            ac_table_id: table_selector & 0x0F,
        });
        cursor += 2;
    }

    let spectral_start = segment[cursor];
    let spectral_end = segment[cursor + 1];
    let approximation = segment[cursor + 2];
    if spectral_start != 0 || spectral_end != 63 || approximation != 0 {
        return Err(WatermarkError::UnsupportedImageCarrier);
    }

    Ok(scan_components)
}

fn decode_jpeg_scan_blocks(
    width: usize,
    height: usize,
    frame_components: &[JpegFrameComponent],
    scan_components: &[JpegScanComponent],
    dc_tables: &[Option<JpegHuffmanTable>],
    ac_tables: &[Option<JpegHuffmanTable>],
    entropy_data: &[u8],
) -> Result<Vec<JpegBlock>, WatermarkError> {
    let max_h = frame_components
        .iter()
        .map(|component| usize::from(component.horizontal_factor))
        .max()
        .unwrap_or(1);
    let max_v = frame_components
        .iter()
        .map(|component| usize::from(component.vertical_factor))
        .max()
        .unwrap_or(1);
    let mcu_cols = ceil_div(width, max_h * JPEG_DCT_BLOCK_SIZE);
    let mcu_rows = ceil_div(height, max_v * JPEG_DCT_BLOCK_SIZE);
    let mut reader = JpegBitReader::new(entropy_data);
    let mut previous_dc = vec![0_i16; frame_components.len()];
    let blocks_per_mcu = scan_components
        .iter()
        .map(|scan_component| {
            let component = &frame_components[scan_component.component_index];
            usize::from(component.horizontal_factor) * usize::from(component.vertical_factor)
        })
        .sum::<usize>();
    let mut blocks = Vec::with_capacity(mcu_cols * mcu_rows * blocks_per_mcu);

    for _ in 0..mcu_rows {
        for _ in 0..mcu_cols {
            for scan_component in scan_components {
                let component = &frame_components[scan_component.component_index];
                let dc_table = dc_tables
                    .get(usize::from(scan_component.dc_table_id))
                    .and_then(|table| table.as_ref())
                    .ok_or(WatermarkError::UnsupportedImageCarrier)?;
                let ac_table = ac_tables
                    .get(usize::from(scan_component.ac_table_id))
                    .and_then(|table| table.as_ref())
                    .ok_or(WatermarkError::UnsupportedImageCarrier)?;
                for _ in 0..usize::from(component.vertical_factor) {
                    for _ in 0..usize::from(component.horizontal_factor) {
                        let coefficients = decode_jpeg_block(
                            &mut reader,
                            dc_table,
                            ac_table,
                            &mut previous_dc[scan_component.component_index],
                        )?;
                        blocks.push(JpegBlock {
                            component_index: scan_component.component_index,
                            coefficients,
                        });
                    }
                }
            }
        }
    }

    Ok(blocks)
}

fn decode_jpeg_block(
    reader: &mut JpegBitReader<'_>,
    dc_table: &JpegHuffmanTable,
    ac_table: &JpegHuffmanTable,
    previous_dc: &mut i16,
) -> Result<[i16; 64], WatermarkError> {
    let mut coefficients = [0_i16; 64];
    let dc_size = dc_table
        .decode_symbol(reader)
        .ok_or(WatermarkError::UnsupportedImageCarrier)?;
    if dc_size > 11 {
        return Err(WatermarkError::UnsupportedImageCarrier);
    }
    let dc_bits = reader
        .read_bits(dc_size)
        .ok_or(WatermarkError::UnsupportedImageCarrier)?;
    let dc_diff = jpeg_extend_value(dc_bits, dc_size);
    let dc = previous_dc.saturating_add(dc_diff);
    coefficients[0] = dc;
    *previous_dc = dc;

    let mut index = 1_usize;
    while index < 64 {
        let symbol = ac_table
            .decode_symbol(reader)
            .ok_or(WatermarkError::UnsupportedImageCarrier)?;
        match symbol {
            0x00 => break,
            0xF0 => index += 16,
            _ => {
                let run = usize::from(symbol >> 4);
                let size = symbol & 0x0F;
                index += run;
                if index >= 64 || size == 0 || size > 10 {
                    return Err(WatermarkError::UnsupportedImageCarrier);
                }
                let bits = reader
                    .read_bits(size)
                    .ok_or(WatermarkError::UnsupportedImageCarrier)?;
                coefficients[index] = jpeg_extend_value(bits, size);
                index += 1;
            }
        }
    }

    Ok(coefficients)
}

fn encode_jpeg_block(
    writer: &mut JpegBitWriter,
    dc_table: &JpegHuffmanTable,
    ac_table: &JpegHuffmanTable,
    coefficients: &[i16; 64],
    previous_dc: &mut i16,
) -> Result<(), WatermarkError> {
    let dc_diff = i32::from(coefficients[0]) - i32::from(*previous_dc);
    let dc_category = jpeg_category(dc_diff);
    write_jpeg_huffman_symbol(writer, dc_table, dc_category)?;
    if dc_category > 0 {
        writer.write_bits(jpeg_amplitude_bits(dc_diff, dc_category), dc_category);
    }
    *previous_dc = coefficients[0];

    let mut zero_run = 0_usize;
    for coefficient in coefficients.iter().take(64).skip(1) {
        if *coefficient == 0 {
            zero_run += 1;
            continue;
        }
        while zero_run > 15 {
            write_jpeg_huffman_symbol(writer, ac_table, 0xF0)?;
            zero_run -= 16;
        }
        let value = i32::from(*coefficient);
        let category = jpeg_category(value);
        let symbol = ((zero_run as u8) << 4) | category;
        write_jpeg_huffman_symbol(writer, ac_table, symbol)?;
        writer.write_bits(jpeg_amplitude_bits(value, category), category);
        zero_run = 0;
    }
    if zero_run > 0 {
        write_jpeg_huffman_symbol(writer, ac_table, 0x00)?;
    }

    Ok(())
}

fn write_jpeg_huffman_symbol(
    writer: &mut JpegBitWriter,
    table: &JpegHuffmanTable,
    symbol: u8,
) -> Result<(), WatermarkError> {
    let (code, len) = table
        .encoding(symbol)
        .ok_or(WatermarkError::UnsupportedImageCarrier)?;
    writer.write_bits(code, len);
    Ok(())
}

fn next_jpeg_marker(content: &[u8], mut cursor: usize) -> Result<usize, WatermarkError> {
    while cursor + 1 < content.len() {
        if content[cursor] == 0xFF && content[cursor + 1] != 0x00 && content[cursor + 1] != 0xFF {
            return Ok(cursor);
        }
        cursor += 1;
    }
    Err(WatermarkError::UnsupportedImageCarrier)
}

fn is_jpeg_standalone_marker(marker: u8) -> bool {
    marker == 0x01 || marker == 0xD8 || marker == 0xD9 || (0xD0..=0xD7).contains(&marker)
}

fn find_jpeg_entropy_end(content: &[u8], mut cursor: usize) -> Result<usize, WatermarkError> {
    while cursor + 1 < content.len() {
        if content[cursor] == 0xFF {
            let marker = content[cursor + 1];
            match marker {
                0x00 => cursor += 2,
                0xFF => cursor += 1,
                0xD0..=0xD7 => return Err(WatermarkError::UnsupportedImageCarrier),
                _ => return Ok(cursor),
            }
        } else {
            cursor += 1;
        }
    }
    Err(WatermarkError::UnsupportedImageCarrier)
}

fn destuff_jpeg_entropy(content: &[u8]) -> Result<Vec<u8>, WatermarkError> {
    let mut output = Vec::with_capacity(content.len());
    let mut cursor = 0_usize;
    while cursor < content.len() {
        if content[cursor] == 0xFF {
            if cursor + 1 >= content.len() {
                return Err(WatermarkError::UnsupportedImageCarrier);
            }
            match content[cursor + 1] {
                0x00 => {
                    output.push(0xFF);
                    cursor += 2;
                }
                0xFF => cursor += 1,
                _ => return Err(WatermarkError::UnsupportedImageCarrier),
            }
        } else {
            output.push(content[cursor]);
            cursor += 1;
        }
    }
    Ok(output)
}

fn force_jpeg_dct_bit(a: &mut i16, b: &mut i16, bit: u8) {
    let diff = *a - *b;
    if bit == 1 {
        if diff < JPEG_DCT_STRENGTH {
            let adjustment = ((JPEG_DCT_STRENGTH - diff) + 1) / 2;
            *a = a.saturating_add(adjustment).clamp(-2047, 2047);
            *b = b.saturating_sub(adjustment).clamp(-2047, 2047);
        }
    } else if diff > -JPEG_DCT_STRENGTH {
        let adjustment = ((JPEG_DCT_STRENGTH + diff) + 1) / 2;
        *a = a.saturating_sub(adjustment).clamp(-2047, 2047);
        *b = b.saturating_add(adjustment).clamp(-2047, 2047);
    }
}

fn jpeg_extend_value(bits: u16, size: u8) -> i16 {
    if size == 0 {
        return 0;
    }
    let threshold = 1_u16 << (size - 1);
    if bits < threshold {
        (i32::from(bits) + 1 - (1_i32 << size)) as i16
    } else {
        bits as i16
    }
}

fn jpeg_category(value: i32) -> u8 {
    let mut magnitude = value.unsigned_abs();
    let mut category = 0_u8;
    while magnitude > 0 {
        category += 1;
        magnitude >>= 1;
    }
    category
}

fn jpeg_amplitude_bits(value: i32, category: u8) -> u16 {
    if category == 0 {
        return 0;
    }
    if value >= 0 {
        value as u16
    } else {
        (value + ((1_i32 << category) - 1)) as u16
    }
}

fn ceil_div(value: usize, divisor: usize) -> usize {
    if divisor == 0 {
        0
    } else {
        value.div_ceil(divisor)
    }
}

struct JpegBitReader<'a> {
    data: &'a [u8],
    byte_index: usize,
    bit_index: u8,
}

impl<'a> JpegBitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_index: 0,
            bit_index: 0,
        }
    }

    fn read_bit(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.byte_index)?;
        let bit = (byte >> (7 - self.bit_index)) & 1;
        self.bit_index += 1;
        if self.bit_index == 8 {
            self.bit_index = 0;
            self.byte_index += 1;
        }
        Some(bit)
    }

    fn read_bits(&mut self, count: u8) -> Option<u16> {
        let mut value = 0_u16;
        for _ in 0..count {
            value = (value << 1) | u16::from(self.read_bit()?);
        }
        Some(value)
    }
}

#[derive(Default)]
struct JpegBitWriter {
    data: Vec<u8>,
    current_byte: u8,
    bits_filled: u8,
}

impl JpegBitWriter {
    fn write_bits(&mut self, bits: u16, count: u8) {
        for shift in (0..count).rev() {
            let bit = ((bits >> shift) & 1) as u8;
            self.current_byte |= bit << (7 - self.bits_filled);
            self.bits_filled += 1;
            if self.bits_filled == 8 {
                self.emit_current_byte();
            }
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits_filled > 0 {
            let remaining = 8 - self.bits_filled;
            self.current_byte |= (1_u8 << remaining) - 1;
            self.emit_current_byte();
        }
        self.data
    }

    fn emit_current_byte(&mut self) {
        self.data.push(self.current_byte);
        if self.current_byte == 0xFF {
            self.data.push(0x00);
        }
        self.current_byte = 0;
        self.bits_filled = 0;
    }
}

#[derive(Clone)]
struct PngChunk {
    chunk_type: [u8; 4],
    data: Vec<u8>,
}

struct PngRaster {
    width: usize,
    height: usize,
    bytes_per_pixel: usize,
    ihdr_data: Vec<u8>,
    ancillary_chunks: Vec<PngChunk>,
    pixels: Vec<u8>,
}

impl PngRaster {
    fn decode(content: &[u8]) -> Result<Self, WatermarkError> {
        if !content.starts_with(PNG_SIGNATURE) {
            return Err(WatermarkError::PngDecodeFailed);
        }

        let mut cursor = PNG_SIGNATURE.len();
        let mut ihdr_data = None;
        let mut idat = Vec::new();
        let mut ancillary_chunks = Vec::new();

        while cursor + 12 <= content.len() {
            let length = u32::from_be_bytes(
                content[cursor..cursor + 4]
                    .try_into()
                    .map_err(|_| WatermarkError::PngDecodeFailed)?,
            ) as usize;
            let chunk_type: [u8; 4] = content[cursor + 4..cursor + 8]
                .try_into()
                .map_err(|_| WatermarkError::PngDecodeFailed)?;
            let data_start = cursor + 8;
            let data_end = data_start + length;
            let chunk_end = data_end + 4;
            if chunk_end > content.len() {
                return Err(WatermarkError::PngDecodeFailed);
            }

            let data = content[data_start..data_end].to_vec();
            match &chunk_type {
                b"IHDR" => ihdr_data = Some(data),
                b"IDAT" => idat.extend_from_slice(&data),
                b"IEND" => break,
                _ => ancillary_chunks.push(PngChunk { chunk_type, data }),
            }
            cursor = chunk_end;
        }

        let ihdr_data = ihdr_data.ok_or(WatermarkError::PngDecodeFailed)?;
        if ihdr_data.len() != 13 {
            return Err(WatermarkError::PngDecodeFailed);
        }

        let width = u32::from_be_bytes(ihdr_data[0..4].try_into().expect("width slice")) as usize;
        let height = u32::from_be_bytes(ihdr_data[4..8].try_into().expect("height slice")) as usize;
        let bit_depth = ihdr_data[8];
        let color_type = ihdr_data[9];
        let compression_method = ihdr_data[10];
        let filter_method = ihdr_data[11];
        let interlace_method = ihdr_data[12];

        if bit_depth != 8 || compression_method != 0 || filter_method != 0 || interlace_method != 0
        {
            return Err(WatermarkError::UnsupportedImageCarrier);
        }

        let bytes_per_pixel = match color_type {
            2 => 3,
            6 => 4,
            0 => 1,
            4 => 2,
            _ => return Err(WatermarkError::UnsupportedImageCarrier),
        };
        if width < PNG_DCT_BLOCK_SIZE || height < PNG_DCT_BLOCK_SIZE {
            return Err(WatermarkError::CarrierCapacityExceeded);
        }

        let decompressed = decompress_bytes(&idat)?;
        let row_len = width * bytes_per_pixel;
        let expected_len = height * (row_len + 1);
        if decompressed.len() != expected_len {
            return Err(WatermarkError::PngDecodeFailed);
        }

        let pixels = unfilter_png_scanlines(&decompressed, width, height, bytes_per_pixel)?;

        Ok(Self {
            width,
            height,
            bytes_per_pixel,
            ihdr_data,
            ancillary_chunks,
            pixels,
        })
    }

    fn encode(&self) -> Result<Vec<u8>, WatermarkError> {
        let row_len = self.row_len();
        let mut encoded_scanlines = Vec::with_capacity(self.height * (row_len + 1));
        for row in 0..self.height {
            encoded_scanlines.push(0);
            let start = row * row_len;
            encoded_scanlines.extend_from_slice(&self.pixels[start..start + row_len]);
        }

        let compressed = compress_bytes(&encoded_scanlines)?;
        let mut output = Vec::new();
        output.extend_from_slice(PNG_SIGNATURE);
        output.extend_from_slice(&build_png_chunk(b"IHDR", &self.ihdr_data));
        for chunk in &self.ancillary_chunks {
            if chunk.chunk_type != *PNG_WATERMARK_CHUNK_TYPE {
                output.extend_from_slice(&build_png_chunk(&chunk.chunk_type, &chunk.data));
            }
        }
        output.extend_from_slice(&build_png_chunk(b"IDAT", &compressed));
        output.extend_from_slice(&build_png_chunk(b"IEND", &[]));
        Ok(output)
    }

    fn row_len(&self) -> usize {
        self.width * self.bytes_per_pixel
    }

    fn block_capacity(&self) -> usize {
        (self.width / PNG_DCT_BLOCK_SIZE) * (self.height / PNG_DCT_BLOCK_SIZE)
    }

    fn channel_index(&self) -> usize {
        0
    }

    fn embed_bit(&mut self, block_index: usize, bit: u8) {
        let mut block = self.read_block(block_index).expect("block");
        let mut coeffs = dct_2d(&block);
        let a = coeffs[PNG_DCT_COEFF_A.0][PNG_DCT_COEFF_A.1];
        let b = coeffs[PNG_DCT_COEFF_B.0][PNG_DCT_COEFF_B.1];
        let difference = if bit == 1 { a - b } else { b - a };
        if difference < PNG_DCT_STRENGTH {
            let adjustment = (PNG_DCT_STRENGTH - difference) / 2.0;
            if bit == 1 {
                coeffs[PNG_DCT_COEFF_A.0][PNG_DCT_COEFF_A.1] += adjustment;
                coeffs[PNG_DCT_COEFF_B.0][PNG_DCT_COEFF_B.1] -= adjustment;
            } else {
                coeffs[PNG_DCT_COEFF_A.0][PNG_DCT_COEFF_A.1] -= adjustment;
                coeffs[PNG_DCT_COEFF_B.0][PNG_DCT_COEFF_B.1] += adjustment;
            }
        }
        block = idct_2d(&coeffs);
        self.write_block(block_index, &block);
    }

    fn extract_bits(&self, logical_bits: usize) -> Option<(Vec<u8>, Vec<u8>)> {
        if logical_bits * PNG_DCT_SPREAD_FACTOR > self.block_capacity() {
            return None;
        }

        let mut bits = Vec::with_capacity(logical_bits);
        let mut confidences = Vec::with_capacity(logical_bits);
        for logical_index in 0..logical_bits {
            let mut ones = 0usize;
            let mut confidence_sum = 0u16;
            for repeat_index in 0..PNG_DCT_SPREAD_FACTOR {
                let block_index = logical_index * PNG_DCT_SPREAD_FACTOR + repeat_index;
                let (bit, confidence) = self.extract_bit(block_index)?;
                ones += bit as usize;
                confidence_sum += u16::from(confidence);
            }
            bits.push((ones * 2 >= PNG_DCT_SPREAD_FACTOR) as u8);
            confidences.push((confidence_sum / PNG_DCT_SPREAD_FACTOR as u16) as u8);
        }

        Some((bits, confidences))
    }

    fn extract_bit(&self, block_index: usize) -> Option<(u8, u8)> {
        let block = self.read_block(block_index)?;
        let coeffs = dct_2d(&block);
        let difference = coeffs[PNG_DCT_COEFF_A.0][PNG_DCT_COEFF_A.1]
            - coeffs[PNG_DCT_COEFF_B.0][PNG_DCT_COEFF_B.1];
        let confidence = ((difference.abs() / PNG_DCT_STRENGTH).min(1.0) * 100.0).round() as u8;
        Some(((difference >= 0.0) as u8, confidence))
    }

    fn read_block(
        &self,
        block_index: usize,
    ) -> Option<[[f64; PNG_DCT_BLOCK_SIZE]; PNG_DCT_BLOCK_SIZE]> {
        let blocks_per_row = self.width / PNG_DCT_BLOCK_SIZE;
        let block_x = (block_index % blocks_per_row) * PNG_DCT_BLOCK_SIZE;
        let block_y = (block_index / blocks_per_row) * PNG_DCT_BLOCK_SIZE;
        if block_y + PNG_DCT_BLOCK_SIZE > self.height {
            return None;
        }

        let mut block = [[0.0; PNG_DCT_BLOCK_SIZE]; PNG_DCT_BLOCK_SIZE];
        let channel = self.channel_index();
        for (y, row) in block.iter_mut().enumerate() {
            for (x, value) in row.iter_mut().enumerate() {
                let pixel_index =
                    ((block_y + y) * self.row_len()) + ((block_x + x) * self.bytes_per_pixel);
                *value = f64::from(self.pixels[pixel_index + channel]) - 128.0;
            }
        }
        Some(block)
    }

    fn write_block(
        &mut self,
        block_index: usize,
        block: &[[f64; PNG_DCT_BLOCK_SIZE]; PNG_DCT_BLOCK_SIZE],
    ) {
        let blocks_per_row = self.width / PNG_DCT_BLOCK_SIZE;
        let block_x = (block_index % blocks_per_row) * PNG_DCT_BLOCK_SIZE;
        let block_y = (block_index / blocks_per_row) * PNG_DCT_BLOCK_SIZE;
        let channel = self.channel_index();
        let row_len = self.row_len();
        for (y, row) in block.iter().enumerate() {
            for (x, value) in row.iter().enumerate() {
                let pixel_index =
                    ((block_y + y) * row_len) + ((block_x + x) * self.bytes_per_pixel);
                self.pixels[pixel_index + channel] =
                    (*value + 128.0).round().clamp(0.0, 255.0) as u8;
            }
        }
    }
}

fn unfilter_png_scanlines(
    encoded: &[u8],
    width: usize,
    height: usize,
    bytes_per_pixel: usize,
) -> Result<Vec<u8>, WatermarkError> {
    let row_len = width * bytes_per_pixel;
    let mut output = vec![0_u8; width * height * bytes_per_pixel];

    for row in 0..height {
        let filter = encoded[row * (row_len + 1)];
        let source_start = row * (row_len + 1) + 1;
        let source = &encoded[source_start..source_start + row_len];
        let target_start = row * row_len;
        let (before, after) = output.split_at_mut(target_start);
        let target = &mut after[..row_len];
        let previous = if row == 0 {
            None
        } else {
            Some(&before[target_start - row_len..target_start])
        };

        match filter {
            0 => target.copy_from_slice(source),
            1 => {
                for index in 0..row_len {
                    let left = if index >= bytes_per_pixel {
                        target[index - bytes_per_pixel]
                    } else {
                        0
                    };
                    target[index] = source[index].wrapping_add(left);
                }
            }
            2 => {
                for index in 0..row_len {
                    let up = previous.map_or(0, |row| row[index]);
                    target[index] = source[index].wrapping_add(up);
                }
            }
            3 => {
                for index in 0..row_len {
                    let left = if index >= bytes_per_pixel {
                        target[index - bytes_per_pixel]
                    } else {
                        0
                    };
                    let up = previous.map_or(0, |row| row[index]);
                    target[index] =
                        source[index].wrapping_add(((u16::from(left) + u16::from(up)) / 2) as u8);
                }
            }
            4 => {
                for index in 0..row_len {
                    let left = if index >= bytes_per_pixel {
                        target[index - bytes_per_pixel]
                    } else {
                        0
                    };
                    let up = previous.map_or(0, |row| row[index]);
                    let up_left = if index >= bytes_per_pixel {
                        previous.map_or(0, |row| row[index - bytes_per_pixel])
                    } else {
                        0
                    };
                    target[index] = source[index].wrapping_add(paeth_predictor(left, up, up_left));
                }
            }
            _ => return Err(WatermarkError::PngDecodeFailed),
        }
    }

    Ok(output)
}

fn paeth_predictor(left: u8, up: u8, up_left: u8) -> u8 {
    let left = i32::from(left);
    let up = i32::from(up);
    let up_left = i32::from(up_left);
    let predictor = left + up - up_left;
    let left_distance = (predictor - left).abs();
    let up_distance = (predictor - up).abs();
    let up_left_distance = (predictor - up_left).abs();

    if left_distance <= up_distance && left_distance <= up_left_distance {
        left as u8
    } else if up_distance <= up_left_distance {
        up as u8
    } else {
        up_left as u8
    }
}

fn dct_2d(
    block: &[[f64; PNG_DCT_BLOCK_SIZE]; PNG_DCT_BLOCK_SIZE],
) -> [[f64; PNG_DCT_BLOCK_SIZE]; PNG_DCT_BLOCK_SIZE] {
    let mut output = [[0.0; PNG_DCT_BLOCK_SIZE]; PNG_DCT_BLOCK_SIZE];
    let n = PNG_DCT_BLOCK_SIZE as f64;

    for (u, output_row) in output.iter_mut().enumerate() {
        for (v, output_value) in output_row.iter_mut().enumerate() {
            let alpha_u = if u == 0 {
                1.0 / n.sqrt()
            } else {
                (2.0 / n).sqrt()
            };
            let alpha_v = if v == 0 {
                1.0 / n.sqrt()
            } else {
                (2.0 / n).sqrt()
            };
            let mut sum = 0.0;
            for (y, block_row) in block.iter().enumerate() {
                for (x, block_value) in block_row.iter().enumerate() {
                    sum += *block_value
                        * (((2 * x + 1) as f64 * u as f64 * PI) / (2.0 * n)).cos()
                        * (((2 * y + 1) as f64 * v as f64 * PI) / (2.0 * n)).cos();
                }
            }
            *output_value = alpha_u * alpha_v * sum;
        }
    }

    output
}

fn idct_2d(
    coeffs: &[[f64; PNG_DCT_BLOCK_SIZE]; PNG_DCT_BLOCK_SIZE],
) -> [[f64; PNG_DCT_BLOCK_SIZE]; PNG_DCT_BLOCK_SIZE] {
    let mut output = [[0.0; PNG_DCT_BLOCK_SIZE]; PNG_DCT_BLOCK_SIZE];
    let n = PNG_DCT_BLOCK_SIZE as f64;

    for (y, output_row) in output.iter_mut().enumerate() {
        for (x, output_value) in output_row.iter_mut().enumerate() {
            let mut sum = 0.0;
            for (u, coeff_row) in coeffs.iter().enumerate() {
                for (v, coeff) in coeff_row.iter().enumerate() {
                    let alpha_u = if u == 0 {
                        1.0 / n.sqrt()
                    } else {
                        (2.0 / n).sqrt()
                    };
                    let alpha_v = if v == 0 {
                        1.0 / n.sqrt()
                    } else {
                        (2.0 / n).sqrt()
                    };
                    sum += alpha_u
                        * alpha_v
                        * *coeff
                        * (((2 * x + 1) as f64 * u as f64 * PI) / (2.0 * n)).cos()
                        * (((2 * y + 1) as f64 * v as f64 * PI) / (2.0 * n)).cos();
                }
            }
            *output_value = sum;
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::{
        BatchByteScanInput, BatchScanInput, JPEG_COMMENT_PREFIX, JPEG_DCT_BLOCK_SIZE,
        JPEG_DCT_COEFF_A_INDEX, JPEG_DCT_COEFF_B_INDEX, JPEG_DCT_STRENGTH, JPEG_SOI, JpegBlock,
        JpegCoefficientImage, JpegFrameComponent, JpegHuffmanTable, JpegScanComponent,
        PDF_COMMENT_PREFIX, PNG_SIGNATURE, WatermarkAlgorithm, WatermarkContentFormat,
        WatermarkImplementationTier, WatermarkPayload, batch_scan, batch_scan_bytes,
        build_png_chunk, build_stored_zip_entry, decode_payload, detect_markers,
        detect_markers_in_bytes_with_format, embed_marker, embed_marker_bytes, encode_payload,
        extract_jpeg_comment_tokens, extract_jpeg_dct_watermark, overlay_text, rebuild_zip_archive,
        verify_bytes_with_format, verify_content,
    };

    const TEST_JPEG_ZIGZAG: [usize; 64] = [
        0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27,
        20, 13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
        58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
    ];
    const TEST_LUMA_DC_BITS: [u8; 16] = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0];
    const TEST_LUMA_DC_VALUES: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    const TEST_LUMA_AC_BITS: [u8; 16] = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125];
    const TEST_LUMA_AC_VALUES: [u8; 162] = [
        0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61,
        0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52,
        0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25,
        0x26, 0x27, 0x28, 0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
        0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64,
        0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x83,
        0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
        0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
        0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3,
        0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8,
        0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA,
    ];

    fn sample_payload() -> WatermarkPayload {
        WatermarkPayload {
            tenant_id: "tenant-alpha".into(),
            project_id: "project-alpha".into(),
            user_id: "user-analyst".into(),
            sequence_number: 42,
            issued_at: Utc::now(),
            snapshot_id: Some("snapshot-a".into()),
        }
    }

    fn minimal_png() -> Vec<u8> {
        let mut output = Vec::from(PNG_SIGNATURE.as_slice());
        output.extend_from_slice(&build_png_chunk(
            b"IHDR",
            &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0],
        ));
        output.extend_from_slice(&build_png_chunk(b"IEND", &[]));
        output
    }

    fn medium_png(width: u32, height: u32) -> Vec<u8> {
        use flate2::{Compression, write::ZlibEncoder};
        use std::io::Write;

        let mut scanlines = Vec::new();
        for y in 0..height {
            scanlines.push(0);
            for x in 0..width {
                let red = ((x * 255) / width.max(1)) as u8;
                let green = ((y * 255) / height.max(1)) as u8;
                let blue = red.wrapping_add(green / 2).wrapping_add(32);
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
        output.extend_from_slice(&build_png_chunk(b"IHDR", &ihdr));
        output.extend_from_slice(&build_png_chunk(b"IDAT", &compressed));
        output.extend_from_slice(&build_png_chunk(b"IEND", &[]));
        output
    }

    fn minimal_jpeg() -> Vec<u8> {
        let mut output = Vec::from(JPEG_SOI.as_slice());
        output.extend_from_slice(&[0xFF, 0xD9]);
        output
    }

    fn medium_jpeg(width: usize, height: usize) -> Vec<u8> {
        assert_eq!(width % JPEG_DCT_BLOCK_SIZE, 0);
        assert_eq!(height % JPEG_DCT_BLOCK_SIZE, 0);
        let quant_table = [1_u16; 64];
        encode_grayscale_jpeg_from_coefficients(width, height, &quant_table, || [0_i16; 64])
    }

    fn recompress_grayscale_jpeg(content: &[u8]) -> Vec<u8> {
        let parsed = JpegCoefficientImage::parse(content).expect("parse watermarked jpeg");
        assert_eq!(parsed.frame_components.len(), 1);
        let quant_table_id = usize::from(parsed.frame_components[0].quant_table_id);
        let quant_table = parsed.quant_tables[quant_table_id].expect("quant table");
        let pixels = decode_grayscale_pixels(&parsed, &quant_table);
        encode_grayscale_jpeg_from_pixels(parsed.width, parsed.height, &pixels, &quant_table)
    }

    fn encode_grayscale_jpeg_from_coefficients(
        width: usize,
        height: usize,
        quant_table: &[u16; 64],
        mut block_builder: impl FnMut() -> [i16; 64],
    ) -> Vec<u8> {
        let block_count = (width / JPEG_DCT_BLOCK_SIZE) * (height / JPEG_DCT_BLOCK_SIZE);
        let blocks = (0..block_count)
            .map(|_| JpegBlock {
                component_index: 0,
                coefficients: block_builder(),
            })
            .collect::<Vec<_>>();
        build_test_jpeg_image(width, height, *quant_table, blocks)
            .encode()
            .expect("encode jpeg")
    }

    fn encode_grayscale_jpeg_from_pixels(
        width: usize,
        height: usize,
        pixels: &[u8],
        quant_table: &[u16; 64],
    ) -> Vec<u8> {
        let blocks_per_row = width / JPEG_DCT_BLOCK_SIZE;
        let blocks_per_col = height / JPEG_DCT_BLOCK_SIZE;
        let mut blocks = Vec::with_capacity(blocks_per_row * blocks_per_col);
        for block_y in 0..blocks_per_col {
            for block_x in 0..blocks_per_row {
                let mut samples = [0_f64; 64];
                for y in 0..JPEG_DCT_BLOCK_SIZE {
                    for x in 0..JPEG_DCT_BLOCK_SIZE {
                        let pixel_x = block_x * JPEG_DCT_BLOCK_SIZE + x;
                        let pixel_y = block_y * JPEG_DCT_BLOCK_SIZE + y;
                        samples[y * JPEG_DCT_BLOCK_SIZE + x] =
                            f64::from(pixels[pixel_y * width + pixel_x]) - 128.0;
                    }
                }
                let dct = test_dct_8x8(&samples);
                let mut coefficients = [0_i16; 64];
                for zigzag_index in 0..64 {
                    let natural_index = TEST_JPEG_ZIGZAG[zigzag_index];
                    coefficients[zigzag_index] =
                        (dct[natural_index] / f64::from(quant_table[zigzag_index])).round() as i16;
                }
                blocks.push(JpegBlock {
                    component_index: 0,
                    coefficients,
                });
            }
        }
        build_test_jpeg_image(width, height, *quant_table, blocks)
            .encode()
            .expect("re-encode jpeg")
    }

    fn decode_grayscale_pixels(jpeg: &JpegCoefficientImage, quant_table: &[u16; 64]) -> Vec<u8> {
        let mut pixels = vec![128_u8; jpeg.width * jpeg.height];
        let blocks_per_row = jpeg.width / JPEG_DCT_BLOCK_SIZE;
        for (block_index, block) in jpeg.blocks.iter().enumerate() {
            let block_x = (block_index % blocks_per_row) * JPEG_DCT_BLOCK_SIZE;
            let block_y = (block_index / blocks_per_row) * JPEG_DCT_BLOCK_SIZE;
            let mut natural_coefficients = [0_f64; 64];
            for zigzag_index in 0..64 {
                let natural_index = TEST_JPEG_ZIGZAG[zigzag_index];
                natural_coefficients[natural_index] = f64::from(block.coefficients[zigzag_index])
                    * f64::from(quant_table[zigzag_index]);
            }
            let samples = test_idct_8x8(&natural_coefficients);
            for y in 0..JPEG_DCT_BLOCK_SIZE {
                for x in 0..JPEG_DCT_BLOCK_SIZE {
                    let pixel_x = block_x + x;
                    let pixel_y = block_y + y;
                    pixels[pixel_y * jpeg.width + pixel_x] =
                        (samples[y * JPEG_DCT_BLOCK_SIZE + x] + 128.0)
                            .round()
                            .clamp(0.0, 255.0) as u8;
                }
            }
        }
        pixels
    }

    fn build_test_jpeg_image(
        width: usize,
        height: usize,
        quant_table: [u16; 64],
        blocks: Vec<JpegBlock>,
    ) -> JpegCoefficientImage {
        let dc_table =
            JpegHuffmanTable::from_counts(&TEST_LUMA_DC_BITS, &TEST_LUMA_DC_VALUES).expect("dc");
        let ac_table =
            JpegHuffmanTable::from_counts(&TEST_LUMA_AC_BITS, &TEST_LUMA_AC_VALUES).expect("ac");
        JpegCoefficientImage {
            prefix: build_test_jpeg_prefix(width, height, &quant_table),
            suffix: vec![0xFF, 0xD9],
            width,
            height,
            frame_components: vec![JpegFrameComponent {
                id: 1,
                horizontal_factor: 1,
                vertical_factor: 1,
                quant_table_id: 0,
            }],
            scan_components: vec![JpegScanComponent {
                component_index: 0,
                dc_table_id: 0,
                ac_table_id: 0,
            }],
            dc_tables: vec![Some(dc_table), None, None, None],
            ac_tables: vec![Some(ac_table), None, None, None],
            quant_tables: vec![Some(quant_table), None, None, None],
            blocks,
        }
    }

    fn build_test_jpeg_prefix(width: usize, height: usize, quant_table: &[u16; 64]) -> Vec<u8> {
        let mut output = Vec::from(JPEG_SOI.as_slice());
        let mut dqt = vec![0x00];
        dqt.extend(quant_table.iter().map(|value| *value as u8));
        output.extend_from_slice(&jpeg_segment(0xDB, &dqt));

        let mut sof0 = Vec::new();
        sof0.push(8);
        sof0.extend_from_slice(&(height as u16).to_be_bytes());
        sof0.extend_from_slice(&(width as u16).to_be_bytes());
        sof0.extend_from_slice(&[1, 1, 0x11, 0]);
        output.extend_from_slice(&jpeg_segment(0xC0, &sof0));

        let mut dht_dc = vec![0x00];
        dht_dc.extend_from_slice(&TEST_LUMA_DC_BITS);
        dht_dc.extend_from_slice(&TEST_LUMA_DC_VALUES);
        output.extend_from_slice(&jpeg_segment(0xC4, &dht_dc));

        let mut dht_ac = vec![0x10];
        dht_ac.extend_from_slice(&TEST_LUMA_AC_BITS);
        dht_ac.extend_from_slice(&TEST_LUMA_AC_VALUES);
        output.extend_from_slice(&jpeg_segment(0xC4, &dht_ac));

        output.extend_from_slice(&jpeg_segment(0xDA, &[1, 1, 0x00, 0, 63, 0]));
        output
    }

    fn jpeg_segment(marker: u8, data: &[u8]) -> Vec<u8> {
        let length = (data.len() + 2) as u16;
        let mut segment = Vec::with_capacity(data.len() + 4);
        segment.extend_from_slice(&[0xFF, marker]);
        segment.extend_from_slice(&length.to_be_bytes());
        segment.extend_from_slice(data);
        segment
    }

    fn test_dct_8x8(samples: &[f64; 64]) -> [f64; 64] {
        let mut output = [0_f64; 64];
        let n = JPEG_DCT_BLOCK_SIZE as f64;
        for u in 0..JPEG_DCT_BLOCK_SIZE {
            for v in 0..JPEG_DCT_BLOCK_SIZE {
                let alpha_u = if u == 0 {
                    1.0 / n.sqrt()
                } else {
                    (2.0 / n).sqrt()
                };
                let alpha_v = if v == 0 {
                    1.0 / n.sqrt()
                } else {
                    (2.0 / n).sqrt()
                };
                let mut sum = 0.0;
                for x in 0..JPEG_DCT_BLOCK_SIZE {
                    for y in 0..JPEG_DCT_BLOCK_SIZE {
                        sum += samples[y * JPEG_DCT_BLOCK_SIZE + x]
                            * (((2 * x + 1) as f64 * u as f64 * std::f64::consts::PI) / (2.0 * n))
                                .cos()
                            * (((2 * y + 1) as f64 * v as f64 * std::f64::consts::PI) / (2.0 * n))
                                .cos();
                    }
                }
                output[u * JPEG_DCT_BLOCK_SIZE + v] = alpha_u * alpha_v * sum;
            }
        }
        output
    }

    fn test_idct_8x8(coefficients: &[f64; 64]) -> [f64; 64] {
        let mut output = [0_f64; 64];
        let n = JPEG_DCT_BLOCK_SIZE as f64;
        for x in 0..JPEG_DCT_BLOCK_SIZE {
            for y in 0..JPEG_DCT_BLOCK_SIZE {
                let mut sum = 0.0;
                for u in 0..JPEG_DCT_BLOCK_SIZE {
                    for v in 0..JPEG_DCT_BLOCK_SIZE {
                        let alpha_u = if u == 0 {
                            1.0 / n.sqrt()
                        } else {
                            (2.0 / n).sqrt()
                        };
                        let alpha_v = if v == 0 {
                            1.0 / n.sqrt()
                        } else {
                            (2.0 / n).sqrt()
                        };
                        sum += alpha_u
                            * alpha_v
                            * coefficients[u * JPEG_DCT_BLOCK_SIZE + v]
                            * (((2 * x + 1) as f64 * u as f64 * std::f64::consts::PI) / (2.0 * n))
                                .cos()
                            * (((2 * y + 1) as f64 * v as f64 * std::f64::consts::PI) / (2.0 * n))
                                .cos();
                    }
                }
                output[y * JPEG_DCT_BLOCK_SIZE + x] = sum;
            }
        }
        output
    }

    fn minimal_pdf() -> Vec<u8> {
        b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000068 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n117\n%%EOF\n"
            .to_vec()
    }

    fn minimal_ooxml_workbook() -> Vec<u8> {
        let entries = vec![
            build_stored_zip_entry(
                "[Content_Types].xml",
                br#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>"#,
            )
            .expect("content types"),
            build_stored_zip_entry(
                "xl/workbook.xml",
                br#"<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>"#,
            )
            .expect("workbook"),
        ];
        rebuild_zip_archive(&entries).expect("ooxml package")
    }

    #[test]
    fn payload_round_trips_through_token_encoding() {
        let payload = sample_payload();
        let token = encode_payload(&payload).expect("token");

        assert_eq!(decode_payload(&token).expect("payload"), payload);
    }

    #[test]
    fn detection_finds_zero_width_text_watermarks_as_algorithm_tier() {
        let token = encode_payload(&sample_payload()).expect("token");
        let matches = detect_markers(&embed_marker("phase5 export", &token));

        assert_eq!(matches.len(), 1);
        assert!(matches[0].verified);
        assert_eq!(matches[0].algorithm, WatermarkAlgorithm::ZeroWidthTextV1);
        assert_eq!(
            matches[0].implementation_tier,
            WatermarkImplementationTier::Algorithm
        );
        assert_eq!(
            matches[0].overlay_text.as_deref(),
            Some("tenant-alpha / project-alpha / user-analyst #42")
        );
    }

    #[test]
    fn legacy_marker_detection_stays_available_for_backward_compatibility() {
        let token = encode_payload(&sample_payload()).expect("token");
        let legacy = format!("phase5 export\n[[SDQP-WM:{token}]]");
        let matches = detect_markers(&legacy);

        assert_eq!(matches.len(), 1);
        assert!(matches[0].verified);
        assert_eq!(
            matches[0].implementation_tier,
            WatermarkImplementationTier::Legacy
        );
    }

    #[test]
    fn batch_scan_marks_text_exports_as_algorithm_verified() {
        let token = encode_payload(&sample_payload()).expect("token");
        let reports = batch_scan(&[
            BatchScanInput {
                document_id: "doc-a".into(),
                content: embed_marker("marked", &token),
            },
            BatchScanInput {
                document_id: "doc-b".into(),
                content: "plain".into(),
            },
        ]);

        assert!(reports[0].verified);
        assert!(reports[0].algorithm_verified);
        assert!(!reports[1].verified);
        assert_eq!(
            overlay_text(&sample_payload()),
            "tenant-alpha / project-alpha / user-analyst #42"
        );
        assert!(
            verify_content(&reports[0].matches[0].token, None)
                .matches
                .is_empty()
        );
    }

    #[test]
    fn image_embedding_uses_png_frequency_provider_when_capacity_allows() {
        let token = encode_payload(&sample_payload()).expect("token");
        let image = medium_png(256, 256);
        let embedded = embed_marker_bytes(&image, &token, WatermarkContentFormat::Image);
        let report =
            verify_bytes_with_format(&embedded, WatermarkContentFormat::Image, Some(&token));

        assert!(report.verified);
        assert!(report.algorithm_verified);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(
            report.matches[0].algorithm,
            WatermarkAlgorithm::PngFrequencyDctV1
        );
        assert_eq!(
            report.matches[0].implementation_tier,
            WatermarkImplementationTier::Algorithm
        );
    }

    #[test]
    fn image_embedding_uses_jpeg_dct_coefficients_when_capacity_allows() {
        let token = encode_payload(&sample_payload()).expect("token");
        let image = medium_jpeg(640, 512);
        let embedded = embed_marker_bytes(&image, &token, WatermarkContentFormat::Image);
        let report =
            verify_bytes_with_format(&embedded, WatermarkContentFormat::Image, Some(&token));

        assert!(report.verified);
        assert!(report.algorithm_verified);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(
            report.matches[0].algorithm,
            WatermarkAlgorithm::JpegCoefficientDctV1
        );
        assert_eq!(
            report.matches[0].implementation_tier,
            WatermarkImplementationTier::Algorithm
        );
        assert!(extract_jpeg_comment_tokens(&embedded).is_empty());
        assert!(
            !embedded
                .windows(JPEG_COMMENT_PREFIX.len())
                .any(|window| window == JPEG_COMMENT_PREFIX)
        );
        assert_eq!(
            extract_jpeg_dct_watermark(&embedded)
                .expect("dct token")
                .token,
            token
        );
        let batch_report = batch_scan_bytes(&[BatchByteScanInput {
            document_id: "jpeg-dct".into(),
            format: WatermarkContentFormat::Image,
            content: embedded.clone(),
        }]);
        assert!(batch_report[0].verified);
        assert!(batch_report[0].algorithm_verified);
        assert_eq!(
            batch_report[0].matches[0].algorithm,
            WatermarkAlgorithm::JpegCoefficientDctV1
        );

        let parsed = JpegCoefficientImage::parse(&embedded).expect("jpeg coefficients");
        let carrier_blocks = parsed.primary_component_block_indices();
        let first = &parsed.blocks[carrier_blocks[0]].coefficients;
        let first_difference = first[JPEG_DCT_COEFF_A_INDEX] - first[JPEG_DCT_COEFF_B_INDEX];
        assert!(first_difference.abs() >= JPEG_DCT_STRENGTH);
    }

    #[test]
    fn jpeg_dct_watermark_survives_same_quality_recompression() {
        let token = encode_payload(&sample_payload()).expect("token");
        let image = medium_jpeg(640, 512);
        let embedded = embed_marker_bytes(&image, &token, WatermarkContentFormat::Image);
        let recompressed = recompress_grayscale_jpeg(&embedded);
        let report =
            verify_bytes_with_format(&recompressed, WatermarkContentFormat::Image, Some(&token));

        assert!(report.verified);
        assert!(report.algorithm_verified);
        assert_eq!(
            report.matches[0].algorithm,
            WatermarkAlgorithm::JpegCoefficientDctV1
        );
        assert!(extract_jpeg_comment_tokens(&recompressed).is_empty());
    }

    #[test]
    fn image_embedding_falls_back_to_metadata_carrier_when_png_is_too_small() {
        let token = encode_payload(&sample_payload()).expect("token");
        let embedded = embed_marker_bytes(&minimal_png(), &token, WatermarkContentFormat::Image);
        let report =
            verify_bytes_with_format(&embedded, WatermarkContentFormat::Image, Some(&token));

        assert!(report.verified);
        assert!(!report.algorithm_verified);
        assert_eq!(
            report.matches[0].algorithm,
            WatermarkAlgorithm::PngChunkCarrierV1
        );
        assert_eq!(
            report.matches[0].implementation_tier,
            WatermarkImplementationTier::Carrier
        );
    }

    #[test]
    fn byte_detection_supports_pdf_png_and_jpeg_payloads() {
        let token = encode_payload(&sample_payload()).expect("token");
        let pdf = embed_marker_bytes(&minimal_pdf(), &token, WatermarkContentFormat::Pdf);
        let png = embed_marker_bytes(&medium_png(256, 256), &token, WatermarkContentFormat::Image);
        let jpeg = embed_marker_bytes(&minimal_jpeg(), &token, WatermarkContentFormat::Image);

        assert!(verify_bytes_with_format(&pdf, WatermarkContentFormat::Pdf, Some(&token)).verified);
        assert!(
            verify_bytes_with_format(&png, WatermarkContentFormat::Image, Some(&token)).verified
        );
        assert!(
            verify_bytes_with_format(&jpeg, WatermarkContentFormat::Image, Some(&token)).verified
        );
        assert_eq!(
            detect_markers_in_bytes_with_format(&pdf, WatermarkContentFormat::Pdf).len(),
            1
        );
        assert!(
            !pdf.windows(PDF_COMMENT_PREFIX.len())
                .any(|window| window == PDF_COMMENT_PREFIX)
        );
        assert!(
            pdf.windows(b"/Type /Metadata".len())
                .any(|window| window == b"/Type /Metadata")
        );
        assert!(
            pdf.windows(b"/Metadata 3 0 R".len())
                .any(|window| window == b"/Metadata 3 0 R")
        );
        assert_eq!(
            batch_scan_bytes(&[
                BatchByteScanInput {
                    document_id: "pdf".into(),
                    format: WatermarkContentFormat::Pdf,
                    content: pdf,
                },
                BatchByteScanInput {
                    document_id: "png".into(),
                    format: WatermarkContentFormat::Image,
                    content: png,
                },
                BatchByteScanInput {
                    document_id: "jpeg".into(),
                    format: WatermarkContentFormat::Image,
                    content: jpeg,
                },
            ])
            .iter()
            .filter(|report| report.verified)
            .count(),
            3
        );
    }

    #[test]
    fn pdf_embedding_uses_native_metadata_object_carrier() {
        let token = encode_payload(&sample_payload()).expect("token");
        let pdf = embed_marker_bytes(&minimal_pdf(), &token, WatermarkContentFormat::Pdf);
        let report = verify_bytes_with_format(&pdf, WatermarkContentFormat::Pdf, Some(&token));

        assert!(report.verified);
        assert!(!report.algorithm_verified);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(
            report.matches[0].algorithm,
            WatermarkAlgorithm::PdfMetadataObjectCarrierV1
        );
        assert_eq!(
            report.matches[0].implementation_tier,
            WatermarkImplementationTier::Carrier
        );
        assert_eq!(
            report.matches[0].content_format,
            WatermarkContentFormat::Pdf
        );
        assert!(
            !pdf.windows(PDF_COMMENT_PREFIX.len())
                .any(|window| window == PDF_COMMENT_PREFIX)
        );
    }

    #[test]
    fn office_embedding_uses_ooxml_custom_xml_carrier() {
        let token = encode_payload(&sample_payload()).expect("token");
        let office = embed_marker_bytes(
            &minimal_ooxml_workbook(),
            &token,
            WatermarkContentFormat::Office,
        );
        let report =
            verify_bytes_with_format(&office, WatermarkContentFormat::Office, Some(&token));

        assert!(report.verified);
        assert!(!report.algorithm_verified);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(
            report.matches[0].algorithm,
            WatermarkAlgorithm::OoxmlCustomXmlCarrierV1
        );
        assert_eq!(
            report.matches[0].implementation_tier,
            WatermarkImplementationTier::Carrier
        );
        assert_eq!(
            report.matches[0].content_format,
            WatermarkContentFormat::Office
        );
        assert_eq!(
            detect_markers_in_bytes_with_format(&office, WatermarkContentFormat::Office).len(),
            1
        );
        assert_eq!(
            batch_scan_bytes(&[BatchByteScanInput {
                document_id: "office".into(),
                format: WatermarkContentFormat::Office,
                content: office,
            }])[0]
                .matches[0]
                .algorithm,
            WatermarkAlgorithm::OoxmlCustomXmlCarrierV1
        );
    }
}
