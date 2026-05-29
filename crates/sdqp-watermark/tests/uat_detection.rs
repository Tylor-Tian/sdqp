use std::io::Write;

use chrono::Utc;
use flate2::{Compression, write::ZlibEncoder};
use sdqp_watermark::{
    BatchByteScanInput, BatchScanInput, WatermarkAlgorithm, WatermarkContentFormat,
    WatermarkImplementationTier, WatermarkPayload, batch_scan, batch_scan_bytes, embed_marker,
    embed_marker_bytes, encode_payload, verify_bytes_with_format, verify_content,
};

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
    let mut scanlines = Vec::new();
    for y in 0..height {
        scanlines.push(0);
        for x in 0..width {
            let red = ((x * 255) / width.max(1)) as u8;
            let green = ((y * 255) / height.max(1)) as u8;
            let blue = red.wrapping_add(green / 3).wrapping_add(24);
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

#[test]
fn uat_watermark_payload_can_be_embedded_detected_and_verified() {
    let payload = WatermarkPayload {
        tenant_id: "tenant-alpha".into(),
        project_id: "project-alpha".into(),
        user_id: "user-analyst".into(),
        sequence_number: 7,
        issued_at: Utc::now(),
        snapshot_id: Some("snapshot-phase5".into()),
    };
    let token = encode_payload(&payload).expect("token");
    let document = embed_marker("judicial export body", &token);

    let verification = verify_content(&document, Some(&token));
    assert!(verification.verified);
    assert!(verification.algorithm_verified);
    assert_eq!(verification.matches.len(), 1);
    assert_eq!(
        verification.matches[0].algorithm,
        WatermarkAlgorithm::ZeroWidthTextV1
    );

    let reports = batch_scan(&[
        BatchScanInput {
            document_id: "marked".into(),
            content: document,
        },
        BatchScanInput {
            document_id: "plain".into(),
            content: "no watermark".into(),
        },
    ]);
    assert!(reports[0].verified);
    assert!(reports[0].algorithm_verified);
    assert!(!reports[1].verified);
}

#[test]
fn uat_image_watermark_distinguishes_algorithmic_png_from_carrier_fallback() {
    let payload = WatermarkPayload {
        tenant_id: "tenant-alpha".into(),
        project_id: "project-alpha".into(),
        user_id: "user-analyst".into(),
        sequence_number: 8,
        issued_at: Utc::now(),
        snapshot_id: Some("snapshot-phase5".into()),
    };
    let token = encode_payload(&payload).expect("token");
    let large_png =
        embed_marker_bytes(&medium_png(256, 256), &token, WatermarkContentFormat::Image);
    let small_png = embed_marker_bytes(
        &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
        &token,
        WatermarkContentFormat::Image,
    );

    let large_report =
        verify_bytes_with_format(&large_png, WatermarkContentFormat::Image, Some(&token));
    let small_report =
        verify_bytes_with_format(&small_png, WatermarkContentFormat::Image, Some(&token));

    assert!(large_report.verified);
    assert!(large_report.algorithm_verified);
    assert_eq!(
        large_report.matches[0].implementation_tier,
        WatermarkImplementationTier::Algorithm
    );
    assert_eq!(
        large_report.matches[0].algorithm,
        WatermarkAlgorithm::PngFrequencyDctV1
    );

    assert!(small_report.verified);
    assert!(!small_report.algorithm_verified);
    assert_eq!(
        small_report.matches[0].implementation_tier,
        WatermarkImplementationTier::Carrier
    );
}

#[test]
fn uat_batch_scan_supports_mixed_document_types() {
    let payload = WatermarkPayload {
        tenant_id: "tenant-alpha".into(),
        project_id: "project-alpha".into(),
        user_id: "user-analyst".into(),
        sequence_number: 9,
        issued_at: Utc::now(),
        snapshot_id: Some("snapshot-phase5".into()),
    };
    let token = encode_payload(&payload).expect("token");
    let pdf = embed_marker_bytes(&minimal_pdf(), &token, WatermarkContentFormat::Pdf);
    let png = embed_marker_bytes(&medium_png(256, 256), &token, WatermarkContentFormat::Image);

    let reports = batch_scan_bytes(&[
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
    ]);

    assert_eq!(reports.len(), 2);
    assert!(reports.iter().all(|report| report.verified));
    assert_eq!(
        reports[0].matches[0].algorithm,
        WatermarkAlgorithm::PdfMetadataObjectCarrierV1
    );
    assert_eq!(
        reports[0].matches[0].implementation_tier,
        WatermarkImplementationTier::Carrier
    );
    assert!(reports[1].algorithm_verified);
}

#[test]
fn uat_office_watermark_supports_ooxml_packages() {
    let payload = WatermarkPayload {
        tenant_id: "tenant-alpha".into(),
        project_id: "project-alpha".into(),
        user_id: "user-analyst".into(),
        sequence_number: 10,
        issued_at: Utc::now(),
        snapshot_id: Some("snapshot-phase5".into()),
    };
    let token = encode_payload(&payload).expect("token");
    let office = embed_marker_bytes(
        &minimal_ooxml_workbook(),
        &token,
        WatermarkContentFormat::Office,
    );

    let report = verify_bytes_with_format(&office, WatermarkContentFormat::Office, Some(&token));
    assert!(report.verified);
    assert!(!report.algorithm_verified);
    assert_eq!(
        report.matches[0].algorithm,
        WatermarkAlgorithm::OoxmlCustomXmlCarrierV1
    );

    let reports = batch_scan_bytes(&[BatchByteScanInput {
        document_id: "office".into(),
        format: WatermarkContentFormat::Office,
        content: office,
    }]);
    assert_eq!(reports.len(), 1);
    assert!(reports[0].verified);
    assert_eq!(
        reports[0].matches[0].content_format,
        WatermarkContentFormat::Office
    );
}
