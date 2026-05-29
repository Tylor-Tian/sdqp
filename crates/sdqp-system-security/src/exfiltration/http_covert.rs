use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpCovertFinding {
    pub suspicious: bool,
    pub reasons: Vec<String>,
}

pub fn inspect_http_covert_channel(
    url: &str,
    headers: &[(String, String)],
    body: &str,
) -> HttpCovertFinding {
    let lowered_url = url.to_ascii_lowercase();
    let lowered_body = body.to_ascii_lowercase();
    let mut reasons = Vec::new();

    if lowered_url.contains("pixel") || lowered_url.contains("beacon") {
        reasons.push("url resembles tracking beacon".into());
    }
    if lowered_url.contains("chunk=") || lowered_body.contains("chunk=") {
        reasons.push("payload contains chunk markers".into());
    }
    if headers.iter().any(|(name, value)| {
        let name = name.to_ascii_lowercase();
        let value = value.to_ascii_lowercase();
        name.contains("x-data") || value.contains("base64") || value.contains("base32")
    }) {
        reasons.push("headers contain encoded payload markers".into());
    }

    HttpCovertFinding {
        suspicious: !reasons.is_empty(),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::inspect_http_covert_channel;

    #[test]
    fn http_detector_flags_beacon_requests() {
        let finding = inspect_http_covert_channel(
            "https://exfil.example/pixel.gif?chunk=abc",
            &[("x-data".into(), "base64:abc".into())],
            "",
        );
        assert!(finding.suspicious);
    }
}
