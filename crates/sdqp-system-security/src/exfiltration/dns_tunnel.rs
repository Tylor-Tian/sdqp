use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsTunnelFinding {
    pub suspicious: bool,
    pub reasons: Vec<String>,
}

pub fn inspect_dns_tunnel(query: &str) -> DnsTunnelFinding {
    let lowered = query.to_ascii_lowercase();
    let mut reasons = Vec::new();

    if lowered.len() > 80 {
        reasons.push("dns query is unusually long".into());
    }
    if lowered.contains(" txt ") || lowered.ends_with(".txt") {
        reasons.push("dns query references txt records".into());
    }
    if lowered.contains("base32") || lowered.contains("chunk") {
        reasons.push("dns query contains encoded chunk markers".into());
    }

    DnsTunnelFinding {
        suspicious: !reasons.is_empty(),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::inspect_dns_tunnel;

    #[test]
    fn dns_tunnel_detector_flags_encoded_chunks() {
        let finding = inspect_dns_tunnel("dns://exfil.example TXT base32 chunk");
        assert!(finding.suspicious);
    }
}
