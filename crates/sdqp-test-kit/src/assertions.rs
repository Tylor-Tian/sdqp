use sdqp_contracts::{HealthStatus, ServiceHealth};

pub fn assert_ready_health_json(json: &str, expected_service: &str) {
    let health: ServiceHealth = serde_json::from_str(json).expect("valid health payload");
    assert_eq!(health.service, expected_service);
    assert_eq!(health.status, HealthStatus::Ready);
}

#[cfg(test)]
mod tests {
    use super::assert_ready_health_json;

    #[test]
    fn assertion_accepts_ready_health_payload() {
        let payload = r#"{"service":"sdqp-api","status":"ready","phase":"phase0","details":{"milestone":"phase0-bootstrap"}}"#;
        assert_ready_health_json(payload, "sdqp-api");
    }
}
