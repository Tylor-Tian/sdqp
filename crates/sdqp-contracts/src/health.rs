use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Ready,
    Degraded,
}

impl HealthStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceHealth {
    pub service: String,
    pub status: HealthStatus,
    pub phase: String,
    pub details: BTreeMap<String, String>,
}

impl ServiceHealth {
    pub fn ready(service: impl Into<String>, phase: impl Into<String>) -> Self {
        let mut details = BTreeMap::new();
        details.insert("milestone".into(), "phase0-bootstrap".into());

        Self {
            service: service.into(),
            status: HealthStatus::Ready,
            phase: phase.into(),
            details,
        }
    }

    pub fn degraded(
        service: impl Into<String>,
        phase: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        let mut details = BTreeMap::new();
        details.insert("reason".into(), reason.into());

        Self {
            service: service.into(),
            status: HealthStatus::Degraded,
            phase: phase.into(),
            details,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HealthStatus, ServiceHealth};

    #[test]
    fn health_status_exposes_expected_string() {
        assert_eq!(HealthStatus::Ready.as_str(), "ready");
        assert_eq!(HealthStatus::Degraded.as_str(), "degraded");
    }

    #[test]
    fn ready_health_has_phase0_milestone() {
        let health = ServiceHealth::ready("sdqp-api", "phase0");
        assert_eq!(health.service, "sdqp-api");
        assert_eq!(health.status, HealthStatus::Ready);
        assert_eq!(
            health.details.get("milestone").map(String::as_str),
            Some("phase0-bootstrap")
        );
    }

    #[test]
    fn degraded_health_tracks_reason() {
        let health = ServiceHealth::degraded("sdqp-worker", "phase0", "queue unavailable");
        assert_eq!(health.status, HealthStatus::Degraded);
        assert_eq!(
            health.details.get("reason").map(String::as_str),
            Some("queue unavailable")
        );
    }
}
