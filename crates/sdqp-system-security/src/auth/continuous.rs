use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::mfa::{MfaChallenge, MfaChallengePayload, MfaMethod};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdaptiveResponse {
    Allow,
    StepUpAuth,
    TerminateSession,
}

impl AdaptiveResponse {
    pub fn for_score(score: f64) -> Self {
        if score < 30.0 {
            Self::Allow
        } else if score < 70.0 {
            Self::StepUpAuth
        } else {
            Self::TerminateSession
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskDimension {
    QueryFrequency,
    DataVolume,
    TemporalPattern,
    PermissionUsage,
    ExportBehavior,
    DevicePosture,
    NetworkContext,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskScore {
    pub score: f64,
    pub dimensions: HashMap<RiskDimension, f64>,
    pub triggered_rules: Vec<String>,
    pub recommended_action: AdaptiveResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePosture {
    pub device_fingerprint: String,
    pub os_version: String,
    pub patch_level_days: u16,
    pub rooted: bool,
    pub disk_encrypted: bool,
    pub edr_running: bool,
}

impl DevicePosture {
    pub fn compliant(&self) -> bool {
        !self.rooted && self.patch_level_days <= 30 && self.disk_encrypted && self.edr_running
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePostureReport {
    pub posture: DevicePosture,
    pub compliant: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct MockDevicePostureCollector;

impl MockDevicePostureCollector {
    pub fn collect(
        &self,
        device_fingerprint: &str,
        posture_profile: Option<&str>,
    ) -> DevicePostureReport {
        let posture = match posture_profile.unwrap_or("trusted") {
            "compromised" => DevicePosture {
                device_fingerprint: device_fingerprint.to_string(),
                os_version: "linux-legacy".into(),
                patch_level_days: 180,
                rooted: true,
                disk_encrypted: false,
                edr_running: false,
            },
            "legacy" => DevicePosture {
                device_fingerprint: device_fingerprint.to_string(),
                os_version: "windows-10".into(),
                patch_level_days: 75,
                rooted: false,
                disk_encrypted: true,
                edr_running: false,
            },
            _ => DevicePosture {
                device_fingerprint: device_fingerprint.to_string(),
                os_version: "windows-11".into(),
                patch_level_days: 7,
                rooted: false,
                disk_encrypted: true,
                edr_running: true,
            },
        };

        let mut reasons = Vec::new();
        if posture.rooted {
            reasons.push("device is rooted".into());
        }
        if posture.patch_level_days > 30 {
            reasons.push("device patch level is stale".into());
        }
        if !posture.disk_encrypted {
            reasons.push("disk encryption is disabled".into());
        }
        if !posture.edr_running {
            reasons.push("edr agent is not running".into());
        }

        DevicePostureReport {
            compliant: posture.compliant(),
            posture,
            reasons,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepUpChallenge {
    pub challenge_id: String,
    pub method: MfaMethod,
    pub reason: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub challenge_payload: Option<MfaChallengePayload>,
}

impl StepUpChallenge {
    pub fn new(method: MfaMethod, reason: impl Into<String>) -> Self {
        let issued_at = Utc::now();
        Self {
            challenge_id: Ulid::new().to_string(),
            method,
            reason: reason.into(),
            issued_at,
            expires_at: issued_at + Duration::minutes(5),
            challenge_payload: None,
        }
    }

    pub fn from_mfa_challenge(challenge: &MfaChallenge, reason: impl Into<String>) -> Self {
        Self {
            challenge_id: challenge.challenge_id.clone(),
            method: challenge.method.clone(),
            reason: reason.into(),
            issued_at: challenge.issued_at,
            expires_at: challenge.expires_at,
            challenge_payload: challenge.challenge_payload.clone(),
        }
    }

    pub fn as_mfa_challenge(&self) -> MfaChallenge {
        MfaChallenge {
            challenge_id: self.challenge_id.clone(),
            method: self.method.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            reason: Some(self.reason.clone()),
            challenge_payload: self.challenge_payload.clone(),
            dev_only_code: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ContinuousAccessSignal {
    pub query_burst: usize,
    pub denied_burst: usize,
    pub export_burst: usize,
    pub ip_drift: bool,
    pub impossible_travel: bool,
    pub exfiltration_hint: bool,
    pub device_posture: Option<DevicePostureReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub score: RiskScore,
    pub reasons: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct ContinuousAccessEvaluator;

impl ContinuousAccessEvaluator {
    pub fn assess(&self, signal: &ContinuousAccessSignal) -> RiskAssessment {
        let mut dimensions = HashMap::new();
        let mut reasons = Vec::new();
        let mut triggered_rules = Vec::new();
        let mut total: f64 = 0.0;

        if signal.query_burst >= 5 {
            dimensions.insert(RiskDimension::QueryFrequency, 28.0);
            triggered_rules.push("query_burst".into());
            reasons.push("query burst exceeds baseline".into());
            total += 28.0;
        }

        if signal.denied_burst >= 2 {
            dimensions.insert(RiskDimension::PermissionUsage, 24.0);
            triggered_rules.push("denied_burst".into());
            reasons.push("denied access burst detected".into());
            total += 24.0;
        }

        if signal.export_burst >= 3 {
            dimensions.insert(RiskDimension::ExportBehavior, 36.0);
            triggered_rules.push("export_burst".into());
            reasons.push("export spike detected".into());
            total += 36.0;
        }

        if signal.ip_drift || signal.impossible_travel {
            dimensions.insert(
                RiskDimension::NetworkContext,
                if signal.impossible_travel { 32.0 } else { 18.0 },
            );
            triggered_rules.push("network_context".into());
            reasons.push("network context drift detected".into());
            total += if signal.impossible_travel { 32.0 } else { 18.0 };
        }

        if signal.exfiltration_hint {
            dimensions.insert(RiskDimension::DataVolume, 30.0);
            triggered_rules.push("exfiltration_hint".into());
            reasons.push("covert-channel indicator detected".into());
            total += 30.0;
        }

        if let Some(posture) = &signal.device_posture
            && !posture.compliant
        {
            dimensions.insert(RiskDimension::DevicePosture, 35.0);
            triggered_rules.push("device_posture".into());
            reasons.extend(posture.reasons.iter().cloned());
            total += 35.0;
        }

        let total = total.min(100.0);
        let recommended_action = AdaptiveResponse::for_score(total);
        RiskAssessment {
            score: RiskScore {
                score: total,
                dimensions,
                triggered_rules,
                recommended_action,
            },
            reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AdaptiveResponse, ContinuousAccessEvaluator, ContinuousAccessSignal,
        MockDevicePostureCollector,
    };

    #[test]
    fn adaptive_response_maps_score_bands() {
        assert_eq!(AdaptiveResponse::for_score(10.0), AdaptiveResponse::Allow);
        assert_eq!(
            AdaptiveResponse::for_score(55.0),
            AdaptiveResponse::StepUpAuth
        );
        assert_eq!(
            AdaptiveResponse::for_score(95.0),
            AdaptiveResponse::TerminateSession
        );
    }

    #[test]
    fn continuous_access_prefers_termination_for_compromised_device_and_exfiltration() {
        let collector = MockDevicePostureCollector;
        let evaluator = ContinuousAccessEvaluator;
        let assessment = evaluator.assess(&ContinuousAccessSignal {
            export_burst: 3,
            exfiltration_hint: true,
            device_posture: Some(collector.collect("device-risky", Some("compromised"))),
            ..ContinuousAccessSignal::default()
        });

        assert_eq!(
            assessment.score.recommended_action,
            AdaptiveResponse::TerminateSession
        );
        assert!(assessment.score.score >= 70.0);
    }
}
