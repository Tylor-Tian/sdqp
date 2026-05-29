use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub integration: String,
    pub credential_id: String,
    pub last_rotated_at: DateTime<Utc>,
    pub max_age_days: i64,
}

impl CredentialRecord {
    pub fn rotation_due_at(&self) -> DateTime<Utc> {
        self.last_rotated_at + Duration::days(self.max_age_days)
    }

    pub fn rotation_required(&self, now: DateTime<Utc>) -> bool {
        now >= self.rotation_due_at()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThirdPartyAssessment {
    pub integration: String,
    pub transport_encrypted: bool,
    pub minimum_scope: String,
    pub security_contact: String,
}

impl ThirdPartyAssessment {
    pub fn approved(&self) -> bool {
        self.transport_encrypted && !self.minimum_scope.trim().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::{CredentialRecord, ThirdPartyAssessment};

    #[test]
    fn credential_rotation_detects_expired_secret() {
        let record = CredentialRecord {
            integration: "hr".into(),
            credential_id: "token-a".into(),
            last_rotated_at: Utc::now() - Duration::days(120),
            max_age_days: 90,
        };

        assert!(record.rotation_required(Utc::now()));
    }

    #[test]
    fn assessment_requires_tls_and_scope() {
        assert!(
            ThirdPartyAssessment {
                integration: "hr".into(),
                transport_encrypted: true,
                minimum_scope: "org.read".into(),
                security_contact: "security@example.internal".into(),
            }
            .approved()
        );
    }
}
