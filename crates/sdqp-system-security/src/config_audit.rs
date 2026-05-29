use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigVersion {
    pub version_id: String,
    pub config_key: String,
    pub payload_hash: String,
    pub approved_by_user_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl ConfigVersion {
    pub fn new(config_key: impl Into<String>, payload: impl AsRef<[u8]>) -> Self {
        let payload_hash = {
            let mut hasher = Sha256::new();
            hasher.update(payload.as_ref());
            hex::encode(hasher.finalize())
        };

        Self {
            version_id: Ulid::new().to_string(),
            config_key: config_key.into(),
            payload_hash,
            approved_by_user_id: None,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigDrift {
    pub key: String,
    pub expected: String,
    pub actual: String,
}

pub fn detect_config_drift(
    baseline: &HashMap<String, String>,
    runtime: &HashMap<String, String>,
) -> Vec<ConfigDrift> {
    baseline
        .iter()
        .filter_map(|(key, expected)| {
            let actual = runtime.get(key)?;
            if actual == expected {
                None
            } else {
                Some(ConfigDrift {
                    key: key.clone(),
                    expected: expected.clone(),
                    actual: actual.clone(),
                })
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{ConfigVersion, detect_config_drift};

    #[test]
    fn config_version_hashes_payload() {
        let version = ConfigVersion::new("kms.rotation.interval_days", "90");
        assert!(!version.payload_hash.is_empty());
    }

    #[test]
    fn drift_detection_returns_changed_keys() {
        let baseline = HashMap::from([("a".to_string(), "1".to_string())]);
        let runtime = HashMap::from([("a".to_string(), "2".to_string())]);
        let drifts = detect_config_drift(&baseline, &runtime);
        assert_eq!(drifts.len(), 1);
    }
}
