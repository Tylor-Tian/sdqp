use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationPolicy {
    pub dek_rotation_days: i64,
    pub kek_rotation_days: i64,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            dek_rotation_days: 90,
            kek_rotation_days: 365,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationRecommendation {
    pub rotate_dek: bool,
    pub rotate_kek_wrap: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotationDueState {
    Current,
    KekRewrapDue,
    DekRotationDue,
    DekAndKekDue,
    Disabled,
    Purged,
}

impl KeyRotationDueState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::KekRewrapDue => "kek_rewrap_due",
            Self::DekRotationDue => "dek_rotation_due",
            Self::DekAndKekDue => "dek_and_kek_due",
            Self::Disabled => "disabled",
            Self::Purged => "purged",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "current" => Some(Self::Current),
            "kek_rewrap_due" => Some(Self::KekRewrapDue),
            "dek_rotation_due" => Some(Self::DekRotationDue),
            "dek_and_kek_due" => Some(Self::DekAndKekDue),
            "disabled" => Some(Self::Disabled),
            "purged" => Some(Self::Purged),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotationRuntimeStatus {
    Current,
    Due,
    Running,
    Completed,
    Failed,
    Skipped,
}

impl KeyRotationRuntimeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Due => "due",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "current" => Some(Self::Current),
            "due" => Some(Self::Due),
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "skipped" => Some(Self::Skipped),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotationOperation {
    None,
    KekRewrap,
    DekRotation,
    DekRotationAndKekRefresh,
}

impl KeyRotationOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::KekRewrap => "kek_rewrap",
            Self::DekRotation => "dek_rotation",
            Self::DekRotationAndKekRefresh => "dek_rotation_and_kek_refresh",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "kek_rewrap" => Some(Self::KekRewrap),
            "dek_rotation" => Some(Self::DekRotation),
            "dek_rotation_and_kek_refresh" => Some(Self::DekRotationAndKekRefresh),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRotationTrigger {
    Manual,
    Runtime,
    SnapshotRefresh,
}

impl KeyRotationTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Runtime => "runtime",
            Self::SnapshotRefresh => "snapshot_refresh",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationInventoryItem {
    pub snapshot_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub provider: String,
    pub kek_id: String,
    pub key_version: Option<String>,
    pub dek_id: String,
    pub created_at: DateTime<Utc>,
    pub last_rewrapped_at: Option<DateTime<Utc>>,
    pub purged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationState {
    pub inventory_id: String,
    pub snapshot_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub provider: String,
    pub kek_id: String,
    pub key_version: Option<String>,
    pub dek_id: String,
    pub created_at: DateTime<Utc>,
    pub last_rewrapped_at: Option<DateTime<Utc>>,
    pub next_dek_rotation_due_at: DateTime<Utc>,
    pub next_kek_rewrap_due_at: DateTime<Utc>,
    pub due_state: KeyRotationDueState,
    pub status: KeyRotationRuntimeStatus,
    pub last_operation: KeyRotationOperation,
    pub last_cycle_id: Option<String>,
    pub last_error: Option<String>,
    pub updated_at: DateTime<Utc>,
}

impl RotationPolicy {
    pub fn evaluate(
        &self,
        created_at: DateTime<Utc>,
        last_rewrapped_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> RotationRecommendation {
        let dek_due = created_at + Duration::days(self.dek_rotation_days) <= now;
        let rewrap_reference = last_rewrapped_at.unwrap_or(created_at);
        let kek_due = rewrap_reference + Duration::days(self.kek_rotation_days) <= now;

        RotationRecommendation {
            rotate_dek: dek_due,
            rotate_kek_wrap: kek_due,
        }
    }

    pub fn next_dek_rotation_due_at(&self, created_at: DateTime<Utc>) -> DateTime<Utc> {
        created_at + Duration::days(self.dek_rotation_days)
    }

    pub fn next_kek_rewrap_due_at(
        &self,
        created_at: DateTime<Utc>,
        last_rewrapped_at: Option<DateTime<Utc>>,
    ) -> DateTime<Utc> {
        last_rewrapped_at.unwrap_or(created_at) + Duration::days(self.kek_rotation_days)
    }

    pub fn due_state(
        &self,
        created_at: DateTime<Utc>,
        last_rewrapped_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
        enabled: bool,
        purged: bool,
    ) -> KeyRotationDueState {
        if !enabled {
            return KeyRotationDueState::Disabled;
        }
        if purged {
            return KeyRotationDueState::Purged;
        }

        let recommendation = self.evaluate(created_at, last_rewrapped_at, now);
        match (recommendation.rotate_dek, recommendation.rotate_kek_wrap) {
            (true, true) => KeyRotationDueState::DekAndKekDue,
            (true, false) => KeyRotationDueState::DekRotationDue,
            (false, true) => KeyRotationDueState::KekRewrapDue,
            (false, false) => KeyRotationDueState::Current,
        }
    }

    pub fn inventory_state(
        &self,
        inventory: &KeyRotationInventoryItem,
        now: DateTime<Utc>,
        enabled: bool,
    ) -> KeyRotationState {
        let due_state = self.due_state(
            inventory.created_at,
            inventory.last_rewrapped_at,
            now,
            enabled,
            inventory.purged,
        );
        let status = match due_state {
            KeyRotationDueState::Current => KeyRotationRuntimeStatus::Current,
            KeyRotationDueState::Disabled | KeyRotationDueState::Purged => {
                KeyRotationRuntimeStatus::Skipped
            }
            _ => KeyRotationRuntimeStatus::Due,
        };

        KeyRotationState {
            inventory_id: format!("snapshot:{}", inventory.snapshot_id),
            snapshot_id: inventory.snapshot_id.clone(),
            tenant_id: inventory.tenant_id.clone(),
            project_id: inventory.project_id.clone(),
            provider: inventory.provider.clone(),
            kek_id: inventory.kek_id.clone(),
            key_version: inventory.key_version.clone(),
            dek_id: inventory.dek_id.clone(),
            created_at: inventory.created_at,
            last_rewrapped_at: inventory.last_rewrapped_at,
            next_dek_rotation_due_at: self.next_dek_rotation_due_at(inventory.created_at),
            next_kek_rewrap_due_at: self
                .next_kek_rewrap_due_at(inventory.created_at, inventory.last_rewrapped_at),
            due_state,
            status,
            last_operation: KeyRotationOperation::None,
            last_cycle_id: None,
            last_error: None,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::{
        KeyRotationDueState, KeyRotationInventoryItem, KeyRotationRuntimeStatus, RotationPolicy,
    };

    #[test]
    fn rotation_policy_flags_old_snapshots() {
        let now = Utc::now();
        let recommendation = RotationPolicy::default().evaluate(
            now - Duration::days(120),
            Some(now - Duration::days(400)),
            now,
        );

        assert!(recommendation.rotate_dek);
        assert!(recommendation.rotate_kek_wrap);
    }

    #[test]
    fn rotation_policy_builds_persistent_inventory_state() {
        let now = Utc::now();
        let inventory = KeyRotationInventoryItem {
            snapshot_id: "snapshot-a".into(),
            tenant_id: "tenant-a".into(),
            project_id: "project-a".into(),
            provider: "vault".into(),
            kek_id: "tenant-a-kek".into(),
            key_version: Some("7".into()),
            dek_id: "dek-a".into(),
            created_at: now - Duration::days(120),
            last_rewrapped_at: Some(now - Duration::days(400)),
            purged: false,
        };

        let state = RotationPolicy::default().inventory_state(&inventory, now, true);

        assert_eq!(state.inventory_id, "snapshot:snapshot-a");
        assert_eq!(state.due_state, KeyRotationDueState::DekAndKekDue);
        assert_eq!(state.status, KeyRotationRuntimeStatus::Due);
        assert_eq!(state.provider, "vault");
        assert_eq!(state.key_version.as_deref(), Some("7"));
        assert_eq!(state.last_rewrapped_at, inventory.last_rewrapped_at);
    }
}
