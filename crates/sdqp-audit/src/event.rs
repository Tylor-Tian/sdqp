use std::{collections::BTreeMap, convert::TryFrom};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorInfo {
    pub user_id: String,
    pub session_id: String,
    pub ip_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetRef {
    pub tenant_id: String,
    pub project_id: Option<String>,
    pub resource_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuditContextValue {
    Text(String),
    Bool(bool),
    Integer(i64),
    StringList(Vec<String>),
}

impl From<String> for AuditContextValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&str> for AuditContextValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_string())
    }
}

impl From<bool> for AuditContextValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for AuditContextValue {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<u64> for AuditContextValue {
    fn from(value: u64) -> Self {
        Self::Integer(i64::try_from(value).unwrap_or(i64::MAX))
    }
}

impl From<usize> for AuditContextValue {
    fn from(value: usize) -> Self {
        Self::Integer(i64::try_from(value).unwrap_or(i64::MAX))
    }
}

impl From<Vec<String>> for AuditContextValue {
    fn from(value: Vec<String>) -> Self {
        Self::StringList(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct AuditContextFields(BTreeMap<String, AuditContextValue>);

impl AuditContextFields {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> AuditContextBuilder {
        AuditContextBuilder::default()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn insert(
        &mut self,
        key: impl Into<String>,
        value: impl Into<AuditContextValue>,
    ) -> Option<AuditContextValue> {
        self.0.insert(key.into(), value.into())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &AuditContextValue)> {
        self.0.iter()
    }
}

impl FromIterator<(String, AuditContextValue)> for AuditContextFields {
    fn from_iter<T: IntoIterator<Item = (String, AuditContextValue)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuditContextBuilder {
    fields: AuditContextFields,
}

impl AuditContextBuilder {
    pub fn field(mut self, key: impl Into<String>, value: impl Into<AuditContextValue>) -> Self {
        self.fields.insert(key, value);
        self
    }

    pub fn build(self) -> AuditContextFields {
        self.fields
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    Query,
    View,
    Export,
    PermissionApply,
    Login,
    ConfigChange,
}

impl ActionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::View => "view",
            Self::Export => "export",
            Self::PermissionApply => "permission_apply",
            Self::Login => "login",
            Self::ConfigChange => "config_change",
        }
    }

    pub fn parse_label(label: &str) -> Option<Self> {
        match label.trim().to_ascii_lowercase().as_str() {
            "query" => Some(Self::Query),
            "view" => Some(Self::View),
            "export" => Some(Self::Export),
            "permissionapply" | "permission_apply" => Some(Self::PermissionApply),
            "login" => Some(Self::Login),
            "configchange" | "config_change" => Some(Self::ConfigChange),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionResult {
    Success,
    Failure,
    Denied,
}

impl ActionResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
        }
    }

    pub fn parse_label(label: &str) -> Option<Self> {
        match label.trim().to_ascii_lowercase().as_str() {
            "success" => Some(Self::Success),
            "failure" => Some(Self::Failure),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub actor: ActorInfo,
    pub action: ActionType,
    pub target: TargetRef,
    pub context: String,
    #[serde(default, skip_serializing_if = "AuditContextFields::is_empty")]
    pub context_fields: AuditContextFields,
    pub result: ActionResult,
    pub data_fingerprint: Option<String>,
    pub prev_hash: String,
    pub event_hash: String,
}

impl AuditEvent {
    pub fn new(
        actor: ActorInfo,
        action: ActionType,
        target: TargetRef,
        context: impl Into<String>,
        result: ActionResult,
        data_fingerprint: Option<String>,
        prev_hash: Option<String>,
    ) -> Self {
        Self::new_with_fields(
            actor,
            action,
            target,
            context,
            AuditContextFields::default(),
            result,
            data_fingerprint,
            prev_hash,
        )
    }

    pub fn new_with_fields(
        actor: ActorInfo,
        action: ActionType,
        target: TargetRef,
        context: impl Into<String>,
        context_fields: AuditContextFields,
        result: ActionResult,
        data_fingerprint: Option<String>,
        prev_hash: Option<String>,
    ) -> Self {
        let timestamp = Utc::now();
        let event_id = Ulid::new().to_string();
        let prev_hash = prev_hash.unwrap_or_else(|| "GENESIS".to_string());
        let context = context.into();
        let event_hash = compute_event_hash(&EventHashInput {
            event_id: &event_id,
            timestamp: &timestamp,
            actor: &actor,
            action: &action,
            target: &target,
            context: &context,
            context_fields: &context_fields,
            result: &result,
            data_fingerprint: data_fingerprint.as_deref(),
            prev_hash: &prev_hash,
        });

        Self {
            event_id,
            timestamp,
            actor,
            action,
            target,
            context,
            context_fields,
            result,
            data_fingerprint,
            prev_hash,
            event_hash,
        }
    }

    pub fn recompute_hash(&self) -> String {
        compute_event_hash(&EventHashInput {
            event_id: &self.event_id,
            timestamp: &self.timestamp,
            actor: &self.actor,
            action: &self.action,
            target: &self.target,
            context: &self.context,
            context_fields: &self.context_fields,
            result: &self.result,
            data_fingerprint: self.data_fingerprint.as_deref(),
            prev_hash: &self.prev_hash,
        })
    }

    pub fn verify_hash(&self) -> bool {
        self.event_hash == self.recompute_hash()
    }
}

struct EventHashInput<'a> {
    event_id: &'a str,
    timestamp: &'a DateTime<Utc>,
    actor: &'a ActorInfo,
    action: &'a ActionType,
    target: &'a TargetRef,
    context: &'a str,
    context_fields: &'a AuditContextFields,
    result: &'a ActionResult,
    data_fingerprint: Option<&'a str>,
    prev_hash: &'a str,
}

fn compute_event_hash(input: &EventHashInput<'_>) -> String {
    let payload = if input.context_fields.is_empty() {
        format!(
            "{}|{}|{}|{}|{}|{:?}|{}|{:?}|{}|{}|{}",
            input.event_id,
            canonical_timestamp(input.timestamp),
            input.actor.user_id,
            input.actor.session_id,
            input.actor.ip_address,
            input.action,
            input.target.resource_id,
            input.result,
            input.context,
            input.data_fingerprint.unwrap_or("-"),
            input.prev_hash
        )
    } else {
        format!(
            "{}|{}|{}|{}|{}|{:?}|{}|{:?}|{}|{}|{}|{}",
            input.event_id,
            canonical_timestamp(input.timestamp),
            input.actor.user_id,
            input.actor.session_id,
            input.actor.ip_address,
            input.action,
            input.target.resource_id,
            input.result,
            input.context,
            serialize_context_fields(input.context_fields),
            input.data_fingerprint.unwrap_or("-"),
            input.prev_hash
        )
    };

    hex::encode(Sha256::digest(payload.as_bytes()))
}

fn canonical_timestamp(timestamp: &DateTime<Utc>) -> String {
    timestamp.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn serialize_context_fields(context_fields: &AuditContextFields) -> String {
    serde_json::to_string(context_fields).expect("audit context fields must serialize")
}

#[cfg(test)]
mod tests {
    use chrono::SecondsFormat;
    use sha2::{Digest, Sha256};

    use super::{ActionResult, ActionType, ActorInfo, AuditContextFields, AuditEvent, TargetRef};

    fn actor() -> ActorInfo {
        ActorInfo {
            user_id: "user-a".into(),
            session_id: "session-a".into(),
            ip_address: "127.0.0.1".into(),
        }
    }

    fn target() -> TargetRef {
        TargetRef {
            tenant_id: "tenant-a".into(),
            project_id: Some("project-a".into()),
            resource_id: "snapshot-1".into(),
        }
    }

    #[test]
    fn audit_event_uses_genesis_hash_when_none_provided() {
        let event = AuditEvent::new(
            actor(),
            ActionType::Query,
            target(),
            "phase1 bootstrap",
            ActionResult::Success,
            None,
            None,
        );

        assert_eq!(event.prev_hash, "GENESIS");
        assert!(!event.event_hash.is_empty());
        assert!(event.verify_hash());
    }

    #[test]
    fn action_and_result_labels_round_trip() {
        assert_eq!(
            ActionType::parse_label(ActionType::ConfigChange.as_str()),
            Some(ActionType::ConfigChange)
        );
        assert_eq!(
            ActionResult::parse_label(ActionResult::Denied.as_str()),
            Some(ActionResult::Denied)
        );
    }

    #[test]
    fn structured_context_fields_round_trip_and_verify_hash() {
        let event = AuditEvent::new_with_fields(
            actor(),
            ActionType::Export,
            target(),
            "evidence package exported",
            AuditContextFields::builder()
                .field("snapshot_id", "snapshot-1")
                .field("template", "judicial")
                .field(
                    "requested_fields",
                    vec!["employee_id".to_string(), "department".to_string()],
                )
                .build(),
            ActionResult::Success,
            Some("sha256:evidence".into()),
            None,
        );

        assert_eq!(
            event
                .context_fields
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            vec!["requested_fields", "snapshot_id", "template"]
        );
        assert!(event.verify_hash());
    }

    #[test]
    fn empty_structured_context_preserves_legacy_hash_shape() {
        let event = AuditEvent::new(
            actor(),
            ActionType::Query,
            target(),
            "legacy-compatible query event",
            ActionResult::Success,
            Some("sha256:legacy".into()),
            Some("prev-hash".into()),
        );
        let legacy_payload = format!(
            "{}|{}|{}|{}|{}|{:?}|{}|{:?}|{}|{}|{}",
            event.event_id,
            event.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true),
            event.actor.user_id,
            event.actor.session_id,
            event.actor.ip_address,
            event.action,
            event.target.resource_id,
            event.result,
            event.context,
            event.data_fingerprint.as_deref().unwrap_or("-"),
            event.prev_hash
        );
        let legacy_hash = hex::encode(Sha256::digest(legacy_payload.as_bytes()));

        assert!(event.context_fields.is_empty());
        assert_eq!(event.event_hash, legacy_hash);
    }
}
