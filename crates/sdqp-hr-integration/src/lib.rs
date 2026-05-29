use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyncSource {
    Feishu,
    FeishuMock,
    Workday,
    WorkdayMock,
    SapSuccessFactors,
    SapSuccessFactorsMock,
    Ldap,
    LdapMock,
    CsvFallback,
}

impl SyncSource {
    pub fn is_mock_adapter(&self) -> bool {
        matches!(
            self,
            Self::FeishuMock | Self::WorkdayMock | Self::SapSuccessFactorsMock | Self::LdapMock
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmploymentStatus {
    Active,
    Departed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgUser {
    pub user_id: String,
    pub department_id: String,
    pub manager_id: Option<String>,
    pub status: EmploymentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_profile: Option<ApproverProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApproverAvailability {
    Available,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverProfile {
    pub availability: ApproverAvailability,
    pub delegate_user_id: Option<String>,
}

impl Default for ApproverProfile {
    fn default() -> Self {
        Self {
            availability: ApproverAvailability::Available,
            delegate_user_id: None,
        }
    }
}

const DEFAULT_APPROVER_SYSTEM_FALLBACK_USER_ID: &str = "user-sysadmin";
const DEFAULT_APPROVER_MAX_MANAGER_HOPS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverResolutionPolicy {
    pub system_fallback_user_id: String,
    #[serde(default)]
    pub escalation_user_ids: Vec<String>,
    #[serde(default = "default_approver_max_manager_hops")]
    pub max_manager_hops: usize,
    #[serde(default = "default_allow_approver_delegation")]
    pub allow_delegation: bool,
}

impl Default for ApproverResolutionPolicy {
    fn default() -> Self {
        Self {
            system_fallback_user_id: DEFAULT_APPROVER_SYSTEM_FALLBACK_USER_ID.into(),
            escalation_user_ids: Vec::new(),
            max_manager_hops: DEFAULT_APPROVER_MAX_MANAGER_HOPS,
            allow_delegation: true,
        }
    }
}

impl ApproverResolutionPolicy {
    pub fn with_system_fallback(system_fallback_user_id: impl Into<String>) -> Self {
        Self {
            system_fallback_user_id: system_fallback_user_id.into(),
            ..Self::default()
        }
    }

    fn normalized(&self) -> Self {
        let system_fallback_user_id = self.system_fallback_user_id.trim();
        Self {
            system_fallback_user_id: if system_fallback_user_id.is_empty() {
                DEFAULT_APPROVER_SYSTEM_FALLBACK_USER_ID.into()
            } else {
                system_fallback_user_id.to_string()
            },
            escalation_user_ids: self
                .escalation_user_ids
                .iter()
                .map(|user_id| user_id.trim())
                .filter(|user_id| !user_id.is_empty())
                .map(str::to_string)
                .collect(),
            max_manager_hops: self.max_manager_hops,
            allow_delegation: self.allow_delegation,
        }
    }
}

const fn default_approver_max_manager_hops() -> usize {
    DEFAULT_APPROVER_MAX_MANAGER_HOPS
}

const fn default_allow_approver_delegation() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApproverRouteKind {
    Direct,
    Delegated,
    EscalatedToManager,
    EscalatedToConfiguredTarget,
    SystemFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverRoute {
    pub requested_user_id: String,
    pub resolved_user_id: String,
    pub route_kind: ApproverRouteKind,
    pub delegated_from: Option<String>,
    pub escalation_target: Option<String>,
    pub used_system_fallback: bool,
    pub traversed_user_ids: Vec<String>,
    pub unavailable_user_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HrEventType {
    Onboard,
    Transfer,
    Departure,
    ManagerChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HrEvent {
    pub event_id: String,
    pub user_id: String,
    pub event_type: HrEventType,
    pub department_id: Option<String>,
    pub manager_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_profile: Option<ApproverProfile>,
    pub occurred_at: DateTime<Utc>,
}

impl HrEvent {
    pub fn new(
        user_id: impl Into<String>,
        event_type: HrEventType,
        department_id: Option<String>,
        manager_id: Option<String>,
    ) -> Self {
        Self {
            event_id: Ulid::new().to_string(),
            user_id: user_id.into(),
            event_type,
            department_id,
            manager_id,
            approver_profile: None,
            occurred_at: Utc::now(),
        }
    }

    pub fn with_approver_profile(mut self, approver_profile: ApproverProfile) -> Self {
        self.approver_profile = Some(approver_profile);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    Transfer,
    Departure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRevocationCommand {
    pub user_id: String,
    pub project_id: Option<String>,
    pub reason: RevocationReason,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HrError {
    #[error("user not found: {0}")]
    UserNotFound(String),
    #[error("invalid csv row: {0}")]
    InvalidCsvRow(String),
    #[error("invalid provider config: {0}")]
    InvalidProviderConfig(String),
    #[error("invalid provider response: {0}")]
    InvalidProviderResponse(String),
}

pub trait HrConnector {
    fn sync_snapshot(&self) -> Result<Vec<OrgUser>, HrError>;
    fn poll_events(&self, cursor: Option<&str>) -> Result<Vec<HrEvent>, HrError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LdapProviderAuth {
    Anonymous,
    SimpleBind {
        bind_dn: String,
        bind_password: String,
    },
}

impl LdapProviderAuth {
    pub fn mode(&self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::SimpleBind { .. } => "simple_bind",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LdapTlsMode {
    Plain,
    StartTls,
    Ldaps,
}

impl LdapTlsMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::StartTls => "start_tls",
            Self::Ldaps => "ldaps",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LdapAttributeMapping {
    pub user_id: String,
    pub department_id: String,
    pub manager_id: String,
    pub status: String,
    pub changed_since: String,
    pub active_status_values: Vec<String>,
    pub departed_status_values: Vec<String>,
}

impl Default for LdapAttributeMapping {
    fn default() -> Self {
        Self {
            user_id: "uid".into(),
            department_id: "departmentNumber".into(),
            manager_id: "manager".into(),
            status: "employeeStatus".into(),
            changed_since: "modifyTimestamp".into(),
            active_status_values: vec!["active".into(), "enabled".into(), "true".into()],
            departed_status_values: vec![
                "departed".into(),
                "inactive".into(),
                "disabled".into(),
                "terminated".into(),
                "false".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LdapProviderConfig {
    pub provider_id: String,
    pub url: String,
    pub auth: LdapProviderAuth,
    pub tls_mode: LdapTlsMode,
    pub base_dn: String,
    pub search_filter: String,
    pub search_scope: String,
    pub page_size: usize,
    pub timeout_ms: u64,
    pub ldapsearch_binary: String,
    pub ca_cert_path: Option<String>,
    pub tls_require_valid_cert: bool,
    pub attribute_mapping: LdapAttributeMapping,
}

impl LdapProviderConfig {
    pub fn validate_real_runtime(&self) -> Result<(), HrError> {
        if self.provider_id.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "provider_id is required".into(),
            ));
        }
        if self.url.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "url is required for LDAP runtime".into(),
            ));
        }
        if !self.url.starts_with("ldap://") && !self.url.starts_with("ldaps://") {
            return Err(HrError::InvalidProviderConfig(
                "LDAP url must use ldap:// or ldaps://".into(),
            ));
        }
        if self.tls_mode == LdapTlsMode::Ldaps && !self.url.starts_with("ldaps://") {
            return Err(HrError::InvalidProviderConfig(
                "ldaps tls_mode requires an ldaps:// url".into(),
            ));
        }
        if self.tls_mode == LdapTlsMode::StartTls && self.url.starts_with("ldaps://") {
            return Err(HrError::InvalidProviderConfig(
                "start_tls tls_mode should use an ldap:// url".into(),
            ));
        }
        if self.base_dn.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "base_dn is required for LDAP search".into(),
            ));
        }
        if self.search_filter.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "search_filter is required for LDAP search".into(),
            ));
        }
        if !matches!(
            self.search_scope.trim().to_ascii_lowercase().as_str(),
            "base" | "one" | "sub"
        ) {
            return Err(HrError::InvalidProviderConfig(
                "search_scope must be base, one, or sub".into(),
            ));
        }
        if self.page_size == 0 {
            return Err(HrError::InvalidProviderConfig(
                "page_size must be greater than zero".into(),
            ));
        }
        if self.timeout_ms == 0 {
            return Err(HrError::InvalidProviderConfig(
                "timeout_ms must be greater than zero".into(),
            ));
        }
        if self.ldapsearch_binary.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "ldapsearch_binary is required for the repo-local LDAP runtime".into(),
            ));
        }
        if self.attribute_mapping.user_id.trim().is_empty()
            || self.attribute_mapping.department_id.trim().is_empty()
            || self.attribute_mapping.manager_id.trim().is_empty()
            || self.attribute_mapping.status.trim().is_empty()
            || self.attribute_mapping.changed_since.trim().is_empty()
        {
            return Err(HrError::InvalidProviderConfig(
                "LDAP user_id, department_id, manager_id, status, and changed_since attribute mappings are required"
                    .into(),
            ));
        }
        match &self.auth {
            LdapProviderAuth::Anonymous => {}
            LdapProviderAuth::SimpleBind {
                bind_dn,
                bind_password,
            } => {
                if bind_dn.trim().is_empty() || bind_password.trim().is_empty() {
                    return Err(HrError::InvalidProviderConfig(
                        "bind_dn and bind_password are required for LDAP simple bind".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn runtime_mode(&self) -> LdapRuntimeMode {
        LdapRuntimeMode::RealDirectorySync
    }

    pub fn snapshot_search_filter(&self) -> String {
        normalized_ldap_filter(&self.search_filter)
    }

    pub fn incremental_search_filter(&self, watermark: Option<&str>) -> String {
        let base = normalized_ldap_filter(&self.search_filter);
        match watermark.filter(|value| !value.trim().is_empty()) {
            Some(watermark) => format!(
                "(&{}({}>={}))",
                base,
                self.attribute_mapping.changed_since,
                escape_ldap_filter_value(watermark)
            ),
            None => base,
        }
    }

    pub fn requested_attributes(&self) -> Vec<String> {
        let mut attrs = Vec::new();
        for attr in [
            &self.attribute_mapping.user_id,
            &self.attribute_mapping.department_id,
            &self.attribute_mapping.manager_id,
            &self.attribute_mapping.status,
            &self.attribute_mapping.changed_since,
        ] {
            if !attrs.iter().any(|existing: &String| existing == attr) {
                attrs.push(attr.clone());
            }
        }
        attrs
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LdapRuntimeMode {
    InMemoryMock,
    RealDirectorySync,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LdapDirectoryEntry {
    pub dn: String,
    pub attributes: HashMap<String, Vec<String>>,
}

impl LdapDirectoryEntry {
    pub fn value(&self, attr: &str) -> Option<&str> {
        self.values(attr)
            .and_then(|values| values.iter().find(|value| !value.trim().is_empty()))
            .map(String::as_str)
    }

    pub fn values(&self, attr: &str) -> Option<&Vec<String>> {
        self.attributes.get(attr).or_else(|| {
            self.attributes
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(attr))
                .map(|(_, values)| values)
        })
    }

    pub fn changed_since_value(&self, mapping: &LdapAttributeMapping) -> Option<String> {
        self.value(&mapping.changed_since).map(str::to_string)
    }

    pub fn to_org_user(&self, mapping: &LdapAttributeMapping) -> Result<OrgUser, HrError> {
        let user_id = self
            .value(&mapping.user_id)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                HrError::InvalidProviderResponse(format!(
                    "LDAP entry {} is missing user id attribute {}",
                    self.dn, mapping.user_id
                ))
            })?
            .to_string();
        let department_id = self
            .value(&mapping.department_id)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                HrError::InvalidProviderResponse(format!(
                    "LDAP entry {} is missing department attribute {}",
                    self.dn, mapping.department_id
                ))
            })?
            .to_string();
        let manager_id = self
            .value(&mapping.manager_id)
            .map(ldap_manager_reference_to_user_id)
            .filter(|value| !value.trim().is_empty());
        let status = self
            .value(&mapping.status)
            .map(|value| map_ldap_employment_status(&mapping.status, value, mapping))
            .unwrap_or(EmploymentStatus::Active);
        Ok(OrgUser {
            user_id,
            department_id,
            manager_id,
            status,
            approver_profile: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LdapDirectorySearchResult {
    pub entries: Vec<LdapDirectoryEntry>,
    pub next_watermark: Option<String>,
}

impl LdapDirectorySearchResult {
    pub fn from_ldif(
        ldif: &str,
        mapping: &LdapAttributeMapping,
    ) -> Result<LdapDirectorySearchResult, HrError> {
        let entries = parse_ldif_entries(ldif)?;
        let next_watermark = entries
            .iter()
            .filter_map(|entry| entry.changed_since_value(mapping))
            .max();
        Ok(Self {
            entries,
            next_watermark,
        })
    }

    pub fn into_org_users(self, mapping: &LdapAttributeMapping) -> Result<Vec<OrgUser>, HrError> {
        self.entries
            .iter()
            .map(|entry| entry.to_org_user(mapping))
            .collect()
    }
}

fn normalized_ldap_filter(filter: &str) -> String {
    let trimmed = filter.trim();
    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        trimmed.to_string()
    } else {
        format!("({trimmed})")
    }
}

fn escape_ldap_filter_value(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '*' => "\\2a".chars().collect::<Vec<_>>(),
            '(' => "\\28".chars().collect(),
            ')' => "\\29".chars().collect(),
            '\\' => "\\5c".chars().collect(),
            '\0' => "\\00".chars().collect(),
            other => vec![other],
        })
        .collect()
}

fn ldap_manager_reference_to_user_id(value: &str) -> String {
    let trimmed = value.trim();
    if let Some((_, rest)) = trimmed.split_once('=')
        && let Some((first_rdn_value, _)) = rest.split_once(',')
    {
        return first_rdn_value.trim().to_string();
    }
    trimmed.to_string()
}

fn map_ldap_employment_status(
    status_attr: &str,
    raw_status: &str,
    mapping: &LdapAttributeMapping,
) -> EmploymentStatus {
    let normalized = raw_status.trim().to_ascii_lowercase();
    if status_attr.eq_ignore_ascii_case("userAccountControl")
        && let Ok(flags) = normalized.parse::<u32>()
    {
        return if flags & 0x2 == 0x2 {
            EmploymentStatus::Departed
        } else {
            EmploymentStatus::Active
        };
    }
    if mapping
        .departed_status_values
        .iter()
        .any(|value| value.eq_ignore_ascii_case(&normalized))
    {
        return EmploymentStatus::Departed;
    }
    if mapping
        .active_status_values
        .iter()
        .any(|value| value.eq_ignore_ascii_case(&normalized))
    {
        return EmploymentStatus::Active;
    }
    EmploymentStatus::Active
}

fn parse_ldif_entries(ldif: &str) -> Result<Vec<LdapDirectoryEntry>, HrError> {
    let mut entries = Vec::new();
    let mut current = Vec::<String>::new();
    let mut logical_lines = Vec::<String>::new();

    for raw_line in ldif.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.starts_with('#') {
            continue;
        }
        if line.trim().is_empty() {
            flush_ldif_record(&mut logical_lines, &mut current, &mut entries)?;
            continue;
        }
        if let Some(continued) = line.strip_prefix(' ') {
            if let Some(last) = logical_lines.last_mut() {
                last.push_str(continued);
            }
            continue;
        }
        logical_lines.push(line.to_string());
    }
    flush_ldif_record(&mut logical_lines, &mut current, &mut entries)?;
    Ok(entries)
}

fn flush_ldif_record(
    logical_lines: &mut Vec<String>,
    current: &mut Vec<String>,
    entries: &mut Vec<LdapDirectoryEntry>,
) -> Result<(), HrError> {
    current.append(logical_lines);
    if current.is_empty() {
        return Ok(());
    }

    let mut dn = String::new();
    let mut attributes: HashMap<String, Vec<String>> = HashMap::new();
    for line in current.drain(..) {
        let Some((attribute, value, encoded)) = parse_ldif_attribute_line(&line) else {
            continue;
        };
        let value = if encoded {
            decode_ldif_base64_utf8(value).ok_or_else(|| {
                HrError::InvalidProviderResponse(format!(
                    "invalid base64 LDAP attribute value for {attribute}"
                ))
            })?
        } else {
            value.trim_start().to_string()
        };
        if attribute.eq_ignore_ascii_case("dn") {
            dn = value;
        } else {
            attributes.entry(attribute).or_default().push(value);
        }
    }
    if dn.is_empty() && attributes.is_empty() {
        return Ok(());
    }
    entries.push(LdapDirectoryEntry { dn, attributes });
    Ok(())
}

fn parse_ldif_attribute_line(line: &str) -> Option<(String, &str, bool)> {
    if let Some((attribute, value)) = line.split_once("::") {
        return Some((attribute.trim().to_string(), value, true));
    }
    let (attribute, value) = line.split_once(':')?;
    Some((attribute.trim().to_string(), value, false))
}

fn decode_ldif_base64_utf8(value: &str) -> Option<String> {
    let bytes = decode_base64(value.trim())?;
    String::from_utf8(bytes).ok()
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let mut buffer = 0u32;
    let mut bits = 0u8;
    let mut output = Vec::new();
    for byte in value.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        if byte == b'=' {
            break;
        }
        let sextet = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        buffer = (buffer << 6) | sextet;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(output)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeishuProviderAuth {
    TenantAccessToken {
        token: String,
    },
    AppCredentials {
        token_url: String,
        app_id: String,
        app_secret: String,
    },
}

impl FeishuProviderAuth {
    pub fn mode(&self) -> &'static str {
        match self {
            Self::TenantAccessToken { .. } => "tenant_access_token",
            Self::AppCredentials { .. } => "app_credentials",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeishuProviderConfig {
    pub provider_id: String,
    pub tenant_key: String,
    pub base_url: String,
    pub auth: FeishuProviderAuth,
    pub users_path: String,
    pub events_path: String,
    pub webhook_verification_token: Option<String>,
    pub page_size: usize,
    pub timeout_ms: u64,
}

impl FeishuProviderConfig {
    pub fn validate_real_runtime(&self) -> Result<(), HrError> {
        if self.provider_id.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "provider_id is required".into(),
            ));
        }
        if self.tenant_key.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "tenant_key is required for Feishu runtime".into(),
            ));
        }
        if self.base_url.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "base_url is required for real Feishu runtime".into(),
            ));
        }
        if self.users_path.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "users_path is required for Feishu snapshot pull".into(),
            ));
        }
        if self.events_path.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "events_path is required for Feishu event polling".into(),
            ));
        }
        match &self.auth {
            FeishuProviderAuth::TenantAccessToken { token } if token.trim().is_empty() => {
                Err(HrError::InvalidProviderConfig(
                    "tenant access token is required for Feishu token auth".into(),
                ))
            }
            FeishuProviderAuth::AppCredentials {
                token_url,
                app_id,
                app_secret,
            } if token_url.trim().is_empty()
                || app_id.trim().is_empty()
                || app_secret.trim().is_empty() =>
            {
                Err(HrError::InvalidProviderConfig(
                    "token_url, app_id, and app_secret are required for Feishu app credentials auth"
                        .into(),
                ))
            }
            _ => Ok(()),
        }
    }

    pub fn runtime_mode(&self) -> FeishuRuntimeMode {
        FeishuRuntimeMode::RealHttpOpenApi
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeishuRuntimeMode {
    InMemoryMock,
    RealHttpOpenApi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FeishuUserStatus {
    #[serde(default, alias = "isActivated", alias = "active")]
    pub is_activated: Option<bool>,
    #[serde(default, alias = "isResigned", alias = "resigned")]
    pub is_resigned: Option<bool>,
    #[serde(default, alias = "employmentStatus", alias = "state")]
    pub employment_status: Option<String>,
}

impl FeishuUserStatus {
    fn employment_status(&self) -> EmploymentStatus {
        if self.is_resigned.unwrap_or(false) {
            return EmploymentStatus::Departed;
        }
        if let Some(status) = self.employment_status.as_deref() {
            let normalized = status.trim().to_ascii_lowercase();
            if matches!(
                normalized.as_str(),
                "departed" | "inactive" | "resigned" | "terminated"
            ) {
                return EmploymentStatus::Departed;
            }
        }
        if self.is_activated == Some(false) {
            EmploymentStatus::Departed
        } else {
            EmploymentStatus::Active
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeishuUserRecord {
    #[serde(alias = "id", alias = "userId", alias = "user_id", alias = "open_id")]
    pub user_id: String,
    #[serde(
        default,
        alias = "departmentIds",
        alias = "department_ids",
        alias = "department_id"
    )]
    pub department_ids: Vec<String>,
    #[serde(
        default,
        alias = "leaderUserId",
        alias = "manager_id",
        alias = "manager"
    )]
    pub leader_user_id: Option<String>,
    #[serde(default)]
    pub status: FeishuUserStatus,
    #[serde(
        default,
        alias = "approverAvailability",
        alias = "approver_availability"
    )]
    pub approver_availability: Option<ApproverAvailability>,
    #[serde(default, alias = "delegateUserId", alias = "delegate_user_id")]
    pub delegate_user_id: Option<String>,
}

impl FeishuUserRecord {
    pub fn to_org_user(&self) -> OrgUser {
        OrgUser {
            user_id: self.user_id.clone(),
            department_id: self
                .department_ids
                .first()
                .cloned()
                .unwrap_or_else(|| "dept-default".into()),
            manager_id: self.leader_user_id.clone(),
            status: self.status.employment_status(),
            approver_profile: self.approver_availability.clone().map(|availability| {
                ApproverProfile {
                    availability,
                    delegate_user_id: self.delegate_user_id.clone(),
                }
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeishuEventType {
    #[serde(alias = "user_created", alias = "hire", alias = "onboard")]
    UserCreated,
    #[serde(
        alias = "user_updated",
        alias = "department_change",
        alias = "departmentChange",
        alias = "transfer"
    )]
    UserUpdated,
    #[serde(alias = "user_deleted", alias = "user_departed", alias = "departure")]
    UserDeleted,
    #[serde(alias = "manager_change", alias = "managerChange")]
    ManagerChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeishuEventRecord {
    #[serde(alias = "id", alias = "eventId", alias = "event_id")]
    pub event_id: String,
    #[serde(alias = "userId", alias = "user_id", alias = "open_id")]
    pub user_id: String,
    #[serde(alias = "type", alias = "eventType", alias = "event_type")]
    pub event_type: FeishuEventType,
    #[serde(default, alias = "departmentId", alias = "department_id")]
    pub department_id: Option<String>,
    #[serde(
        default,
        alias = "leaderUserId",
        alias = "manager_id",
        alias = "manager"
    )]
    pub leader_user_id: Option<String>,
    #[serde(
        default,
        alias = "approverAvailability",
        alias = "approver_availability"
    )]
    pub approver_availability: Option<ApproverAvailability>,
    #[serde(default, alias = "delegateUserId", alias = "delegate_user_id")]
    pub delegate_user_id: Option<String>,
    #[serde(alias = "occurredAt", alias = "occurred_at", alias = "event_time")]
    pub occurred_at: DateTime<Utc>,
}

impl FeishuEventRecord {
    pub fn to_hr_event(&self) -> HrEvent {
        HrEvent {
            event_id: self.event_id.clone(),
            user_id: self.user_id.clone(),
            event_type: match self.event_type {
                FeishuEventType::UserCreated => HrEventType::Onboard,
                FeishuEventType::UserUpdated => HrEventType::Transfer,
                FeishuEventType::UserDeleted => HrEventType::Departure,
                FeishuEventType::ManagerChange => HrEventType::ManagerChange,
            },
            department_id: self.department_id.clone(),
            manager_id: self.leader_user_id.clone(),
            approver_profile: self.approver_availability.clone().map(|availability| {
                ApproverProfile {
                    availability,
                    delegate_user_id: self.delegate_user_id.clone(),
                }
            }),
            occurred_at: self.occurred_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeishuSnapshotPage {
    #[serde(default, alias = "items", alias = "users")]
    pub users: Vec<FeishuUserRecord>,
    #[serde(
        default,
        alias = "page_token",
        alias = "next_cursor",
        alias = "nextCursor"
    )]
    pub next_cursor: Option<String>,
}

impl FeishuSnapshotPage {
    pub fn into_org_users(self) -> Vec<OrgUser> {
        self.users
            .into_iter()
            .map(|user| user.to_org_user())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeishuEventPage {
    #[serde(default, alias = "items", alias = "events")]
    pub events: Vec<FeishuEventRecord>,
    #[serde(
        default,
        alias = "page_token",
        alias = "next_cursor",
        alias = "nextCursor"
    )]
    pub next_cursor: Option<String>,
}

impl FeishuEventPage {
    pub fn into_hr_events(self) -> Vec<HrEvent> {
        let mut events = self
            .events
            .into_iter()
            .map(|event| event.to_hr_event())
            .collect::<Vec<_>>();
        events.sort_by(|left, right| {
            left.occurred_at
                .cmp(&right.occurred_at)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
        events
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: serde::Deserialize<'de>"))]
pub struct FeishuApiDataPage<T> {
    #[serde(default, alias = "items", alias = "users", alias = "events")]
    pub items: Vec<T>,
    #[serde(
        default,
        alias = "page_token",
        alias = "next_cursor",
        alias = "nextCursor"
    )]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FeishuSnapshotPayload {
    Page(FeishuSnapshotPage),
    OpenApi {
        data: FeishuApiDataPage<FeishuUserRecord>,
    },
}

impl FeishuSnapshotPayload {
    pub fn into_page(self) -> FeishuSnapshotPage {
        match self {
            Self::Page(page) => page,
            Self::OpenApi { data } => FeishuSnapshotPage {
                users: data.items,
                next_cursor: data.next_cursor,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FeishuEventPayload {
    Page(FeishuEventPage),
    OpenApi {
        data: FeishuApiDataPage<FeishuEventRecord>,
    },
}

impl FeishuEventPayload {
    pub fn into_page(self) -> FeishuEventPage {
        match self {
            Self::Page(page) => page,
            Self::OpenApi { data } => FeishuEventPage {
                events: data.items,
                next_cursor: data.next_cursor,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeishuWebhookEnvelope {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default, alias = "challenge")]
    pub challenge: Option<String>,
    #[serde(default, alias = "events")]
    pub events: Vec<FeishuEventRecord>,
    #[serde(default, alias = "event")]
    pub event: Option<FeishuEventRecord>,
    #[serde(default, alias = "next_cursor", alias = "page_token")]
    pub next_cursor: Option<String>,
}

impl FeishuWebhookEnvelope {
    pub fn into_event_page(self) -> FeishuEventPage {
        let mut events = self.events;
        if let Some(event) = self.event {
            events.push(event);
        }
        FeishuEventPage {
            events,
            next_cursor: self.next_cursor,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkdayProviderAuth {
    BearerToken {
        token: String,
    },
    OAuthClientCredentials {
        token_url: String,
        client_id: String,
        client_secret: String,
        scope: Option<String>,
    },
}

impl WorkdayProviderAuth {
    pub fn mode(&self) -> &'static str {
        match self {
            Self::BearerToken { .. } => "bearer_token",
            Self::OAuthClientCredentials { .. } => "oauth_client_credentials",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkdayProviderConfig {
    pub provider_id: String,
    pub tenant: String,
    pub base_url: String,
    pub auth: WorkdayProviderAuth,
    pub workers_path: String,
    pub events_path: String,
    pub webhook_secret: Option<String>,
    pub page_size: usize,
    pub timeout_ms: u64,
}

impl WorkdayProviderConfig {
    pub fn validate_real_runtime(&self) -> Result<(), HrError> {
        if self.provider_id.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "provider_id is required".into(),
            ));
        }
        if self.base_url.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "base_url is required for real Workday runtime".into(),
            ));
        }
        if self.workers_path.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "workers_path is required for snapshot pull".into(),
            ));
        }
        if self.events_path.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "events_path is required for event polling".into(),
            ));
        }
        match &self.auth {
            WorkdayProviderAuth::BearerToken { token } if token.trim().is_empty() => {
                Err(HrError::InvalidProviderConfig(
                    "bearer token is required for Workday bearer auth".into(),
                ))
            }
            WorkdayProviderAuth::OAuthClientCredentials {
                token_url,
                client_id,
                client_secret,
                ..
            } if token_url.trim().is_empty()
                || client_id.trim().is_empty()
                || client_secret.trim().is_empty() =>
            {
                Err(HrError::InvalidProviderConfig(
                    "token_url, client_id, and client_secret are required for Workday OAuth".into(),
                ))
            }
            _ => Ok(()),
        }
    }

    pub fn runtime_mode(&self) -> WorkdayRuntimeMode {
        WorkdayRuntimeMode::RealHttp
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkdayRuntimeMode {
    InMemoryMock,
    RealHttp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkdayWorkerRecord {
    #[serde(alias = "id", alias = "workerId", alias = "worker_id")]
    pub worker_id: String,
    #[serde(
        alias = "supervisoryOrgId",
        alias = "supervisory_organization_id",
        alias = "department_id"
    )]
    pub supervisory_org_id: String,
    #[serde(
        default,
        alias = "managerWorkerId",
        alias = "manager_id",
        alias = "manager"
    )]
    pub manager_worker_id: Option<String>,
    #[serde(alias = "isActive", alias = "active")]
    pub active: bool,
}

impl WorkdayWorkerRecord {
    pub fn to_org_user(&self) -> OrgUser {
        OrgUser {
            user_id: self.worker_id.clone(),
            department_id: self.supervisory_org_id.clone(),
            manager_id: self.manager_worker_id.clone(),
            status: if self.active {
                EmploymentStatus::Active
            } else {
                EmploymentStatus::Departed
            },
            approver_profile: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkdayEventType {
    #[serde(alias = "hire", alias = "onboard", alias = "worker_hired")]
    Hire,
    #[serde(alias = "transfer", alias = "worker_transferred")]
    Transfer,
    #[serde(
        alias = "termination",
        alias = "departure",
        alias = "worker_terminated"
    )]
    Termination,
    #[serde(alias = "manager_change", alias = "managerChanged")]
    ManagerChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkdayEventRecord {
    #[serde(alias = "id", alias = "eventId", alias = "event_id")]
    pub event_id: String,
    #[serde(alias = "workerId", alias = "worker_id")]
    pub worker_id: String,
    #[serde(alias = "type", alias = "eventType", alias = "event_type")]
    pub event_type: WorkdayEventType,
    #[serde(
        default,
        alias = "supervisoryOrgId",
        alias = "supervisory_organization_id",
        alias = "department_id"
    )]
    pub supervisory_org_id: Option<String>,
    #[serde(
        default,
        alias = "managerWorkerId",
        alias = "manager_id",
        alias = "manager"
    )]
    pub manager_worker_id: Option<String>,
    #[serde(alias = "occurredAt", alias = "effective_at")]
    pub occurred_at: DateTime<Utc>,
}

impl WorkdayEventRecord {
    pub fn to_hr_event(&self) -> HrEvent {
        HrEvent {
            event_id: self.event_id.clone(),
            user_id: self.worker_id.clone(),
            event_type: match self.event_type {
                WorkdayEventType::Hire => HrEventType::Onboard,
                WorkdayEventType::Transfer => HrEventType::Transfer,
                WorkdayEventType::Termination => HrEventType::Departure,
                WorkdayEventType::ManagerChange => HrEventType::ManagerChange,
            },
            department_id: self.supervisory_org_id.clone(),
            manager_id: self.manager_worker_id.clone(),
            approver_profile: None,
            occurred_at: self.occurred_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkdaySnapshotPage {
    #[serde(default, alias = "Resources", alias = "data")]
    pub workers: Vec<WorkdayWorkerRecord>,
    #[serde(default, alias = "nextCursor", alias = "next")]
    pub next_cursor: Option<String>,
}

impl WorkdaySnapshotPage {
    pub fn into_org_users(self) -> Vec<OrgUser> {
        self.workers
            .into_iter()
            .map(|worker| worker.to_org_user())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkdayEventPage {
    #[serde(default, alias = "Resources", alias = "data")]
    pub events: Vec<WorkdayEventRecord>,
    #[serde(default, alias = "nextCursor", alias = "next")]
    pub next_cursor: Option<String>,
}

impl WorkdayEventPage {
    pub fn into_hr_events(self) -> Vec<HrEvent> {
        let mut events = self
            .events
            .into_iter()
            .map(|event| event.to_hr_event())
            .collect::<Vec<_>>();
        events.sort_by(|left, right| {
            left.occurred_at
                .cmp(&right.occurred_at)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
        events
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkdayWebhookEnvelope {
    #[serde(default, alias = "Events", alias = "data")]
    pub events: Vec<WorkdayEventRecord>,
    #[serde(default, alias = "cursor")]
    pub next_cursor: Option<String>,
}

impl WorkdayWebhookEnvelope {
    pub fn into_event_page(self) -> WorkdayEventPage {
        WorkdayEventPage {
            events: self.events,
            next_cursor: self.next_cursor,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkdayMockAdapter {
    workers: Vec<WorkdayWorkerRecord>,
    events: Vec<WorkdayEventRecord>,
}

impl WorkdayMockAdapter {
    pub fn new(workers: Vec<WorkdayWorkerRecord>, events: Vec<WorkdayEventRecord>) -> Self {
        Self { workers, events }
    }

    pub fn runtime_mode(&self) -> WorkdayRuntimeMode {
        WorkdayRuntimeMode::InMemoryMock
    }
}

pub type WorkdayAdapter = WorkdayMockAdapter;

impl HrConnector for WorkdayMockAdapter {
    fn sync_snapshot(&self) -> Result<Vec<OrgUser>, HrError> {
        Ok(self
            .workers
            .iter()
            .map(WorkdayWorkerRecord::to_org_user)
            .collect())
    }

    fn poll_events(&self, cursor: Option<&str>) -> Result<Vec<HrEvent>, HrError> {
        Ok(self
            .events
            .iter()
            .filter(|event| cursor.is_none_or(|cursor| event.event_id.as_str() > cursor))
            .map(WorkdayEventRecord::to_hr_event)
            .collect())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SapSuccessFactorsProviderAuth {
    BearerToken {
        token: String,
    },
    OAuthClientCredentials {
        token_url: String,
        client_id: String,
        client_secret: String,
        scope: Option<String>,
    },
    BasicAuth {
        username: String,
        password: String,
    },
}

impl SapSuccessFactorsProviderAuth {
    pub fn mode(&self) -> &'static str {
        match self {
            Self::BearerToken { .. } => "bearer_token",
            Self::OAuthClientCredentials { .. } => "oauth_client_credentials",
            Self::BasicAuth { .. } => "basic_auth",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SapSuccessFactorsProviderConfig {
    pub provider_id: String,
    pub company_id: String,
    pub base_url: String,
    pub auth: SapSuccessFactorsProviderAuth,
    pub users_path: String,
    pub events_path: String,
    pub webhook_secret: Option<String>,
    pub page_size: usize,
    pub timeout_ms: u64,
}

impl SapSuccessFactorsProviderConfig {
    pub fn validate_real_runtime(&self) -> Result<(), HrError> {
        if self.provider_id.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "provider_id is required".into(),
            ));
        }
        if self.company_id.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "company_id is required for SAP SuccessFactors runtime".into(),
            ));
        }
        if self.base_url.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "base_url is required for real SAP SuccessFactors runtime".into(),
            ));
        }
        if self.users_path.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "users_path is required for SAP SuccessFactors snapshot pull".into(),
            ));
        }
        if self.events_path.trim().is_empty() {
            return Err(HrError::InvalidProviderConfig(
                "events_path is required for SAP SuccessFactors event polling".into(),
            ));
        }
        match &self.auth {
            SapSuccessFactorsProviderAuth::BearerToken { token } if token.trim().is_empty() => {
                Err(HrError::InvalidProviderConfig(
                    "bearer token is required for SAP SuccessFactors bearer auth".into(),
                ))
            }
            SapSuccessFactorsProviderAuth::OAuthClientCredentials {
                token_url,
                client_id,
                client_secret,
                ..
            } if token_url.trim().is_empty()
                || client_id.trim().is_empty()
                || client_secret.trim().is_empty() =>
            {
                Err(HrError::InvalidProviderConfig(
                    "token_url, client_id, and client_secret are required for SAP SuccessFactors OAuth".into(),
                ))
            }
            SapSuccessFactorsProviderAuth::BasicAuth { username, password }
                if username.trim().is_empty() || password.trim().is_empty() =>
            {
                Err(HrError::InvalidProviderConfig(
                    "username and password are required for SAP SuccessFactors basic auth".into(),
                ))
            }
            _ => Ok(()),
        }
    }

    pub fn runtime_mode(&self) -> SapSuccessFactorsRuntimeMode {
        SapSuccessFactorsRuntimeMode::RealHttpOData
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SapSuccessFactorsRuntimeMode {
    InMemoryMock,
    RealHttpOData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SapEmploymentState {
    #[serde(alias = "active", alias = "ACTIVE", alias = "A")]
    Active,
    #[serde(
        alias = "inactive",
        alias = "INACTIVE",
        alias = "I",
        alias = "terminated",
        alias = "TERMINATED"
    )]
    Inactive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SapSuccessFactorsEmployeeRecord {
    #[serde(alias = "personIdExternal", alias = "userId", alias = "user_id")]
    pub person_id_external: String,
    #[serde(
        alias = "department",
        alias = "departmentExternalCode",
        alias = "department_external_code"
    )]
    pub department_external_code: String,
    #[serde(
        default,
        alias = "manager",
        alias = "managerId",
        alias = "managerPersonIdExternal",
        alias = "manager_person_id_external"
    )]
    pub manager_person_id_external: Option<String>,
    #[serde(alias = "employmentStatus", alias = "status")]
    pub employment_status: SapEmploymentState,
}

impl SapSuccessFactorsEmployeeRecord {
    pub fn to_org_user(&self) -> OrgUser {
        OrgUser {
            user_id: self.person_id_external.clone(),
            department_id: self.department_external_code.clone(),
            manager_id: self.manager_person_id_external.clone(),
            status: match self.employment_status {
                SapEmploymentState::Active => EmploymentStatus::Active,
                SapEmploymentState::Inactive => EmploymentStatus::Departed,
            },
            approver_profile: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SapSuccessFactorsEventType {
    #[serde(alias = "hire", alias = "onboard", alias = "HIRE")]
    Hire,
    #[serde(
        alias = "department_change",
        alias = "departmentChange",
        alias = "transfer",
        alias = "JOB_CHANGE"
    )]
    DepartmentChange,
    #[serde(alias = "termination", alias = "departure", alias = "TERMINATION")]
    Termination,
    #[serde(
        alias = "manager_change",
        alias = "managerChange",
        alias = "MANAGER_CHANGE"
    )]
    ManagerChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SapSuccessFactorsEventRecord {
    #[serde(alias = "id", alias = "eventId", alias = "event_id")]
    pub event_id: String,
    #[serde(alias = "personIdExternal", alias = "userId", alias = "user_id")]
    pub person_id_external: String,
    #[serde(alias = "type", alias = "eventType", alias = "event_type")]
    pub event_type: SapSuccessFactorsEventType,
    #[serde(
        default,
        alias = "department",
        alias = "departmentExternalCode",
        alias = "department_external_code"
    )]
    pub department_external_code: Option<String>,
    #[serde(
        default,
        alias = "manager",
        alias = "managerId",
        alias = "managerPersonIdExternal",
        alias = "manager_person_id_external"
    )]
    pub manager_person_id_external: Option<String>,
    #[serde(
        alias = "occurredAt",
        alias = "occurred_at",
        alias = "effectiveStartDate",
        alias = "lastModifiedDateTime"
    )]
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SapSuccessFactorsMockAdapter {
    employees: Vec<SapSuccessFactorsEmployeeRecord>,
    events: Vec<SapSuccessFactorsEventRecord>,
}

impl SapSuccessFactorsEventRecord {
    pub fn to_hr_event(&self) -> HrEvent {
        HrEvent {
            event_id: self.event_id.clone(),
            user_id: self.person_id_external.clone(),
            event_type: match self.event_type {
                SapSuccessFactorsEventType::Hire => HrEventType::Onboard,
                SapSuccessFactorsEventType::DepartmentChange => HrEventType::Transfer,
                SapSuccessFactorsEventType::Termination => HrEventType::Departure,
                SapSuccessFactorsEventType::ManagerChange => HrEventType::ManagerChange,
            },
            department_id: self.department_external_code.clone(),
            manager_id: self.manager_person_id_external.clone(),
            approver_profile: None,
            occurred_at: self.occurred_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SapSuccessFactorsSnapshotPage {
    #[serde(default, alias = "results", alias = "Resources", alias = "data")]
    pub employees: Vec<SapSuccessFactorsEmployeeRecord>,
    #[serde(default, alias = "nextCursor", alias = "next", alias = "__next")]
    pub next_cursor: Option<String>,
}

impl SapSuccessFactorsSnapshotPage {
    pub fn into_org_users(self) -> Vec<OrgUser> {
        self.employees
            .into_iter()
            .map(|employee| employee.to_org_user())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SapSuccessFactorsEventPage {
    #[serde(default, alias = "results", alias = "Resources", alias = "data")]
    pub events: Vec<SapSuccessFactorsEventRecord>,
    #[serde(default, alias = "nextCursor", alias = "next", alias = "__next")]
    pub next_cursor: Option<String>,
}

impl SapSuccessFactorsEventPage {
    pub fn into_hr_events(self) -> Vec<HrEvent> {
        let mut events = self
            .events
            .into_iter()
            .map(|event| event.to_hr_event())
            .collect::<Vec<_>>();
        events.sort_by(|left, right| {
            left.occurred_at
                .cmp(&right.occurred_at)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
        events
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SapSuccessFactorsWebhookEnvelope {
    #[serde(default, alias = "Events", alias = "data", alias = "results")]
    pub events: Vec<SapSuccessFactorsEventRecord>,
    #[serde(default, alias = "cursor", alias = "nextCursor", alias = "__next")]
    pub next_cursor: Option<String>,
}

impl SapSuccessFactorsWebhookEnvelope {
    pub fn into_event_page(self) -> SapSuccessFactorsEventPage {
        SapSuccessFactorsEventPage {
            events: self.events,
            next_cursor: self.next_cursor,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SapSuccessFactorsODataEmployeeEnvelope {
    #[serde(default)]
    pub results: Vec<SapSuccessFactorsEmployeeRecord>,
    #[serde(default, rename = "__next", alias = "next", alias = "nextCursor")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SapSuccessFactorsODataEventEnvelope {
    #[serde(default)]
    pub results: Vec<SapSuccessFactorsEventRecord>,
    #[serde(default, rename = "__next", alias = "next", alias = "nextCursor")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SapSuccessFactorsSnapshotPayload {
    Page(SapSuccessFactorsSnapshotPage),
    OData {
        d: SapSuccessFactorsODataEmployeeEnvelope,
    },
}

impl SapSuccessFactorsSnapshotPayload {
    pub fn into_page(self) -> SapSuccessFactorsSnapshotPage {
        match self {
            Self::Page(page) => page,
            Self::OData { d } => SapSuccessFactorsSnapshotPage {
                employees: d.results,
                next_cursor: d.next_cursor,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SapSuccessFactorsEventPayload {
    Page(SapSuccessFactorsEventPage),
    OData {
        d: SapSuccessFactorsODataEventEnvelope,
    },
}

impl SapSuccessFactorsEventPayload {
    pub fn into_page(self) -> SapSuccessFactorsEventPage {
        match self {
            Self::Page(page) => page,
            Self::OData { d } => SapSuccessFactorsEventPage {
                events: d.results,
                next_cursor: d.next_cursor,
            },
        }
    }
}

impl SapSuccessFactorsMockAdapter {
    pub fn new(
        employees: Vec<SapSuccessFactorsEmployeeRecord>,
        events: Vec<SapSuccessFactorsEventRecord>,
    ) -> Self {
        Self { employees, events }
    }

    pub fn runtime_mode(&self) -> SapSuccessFactorsRuntimeMode {
        SapSuccessFactorsRuntimeMode::InMemoryMock
    }
}

pub type SapSuccessFactorsAdapter = SapSuccessFactorsMockAdapter;

impl HrConnector for SapSuccessFactorsMockAdapter {
    fn sync_snapshot(&self) -> Result<Vec<OrgUser>, HrError> {
        Ok(self
            .employees
            .iter()
            .map(SapSuccessFactorsEmployeeRecord::to_org_user)
            .collect())
    }

    fn poll_events(&self, cursor: Option<&str>) -> Result<Vec<HrEvent>, HrError> {
        Ok(self
            .events
            .iter()
            .filter(|event| cursor.is_none_or(|cursor| event.event_id.as_str() > cursor))
            .map(SapSuccessFactorsEventRecord::to_hr_event)
            .collect())
    }
}

#[derive(Debug, Clone)]
pub struct FeishuMockAdapter {
    snapshot: Vec<OrgUser>,
    events: Vec<HrEvent>,
}

impl FeishuMockAdapter {
    pub fn new(snapshot: Vec<OrgUser>, events: Vec<HrEvent>) -> Self {
        Self { snapshot, events }
    }

    pub fn runtime_mode(&self) -> FeishuRuntimeMode {
        FeishuRuntimeMode::InMemoryMock
    }
}

pub type FeishuAdapter = FeishuMockAdapter;

impl HrConnector for FeishuMockAdapter {
    fn sync_snapshot(&self) -> Result<Vec<OrgUser>, HrError> {
        Ok(self.snapshot.clone())
    }

    fn poll_events(&self, cursor: Option<&str>) -> Result<Vec<HrEvent>, HrError> {
        Ok(self
            .events
            .iter()
            .filter(|event| cursor.is_none_or(|cursor| event.event_id.as_str() > cursor))
            .cloned()
            .collect())
    }
}

#[derive(Debug, Clone)]
pub struct LdapMockAdapter {
    snapshot: Vec<OrgUser>,
}

impl LdapMockAdapter {
    pub fn new(snapshot: Vec<OrgUser>) -> Self {
        Self { snapshot }
    }
}

pub type LdapAdapter = LdapMockAdapter;

impl HrConnector for LdapMockAdapter {
    fn sync_snapshot(&self) -> Result<Vec<OrgUser>, HrError> {
        Ok(self.snapshot.clone())
    }

    fn poll_events(&self, _cursor: Option<&str>) -> Result<Vec<HrEvent>, HrError> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone)]
pub struct CsvAdapter {
    csv_body: String,
}

impl CsvAdapter {
    pub fn new(csv_body: impl Into<String>) -> Self {
        Self {
            csv_body: csv_body.into(),
        }
    }
}

impl HrConnector for CsvAdapter {
    fn sync_snapshot(&self) -> Result<Vec<OrgUser>, HrError> {
        let mut users = Vec::new();
        for line in self.csv_body.lines().skip(1) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let columns = trimmed.split(',').map(str::trim).collect::<Vec<_>>();
            if columns.len() != 4 {
                return Err(HrError::InvalidCsvRow(trimmed.to_string()));
            }

            users.push(OrgUser {
                user_id: columns[0].to_string(),
                department_id: columns[1].to_string(),
                manager_id: (!columns[2].is_empty()).then(|| columns[2].to_string()),
                status: match columns[3].to_ascii_lowercase().as_str() {
                    "active" => EmploymentStatus::Active,
                    "departed" => EmploymentStatus::Departed,
                    _ => return Err(HrError::InvalidCsvRow(trimmed.to_string())),
                },
                approver_profile: None,
            });
        }
        Ok(users)
    }

    fn poll_events(&self, _cursor: Option<&str>) -> Result<Vec<HrEvent>, HrError> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HrSyncReport {
    pub source: SyncSource,
    pub synced_user_count: usize,
    pub applied_event_count: usize,
    pub revocation_commands: Vec<AccessRevocationCommand>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct HrSyncOrchestrator {
    directory: OrgDirectory,
}

impl HrSyncOrchestrator {
    pub fn new(directory: OrgDirectory) -> Self {
        Self { directory }
    }

    pub fn directory(&self) -> &OrgDirectory {
        &self.directory
    }

    pub fn into_directory(self) -> OrgDirectory {
        self.directory
    }

    pub fn sync_connector(
        &mut self,
        source: SyncSource,
        connector: &dyn HrConnector,
        cursor: Option<&str>,
    ) -> Result<HrSyncReport, HrError> {
        let snapshot = connector.sync_snapshot()?;
        let synced_user_count = snapshot.len();
        self.directory.sync_snapshot(source.clone(), snapshot);

        let mut events = connector.poll_events(cursor)?;
        events.sort_by(|left, right| {
            left.occurred_at
                .cmp(&right.occurred_at)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });

        let mut applied_event_count = 0;
        let mut revocation_commands = Vec::new();
        let mut next_cursor = cursor.map(str::to_string);
        for event in events {
            let already_processed = self.directory.has_processed_event(&event.event_id);
            let event_id = event.event_id.clone();
            let commands = self.directory.apply_event(event)?;
            if !already_processed {
                applied_event_count += 1;
            }
            revocation_commands.extend(commands);
            next_cursor = Some(event_id);
        }

        Ok(HrSyncReport {
            source,
            synced_user_count,
            applied_event_count,
            revocation_commands,
            next_cursor,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HrEventListenerCheckpoint {
    pub source: SyncSource,
    pub cursor: Option<String>,
}

/// Keeps per-source sync cursors so webhook and polling listeners can reuse one contract.
#[derive(Debug, Default, Clone)]
pub struct HrEventListener {
    checkpoints: HashMap<SyncSource, Option<String>>,
}

impl HrEventListener {
    pub fn checkpoint(&self, source: &SyncSource) -> Option<&str> {
        self.checkpoints
            .get(source)
            .and_then(|cursor| cursor.as_deref())
    }

    pub fn checkpoints(&self) -> Vec<HrEventListenerCheckpoint> {
        self.checkpoints
            .iter()
            .map(|(source, cursor)| HrEventListenerCheckpoint {
                source: source.clone(),
                cursor: cursor.clone(),
            })
            .collect()
    }

    pub fn process_connector(
        &mut self,
        orchestrator: &mut HrSyncOrchestrator,
        source: SyncSource,
        connector: &dyn HrConnector,
    ) -> Result<HrSyncReport, HrError> {
        let cursor = self
            .checkpoints
            .get(&source)
            .and_then(|existing| existing.clone());
        let report = orchestrator.sync_connector(source.clone(), connector, cursor.as_deref())?;
        self.checkpoints.insert(source, report.next_cursor.clone());
        Ok(report)
    }
}

#[derive(Debug, Default, Clone)]
pub struct OrgDirectory {
    users: HashMap<String, OrgUser>,
    approver_profiles: HashMap<String, ApproverProfile>,
    processed_events: HashSet<String>,
}

impl OrgDirectory {
    pub fn sync_snapshot(&mut self, _source: SyncSource, users: Vec<OrgUser>) -> usize {
        for user in users {
            let user_id = user.user_id.clone();
            let explicit_profile = user.approver_profile.clone();
            self.users.insert(user_id.clone(), user);
            self.sync_profile_for_user(&user_id, explicit_profile);
        }
        self.users.len()
    }

    pub fn get_user(&self, user_id: &str) -> Option<&OrgUser> {
        self.users.get(user_id)
    }

    pub fn list_users(&self) -> Vec<OrgUser> {
        self.users.values().cloned().collect()
    }

    pub fn has_processed_event(&self, event_id: &str) -> bool {
        self.processed_events.contains(event_id)
    }

    pub fn approver_profile(&self, user_id: &str) -> Option<&ApproverProfile> {
        self.approver_profiles.get(user_id)
    }

    pub fn set_approver_availability(
        &mut self,
        user_id: &str,
        availability: ApproverAvailability,
    ) -> Result<(), HrError> {
        if !self.users.contains_key(user_id) {
            return Err(HrError::UserNotFound(user_id.to_string()));
        }
        let mut profile = self.current_profile_for_user(user_id);
        profile.availability = availability;
        self.sync_profile_for_user(user_id, Some(profile));
        Ok(())
    }

    pub fn set_approver_delegate(
        &mut self,
        user_id: &str,
        delegate_user_id: Option<String>,
    ) -> Result<(), HrError> {
        if !self.users.contains_key(user_id) {
            return Err(HrError::UserNotFound(user_id.to_string()));
        }
        if let Some(delegate_user_id) = delegate_user_id.as_deref()
            && !self.users.contains_key(delegate_user_id)
        {
            return Err(HrError::UserNotFound(delegate_user_id.to_string()));
        }
        let mut profile = self.current_profile_for_user(user_id);
        profile.delegate_user_id = delegate_user_id;
        self.sync_profile_for_user(user_id, Some(profile));
        Ok(())
    }

    pub fn resolve_manager(&self, user_id: &str) -> Result<String, HrError> {
        let user = self
            .users
            .get(user_id)
            .ok_or_else(|| HrError::UserNotFound(user_id.to_string()))?;
        user.manager_id
            .clone()
            .ok_or_else(|| HrError::UserNotFound(format!("manager:{user_id}")))
    }

    pub fn resolve_effective_approver(
        &self,
        user_id: &str,
        system_fallback_user_id: &str,
    ) -> Result<ApproverRoute, HrError> {
        self.resolve_effective_approver_with_policy(
            user_id,
            &ApproverResolutionPolicy::with_system_fallback(system_fallback_user_id),
        )
    }

    pub fn reroute_unavailable_approver(
        &self,
        user_id: &str,
        system_fallback_user_id: &str,
    ) -> Result<ApproverRoute, HrError> {
        self.reroute_unavailable_approver_with_policy(
            user_id,
            &ApproverResolutionPolicy::with_system_fallback(system_fallback_user_id),
        )
    }

    pub fn resolve_effective_approver_with_policy(
        &self,
        user_id: &str,
        policy: &ApproverResolutionPolicy,
    ) -> Result<ApproverRoute, HrError> {
        self.route_approver(user_id, policy, true)
    }

    pub fn reroute_unavailable_approver_with_policy(
        &self,
        user_id: &str,
        policy: &ApproverResolutionPolicy,
    ) -> Result<ApproverRoute, HrError> {
        self.route_approver(user_id, policy, false)
    }

    pub fn apply_event(&mut self, event: HrEvent) -> Result<Vec<AccessRevocationCommand>, HrError> {
        if !self.processed_events.insert(event.event_id.clone()) {
            return Ok(Vec::new());
        }

        match event.event_type {
            HrEventType::Onboard => {
                let department_id = event.department_id.unwrap_or_else(|| "dept-default".into());
                let user_id = event.user_id.clone();
                self.users.insert(
                    user_id.clone(),
                    OrgUser {
                        user_id: user_id.clone(),
                        department_id,
                        manager_id: event.manager_id,
                        status: EmploymentStatus::Active,
                        approver_profile: event.approver_profile.clone(),
                    },
                );
                self.sync_profile_for_user(&user_id, event.approver_profile);
                Ok(Vec::new())
            }
            HrEventType::Transfer => {
                let user_id = event.user_id.clone();
                let user = self
                    .users
                    .get_mut(&user_id)
                    .ok_or_else(|| HrError::UserNotFound(user_id.clone()))?;
                if let Some(department_id) = event.department_id {
                    user.department_id = department_id;
                }
                if event.manager_id.is_some() {
                    user.manager_id = event.manager_id;
                }
                let user_id = user.user_id.clone();
                let explicit_profile = event.approver_profile.clone();
                let revocation_user_id = user.user_id.clone();
                let _ = user;
                self.sync_profile_for_user(&user_id, explicit_profile);

                Ok(vec![AccessRevocationCommand {
                    user_id: revocation_user_id,
                    project_id: None,
                    reason: RevocationReason::Transfer,
                }])
            }
            HrEventType::Departure => {
                let user_id = event.user_id.clone();
                let user = self
                    .users
                    .get_mut(&user_id)
                    .ok_or_else(|| HrError::UserNotFound(user_id.clone()))?;
                user.status = EmploymentStatus::Departed;
                let user_id = user.user_id.clone();
                let explicit_profile = event.approver_profile.clone();
                let revocation_user_id = user.user_id.clone();
                let _ = user;
                self.sync_profile_for_user(&user_id, explicit_profile);

                Ok(vec![AccessRevocationCommand {
                    user_id: revocation_user_id,
                    project_id: None,
                    reason: RevocationReason::Departure,
                }])
            }
            HrEventType::ManagerChange => {
                let user_id = event.user_id.clone();
                let user = self
                    .users
                    .get_mut(&user_id)
                    .ok_or_else(|| HrError::UserNotFound(user_id.clone()))?;
                user.manager_id = event.manager_id;
                let explicit_profile = event.approver_profile.clone();
                let user_id = user.user_id.clone();
                let _ = user;
                self.sync_profile_for_user(&user_id, explicit_profile);
                Ok(Vec::new())
            }
        }
    }

    fn route_approver(
        &self,
        user_id: &str,
        policy: &ApproverResolutionPolicy,
        allow_direct_root: bool,
    ) -> Result<ApproverRoute, HrError> {
        let policy = policy.normalized();
        let requested_user_id = user_id.to_string();
        let mut current = requested_user_id.clone();
        let mut visited = HashSet::new();
        let mut traversed_user_ids = vec![current.clone()];
        let mut unavailable_user_ids = Vec::new();
        let mut allow_direct = allow_direct_root;
        let mut escalation_target = None;
        let mut manager_hops = 0usize;

        loop {
            if !visited.insert(current.clone()) {
                return Ok(fallback_approver_route(
                    requested_user_id,
                    &policy.system_fallback_user_id,
                    traversed_user_ids,
                    unavailable_user_ids,
                ));
            }

            let user = self
                .users
                .get(&current)
                .ok_or_else(|| HrError::UserNotFound(current.clone()))?;

            if allow_direct && self.is_approver_available(&current) {
                return Ok(ApproverRoute {
                    requested_user_id,
                    resolved_user_id: current.clone(),
                    route_kind: if current == user_id {
                        ApproverRouteKind::Direct
                    } else {
                        ApproverRouteKind::EscalatedToManager
                    },
                    delegated_from: None,
                    escalation_target,
                    used_system_fallback: false,
                    traversed_user_ids,
                    unavailable_user_ids,
                });
            }
            push_unique(&mut unavailable_user_ids, current.clone());

            if policy.allow_delegation
                && let Some(route) = self.available_delegate_route(
                    requested_user_id.clone(),
                    &current,
                    escalation_target.clone(),
                    &mut traversed_user_ids,
                    &mut unavailable_user_ids,
                )
            {
                return Ok(route);
            }

            if manager_hops < policy.max_manager_hops
                && let Some(manager_id) = user.manager_id.clone()
            {
                escalation_target = Some(manager_id.clone());
                current = manager_id;
                push_unique(&mut traversed_user_ids, current.clone());
                allow_direct = true;
                manager_hops += 1;
                continue;
            }

            break;
        }

        for configured_target in &policy.escalation_user_ids {
            if configured_target == user_id {
                continue;
            }
            push_unique(&mut traversed_user_ids, configured_target.clone());
            if self.is_approver_available(configured_target) {
                return Ok(ApproverRoute {
                    requested_user_id,
                    resolved_user_id: configured_target.clone(),
                    route_kind: ApproverRouteKind::EscalatedToConfiguredTarget,
                    delegated_from: None,
                    escalation_target: Some(configured_target.clone()),
                    used_system_fallback: false,
                    traversed_user_ids,
                    unavailable_user_ids,
                });
            }
            push_unique(&mut unavailable_user_ids, configured_target.clone());
            if policy.allow_delegation
                && let Some(route) = self.available_delegate_route(
                    requested_user_id.clone(),
                    configured_target,
                    Some(configured_target.clone()),
                    &mut traversed_user_ids,
                    &mut unavailable_user_ids,
                )
            {
                return Ok(route);
            }
        }

        Ok(fallback_approver_route(
            requested_user_id,
            &policy.system_fallback_user_id,
            traversed_user_ids,
            unavailable_user_ids,
        ))
    }

    fn is_approver_available(&self, user_id: &str) -> bool {
        let Some(user) = self.users.get(user_id) else {
            return false;
        };
        if user.status != EmploymentStatus::Active {
            return false;
        }
        self.current_profile_for_user(user_id).availability == ApproverAvailability::Available
    }

    fn current_profile_for_user(&self, user_id: &str) -> ApproverProfile {
        self.approver_profiles
            .get(user_id)
            .cloned()
            .or_else(|| {
                self.users
                    .get(user_id)
                    .and_then(|user| user.approver_profile.clone())
            })
            .unwrap_or_default()
    }

    fn sync_profile_for_user(
        &mut self,
        user_id: &str,
        explicit_profile: Option<ApproverProfile>,
    ) -> ApproverProfile {
        let profile = explicit_profile.unwrap_or_else(|| self.current_profile_for_user(user_id));
        self.approver_profiles
            .insert(user_id.to_string(), profile.clone());
        if let Some(user) = self.users.get_mut(user_id) {
            user.approver_profile = Some(profile.clone());
        }
        profile
    }

    fn available_delegate_route(
        &self,
        requested_user_id: String,
        delegated_from: &str,
        escalation_target: Option<String>,
        traversed_user_ids: &mut Vec<String>,
        unavailable_user_ids: &mut Vec<String>,
    ) -> Option<ApproverRoute> {
        let delegate_user_id = self
            .approver_profiles
            .get(delegated_from)
            .and_then(|profile| profile.delegate_user_id.clone())?;
        if delegate_user_id == delegated_from || !self.users.contains_key(&delegate_user_id) {
            return None;
        }
        push_unique(traversed_user_ids, delegate_user_id.clone());
        if self.is_approver_available(&delegate_user_id) {
            Some(ApproverRoute {
                requested_user_id,
                resolved_user_id: delegate_user_id,
                route_kind: ApproverRouteKind::Delegated,
                delegated_from: Some(delegated_from.to_string()),
                escalation_target,
                used_system_fallback: false,
                traversed_user_ids: traversed_user_ids.clone(),
                unavailable_user_ids: unavailable_user_ids.clone(),
            })
        } else {
            push_unique(unavailable_user_ids, delegate_user_id);
            None
        }
    }
}

fn fallback_approver_route(
    requested_user_id: String,
    system_fallback_user_id: &str,
    mut traversed_user_ids: Vec<String>,
    unavailable_user_ids: Vec<String>,
) -> ApproverRoute {
    push_unique(&mut traversed_user_ids, system_fallback_user_id.to_string());
    ApproverRoute {
        requested_user_id,
        resolved_user_id: system_fallback_user_id.to_string(),
        route_kind: ApproverRouteKind::SystemFallback,
        delegated_from: None,
        escalation_target: Some(system_fallback_user_id.to_string()),
        used_system_fallback: true,
        traversed_user_ids,
        unavailable_user_ids,
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use ulid::Ulid;

    use super::{
        ApproverAvailability, ApproverResolutionPolicy, ApproverRouteKind, CsvAdapter,
        EmploymentStatus, FeishuAdapter, FeishuEventPayload, FeishuEventRecord, FeishuEventType,
        FeishuProviderAuth, FeishuProviderConfig, FeishuRuntimeMode, FeishuSnapshotPage,
        FeishuSnapshotPayload, FeishuUserRecord, FeishuUserStatus, FeishuWebhookEnvelope,
        HrConnector, HrEvent, HrEventListener, HrEventType, HrSyncOrchestrator, LdapAdapter,
        LdapAttributeMapping, LdapDirectorySearchResult, LdapProviderAuth, LdapProviderConfig,
        LdapRuntimeMode, LdapTlsMode, OrgDirectory, OrgUser, RevocationReason, SapEmploymentState,
        SapSuccessFactorsAdapter, SapSuccessFactorsEmployeeRecord, SapSuccessFactorsEventPayload,
        SapSuccessFactorsEventRecord, SapSuccessFactorsEventType, SapSuccessFactorsProviderAuth,
        SapSuccessFactorsProviderConfig, SapSuccessFactorsRuntimeMode,
        SapSuccessFactorsSnapshotPage, SapSuccessFactorsSnapshotPayload,
        SapSuccessFactorsWebhookEnvelope, SyncSource, WorkdayAdapter, WorkdayEventRecord,
        WorkdayEventType, WorkdayProviderAuth, WorkdayProviderConfig, WorkdayRuntimeMode,
        WorkdaySnapshotPage, WorkdayWebhookEnvelope, WorkdayWorkerRecord,
    };
    use chrono::Utc;

    #[test]
    fn snapshot_sync_supports_feishu_workday_sap_and_csv_fallback_sources() {
        let mut directory = OrgDirectory::default();
        assert_eq!(
            directory.sync_snapshot(
                SyncSource::FeishuMock,
                vec![OrgUser {
                    user_id: "user-a".into(),
                    department_id: "dept-risk".into(),
                    manager_id: Some("manager-a".into()),
                    status: EmploymentStatus::Active,
                    approver_profile: None,
                }],
            ),
            1
        );
        assert_eq!(
            directory.sync_snapshot(
                SyncSource::WorkdayMock,
                vec![OrgUser {
                    user_id: "user-b".into(),
                    department_id: "sup-org-risk".into(),
                    manager_id: Some("manager-b".into()),
                    status: EmploymentStatus::Active,
                    approver_profile: None,
                }],
            ),
            2
        );
        assert_eq!(
            directory.sync_snapshot(
                SyncSource::SapSuccessFactorsMock,
                vec![OrgUser {
                    user_id: "user-c".into(),
                    department_id: "sf-risk".into(),
                    manager_id: Some("manager-c".into()),
                    status: EmploymentStatus::Active,
                    approver_profile: None,
                }],
            ),
            3
        );
        assert_eq!(
            directory.sync_snapshot(SyncSource::CsvFallback, Vec::new()),
            3
        );
    }

    #[test]
    fn transfer_event_updates_department_and_emits_revocation() {
        let mut directory = OrgDirectory::default();
        directory.sync_snapshot(
            SyncSource::LdapMock,
            vec![OrgUser {
                user_id: "user-a".into(),
                department_id: "dept-risk".into(),
                manager_id: Some("manager-a".into()),
                status: EmploymentStatus::Active,
                approver_profile: None,
            }],
        );

        let commands = directory
            .apply_event(HrEvent::new(
                "user-a",
                HrEventType::Transfer,
                Some("dept-fraud".into()),
                Some("manager-b".into()),
            ))
            .expect("transfer");

        assert_eq!(
            directory.get_user("user-a").expect("user").department_id,
            "dept-fraud"
        );
        assert_eq!(commands[0].reason, RevocationReason::Transfer);
    }

    #[test]
    fn departure_event_marks_user_departed() {
        let mut directory = OrgDirectory::default();
        directory.sync_snapshot(
            SyncSource::FeishuMock,
            vec![OrgUser {
                user_id: "user-a".into(),
                department_id: "dept-risk".into(),
                manager_id: Some("manager-a".into()),
                status: EmploymentStatus::Active,
                approver_profile: None,
            }],
        );

        let commands = directory
            .apply_event(HrEvent::new("user-a", HrEventType::Departure, None, None))
            .expect("departure");

        assert_eq!(
            directory.get_user("user-a").expect("user").status,
            EmploymentStatus::Departed
        );
        assert_eq!(commands[0].reason, RevocationReason::Departure);
    }

    #[test]
    fn duplicate_event_is_ignored_for_idempotent_webhook_processing() {
        let mut directory = OrgDirectory::default();
        directory.sync_snapshot(
            SyncSource::FeishuMock,
            vec![OrgUser {
                user_id: "user-a".into(),
                department_id: "dept-risk".into(),
                manager_id: Some("manager-a".into()),
                status: EmploymentStatus::Active,
                approver_profile: None,
            }],
        );
        let event = HrEvent::new("user-a", HrEventType::Departure, None, None);
        let first = directory.apply_event(event.clone()).expect("first");
        let second = directory.apply_event(event).expect("second");
        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
    }

    #[test]
    fn adapters_support_feishu_workday_sap_ldap_and_csv_snapshots() {
        let snapshot = vec![OrgUser {
            user_id: "user-a".into(),
            department_id: "dept-risk".into(),
            manager_id: Some("manager-a".into()),
            status: EmploymentStatus::Active,
            approver_profile: None,
        }];
        let event = HrEvent::new(
            "user-a",
            HrEventType::Transfer,
            Some("dept-fraud".into()),
            None,
        );

        let feishu = FeishuAdapter::new(snapshot.clone(), vec![event.clone()]);
        assert_eq!(feishu.sync_snapshot().expect("snapshot").len(), 1);
        assert_eq!(feishu.poll_events(None).expect("events").len(), 1);

        let workday = WorkdayAdapter::new(
            vec![WorkdayWorkerRecord {
                worker_id: "user-a".into(),
                supervisory_org_id: "sup-org-risk".into(),
                manager_worker_id: Some("manager-a".into()),
                active: true,
            }],
            vec![WorkdayEventRecord {
                event_id: Ulid::new().to_string(),
                worker_id: "user-a".into(),
                event_type: WorkdayEventType::Transfer,
                supervisory_org_id: Some("sup-org-fraud".into()),
                manager_worker_id: Some("manager-b".into()),
                occurred_at: Utc::now(),
            }],
        );
        assert_eq!(workday.sync_snapshot().expect("snapshot").len(), 1);
        assert_eq!(workday.poll_events(None).expect("events").len(), 1);

        let sap = SapSuccessFactorsAdapter::new(
            vec![SapSuccessFactorsEmployeeRecord {
                person_id_external: "user-a".into(),
                department_external_code: "sf-risk".into(),
                manager_person_id_external: Some("manager-a".into()),
                employment_status: SapEmploymentState::Active,
            }],
            vec![SapSuccessFactorsEventRecord {
                event_id: Ulid::new().to_string(),
                person_id_external: "user-a".into(),
                event_type: SapSuccessFactorsEventType::DepartmentChange,
                department_external_code: Some("sf-fraud".into()),
                manager_person_id_external: Some("manager-b".into()),
                occurred_at: Utc::now(),
            }],
        );
        assert_eq!(sap.sync_snapshot().expect("snapshot").len(), 1);
        assert_eq!(sap.poll_events(None).expect("events").len(), 1);

        let ldap = LdapAdapter::new(snapshot.clone());
        assert_eq!(ldap.sync_snapshot().expect("snapshot").len(), 1);
        assert!(ldap.poll_events(None).expect("events").is_empty());

        let csv = CsvAdapter::new(
            "user_id,department_id,manager_id,status\nuser-a,dept-risk,manager-a,active\n",
        );
        assert_eq!(csv.sync_snapshot().expect("snapshot").len(), 1);
    }

    #[test]
    fn ldap_real_provider_config_validates_directory_sync_runtime() {
        let config = LdapProviderConfig {
            provider_id: "ldap-primary".into(),
            url: "ldap://ldap.example.internal:389".into(),
            auth: LdapProviderAuth::SimpleBind {
                bind_dn: "cn=sdqp-sync,ou=svc,dc=example,dc=internal".into(),
                bind_password: "secret".into(),
            },
            tls_mode: LdapTlsMode::StartTls,
            base_dn: "ou=People,dc=example,dc=internal".into(),
            search_filter: "(&(objectClass=person)(employeeType=employee))".into(),
            search_scope: "sub".into(),
            page_size: 500,
            timeout_ms: 5_000,
            ldapsearch_binary: "ldapsearch".into(),
            ca_cert_path: Some("/etc/ssl/certs/company-ca.pem".into()),
            tls_require_valid_cert: true,
            attribute_mapping: LdapAttributeMapping {
                user_id: "uid".into(),
                department_id: "departmentNumber".into(),
                manager_id: "manager".into(),
                status: "userAccountControl".into(),
                changed_since: "modifyTimestamp".into(),
                active_status_values: vec!["active".into()],
                departed_status_values: vec!["departed".into()],
            },
        };

        config.validate_real_runtime().expect("valid LDAP config");
        assert_eq!(config.auth.mode(), "simple_bind");
        assert_eq!(config.tls_mode.as_str(), "start_tls");
        assert_eq!(config.runtime_mode(), LdapRuntimeMode::RealDirectorySync);
        assert_eq!(
            config.incremental_search_filter(Some("20260426090000Z")),
            "(&(&(objectClass=person)(employeeType=employee))(modifyTimestamp>=20260426090000Z))"
        );

        let invalid = LdapProviderConfig {
            page_size: 0,
            ..config
        };
        assert!(invalid.validate_real_runtime().is_err());
    }

    #[test]
    fn ldap_ldif_mapping_normalizes_users_status_manager_and_watermark() {
        let mapping = LdapAttributeMapping {
            user_id: "uid".into(),
            department_id: "departmentNumber".into(),
            manager_id: "manager".into(),
            status: "userAccountControl".into(),
            changed_since: "modifyTimestamp".into(),
            active_status_values: Vec::new(),
            departed_status_values: Vec::new(),
        };
        let ldif = r#"
dn: uid=user-a,ou=People,dc=example,dc=internal
uid: user-a
departmentNumber: dept-risk
manager: uid=manager-a,ou=People,dc=example,dc=internal
userAccountControl: 512
modifyTimestamp: 20260426090000Z

dn: uid=user-b,ou=People,dc=example,dc=internal
uid: user-b
departmentNumber: dept-ops
manager: uid=manager-b,ou=People,dc=example,dc=internal
userAccountControl: 514
modifyTimestamp: 20260426100000Z
"#;

        let result = LdapDirectorySearchResult::from_ldif(ldif, &mapping).expect("ldif");
        assert_eq!(result.next_watermark.as_deref(), Some("20260426100000Z"));
        let users = result.into_org_users(&mapping).expect("users");
        assert_eq!(users[0].user_id, "user-a");
        assert_eq!(users[0].department_id, "dept-risk");
        assert_eq!(users[0].manager_id.as_deref(), Some("manager-a"));
        assert_eq!(users[0].status, EmploymentStatus::Active);
        assert_eq!(users[1].status, EmploymentStatus::Departed);
    }

    #[test]
    fn workday_adapter_normalizes_snapshot_and_events_into_generic_hr_contract() {
        let worker_snapshot = vec![WorkdayWorkerRecord {
            worker_id: "user-a".into(),
            supervisory_org_id: "sup-org-risk".into(),
            manager_worker_id: Some("manager-a".into()),
            active: true,
        }];
        let event_id = Ulid::new().to_string();
        let adapter = WorkdayAdapter::new(
            worker_snapshot,
            vec![WorkdayEventRecord {
                event_id: event_id.clone(),
                worker_id: "user-a".into(),
                event_type: WorkdayEventType::Termination,
                supervisory_org_id: Some("sup-org-risk".into()),
                manager_worker_id: Some("manager-a".into()),
                occurred_at: Utc::now(),
            }],
        );

        let snapshot = adapter.sync_snapshot().expect("snapshot");
        assert_eq!(snapshot[0].department_id, "sup-org-risk");
        assert_eq!(snapshot[0].manager_id.as_deref(), Some("manager-a"));

        let events = adapter.poll_events(None).expect("events");
        assert_eq!(events[0].event_id, event_id);
        assert_eq!(events[0].event_type, HrEventType::Departure);
    }

    #[test]
    fn feishu_real_provider_config_validates_auth_and_runtime_mode() {
        let config = FeishuProviderConfig {
            provider_id: "feishu-primary".into(),
            tenant_key: "tenant-alpha".into(),
            base_url: "https://open.feishu.cn".into(),
            auth: FeishuProviderAuth::AppCredentials {
                token_url: "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
                    .into(),
                app_id: "cli_a".into(),
                app_secret: "secret".into(),
            },
            users_path: "/open-apis/contact/v3/users".into(),
            events_path: "/open-apis/contact/v3/events".into(),
            webhook_verification_token: Some("webhook-token".into()),
            page_size: 100,
            timeout_ms: 3_000,
        };

        config.validate_real_runtime().expect("valid feishu config");
        assert_eq!(config.auth.mode(), "app_credentials");
        assert_eq!(config.runtime_mode(), FeishuRuntimeMode::RealHttpOpenApi);

        let invalid = FeishuProviderConfig {
            base_url: String::new(),
            ..config
        };
        assert!(invalid.validate_real_runtime().is_err());
    }

    #[test]
    fn feishu_snapshot_event_and_webhook_payloads_normalize_real_provider_shapes() {
        let snapshot = FeishuSnapshotPage {
            users: vec![FeishuUserRecord {
                user_id: "user-a".into(),
                department_ids: vec!["dept-risk".into()],
                leader_user_id: Some("manager-a".into()),
                status: FeishuUserStatus {
                    is_activated: Some(true),
                    is_resigned: Some(false),
                    employment_status: None,
                },
                approver_availability: Some(ApproverAvailability::Available),
                delegate_user_id: None,
            }],
            next_cursor: Some("snapshot-cursor-1".into()),
        };
        let users = snapshot.into_org_users();
        assert_eq!(users[0].user_id, "user-a");
        assert_eq!(users[0].department_id, "dept-risk");
        assert_eq!(users[0].manager_id.as_deref(), Some("manager-a"));
        assert_eq!(
            users[0]
                .approver_profile
                .as_ref()
                .expect("profile")
                .availability,
            ApproverAvailability::Available
        );

        let openapi_payload = FeishuEventPayload::OpenApi {
            data: super::FeishuApiDataPage {
                items: vec![FeishuEventRecord {
                    event_id: "evt-feishu-poll-001".into(),
                    user_id: "user-a".into(),
                    event_type: FeishuEventType::UserDeleted,
                    department_id: Some("dept-risk".into()),
                    leader_user_id: Some("manager-a".into()),
                    approver_availability: None,
                    delegate_user_id: None,
                    occurred_at: Utc::now(),
                }],
                next_cursor: Some("evt-feishu-poll-001".into()),
            },
        };
        let event_page = openapi_payload.into_page();
        assert_eq!(
            event_page.next_cursor.as_deref(),
            Some("evt-feishu-poll-001")
        );
        let events = event_page.into_hr_events();
        assert_eq!(events[0].event_type, HrEventType::Departure);

        let webhook = FeishuWebhookEnvelope {
            token: Some("webhook-token".into()),
            challenge: None,
            events: Vec::new(),
            event: Some(FeishuEventRecord {
                event_id: "evt-feishu-webhook-001".into(),
                user_id: "manager-a".into(),
                event_type: FeishuEventType::ManagerChange,
                department_id: Some("dept-risk".into()),
                leader_user_id: None,
                approver_availability: Some(ApproverAvailability::Unavailable),
                delegate_user_id: Some("delegate-a".into()),
                occurred_at: Utc::now(),
            }),
            next_cursor: Some("evt-feishu-webhook-001".into()),
        };
        let page = webhook.into_event_page();
        assert_eq!(page.next_cursor.as_deref(), Some("evt-feishu-webhook-001"));

        let snapshot_payload = FeishuSnapshotPayload::OpenApi {
            data: super::FeishuApiDataPage {
                items: vec![FeishuUserRecord {
                    user_id: "user-b".into(),
                    department_ids: vec!["dept-ops".into()],
                    leader_user_id: None,
                    status: FeishuUserStatus {
                        is_activated: Some(false),
                        is_resigned: None,
                        employment_status: None,
                    },
                    approver_availability: None,
                    delegate_user_id: None,
                }],
                next_cursor: None,
            },
        };
        let users = snapshot_payload.into_page().into_org_users();
        assert_eq!(users[0].status, EmploymentStatus::Departed);
    }

    #[test]
    fn workday_real_provider_config_validates_auth_and_runtime_mode() {
        let config = WorkdayProviderConfig {
            provider_id: "workday-primary".into(),
            tenant: "tenant-alpha".into(),
            base_url: "https://wd.example".into(),
            auth: WorkdayProviderAuth::OAuthClientCredentials {
                token_url: "https://wd.example/oauth2/token".into(),
                client_id: "client".into(),
                client_secret: "secret".into(),
                scope: Some("workers events".into()),
            },
            workers_path: "/ccx/service/customreport2/sdqp/workers".into(),
            events_path: "/ccx/api/events/v1/workers".into(),
            webhook_secret: Some("webhook-secret".into()),
            page_size: 100,
            timeout_ms: 3_000,
        };

        config
            .validate_real_runtime()
            .expect("valid workday config");
        assert_eq!(config.auth.mode(), "oauth_client_credentials");
        assert_eq!(config.runtime_mode(), WorkdayRuntimeMode::RealHttp);

        let invalid = WorkdayProviderConfig {
            base_url: String::new(),
            ..config
        };
        assert!(invalid.validate_real_runtime().is_err());
    }

    #[test]
    fn workday_snapshot_page_and_webhook_envelope_normalize_real_provider_payloads() {
        let snapshot = WorkdaySnapshotPage {
            workers: vec![WorkdayWorkerRecord {
                worker_id: "user-a".into(),
                supervisory_org_id: "sup-org-risk".into(),
                manager_worker_id: Some("manager-a".into()),
                active: true,
            }],
            next_cursor: Some("snapshot-cursor-1".into()),
        };
        let users = snapshot.into_org_users();
        assert_eq!(users[0].user_id, "user-a");
        assert_eq!(users[0].department_id, "sup-org-risk");
        assert_eq!(users[0].manager_id.as_deref(), Some("manager-a"));

        let webhook = WorkdayWebhookEnvelope {
            events: vec![WorkdayEventRecord {
                event_id: "evt-workday-001".into(),
                worker_id: "user-a".into(),
                event_type: WorkdayEventType::Termination,
                supervisory_org_id: Some("sup-org-risk".into()),
                manager_worker_id: Some("manager-a".into()),
                occurred_at: Utc::now(),
            }],
            next_cursor: Some("evt-workday-001".into()),
        };
        let page = webhook.into_event_page();
        assert_eq!(page.next_cursor.as_deref(), Some("evt-workday-001"));
        let events = page.into_hr_events();
        assert_eq!(events[0].event_type, HrEventType::Departure);
        assert_eq!(events[0].user_id, "user-a");
    }

    #[test]
    fn sap_real_provider_config_validates_auth_and_runtime_mode() {
        let config = SapSuccessFactorsProviderConfig {
            provider_id: "sap-successfactors-primary".into(),
            company_id: "company-alpha".into(),
            base_url: "https://api.successfactors.example".into(),
            auth: SapSuccessFactorsProviderAuth::OAuthClientCredentials {
                token_url: "https://api.successfactors.example/oauth/token".into(),
                client_id: "client".into(),
                client_secret: "secret".into(),
                scope: Some("odata.read events.read".into()),
            },
            users_path: "/odata/v2/User".into(),
            events_path: "/odata/v2/EmpJob".into(),
            webhook_secret: Some("sap-webhook-secret".into()),
            page_size: 100,
            timeout_ms: 3_000,
        };

        config.validate_real_runtime().expect("valid sap config");
        assert_eq!(config.auth.mode(), "oauth_client_credentials");
        assert_eq!(
            config.runtime_mode(),
            SapSuccessFactorsRuntimeMode::RealHttpOData
        );

        let invalid = SapSuccessFactorsProviderConfig {
            company_id: String::new(),
            ..config
        };
        assert!(invalid.validate_real_runtime().is_err());
    }

    #[test]
    fn sap_snapshot_and_webhook_payloads_normalize_real_provider_shapes() {
        let snapshot = SapSuccessFactorsSnapshotPage {
            employees: vec![SapSuccessFactorsEmployeeRecord {
                person_id_external: "user-a".into(),
                department_external_code: "sf-risk".into(),
                manager_person_id_external: Some("manager-a".into()),
                employment_status: SapEmploymentState::Active,
            }],
            next_cursor: Some("snapshot-cursor-1".into()),
        };
        let users = snapshot.into_org_users();
        assert_eq!(users[0].user_id, "user-a");
        assert_eq!(users[0].department_id, "sf-risk");
        assert_eq!(users[0].manager_id.as_deref(), Some("manager-a"));

        let odata_payload = SapSuccessFactorsEventPayload::OData {
            d: super::SapSuccessFactorsODataEventEnvelope {
                results: vec![SapSuccessFactorsEventRecord {
                    event_id: "evt-sap-odata-001".into(),
                    person_id_external: "user-a".into(),
                    event_type: SapSuccessFactorsEventType::Termination,
                    department_external_code: Some("sf-risk".into()),
                    manager_person_id_external: Some("manager-a".into()),
                    occurred_at: Utc::now(),
                }],
                next_cursor: Some("odata-next".into()),
            },
        };
        let event_page = odata_payload.into_page();
        assert_eq!(event_page.next_cursor.as_deref(), Some("odata-next"));
        let events = event_page.into_hr_events();
        assert_eq!(events[0].event_type, HrEventType::Departure);
        assert_eq!(events[0].user_id, "user-a");

        let webhook = SapSuccessFactorsWebhookEnvelope {
            events: vec![SapSuccessFactorsEventRecord {
                event_id: "evt-sap-webhook-001".into(),
                person_id_external: "manager-a".into(),
                event_type: SapSuccessFactorsEventType::ManagerChange,
                department_external_code: Some("sf-risk".into()),
                manager_person_id_external: None,
                occurred_at: Utc::now(),
            }],
            next_cursor: Some("evt-sap-webhook-001".into()),
        };
        let page = webhook.into_event_page();
        assert_eq!(page.next_cursor.as_deref(), Some("evt-sap-webhook-001"));

        let snapshot_payload =
            SapSuccessFactorsSnapshotPayload::Page(SapSuccessFactorsSnapshotPage {
                employees: vec![SapSuccessFactorsEmployeeRecord {
                    person_id_external: "user-b".into(),
                    department_external_code: "sf-ops".into(),
                    manager_person_id_external: None,
                    employment_status: SapEmploymentState::Inactive,
                }],
                next_cursor: None,
            });
        let users = snapshot_payload.into_page().into_org_users();
        assert_eq!(users[0].status, EmploymentStatus::Departed);
    }

    #[test]
    fn sap_adapter_normalizes_snapshot_and_events_into_generic_hr_contract() {
        let employee_snapshot = vec![SapSuccessFactorsEmployeeRecord {
            person_id_external: "user-a".into(),
            department_external_code: "sf-risk".into(),
            manager_person_id_external: Some("manager-a".into()),
            employment_status: SapEmploymentState::Active,
        }];
        let event_id = Ulid::new().to_string();
        let adapter = SapSuccessFactorsAdapter::new(
            employee_snapshot,
            vec![SapSuccessFactorsEventRecord {
                event_id: event_id.clone(),
                person_id_external: "user-a".into(),
                event_type: SapSuccessFactorsEventType::Termination,
                department_external_code: Some("sf-risk".into()),
                manager_person_id_external: Some("manager-a".into()),
                occurred_at: Utc::now(),
            }],
        );

        let snapshot = adapter.sync_snapshot().expect("snapshot");
        assert_eq!(snapshot[0].department_id, "sf-risk");
        assert_eq!(snapshot[0].manager_id.as_deref(), Some("manager-a"));

        let events = adapter.poll_events(None).expect("events");
        assert_eq!(events[0].event_id, event_id);
        assert_eq!(events[0].event_type, HrEventType::Departure);
    }

    #[test]
    fn sync_orchestrator_applies_workday_snapshot_and_events_with_cursor_progression() {
        let mut orchestrator = HrSyncOrchestrator::new(OrgDirectory::default());
        let earlier_event_id = "evt-workday-001".to_string();
        let later_event_id = "evt-workday-002".to_string();
        let adapter = WorkdayAdapter::new(
            vec![
                WorkdayWorkerRecord {
                    worker_id: "manager-a".into(),
                    supervisory_org_id: "sup-org-risk".into(),
                    manager_worker_id: None,
                    active: true,
                },
                WorkdayWorkerRecord {
                    worker_id: "user-a".into(),
                    supervisory_org_id: "sup-org-risk".into(),
                    manager_worker_id: Some("manager-a".into()),
                    active: true,
                },
            ],
            vec![
                WorkdayEventRecord {
                    event_id: later_event_id.clone(),
                    worker_id: "user-a".into(),
                    event_type: WorkdayEventType::Termination,
                    supervisory_org_id: Some("sup-org-fraud".into()),
                    manager_worker_id: Some("manager-a".into()),
                    occurred_at: Utc::now() + chrono::Duration::minutes(2),
                },
                WorkdayEventRecord {
                    event_id: earlier_event_id.clone(),
                    worker_id: "user-a".into(),
                    event_type: WorkdayEventType::Transfer,
                    supervisory_org_id: Some("sup-org-fraud".into()),
                    manager_worker_id: Some("manager-a".into()),
                    occurred_at: Utc::now() + chrono::Duration::minutes(1),
                },
            ],
        );

        let report = orchestrator
            .sync_connector(SyncSource::WorkdayMock, &adapter, None)
            .expect("sync report");

        assert_eq!(report.synced_user_count, 2);
        assert_eq!(report.applied_event_count, 2);
        assert_eq!(report.next_cursor.as_deref(), Some(later_event_id.as_str()));
        assert!(
            report
                .revocation_commands
                .iter()
                .any(|command| command.reason == RevocationReason::Transfer)
        );
        assert!(
            report
                .revocation_commands
                .iter()
                .any(|command| command.reason == RevocationReason::Departure)
        );
        assert_eq!(
            orchestrator
                .directory()
                .get_user("user-a")
                .expect("user")
                .status,
            EmploymentStatus::Departed
        );
    }

    #[test]
    fn event_listener_tracks_sap_connector_checkpoints() {
        let mut orchestrator = HrSyncOrchestrator::new(OrgDirectory::default());
        let mut listener = HrEventListener::default();
        let first_event_id = "evt-sap-001".to_string();
        let second_event_id = "evt-sap-002".to_string();
        let adapter = SapSuccessFactorsAdapter::new(
            vec![
                SapSuccessFactorsEmployeeRecord {
                    person_id_external: "manager-a".into(),
                    department_external_code: "sf-risk".into(),
                    manager_person_id_external: None,
                    employment_status: SapEmploymentState::Active,
                },
                SapSuccessFactorsEmployeeRecord {
                    person_id_external: "user-a".into(),
                    department_external_code: "sf-risk".into(),
                    manager_person_id_external: Some("manager-a".into()),
                    employment_status: SapEmploymentState::Active,
                },
            ],
            vec![
                SapSuccessFactorsEventRecord {
                    event_id: second_event_id.clone(),
                    person_id_external: "user-a".into(),
                    event_type: SapSuccessFactorsEventType::Termination,
                    department_external_code: Some("sf-risk".into()),
                    manager_person_id_external: Some("manager-a".into()),
                    occurred_at: Utc::now() + chrono::Duration::minutes(2),
                },
                SapSuccessFactorsEventRecord {
                    event_id: first_event_id.clone(),
                    person_id_external: "user-a".into(),
                    event_type: SapSuccessFactorsEventType::DepartmentChange,
                    department_external_code: Some("sf-fraud".into()),
                    manager_person_id_external: Some("manager-a".into()),
                    occurred_at: Utc::now() + chrono::Duration::minutes(1),
                },
            ],
        );

        let first_report = listener
            .process_connector(
                &mut orchestrator,
                SyncSource::SapSuccessFactorsMock,
                &adapter,
            )
            .expect("first listener pass");
        assert_eq!(first_report.applied_event_count, 2);
        assert_eq!(
            listener.checkpoint(&SyncSource::SapSuccessFactorsMock),
            first_report.next_cursor.as_deref()
        );

        let second_report = listener
            .process_connector(
                &mut orchestrator,
                SyncSource::SapSuccessFactorsMock,
                &adapter,
            )
            .expect("second listener pass");
        assert_eq!(second_report.applied_event_count, 0);
        assert_eq!(
            second_report.next_cursor.as_deref(),
            first_report.next_cursor.as_deref()
        );
        assert_eq!(listener.checkpoints().len(), 1);
    }

    #[test]
    fn approver_routing_prefers_delegate_before_manager_chain() {
        let mut directory = OrgDirectory::default();
        directory.sync_snapshot(
            SyncSource::FeishuMock,
            vec![
                OrgUser {
                    user_id: "user-sysadmin".into(),
                    department_id: "dept-admin".into(),
                    manager_id: None,
                    status: EmploymentStatus::Active,
                    approver_profile: None,
                },
                OrgUser {
                    user_id: "manager-b".into(),
                    department_id: "dept-risk".into(),
                    manager_id: None,
                    status: EmploymentStatus::Active,
                    approver_profile: None,
                },
                OrgUser {
                    user_id: "delegate-a".into(),
                    department_id: "dept-risk".into(),
                    manager_id: Some("manager-b".into()),
                    status: EmploymentStatus::Active,
                    approver_profile: None,
                },
                OrgUser {
                    user_id: "manager-a".into(),
                    department_id: "dept-risk".into(),
                    manager_id: Some("manager-b".into()),
                    status: EmploymentStatus::Active,
                    approver_profile: None,
                },
            ],
        );
        directory
            .set_approver_availability("manager-a", ApproverAvailability::Unavailable)
            .expect("availability");
        directory
            .set_approver_delegate("manager-a", Some("delegate-a".into()))
            .expect("delegate");

        let route = directory
            .resolve_effective_approver("manager-a", "user-sysadmin")
            .expect("route");

        assert_eq!(route.resolved_user_id, "delegate-a");
        assert_eq!(route.delegated_from.as_deref(), Some("manager-a"));
        assert!(route.escalation_target.is_none());
    }

    #[test]
    fn approver_routing_escalates_up_chain_and_falls_back_to_system_admin() {
        let mut directory = OrgDirectory::default();
        directory.sync_snapshot(
            SyncSource::WorkdayMock,
            vec![
                OrgUser {
                    user_id: "user-sysadmin".into(),
                    department_id: "dept-admin".into(),
                    manager_id: None,
                    status: EmploymentStatus::Active,
                    approver_profile: None,
                },
                OrgUser {
                    user_id: "manager-b".into(),
                    department_id: "dept-risk".into(),
                    manager_id: None,
                    status: EmploymentStatus::Active,
                    approver_profile: None,
                },
                OrgUser {
                    user_id: "manager-a".into(),
                    department_id: "dept-risk".into(),
                    manager_id: Some("manager-b".into()),
                    status: EmploymentStatus::Active,
                    approver_profile: None,
                },
            ],
        );
        directory
            .set_approver_availability("manager-a", ApproverAvailability::Unavailable)
            .expect("availability");
        directory
            .set_approver_availability("manager-b", ApproverAvailability::Unavailable)
            .expect("availability");

        let escalated = directory
            .reroute_unavailable_approver("manager-a", "user-sysadmin")
            .expect("route");
        assert_eq!(escalated.resolved_user_id, "user-sysadmin");
        assert_eq!(
            escalated.escalation_target.as_deref(),
            Some("user-sysadmin")
        );
        assert!(escalated.used_system_fallback);
    }

    #[test]
    fn approver_resolution_policy_tracks_delegate_escalation_and_unavailable_users() {
        let mut directory = OrgDirectory::default();
        directory.sync_snapshot(
            SyncSource::Workday,
            vec![
                OrgUser {
                    user_id: "user-sysadmin".into(),
                    department_id: "dept-admin".into(),
                    manager_id: None,
                    status: EmploymentStatus::Active,
                    approver_profile: None,
                },
                OrgUser {
                    user_id: "manager-a".into(),
                    department_id: "dept-risk".into(),
                    manager_id: None,
                    status: EmploymentStatus::Active,
                    approver_profile: None,
                },
            ],
        );
        directory.sync_snapshot(
            SyncSource::SapSuccessFactors,
            vec![OrgUser {
                user_id: "delegate-a".into(),
                department_id: "dept-risk".into(),
                manager_id: None,
                status: EmploymentStatus::Active,
                approver_profile: None,
            }],
        );
        directory.sync_snapshot(
            SyncSource::Ldap,
            vec![OrgUser {
                user_id: "security-a".into(),
                department_id: "dept-security".into(),
                manager_id: None,
                status: EmploymentStatus::Active,
                approver_profile: None,
            }],
        );
        directory
            .set_approver_availability("manager-a", ApproverAvailability::Unavailable)
            .expect("availability");
        directory
            .set_approver_delegate("manager-a", Some("delegate-a".into()))
            .expect("delegate");

        let policy = ApproverResolutionPolicy {
            system_fallback_user_id: "user-sysadmin".into(),
            escalation_user_ids: vec!["security-a".into()],
            max_manager_hops: 2,
            allow_delegation: true,
        };
        let delegated = directory
            .resolve_effective_approver_with_policy("manager-a", &policy)
            .expect("delegated route");
        assert_eq!(delegated.route_kind, ApproverRouteKind::Delegated);
        assert_eq!(delegated.resolved_user_id, "delegate-a");
        assert_eq!(delegated.delegated_from.as_deref(), Some("manager-a"));
        assert!(
            delegated
                .unavailable_user_ids
                .iter()
                .any(|user_id| user_id == "manager-a")
        );

        directory
            .set_approver_availability("delegate-a", ApproverAvailability::Unavailable)
            .expect("delegate availability");
        let escalated = directory
            .resolve_effective_approver_with_policy("manager-a", &policy)
            .expect("escalated route");
        assert_eq!(
            escalated.route_kind,
            ApproverRouteKind::EscalatedToConfiguredTarget
        );
        assert_eq!(escalated.resolved_user_id, "security-a");
        assert!(
            escalated
                .unavailable_user_ids
                .iter()
                .any(|user_id| user_id == "delegate-a")
        );

        directory
            .set_approver_availability("security-a", ApproverAvailability::Unavailable)
            .expect("escalation availability");
        let fallback = directory
            .resolve_effective_approver_with_policy("manager-a", &policy)
            .expect("fallback route");
        assert_eq!(fallback.route_kind, ApproverRouteKind::SystemFallback);
        assert_eq!(fallback.resolved_user_id, "user-sysadmin");
        assert!(fallback.used_system_fallback);
    }
}
