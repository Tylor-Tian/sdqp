use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimUser {
    pub external_id: String,
    pub tenant_id: String,
    pub user_name: String,
    pub display_name: String,
    pub email: String,
    pub active: bool,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimGroup {
    pub external_id: String,
    pub tenant_id: String,
    pub display_name: String,
    pub active: bool,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ScimUserPatch {
    Upsert {
        user: ScimUser,
    },
    Patch {
        external_id: String,
        user_name: Option<String>,
        display_name: Option<String>,
        email: Option<String>,
        active: Option<bool>,
        groups: Option<Vec<String>>,
    },
    Disable {
        external_id: String,
    },
    Delete {
        external_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ScimGroupPatch {
    Upsert {
        group: ScimGroup,
    },
    Patch {
        external_id: String,
        display_name: Option<String>,
        active: Option<bool>,
    },
    PatchMembers {
        external_id: String,
        #[serde(default)]
        add_members: Vec<String>,
        #[serde(default)]
        remove_members: Vec<String>,
    },
    Disable {
        external_id: String,
    },
    Delete {
        external_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ScimSyncSummary {
    pub users_changed: usize,
    pub users_disabled: usize,
    pub groups_changed: usize,
    pub groups_disabled: usize,
    pub memberships_changed: usize,
}

impl ScimSyncSummary {
    pub fn merge(&mut self, other: ScimSyncSummary) {
        self.users_changed += other.users_changed;
        self.users_disabled += other.users_disabled;
        self.groups_changed += other.groups_changed;
        self.groups_disabled += other.groups_disabled;
        self.memberships_changed += other.memberships_changed;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimProviderConfig {
    pub provider: String,
    pub base_url: String,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimSyncConfig {
    pub provider: String,
    pub base_url: String,
    pub token: String,
    pub tenant_id: String,
    pub page_size: usize,
    pub timeout_ms: u64,
    pub retry_attempts: usize,
    pub retry_backoff_ms: u64,
    pub disable_missing_users: bool,
    pub disable_missing_groups: bool,
    pub delete_missing_users: bool,
    pub delete_missing_groups: bool,
}

impl ScimSyncConfig {
    pub fn from_provider_config(config: ScimProviderConfig, tenant_id: impl Into<String>) -> Self {
        Self {
            provider: config.provider,
            base_url: config.base_url,
            token: config.token,
            tenant_id: tenant_id.into(),
            page_size: 100,
            timeout_ms: 5_000,
            retry_attempts: 2,
            retry_backoff_ms: 250,
            disable_missing_users: true,
            disable_missing_groups: true,
            delete_missing_users: false,
            delete_missing_groups: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimLifecyclePolicy {
    pub disable_missing_users: bool,
    pub disable_missing_groups: bool,
    pub delete_missing_users: bool,
    pub delete_missing_groups: bool,
}

impl From<&ScimSyncConfig> for ScimLifecyclePolicy {
    fn from(config: &ScimSyncConfig) -> Self {
        Self {
            disable_missing_users: config.disable_missing_users,
            disable_missing_groups: config.disable_missing_groups,
            delete_missing_users: config.delete_missing_users,
            delete_missing_groups: config.delete_missing_groups,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimPageRequest {
    pub start_index: usize,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimResourcePage<T> {
    pub resources: Vec<T>,
    pub total_results: usize,
    pub start_index: usize,
    pub items_per_page: usize,
}

impl<T> ScimResourcePage<T> {
    pub fn next_start_index(&self) -> Option<usize> {
        let next = self.start_index + self.items_per_page;
        (self.items_per_page > 0 && next <= self.total_results).then_some(next)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimSyncCursor {
    pub provider: String,
    pub base_url: String,
    pub last_success_at: DateTime<Utc>,
    pub users_total: usize,
    pub groups_total: usize,
    pub pages_fetched: usize,
    pub last_user_start_index: usize,
    pub last_group_start_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimDirectorySnapshot {
    pub users: Vec<ScimUser>,
    pub groups: Vec<ScimGroup>,
    pub cursor: ScimSyncCursor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScimMembershipChangeKind {
    Add,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimMembershipChange {
    pub group_external_id: String,
    pub user_external_id: String,
    pub change: ScimMembershipChangeKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimSyncPlan {
    pub user_patches: Vec<ScimUserPatch>,
    pub group_patches: Vec<ScimGroupPatch>,
    pub membership_changes: Vec<ScimMembershipChange>,
    pub summary: ScimSyncSummary,
    pub cursor: ScimSyncCursor,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScimSyncError {
    #[error("scim token is invalid")]
    InvalidToken,
    #[error("unknown scim provider: {0}")]
    UnknownProvider(String),
    #[error("scim provider does not implement resource synchronization: {0}")]
    UnsupportedProvider(String),
    #[error("scim provider configuration error: {0}")]
    ProviderConfiguration(String),
    #[error("scim provider request error: {0}")]
    ProviderRequest(String),
    #[error("scim provider returned status {status}: {body}")]
    ProviderStatus { status: u16, body: String },
    #[error("scim provider payload parse error: {0}")]
    ProviderParse(String),
    #[error("scim identity not found: {0}")]
    NotFound(String),
}

#[async_trait]
pub trait ScimDirectoryProvider: Send + Sync {
    fn provider_name(&self) -> &str;
    fn authorize(&self, token: &str) -> Result<(), ScimSyncError>;
    async fn users_page(
        &self,
        request: ScimPageRequest,
    ) -> Result<ScimResourcePage<ScimUser>, ScimSyncError>;
    async fn groups_page(
        &self,
        request: ScimPageRequest,
    ) -> Result<ScimResourcePage<ScimGroup>, ScimSyncError>;
}

#[derive(Debug, Clone)]
pub struct MockScimDirectory {
    expected_token: String,
}

impl MockScimDirectory {
    pub fn new(expected_token: impl Into<String>) -> Self {
        Self {
            expected_token: expected_token.into(),
        }
    }

    pub fn authorize(&self, token: &str) -> Result<(), ScimSyncError> {
        if token == self.expected_token {
            Ok(())
        } else {
            Err(ScimSyncError::InvalidToken)
        }
    }
}

#[async_trait]
impl ScimDirectoryProvider for MockScimDirectory {
    fn provider_name(&self) -> &str {
        "mock"
    }

    fn authorize(&self, token: &str) -> Result<(), ScimSyncError> {
        self.authorize(token)
    }

    async fn users_page(
        &self,
        _request: ScimPageRequest,
    ) -> Result<ScimResourcePage<ScimUser>, ScimSyncError> {
        Err(ScimSyncError::UnsupportedProvider("mock".into()))
    }

    async fn groups_page(
        &self,
        _request: ScimPageRequest,
    ) -> Result<ScimResourcePage<ScimGroup>, ScimSyncError> {
        Err(ScimSyncError::UnsupportedProvider("mock".into()))
    }
}

#[derive(Debug, Clone)]
pub struct BearerScimDirectory {
    _base_url: String,
    expected_token: String,
}

impl BearerScimDirectory {
    pub fn from_config(config: ScimProviderConfig) -> Result<Self, ScimSyncError> {
        if config.base_url.trim().is_empty() {
            return Err(ScimSyncError::ProviderConfiguration(
                "scim.base_url must not be empty".into(),
            ));
        }
        if config.token.trim().is_empty() {
            return Err(ScimSyncError::ProviderConfiguration(
                "scim.token must not be empty".into(),
            ));
        }

        Ok(Self {
            _base_url: config.base_url,
            expected_token: config.token,
        })
    }

    pub fn authorize(&self, token: &str) -> Result<(), ScimSyncError> {
        if token == self.expected_token {
            Ok(())
        } else {
            Err(ScimSyncError::InvalidToken)
        }
    }
}

#[async_trait]
impl ScimDirectoryProvider for BearerScimDirectory {
    fn provider_name(&self) -> &str {
        "bearer"
    }

    fn authorize(&self, token: &str) -> Result<(), ScimSyncError> {
        self.authorize(token)
    }

    async fn users_page(
        &self,
        _request: ScimPageRequest,
    ) -> Result<ScimResourcePage<ScimUser>, ScimSyncError> {
        Err(ScimSyncError::UnsupportedProvider("bearer".into()))
    }

    async fn groups_page(
        &self,
        _request: ScimPageRequest,
    ) -> Result<ScimResourcePage<ScimGroup>, ScimSyncError> {
        Err(ScimSyncError::UnsupportedProvider("bearer".into()))
    }
}

#[derive(Debug, Clone)]
pub struct HttpScimDirectory {
    config: ScimSyncConfig,
    client: Client,
}

impl HttpScimDirectory {
    pub fn from_config(config: ScimSyncConfig) -> Result<Self, ScimSyncError> {
        if config.base_url.trim().is_empty() {
            return Err(ScimSyncError::ProviderConfiguration(
                "scim.base_url must not be empty".into(),
            ));
        }
        if config.token.trim().is_empty() {
            return Err(ScimSyncError::ProviderConfiguration(
                "scim.token must not be empty".into(),
            ));
        }
        if config.page_size == 0 {
            return Err(ScimSyncError::ProviderConfiguration(
                "scim.page_size must be greater than zero".into(),
            ));
        }
        Url::parse(&config.base_url).map_err(|error| {
            ScimSyncError::ProviderConfiguration(format!("invalid scim.base_url: {error}"))
        })?;

        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms.max(1)))
            .build()
            .map_err(|error| ScimSyncError::ProviderRequest(error.to_string()))?;
        Ok(Self { config, client })
    }

    async fn fetch_json_page(
        &self,
        resource: &str,
        request: &ScimPageRequest,
    ) -> Result<ScimListResponse, ScimSyncError> {
        let url = format!(
            "{}/{}",
            self.config.base_url.trim_end_matches('/'),
            resource.trim_start_matches('/')
        );
        let mut last_error = None;
        let attempts = self.config.retry_attempts.max(1);

        for _ in 0..attempts {
            match self
                .client
                .get(&url)
                .bearer_auth(&self.config.token)
                .query(&[
                    ("startIndex", request.start_index),
                    ("count", request.count),
                ])
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    let body = response.text().await.map_err(|error| {
                        ScimSyncError::ProviderRequest(format!("failed reading response: {error}"))
                    })?;
                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        return Err(ScimSyncError::InvalidToken);
                    }
                    if status.is_success() {
                        return serde_json::from_str::<ScimListResponse>(&body).map_err(|error| {
                            ScimSyncError::ProviderParse(format!(
                                "invalid SCIM ListResponse from {resource}: {error}"
                            ))
                        });
                    }
                    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                        last_error = Some(ScimSyncError::ProviderStatus {
                            status: status.as_u16(),
                            body,
                        });
                        continue;
                    }
                    return Err(ScimSyncError::ProviderStatus {
                        status: status.as_u16(),
                        body,
                    });
                }
                Err(error) => {
                    last_error = Some(ScimSyncError::ProviderRequest(error.to_string()));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            ScimSyncError::ProviderRequest("SCIM request failed without response".into())
        }))
    }

    fn parse_user(&self, value: Value) -> Result<ScimUser, ScimSyncError> {
        let external_id = resource_external_id(&value)?;
        let user_name = string_field(&value, "userName")
            .or_else(|| string_field(&value, "username"))
            .unwrap_or_else(|| external_id.clone());
        let display_name = string_field(&value, "displayName").unwrap_or_else(|| user_name.clone());
        let email = parse_email(&value).unwrap_or_else(|| format!("{user_name}@unknown.invalid"));
        let active = value.get("active").and_then(Value::as_bool).unwrap_or(true);
        let groups = parse_ref_values(value.get("groups"));

        Ok(ScimUser {
            external_id,
            tenant_id: self.config.tenant_id.clone(),
            user_name,
            display_name,
            email,
            active,
            groups,
        })
    }

    fn parse_group(&self, value: Value) -> Result<ScimGroup, ScimSyncError> {
        let external_id = resource_external_id(&value)?;
        let display_name =
            string_field(&value, "displayName").unwrap_or_else(|| external_id.clone());
        let active = value.get("active").and_then(Value::as_bool).unwrap_or(true);
        let members = parse_ref_values(value.get("members"));

        Ok(ScimGroup {
            external_id,
            tenant_id: self.config.tenant_id.clone(),
            display_name,
            active,
            members,
        })
    }
}

#[async_trait]
impl ScimDirectoryProvider for HttpScimDirectory {
    fn provider_name(&self) -> &str {
        &self.config.provider
    }

    fn authorize(&self, token: &str) -> Result<(), ScimSyncError> {
        if token == self.config.token {
            Ok(())
        } else {
            Err(ScimSyncError::InvalidToken)
        }
    }

    async fn users_page(
        &self,
        request: ScimPageRequest,
    ) -> Result<ScimResourcePage<ScimUser>, ScimSyncError> {
        let response = self.fetch_json_page("Users", &request).await?;
        let resources = response
            .resources
            .into_iter()
            .map(|value| self.parse_user(value))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ScimResourcePage {
            resources,
            total_results: response.total_results.unwrap_or_default(),
            start_index: response.start_index.unwrap_or(request.start_index),
            items_per_page: response.items_per_page.unwrap_or(request.count),
        })
    }

    async fn groups_page(
        &self,
        request: ScimPageRequest,
    ) -> Result<ScimResourcePage<ScimGroup>, ScimSyncError> {
        let response = self.fetch_json_page("Groups", &request).await?;
        let resources = response
            .resources
            .into_iter()
            .map(|value| self.parse_group(value))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ScimResourcePage {
            resources,
            total_results: response.total_results.unwrap_or_default(),
            start_index: response.start_index.unwrap_or(request.start_index),
            items_per_page: response.items_per_page.unwrap_or(request.count),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ScimDirectoryRegistry {
    directory: ScimProviderEntry,
    sync_config: ScimSyncConfig,
}

impl ScimDirectoryRegistry {
    pub fn from_config(config: ScimProviderConfig) -> Result<Self, ScimSyncError> {
        Self::from_sync_config(ScimSyncConfig::from_provider_config(config, "tenant-alpha"))
    }

    pub fn from_sync_config(config: ScimSyncConfig) -> Result<Self, ScimSyncError> {
        let provider = normalized_provider(&config.provider);
        let directory = match provider.as_str() {
            "mock" => ScimProviderEntry::Mock(MockScimDirectory::new(config.token.clone())),
            "bearer" => {
                ScimProviderEntry::Bearer(BearerScimDirectory::from_config(ScimProviderConfig {
                    provider: config.provider.clone(),
                    base_url: config.base_url.clone(),
                    token: config.token.clone(),
                })?)
            }
            "scim20" | "scim2" | "generic-scim" | "okta" | "entra" | "azure-ad" => {
                ScimProviderEntry::Http(HttpScimDirectory::from_config(config.clone())?)
            }
            other => return Err(ScimSyncError::UnknownProvider(other.into())),
        };

        Ok(Self {
            directory,
            sync_config: config,
        })
    }

    pub fn provider_name(&self) -> &str {
        self.directory.provider_name()
    }

    pub fn sync_config(&self) -> &ScimSyncConfig {
        &self.sync_config
    }

    pub fn authorize(&self, token: &str) -> Result<(), ScimSyncError> {
        self.directory.authorize(token)
    }

    pub async fn pull_snapshot(
        &self,
        _previous_cursor: Option<&ScimSyncCursor>,
    ) -> Result<ScimDirectorySnapshot, ScimSyncError> {
        let page_size = self.sync_config.page_size.max(1);
        let mut users = Vec::new();
        let mut groups = Vec::new();
        let mut pages_fetched = 0;
        let mut user_page_starts = Vec::new();
        let mut group_page_starts = Vec::new();

        let mut start_index = 1;
        loop {
            let page = self
                .directory
                .users_page(ScimPageRequest {
                    start_index,
                    count: page_size,
                })
                .await?;
            user_page_starts.push(page.start_index);
            pages_fetched += 1;
            let next_start_index = page.next_start_index();
            users.extend(page.resources);
            let Some(next) = next_start_index else {
                break;
            };
            start_index = next;
        }

        start_index = 1;
        loop {
            let page = self
                .directory
                .groups_page(ScimPageRequest {
                    start_index,
                    count: page_size,
                })
                .await?;
            group_page_starts.push(page.start_index);
            pages_fetched += 1;
            let next_start_index = page.next_start_index();
            groups.extend(page.resources);
            let Some(next) = next_start_index else {
                break;
            };
            start_index = next;
        }

        let cursor = ScimSyncCursor {
            provider: self.sync_config.provider.clone(),
            base_url: self.sync_config.base_url.clone(),
            last_success_at: Utc::now(),
            users_total: users.len(),
            groups_total: groups.len(),
            pages_fetched,
            last_user_start_index: user_page_starts.last().copied().unwrap_or(1),
            last_group_start_index: group_page_starts.last().copied().unwrap_or(1),
        };

        Ok(ScimDirectorySnapshot {
            users,
            groups,
            cursor,
        })
    }
}

#[derive(Debug, Clone)]
enum ScimProviderEntry {
    Mock(MockScimDirectory),
    Bearer(BearerScimDirectory),
    Http(HttpScimDirectory),
}

impl ScimProviderEntry {
    fn provider_name(&self) -> &str {
        match self {
            Self::Mock(directory) => directory.provider_name(),
            Self::Bearer(directory) => directory.provider_name(),
            Self::Http(directory) => directory.provider_name(),
        }
    }

    fn authorize(&self, token: &str) -> Result<(), ScimSyncError> {
        match self {
            Self::Mock(directory) => directory.authorize(token),
            Self::Bearer(directory) => directory.authorize(token),
            Self::Http(directory) => directory.authorize(token),
        }
    }

    async fn users_page(
        &self,
        request: ScimPageRequest,
    ) -> Result<ScimResourcePage<ScimUser>, ScimSyncError> {
        match self {
            Self::Mock(directory) => directory.users_page(request).await,
            Self::Bearer(directory) => directory.users_page(request).await,
            Self::Http(directory) => directory.users_page(request).await,
        }
    }

    async fn groups_page(
        &self,
        request: ScimPageRequest,
    ) -> Result<ScimResourcePage<ScimGroup>, ScimSyncError> {
        match self {
            Self::Mock(directory) => directory.groups_page(request).await,
            Self::Bearer(directory) => directory.groups_page(request).await,
            Self::Http(directory) => directory.groups_page(request).await,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ScimIdentityState {
    pub users: HashMap<String, ScimUser>,
    pub groups: HashMap<String, ScimGroup>,
}

impl ScimIdentityState {
    pub fn new(users: Vec<ScimUser>, groups: Vec<ScimGroup>) -> Self {
        Self {
            users: users
                .into_iter()
                .map(|user| (user.external_id.clone(), user))
                .collect(),
            groups: groups
                .into_iter()
                .map(|group| (group.external_id.clone(), group))
                .collect(),
        }
    }

    pub fn apply_user_patch(
        &mut self,
        patch: ScimUserPatch,
    ) -> Result<ScimSyncSummary, ScimSyncError> {
        let mut summary = ScimSyncSummary::default();
        match patch {
            ScimUserPatch::Upsert { user } => {
                self.users.insert(user.external_id.clone(), user);
                summary.users_changed = 1;
            }
            ScimUserPatch::Patch {
                external_id,
                user_name,
                display_name,
                email,
                active,
                groups,
            } => {
                let user = self
                    .users
                    .get_mut(&external_id)
                    .ok_or_else(|| ScimSyncError::NotFound(external_id.clone()))?;
                if let Some(user_name) = user_name {
                    user.user_name = user_name;
                }
                if let Some(display_name) = display_name {
                    user.display_name = display_name;
                }
                if let Some(email) = email {
                    user.email = email;
                }
                if let Some(active) = active {
                    user.active = active;
                    if !active {
                        summary.users_disabled = 1;
                    }
                }
                if let Some(groups) = groups {
                    user.groups = canonical_vec(groups);
                    summary.memberships_changed = 1;
                }
                summary.users_changed = 1;
            }
            ScimUserPatch::Disable { external_id } => {
                let user = self
                    .users
                    .get_mut(&external_id)
                    .ok_or_else(|| ScimSyncError::NotFound(external_id.clone()))?;
                user.active = false;
                summary.users_disabled = 1;
            }
            ScimUserPatch::Delete { external_id } => {
                self.users
                    .remove(&external_id)
                    .ok_or_else(|| ScimSyncError::NotFound(external_id.clone()))?;
                summary.users_changed = 1;
            }
        }
        Ok(summary)
    }

    pub fn apply_group_patch(
        &mut self,
        patch: ScimGroupPatch,
    ) -> Result<ScimSyncSummary, ScimSyncError> {
        let mut summary = ScimSyncSummary::default();
        match patch {
            ScimGroupPatch::Upsert { mut group } => {
                group.members = canonical_vec(group.members);
                let existing_members = self
                    .groups
                    .get(&group.external_id)
                    .map(|group| group.members.clone())
                    .unwrap_or_default();
                summary.memberships_changed =
                    symmetric_diff_count(&existing_members, &group.members);
                self.groups.insert(group.external_id.clone(), group);
                summary.groups_changed = 1;
            }
            ScimGroupPatch::Patch {
                external_id,
                display_name,
                active,
            } => {
                let group = self
                    .groups
                    .get_mut(&external_id)
                    .ok_or_else(|| ScimSyncError::NotFound(external_id.clone()))?;
                if let Some(display_name) = display_name {
                    group.display_name = display_name;
                }
                if let Some(active) = active {
                    group.active = active;
                    if !active {
                        summary.groups_disabled = 1;
                    }
                }
                summary.groups_changed = 1;
            }
            ScimGroupPatch::PatchMembers {
                external_id,
                add_members,
                remove_members,
            } => {
                let group = self
                    .groups
                    .get_mut(&external_id)
                    .ok_or_else(|| ScimSyncError::NotFound(external_id.clone()))?;
                let mut members = group.members.iter().cloned().collect::<BTreeSet<_>>();
                let mut changed = 0;
                for member in add_members {
                    if members.insert(member) {
                        changed += 1;
                    }
                }
                for member in remove_members {
                    if members.remove(&member) {
                        changed += 1;
                    }
                }
                group.members = members.into_iter().collect();
                summary.groups_changed = 1;
                summary.memberships_changed = changed;
            }
            ScimGroupPatch::Disable { external_id } => {
                let group = self
                    .groups
                    .get_mut(&external_id)
                    .ok_or_else(|| ScimSyncError::NotFound(external_id.clone()))?;
                group.active = false;
                summary.groups_disabled = 1;
            }
            ScimGroupPatch::Delete { external_id } => {
                self.groups
                    .remove(&external_id)
                    .ok_or_else(|| ScimSyncError::NotFound(external_id.clone()))?;
                summary.groups_changed = 1;
            }
        }
        Ok(summary)
    }
}

pub fn build_scim_sync_plan(
    current_users: &[ScimUser],
    current_groups: &[ScimGroup],
    provider_snapshot: ScimDirectorySnapshot,
    policy: ScimLifecyclePolicy,
) -> ScimSyncPlan {
    let current_groups = canonical_group_map(current_groups);
    let desired_groups = canonical_group_map(&provider_snapshot.groups);
    let current_users = canonical_user_map(with_group_memberships(
        current_users,
        current_groups.values(),
    ));
    let desired_users = canonical_user_map(with_group_memberships(
        &provider_snapshot.users,
        desired_groups.values(),
    ));

    let mut group_patches = Vec::new();
    let mut user_patches = Vec::new();
    let mut membership_changes = Vec::new();
    let mut summary = ScimSyncSummary::default();

    for desired in desired_groups.values() {
        match current_groups.get(&desired.external_id) {
            Some(current) => {
                let member_changes = membership_diff(current, desired);
                summary.memberships_changed += member_changes.len();
                membership_changes.extend(member_changes);
                if current != desired {
                    group_patches.push(ScimGroupPatch::Upsert {
                        group: desired.clone(),
                    });
                    summary.groups_changed += 1;
                }
            }
            None => {
                membership_changes.extend(desired.members.iter().map(|member| {
                    ScimMembershipChange {
                        group_external_id: desired.external_id.clone(),
                        user_external_id: member.clone(),
                        change: ScimMembershipChangeKind::Add,
                    }
                }));
                summary.memberships_changed += desired.members.len();
                group_patches.push(ScimGroupPatch::Upsert {
                    group: desired.clone(),
                });
                summary.groups_changed += 1;
            }
        }
    }

    for current in current_groups.values() {
        if desired_groups.contains_key(&current.external_id) {
            continue;
        }
        if policy.delete_missing_groups {
            group_patches.push(ScimGroupPatch::Delete {
                external_id: current.external_id.clone(),
            });
            summary.groups_changed += 1;
        } else if policy.disable_missing_groups && current.active {
            group_patches.push(ScimGroupPatch::Disable {
                external_id: current.external_id.clone(),
            });
            summary.groups_disabled += 1;
        }
    }

    for desired in desired_users.values() {
        match current_users.get(&desired.external_id) {
            Some(current) if current == desired => {}
            _ => {
                if !desired.active {
                    summary.users_disabled += 1;
                } else {
                    summary.users_changed += 1;
                }
                user_patches.push(ScimUserPatch::Upsert {
                    user: desired.clone(),
                });
            }
        }
    }

    for current in current_users.values() {
        if desired_users.contains_key(&current.external_id) {
            continue;
        }
        if policy.delete_missing_users {
            user_patches.push(ScimUserPatch::Delete {
                external_id: current.external_id.clone(),
            });
            summary.users_changed += 1;
        } else if policy.disable_missing_users && current.active {
            user_patches.push(ScimUserPatch::Disable {
                external_id: current.external_id.clone(),
            });
            summary.users_disabled += 1;
        }
    }

    ScimSyncPlan {
        user_patches,
        group_patches,
        membership_changes,
        summary,
        cursor: provider_snapshot.cursor,
    }
}

#[derive(Debug, Deserialize)]
struct ScimListResponse {
    #[serde(rename = "totalResults")]
    total_results: Option<usize>,
    #[serde(rename = "startIndex")]
    start_index: Option<usize>,
    #[serde(rename = "itemsPerPage")]
    items_per_page: Option<usize>,
    #[serde(rename = "Resources", default)]
    resources: Vec<Value>,
}

fn normalized_provider(provider: &str) -> String {
    provider.trim().to_ascii_lowercase()
}

fn resource_external_id(value: &Value) -> Result<String, ScimSyncError> {
    string_field(value, "externalId")
        .or_else(|| string_field(value, "id"))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ScimSyncError::ProviderParse("SCIM resource missing externalId/id".into()))
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value.get(field)?.as_str().map(str::to_string)
}

fn parse_email(value: &Value) -> Option<String> {
    let emails = value.get("emails")?.as_array()?;
    emails
        .iter()
        .find(|email| {
            email
                .get("primary")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .or_else(|| emails.first())
        .and_then(|email| email.get("value"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn parse_ref_values(value: Option<&Value>) -> Vec<String> {
    canonical_vec(
        value
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| {
                item.get("value")
                    .or_else(|| item.get("display"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect(),
    )
}

fn canonical_vec(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn canonical_group_map(groups: &[ScimGroup]) -> HashMap<String, ScimGroup> {
    groups
        .iter()
        .cloned()
        .map(|mut group| {
            group.members = canonical_vec(group.members);
            (group.external_id.clone(), group)
        })
        .collect()
}

fn canonical_user_map(users: Vec<ScimUser>) -> HashMap<String, ScimUser> {
    users
        .into_iter()
        .map(|mut user| {
            user.groups = canonical_vec(user.groups);
            (user.external_id.clone(), user)
        })
        .collect()
}

fn with_group_memberships<'a, I>(users: &[ScimUser], groups: I) -> Vec<ScimUser>
where
    I: IntoIterator<Item = &'a ScimGroup>,
{
    let mut groups_by_user = HashMap::<String, BTreeSet<String>>::new();
    for group in groups {
        for member in &group.members {
            groups_by_user
                .entry(member.clone())
                .or_default()
                .insert(group.external_id.clone());
        }
    }

    users
        .iter()
        .cloned()
        .map(|mut user| {
            let mut groups = user.groups.into_iter().collect::<BTreeSet<_>>();
            if let Some(group_memberships) = groups_by_user.remove(&user.external_id) {
                groups.extend(group_memberships);
            }
            user.groups = groups.into_iter().collect();
            user
        })
        .collect()
}

fn membership_diff(current: &ScimGroup, desired: &ScimGroup) -> Vec<ScimMembershipChange> {
    let current_members = current.members.iter().cloned().collect::<BTreeSet<_>>();
    let desired_members = desired.members.iter().cloned().collect::<BTreeSet<_>>();
    let mut changes = Vec::new();
    for member in desired_members.difference(&current_members) {
        changes.push(ScimMembershipChange {
            group_external_id: desired.external_id.clone(),
            user_external_id: member.clone(),
            change: ScimMembershipChangeKind::Add,
        });
    }
    for member in current_members.difference(&desired_members) {
        changes.push(ScimMembershipChange {
            group_external_id: desired.external_id.clone(),
            user_external_id: member.clone(),
            change: ScimMembershipChangeKind::Remove,
        });
    }
    changes
}

fn symmetric_diff_count(left: &[String], right: &[String]) -> usize {
    let left = left.iter().cloned().collect::<BTreeSet<_>>();
    let right = right.iter().cloned().collect::<BTreeSet<_>>();
    left.symmetric_difference(&right).count()
}

#[cfg(test)]
mod tests {
    use super::{
        MockScimDirectory, ScimDirectoryRegistry, ScimGroup, ScimGroupPatch, ScimIdentityState,
        ScimLifecyclePolicy, ScimProviderConfig, ScimSyncConfig, ScimSyncCursor, ScimSyncError,
        ScimUser, ScimUserPatch, build_scim_sync_plan,
    };
    use axum::{
        Json, Router,
        extract::{Query, State},
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::get,
    };
    use chrono::Utc;
    use serde_json::{Value, json};
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    #[test]
    fn mock_scim_directory_rejects_invalid_token() {
        let directory = MockScimDirectory::new("token-a");
        assert!(directory.authorize("wrong").is_err());
        assert!(directory.authorize("token-a").is_ok());
    }

    #[tokio::test]
    async fn bearer_scim_registry_authorizes_expected_token_but_does_not_sync() {
        let registry = ScimDirectoryRegistry::from_config(ScimProviderConfig {
            provider: "bearer".into(),
            base_url: "https://idp.example.internal/scim".into(),
            token: "token-b".into(),
        })
        .expect("registry");

        assert!(registry.authorize("token-b").is_ok());
        assert!(registry.authorize("wrong").is_err());
        let error = registry.pull_snapshot(None).await.expect_err("sync");
        assert_eq!(error, ScimSyncError::UnsupportedProvider("bearer".into()));
    }

    #[test]
    fn sync_plan_closes_disable_delete_and_membership_lifecycle() {
        let current_users = vec![
            ScimUser {
                external_id: "u-1".into(),
                tenant_id: "tenant-alpha".into(),
                user_name: "user-one".into(),
                display_name: "User One".into(),
                email: "one@example.internal".into(),
                active: true,
                groups: vec!["g-1".into()],
            },
            ScimUser {
                external_id: "u-stale".into(),
                tenant_id: "tenant-alpha".into(),
                user_name: "stale".into(),
                display_name: "Stale".into(),
                email: "stale@example.internal".into(),
                active: true,
                groups: vec!["g-stale".into()],
            },
        ];
        let current_groups = vec![
            ScimGroup {
                external_id: "g-1".into(),
                tenant_id: "tenant-alpha".into(),
                display_name: "Analysts".into(),
                active: true,
                members: vec!["u-1".into(), "u-stale".into()],
            },
            ScimGroup {
                external_id: "g-stale".into(),
                tenant_id: "tenant-alpha".into(),
                display_name: "Stale".into(),
                active: true,
                members: vec!["u-stale".into()],
            },
        ];
        let snapshot = super::ScimDirectorySnapshot {
            users: vec![ScimUser {
                external_id: "u-1".into(),
                tenant_id: "tenant-alpha".into(),
                user_name: "user-one".into(),
                display_name: "User One Changed".into(),
                email: "one@example.internal".into(),
                active: false,
                groups: vec!["g-1".into()],
            }],
            groups: vec![ScimGroup {
                external_id: "g-1".into(),
                tenant_id: "tenant-alpha".into(),
                display_name: "Analysts".into(),
                active: true,
                members: vec!["u-1".into()],
            }],
            cursor: ScimSyncCursor {
                provider: "scim20".into(),
                base_url: "http://idp/scim".into(),
                last_success_at: Utc::now(),
                users_total: 1,
                groups_total: 1,
                pages_fetched: 2,
                last_user_start_index: 1,
                last_group_start_index: 1,
            },
        };

        let plan = build_scim_sync_plan(
            &current_users,
            &current_groups,
            snapshot,
            ScimLifecyclePolicy {
                disable_missing_users: true,
                disable_missing_groups: false,
                delete_missing_users: false,
                delete_missing_groups: true,
            },
        );

        assert_eq!(plan.summary.users_disabled, 2);
        assert_eq!(plan.summary.groups_changed, 2);
        assert_eq!(plan.summary.memberships_changed, 1);
        assert!(matches!(
            plan.user_patches.last(),
            Some(ScimUserPatch::Disable { external_id }) if external_id == "u-stale"
        ));
        assert!(matches!(
            plan.group_patches.last(),
            Some(ScimGroupPatch::Delete { external_id }) if external_id == "g-stale"
        ));
    }

    #[test]
    fn identity_state_applies_patch_and_membership_changes() {
        let mut state = ScimIdentityState::new(
            vec![ScimUser {
                external_id: "u-1".into(),
                tenant_id: "tenant-alpha".into(),
                user_name: "user-one".into(),
                display_name: "User One".into(),
                email: "one@example.internal".into(),
                active: true,
                groups: vec![],
            }],
            vec![ScimGroup {
                external_id: "g-1".into(),
                tenant_id: "tenant-alpha".into(),
                display_name: "Analysts".into(),
                active: true,
                members: vec![],
            }],
        );

        let summary = state
            .apply_group_patch(ScimGroupPatch::PatchMembers {
                external_id: "g-1".into(),
                add_members: vec!["u-1".into()],
                remove_members: vec![],
            })
            .expect("membership patch");
        assert_eq!(summary.memberships_changed, 1);

        let summary = state
            .apply_user_patch(ScimUserPatch::Patch {
                external_id: "u-1".into(),
                user_name: None,
                display_name: Some("User One Renamed".into()),
                email: None,
                active: Some(false),
                groups: Some(vec!["g-1".into()]),
            })
            .expect("user patch");
        assert_eq!(summary.users_disabled, 1);
        assert!(!state.users["u-1"].active);
    }

    #[derive(Clone)]
    struct ScimServerState {
        token: String,
        users: Arc<Mutex<Vec<Value>>>,
        groups: Arc<Mutex<Vec<Value>>>,
    }

    async fn list_users(
        State(state): State<ScimServerState>,
        headers: HeaderMap,
        Query(query): Query<HashMap<String, usize>>,
    ) -> impl IntoResponse {
        list_resources(
            &state,
            &headers,
            &query,
            state.users.lock().expect("users").clone(),
        )
    }

    async fn list_groups(
        State(state): State<ScimServerState>,
        headers: HeaderMap,
        Query(query): Query<HashMap<String, usize>>,
    ) -> impl IntoResponse {
        list_resources(
            &state,
            &headers,
            &query,
            state.groups.lock().expect("groups").clone(),
        )
    }

    fn list_resources(
        state: &ScimServerState,
        headers: &HeaderMap,
        query: &HashMap<String, usize>,
        resources: Vec<Value>,
    ) -> axum::response::Response {
        let authorized = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(|value| value == format!("Bearer {}", state.token))
            .unwrap_or(false);
        if !authorized {
            return StatusCode::UNAUTHORIZED.into_response();
        }

        let start_index = query.get("startIndex").copied().unwrap_or(1).max(1);
        let count = query.get("count").copied().unwrap_or(100).max(1);
        let start = start_index.saturating_sub(1);
        let page = resources
            .iter()
            .skip(start)
            .take(count)
            .cloned()
            .collect::<Vec<_>>();

        Json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": resources.len(),
            "startIndex": start_index,
            "itemsPerPage": page.len(),
            "Resources": page
        }))
        .into_response()
    }

    #[tokio::test]
    async fn scim20_provider_fetches_paginated_users_groups() {
        let state = ScimServerState {
            token: "provider-token".into(),
            users: Arc::new(Mutex::new(vec![
                json!({
                    "id": "idp-u-1",
                    "externalId": "u-1",
                    "userName": "user-one",
                    "displayName": "User One",
                    "active": true,
                    "emails": [{"value": "one@example.internal", "primary": true}],
                    "groups": [{"value": "g-1"}]
                }),
                json!({
                    "id": "idp-u-2",
                    "externalId": "u-2",
                    "userName": "user-two",
                    "displayName": "User Two",
                    "active": true,
                    "emails": [{"value": "two@example.internal"}],
                    "groups": [{"value": "g-1"}]
                }),
            ])),
            groups: Arc::new(Mutex::new(vec![json!({
                "id": "idp-g-1",
                "externalId": "g-1",
                "displayName": "Analysts",
                "members": [{"value": "u-1"}, {"value": "u-2"}]
            })])),
        };
        let app = Router::new()
            .route("/scim/Users", get(list_users))
            .route("/scim/Groups", get(list_groups))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server");
        });

        let registry = ScimDirectoryRegistry::from_sync_config(ScimSyncConfig {
            provider: "scim20".into(),
            base_url: format!("http://{addr}/scim"),
            token: "provider-token".into(),
            tenant_id: "tenant-alpha".into(),
            page_size: 1,
            timeout_ms: 5_000,
            retry_attempts: 2,
            retry_backoff_ms: 0,
            disable_missing_users: true,
            disable_missing_groups: true,
            delete_missing_users: false,
            delete_missing_groups: false,
        })
        .expect("registry");

        let snapshot = registry.pull_snapshot(None).await.expect("snapshot");
        assert_eq!(snapshot.users.len(), 2);
        assert_eq!(snapshot.groups.len(), 1);
        assert_eq!(snapshot.cursor.pages_fetched, 3);
        assert_eq!(snapshot.users[0].groups, vec!["g-1"]);
        assert_eq!(snapshot.groups[0].members, vec!["u-1", "u-2"]);
    }
}
