pub mod dlp;
mod observability;
mod persistence;
mod phase2;
mod phase4;
mod phase5;
mod phase6;
mod phase7;
mod phase8;
mod phase9;
mod stage11_ueba;
mod stage7_governance;
pub mod watermark_grpc;

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use axum::{
    Extension, Router,
    extract::{Json, Request, State},
    http::{
        HeaderMap, StatusCode,
        header::{self, HeaderValue},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use chrono::{DateTime, Utc};
use observability::HttpMetrics;
use sdqp_audit::{
    ActionResult, ActionType, ActorInfo, AuditCheckpoint, AuditContextFields, AuditEvent,
    AuditForwardRequest, AuditForwarderConfig, AuditForwarderProvider, AuditForwarderRegistry,
    AuditRetentionConfig, AuditTrail, CheckpointSignerConfig, CheckpointSignerProvider,
    CheckpointSignerRegistry, ControlledDeletionRecord, KafkaAuditForwarderConfig,
    SyslogAuditForwarderConfig, TargetRef, WebhookAuditForwarderConfig, build_archive_plan,
    build_audit_forwarder_registry, build_checkpoint_signer_registry, verify_archive_bundle,
};
use sdqp_config::{
    ApiSettings, AppSettings, AuditSettings, CredentialRotationSettings, IdentityProviderSettings,
    IntegrationSettings, KafkaSettings, SecurityApiKeySettings, SecuritySettings,
    settings::KmsRotationSettings, settings::UebaSettings,
};
use sdqp_contracts::{PHASE0_MILESTONE, ServiceHealth};
use sdqp_core::{ProjectId, RequestContext, TenantId, UserId};
use sdqp_system_security::{
    AdaptiveResponse, ApiKeyRecord, ConfigDrift, ConfigVersion, ContinuousAccessEvaluator,
    ContinuousAccessSignal, CredentialKind, CredentialRotationPolicy, CredentialRotationState,
    CredentialRotationStatus, DevicePostureReport, IntegrationRateLimiter,
    IntegrationRequestContext, IntegrationSecurityConfig, IntegrationSecurityError,
    IntegrationSecurityPolicy, MfaChallenge, MfaChallengePayload, MfaMethod, MfaProviderConfig,
    MfaProviderRegistry, MfaRegistration, MfaVerification, MockDevicePostureCollector, MtlsPolicy,
    OidcProviderConfig, RateLimitPolicy, Role, SamlProviderConfig, ScimDirectoryRegistry,
    ScimGroup, ScimGroupPatch, ScimLifecyclePolicy, ScimMembershipChange, ScimSyncConfig,
    ScimSyncCursor, ScimSyncError, ScimSyncPlan, ScimSyncSummary, ScimUser, ScimUserPatch,
    SessionBinding, SessionClaims, SessionPolicy, SsoError, SsoProtocol, SsoProviderRegistry,
    StepUpChallenge, TeeProviderConfig, TeeProviderRegistry, TrustedAuthenticationSource,
    WebAuthnAssertion, WebAuthnRequestOptions, build_scim_sync_plan, detect_config_drift,
    enforce_separation_of_duties, generate_integration_api_key_secret, issue_access_token,
    issue_refresh_token, parse_access_token, refresh_token_fingerprint, rotate_refresh_token,
};
use sdqp_tenant_isolation::{
    IsolationError, ProjectContext, ProjectLifecycle, ProjectObjectNamespace, ProjectState,
    TenantContext, TenantIsolationGuard,
};
use serde::{Deserialize, Serialize};
use tracing::Instrument;

pub use phase2::{
    ActiveGrantResponse, AdapterHealthResponse, AdapterRegistrationRequest, CancelTaskResponse,
    PermissionApplicationRequest, QueryPriorityLevel, QueryPriorityResponse,
    QueryRuntimeControlSurface, QuerySubmitRequest, QuerySubmitResponse, QueryTaskStatusResponse,
    QueryWorkbenchRuntimeState, SnapshotMetadataResponse,
};
pub use phase4::{
    AnalysisResponseFormat, AnalysisTemplateConfig, AnalysisTemplateDeleteResponse,
    AnalysisTemplateListResponse, AnalysisTemplateResponse, AnalysisTemplateUpsertRequest,
    AnalysisTemplateVisibility, DrilldownRequest, FieldDisplayPolicyResponse,
    PivotAnalysisArrowMetadata, PivotAnalysisRequest, PivotAnalysisResponse, PivotBucketResponse,
    PivotMetricKind, SnapshotPageArrowMetadata, SnapshotPageResponse,
};
pub use phase5::{
    BatchScanDocumentRequest, BatchScanDocumentResponse, BatchScanRequest, BatchScanResponse,
    DlpDetectionSummaryResponse, DlpInspectionContextRequest, DlpPolicyDecisionResponse,
    DlpPolicyEvaluateRequest, DlpPolicyEvaluateResponse, DlpProviderConfigRequest, DlpRequestScope,
    EvidenceExportRequest, EvidenceExportResponse, ExportDownloadAuthorizationRequest,
    ExportDownloadAuthorizationResponse, WatermarkDetectRequest, WatermarkDetectResponse,
    WatermarkMatchResponse, WatermarkVerifyRequest, WatermarkVerifyResponse,
};
pub use phase6::{
    UebaAlertResponse, UebaAlertsResponse, UebaBaselinesResponse, UebaCalibrationRequest,
    UebaCalibrationResultResponse, UebaCalibrationRunResponse, UebaEntityBaselineResponse,
    UebaGovernanceRuleResponse, UebaReplayRequest, UebaReplayRunResponse,
    UebaReplaySummaryResponse, UebaRuleCreateRequest, UebaRuleTuneRequest, UebaRulesResponse,
    UebaTuningProposalApplyRequest, UebaTuningProposalApplyResponse, UebaTuningProposalRequest,
    UebaTuningProposalResponse, UebaUserBaselineResponse,
};
pub use phase7::{AuditEventResponse, AuditSearchResponse};
pub use phase8::{
    KeyRotationAttemptResponse, KeyRotationRunRequest, KeyRotationRunResponse,
    KeyRotationStateResponse, KeyRotationStatesResponse, SnapshotLifecycleResponse,
    SnapshotRefreshResponse,
};
pub use phase9::{
    ClassificationCatalogEntryResponse, ClassificationCatalogResponse,
    ClassificationPoliciesResponse, ClassificationPolicyResponse,
    ClassificationRuleVersionResponse, ClassificationRuleVersionsResponse,
    ConfirmClassificationRequest, CreateClassificationRuleVersionRequest, RegulationResponse,
    RetentionPolicyResponse,
};
pub use stage7_governance::{
    ApprovalCallbackRequest, ApprovalCallbackResponse, ApprovalTaskResponse, ApprovalTasksResponse,
    ApproverResolutionRequest, ApproverResolutionResponse, AuditPermissionTransitionRequest,
    AuditPermissionTransitionResponse, FeishuHrRuntimeResponse, HrEventRequest, HrEventResponse,
    LdapHrRuntimeResponse, PermissionGrantRecordResponse, PermissionGrantsResponse,
    PermissionLifecycleTransitionResponse, SapSuccessFactorsHrRuntimeResponse,
    WorkdayHrRuntimeResponse,
};

const API_TOKEN_SECRET: &str = "sdqp-phase1-dev-secret";

pub struct ApiState {
    settings: ApiSettings,
    identity_provider: IdentityProviderSettings,
    integrations: IntegrationSettings,
    ueba: UebaSettings,
    users: Arc<Mutex<HashMap<String, UserAccount>>>,
    scim_groups: Arc<Mutex<HashMap<String, ScimGroup>>>,
    projects: Arc<Mutex<HashMap<String, ProjectContext>>>,
    sessions: Arc<Mutex<SessionRegistry>>,
    audit: Arc<Mutex<AuditTrail>>,
    controlled_deletions: Arc<Mutex<HashMap<String, ControlledDeletionRecord>>>,
    permissions: Arc<Mutex<sdqp_permission_engine::PermissionRegistry>>,
    tasks: Arc<Mutex<sdqp_datasource_adapter::QueryTaskRegistry>>,
    snapshots: Arc<Mutex<sdqp_encryption::InMemorySnapshotStore>>,
    snapshot_objects: Arc<dyn sdqp_encryption::SnapshotObjectStore>,
    cache_index: Arc<Mutex<HashMap<String, String>>>,
    task_scope: Arc<Mutex<HashMap<String, phase2::TaskScope>>>,
    query_runtime: Arc<Mutex<HashMap<String, phase2::QueryWorkbenchRuntimeState>>>,
    adapter_scheduler: sdqp_datasource_adapter::AdapterLifecycleScheduler,
    cipher: Arc<dyn sdqp_encryption::EnvelopeCipher>,
    pipeline: sdqp_encryption::DecryptionPipelineConfig,
    snapshot_bucket: String,
    rotation_policy: sdqp_encryption::RotationPolicy,
    key_rotation: KmsRotationSettings,
    key_rotation_states: Arc<Mutex<HashMap<String, sdqp_encryption::KeyRotationState>>>,
    runtime_config: Arc<Mutex<HashMap<String, String>>>,
    dlp_policy: dlp::DlpPolicyProviderRegistry,
    export_tasks: Arc<Mutex<HashMap<String, phase5::ExportTaskRecord>>>,
    download_tokens: Arc<Mutex<HashMap<String, phase5::DownloadAuthorizationRecord>>>,
    analysis_templates: Arc<Mutex<HashMap<String, phase4::AnalysisTemplateRecord>>>,
    ueba_governance: Arc<Mutex<phase6::UebaGovernanceRuntime>>,
    metrics: Arc<HttpMetrics>,
    kafka: KafkaSettings,
    audit_signers: CheckpointSignerRegistry,
    audit_forwarder: AuditForwarderRegistry,
    audit_retention: AuditRetentionConfig,
    audit_retention_running: AtomicBool,
    sso: SsoProviderRegistry,
    scim: ScimDirectoryRegistry,
    scim_cursor: Arc<Mutex<Option<ScimSyncCursor>>>,
    mfa: MfaProviderRegistry,
    device_posture: MockDevicePostureCollector,
    risk: ContinuousAccessEvaluator,
    integration_security: Arc<Mutex<IntegrationSecurityPolicy>>,
    integration_rate_limiter: Arc<IntegrationRateLimiter>,
    credential_rotation: CredentialRotationSettings,
    credential_rotation_states: Arc<Mutex<HashMap<String, CredentialRotationState>>>,
    tee: TeeProviderRegistry,
    persistence: Option<Arc<persistence::ApiPersistence>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserAccount {
    username: String,
    display_name: String,
    email: String,
    password: String,
    user_id: String,
    tenant_id: String,
    external_id: Option<String>,
    active: bool,
    auth_source: TrustedAuthenticationSource,
    roles: Vec<Role>,
    mfa_method: MfaMethod,
    #[serde(default)]
    mfa_registration: Option<MfaRegistration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingSession {
    account: UserAccount,
    binding: SessionBinding,
    challenge: MfaChallenge,
    auth_source: TrustedAuthenticationSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActiveSession {
    claims: SessionClaims,
    refresh_token: String,
    previous_refresh_token_fingerprint: Option<String>,
    roles: Vec<Role>,
    mfa_method: MfaMethod,
    auth_source: TrustedAuthenticationSource,
    risk_score: u8,
    device_posture: Option<DevicePostureReport>,
    revoked: bool,
    step_up_required: bool,
    step_up_challenge: Option<StepUpChallenge>,
}

#[derive(Debug, Default)]
struct SessionRegistry {
    pending: HashMap<String, PendingSession>,
    active: HashMap<String, ActiveSession>,
}

struct ApiRuntimeConfig {
    settings: ApiSettings,
    identity_provider: IdentityProviderSettings,
    integrations: IntegrationSettings,
    ueba: UebaSettings,
    audit_settings: AuditSettings,
    security: SecuritySettings,
    kms_rotation: KmsRotationSettings,
    kafka: KafkaSettings,
    snapshot_bucket: String,
    snapshot_objects: Arc<dyn sdqp_encryption::SnapshotObjectStore>,
}

struct ApiRuntimeState {
    users: HashMap<String, UserAccount>,
    scim_groups: HashMap<String, ScimGroup>,
    projects: HashMap<String, ProjectContext>,
    sessions: SessionRegistry,
    audit: AuditTrail,
    runtime: phase2::QueryRuntime,
    runtime_config: HashMap<String, String>,
    query_runtime: HashMap<String, phase2::QueryWorkbenchRuntimeState>,
    analysis_templates: HashMap<String, phase4::AnalysisTemplateRecord>,
    scim_cursor: Option<ScimSyncCursor>,
    credential_rotation_states: HashMap<String, CredentialRotationState>,
    key_rotation_states: HashMap<String, sdqp_encryption::KeyRotationState>,
    persistence: Option<Arc<persistence::ApiPersistence>>,
}

#[derive(Debug, Clone)]
struct AuthenticatedSession {
    claims: SessionClaims,
    roles: Vec<Role>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub device_fingerprint: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub pending_session_id: String,
    pub mfa_required: bool,
    pub method: String,
    pub challenge_id: Option<String>,
    pub challenge: Option<MfaChallengeResponse>,
    pub auth_source: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    pub pending_session_id: String,
    pub code: Option<String>,
    pub webauthn_assertion: Option<WebAuthnAssertion>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPairResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct SsoStartRequest {
    pub protocol: String,
    pub login_hint: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SsoStartResponse {
    pub authorization_url: String,
    pub relay_state: String,
    pub mock_code: String,
}

#[derive(Debug, Deserialize)]
pub struct SsoCallbackRequest {
    pub protocol: String,
    pub code: String,
    pub device_fingerprint: String,
}

#[derive(Debug, Deserialize)]
pub struct DevicePostureRequest {
    pub refresh_token: String,
    pub profile: Option<String>,
    pub ip_drift: bool,
    pub impossible_travel: bool,
    pub exfiltration_hint: bool,
    pub query_burst: Option<usize>,
    pub denied_burst: Option<usize>,
    pub export_burst: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebAuthnRequestResponse {
    pub challenge: String,
    pub rp_id: String,
    pub origin: String,
    pub credential_id: String,
    pub timeout_ms: u64,
    pub user_verification: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaChallengeResponse {
    pub challenge_id: String,
    pub method: String,
    pub reason: Option<String>,
    pub expires_at: DateTime<chrono::Utc>,
    pub webauthn_request: Option<WebAuthnRequestResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DevicePostureResponse {
    pub risk_score: u8,
    pub action: String,
    pub compliant: bool,
    pub reasons: Vec<String>,
    pub step_up_required: bool,
    pub step_up_challenge: Option<MfaChallengeResponse>,
    pub session_revoked: bool,
}

#[derive(Debug, Deserialize)]
pub struct StepUpVerifyRequest {
    pub refresh_token: String,
    pub code: Option<String>,
    pub webauthn_assertion: Option<WebAuthnAssertion>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogoutResponse {
    pub revoked: bool,
}

#[derive(Debug, Deserialize)]
pub struct ScimProviderSyncRequest {
    #[serde(default)]
    pub dry_run: bool,
    pub disable_missing_users: Option<bool>,
    pub disable_missing_groups: Option<bool>,
    pub delete_missing_users: Option<bool>,
    pub delete_missing_groups: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScimProviderSyncResponse {
    pub provider: String,
    pub dry_run: bool,
    pub summary: ScimSyncSummary,
    pub cursor: ScimSyncCursor,
    pub user_patches: usize,
    pub group_patches: usize,
    pub membership_changes: Vec<ScimMembershipChange>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CredentialRotationRunRequest {
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub credential_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialRotationStateResponse {
    pub credential_id: String,
    pub kind: String,
    pub status: String,
    pub last_rotated_at: Option<DateTime<chrono::Utc>>,
    pub next_rotation_due_at: DateTime<chrono::Utc>,
    pub last_attempt_at: Option<DateTime<chrono::Utc>>,
    pub attempts: u32,
    pub active_version: Option<String>,
    pub last_error: Option<String>,
    pub manual_intervention_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialRotationStatesResponse {
    pub states: Vec<CredentialRotationStateResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialRotationAttemptResponse {
    pub credential_id: String,
    pub kind: String,
    pub status: String,
    pub rotated: bool,
    pub repo_local_automation: bool,
    pub retryable: bool,
    pub manual_intervention_required: bool,
    pub new_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_secret: Option<String>,
    pub next_rotation_due_at: DateTime<chrono::Utc>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialRotationRunResponse {
    pub evaluated: usize,
    pub rotated: usize,
    pub failed: usize,
    pub manual_intervention: usize,
    pub skipped: usize,
    pub audit_checkpoint_id: String,
    pub results: Vec<CredentialRotationAttemptResponse>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigChangeRequest {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigChangeResponse {
    pub accepted: bool,
    pub version_id: String,
    pub checkpoint_id: String,
    pub audit_events: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigDriftEntryResponse {
    pub key: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigDriftResponse {
    pub drifts: Vec<ConfigDriftEntryResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectSummaryResponse {
    pub project_id: String,
    pub tenant_id: String,
    pub state: String,
    pub object_bucket: String,
    pub object_prefix: String,
    pub can_accept_new_permissions: bool,
    pub can_export: bool,
    pub read_only: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectsListResponse {
    pub projects: Vec<ProjectSummaryResponse>,
}

#[derive(Debug, Deserialize)]
pub struct ProjectCreateRequest {
    pub project_id: String,
    pub initial_state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectCreateResponse {
    pub project: ProjectSummaryResponse,
    pub checkpoint_id: String,
    pub runtime_created: bool,
}

#[derive(Debug, Deserialize)]
pub struct ProjectStateChangeRequest {
    pub next_state: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectStateChangeResponse {
    pub project_id: String,
    pub previous_state: String,
    pub current_state: String,
    pub revoked_permissions: usize,
    pub deleted_snapshots: usize,
    pub deleted_objects: usize,
    pub checkpoint_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectDeleteResponse {
    pub project_id: String,
    pub previous_state: String,
    pub current_state: String,
    pub object_bucket: String,
    pub object_prefix: String,
    pub revoked_permissions: usize,
    pub deleted_snapshots: usize,
    pub deleted_objects: usize,
    pub checkpoint_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectAccessResponse {
    pub scope_key: String,
    pub project_state: String,
    pub audit_chain_valid: bool,
    pub audit_events: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    step_up_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    step_up_challenge: Option<MfaChallengeResponse>,
}

pub(crate) type ApiErrorResponse = Box<Response>;

impl ApiState {
    fn new(settings: ApiSettings) -> Self {
        let mut app_settings = AppSettings::local_dev();
        app_settings.api = settings;
        Self::from_app_settings(app_settings)
    }

    fn from_app_settings(app_settings: AppSettings) -> Self {
        let runtime = phase2::build_query_runtime(&app_settings);
        let identity_provider = app_settings.identity_provider.clone();
        let api_settings = app_settings.api.clone();
        let integrations = app_settings.integrations.clone();
        let ueba = app_settings.ueba.clone();
        let audit_settings = app_settings.audit.clone();
        let security = app_settings.security.clone();
        let kafka = app_settings.kafka.clone();
        let snapshot_bucket = app_settings.object_store.bucket_snapshots.clone();
        let kms_rotation = app_settings.kms.rotation.clone();
        let runtime_config = build_runtime_config(&app_settings);
        Self::from_runtime(
            ApiRuntimeConfig {
                settings: api_settings,
                identity_provider,
                integrations,
                ueba,
                audit_settings,
                security: security.clone(),
                kms_rotation,
                kafka,
                snapshot_bucket,
                snapshot_objects: Arc::new(sdqp_encryption::InMemorySnapshotObjectStore::default()),
            },
            ApiRuntimeState {
                users: build_user_directory(&security),
                scim_groups: HashMap::new(),
                projects: build_project_registry(),
                sessions: SessionRegistry::default(),
                audit: AuditTrail::default(),
                runtime,
                runtime_config,
                query_runtime: HashMap::new(),
                analysis_templates: HashMap::new(),
                scim_cursor: None,
                credential_rotation_states: HashMap::new(),
                key_rotation_states: HashMap::new(),
                persistence: None,
            },
        )
    }

    async fn new_persistent(settings: AppSettings) -> Result<Self, persistence::PersistenceError> {
        let persistence = persistence::ApiPersistence::initialize(&settings).await?;
        let runtime_config = build_runtime_config(&settings)
            .into_iter()
            .chain(persistence.load_runtime_config().await?)
            .collect();
        let mut runtime = phase2::build_query_runtime(&settings);
        runtime.0 = stage7_governance::load_permission_registry(persistence.as_ref()).await?;
        for (scope, snapshot) in persistence.load_query_tasks().await? {
            runtime.4.insert(snapshot.task_id.clone(), scope);
            runtime.1.restore_task(snapshot);
        }
        let query_runtime = persistence.load_query_workbench_runtime_states().await?;
        for snapshot in persistence.load_snapshots().await? {
            runtime.2.restore_record(snapshot);
        }
        runtime.3.extend(persistence.load_cache_index().await?);
        let api_settings = settings.api.clone();
        let identity_provider = settings.identity_provider.clone();
        let integrations = settings.integrations.clone();
        let ueba = settings.ueba.clone();
        let audit_settings = settings.audit.clone();
        let kms_rotation = settings.kms.rotation.clone();
        let mut security = settings.security.clone();
        let persisted_integration_api_keys = persistence.load_integration_api_keys().await?;
        if !persisted_integration_api_keys.is_empty() {
            security.integration_api_keys = persisted_integration_api_keys
                .into_iter()
                .map(|key| SecurityApiKeySettings {
                    key_id: key.key_id,
                    secret: key.secret,
                    scopes: key.scopes,
                    allowed_ips: key.allowed_ips,
                })
                .collect();
        }
        let kafka = settings.kafka.clone();
        let snapshot_bucket = settings.object_store.bucket_snapshots.clone();
        let object_store_endpoint = settings.object_store.endpoint.clone();
        let object_store_region = settings.object_store.region.clone();
        let object_store_access_key = settings.object_store.access_key.clone();
        let object_store_secret_key = settings.object_store.secret_key.clone();
        let scim_cursor = persistence
            .load_scim_sync_cursor(&identity_provider.scim_provider)
            .await?;

        Ok(Self::from_runtime(
            ApiRuntimeConfig {
                settings: api_settings,
                identity_provider,
                integrations,
                ueba,
                audit_settings,
                security: security.clone(),
                kms_rotation,
                kafka,
                snapshot_bucket,
                snapshot_objects: Arc::new(sdqp_encryption::S3CompatibleObjectStore::new(
                    object_store_endpoint,
                    object_store_region,
                    object_store_access_key,
                    object_store_secret_key,
                )),
            },
            ApiRuntimeState {
                users: hydrate_user_directory(persistence.load_users().await?, &security),
                scim_groups: persistence.load_scim_groups().await?,
                projects: persistence.load_projects().await?,
                sessions: persistence.load_sessions().await?,
                audit: persistence.load_audit_trail().await?,
                runtime,
                runtime_config,
                query_runtime,
                analysis_templates: persistence.load_analysis_templates().await?,
                scim_cursor,
                credential_rotation_states: persistence.load_credential_rotation_states().await?,
                key_rotation_states: persistence.load_key_rotation_states().await?,
                persistence: Some(persistence),
            },
        ))
    }

    fn from_runtime(config: ApiRuntimeConfig, runtime_state: ApiRuntimeState) -> Self {
        let ApiRuntimeConfig {
            settings,
            identity_provider,
            integrations,
            ueba,
            audit_settings,
            security,
            kms_rotation,
            kafka,
            snapshot_bucket,
            snapshot_objects,
        } = config;
        let ApiRuntimeState {
            users,
            scim_groups,
            projects,
            sessions,
            audit: audit_trail,
            runtime,
            runtime_config,
            query_runtime,
            analysis_templates,
            scim_cursor,
            credential_rotation_states,
            key_rotation_states,
            persistence,
        } = runtime_state;
        let projects = projects
            .into_iter()
            .map(|(project_id, project)| {
                (
                    project_id,
                    project.with_object_bucket(snapshot_bucket.clone()),
                )
            })
            .collect::<HashMap<_, _>>();

        let (
            permissions,
            tasks,
            snapshots,
            cache_index,
            task_scope,
            adapter_scheduler,
            _adapter_registry,
            cipher,
            pipeline,
        ) = runtime;
        let dlp_policy = dlp::DlpPolicyProviderRegistry::from_settings(&integrations.dlp);

        Self {
            settings,
            identity_provider: identity_provider.clone(),
            integrations,
            ueba,
            users: Arc::new(Mutex::new(users)),
            scim_groups: Arc::new(Mutex::new(scim_groups)),
            projects: Arc::new(Mutex::new(projects)),
            sessions: Arc::new(Mutex::new(sessions)),
            audit: Arc::new(Mutex::new(audit_trail)),
            controlled_deletions: Arc::new(Mutex::new(HashMap::new())),
            permissions: Arc::new(Mutex::new(permissions)),
            tasks: Arc::new(Mutex::new(tasks)),
            snapshots: Arc::new(Mutex::new(snapshots)),
            snapshot_objects,
            cache_index: Arc::new(Mutex::new(cache_index)),
            task_scope: Arc::new(Mutex::new(task_scope)),
            query_runtime: Arc::new(Mutex::new(query_runtime)),
            adapter_scheduler,
            cipher,
            pipeline,
            snapshot_bucket,
            rotation_policy: sdqp_encryption::RotationPolicy {
                dek_rotation_days: kms_rotation.dek_rotation_days,
                kek_rotation_days: kms_rotation.kek_rotation_days,
            },
            key_rotation: kms_rotation,
            key_rotation_states: Arc::new(Mutex::new(key_rotation_states)),
            runtime_config: Arc::new(Mutex::new(runtime_config)),
            dlp_policy,
            export_tasks: Arc::new(Mutex::new(HashMap::new())),
            download_tokens: Arc::new(Mutex::new(HashMap::new())),
            analysis_templates: Arc::new(Mutex::new(analysis_templates)),
            ueba_governance: Arc::new(Mutex::new(phase6::UebaGovernanceRuntime::default())),
            metrics: Arc::new(HttpMetrics::default()),
            kafka,
            audit_signers: build_checkpoint_signers(&audit_settings),
            audit_forwarder: build_audit_forwarder(&audit_settings),
            audit_retention: build_audit_retention_config(&audit_settings),
            audit_retention_running: AtomicBool::new(false),
            sso: build_sso_registry(&identity_provider),
            scim: build_scim_registry(&identity_provider),
            scim_cursor: Arc::new(Mutex::new(scim_cursor)),
            mfa: build_mfa_registry(&security),
            device_posture: MockDevicePostureCollector,
            risk: ContinuousAccessEvaluator,
            integration_security: Arc::new(Mutex::new(build_integration_security_policy(
                &security,
            ))),
            integration_rate_limiter: Arc::new(IntegrationRateLimiter::new(
                build_rate_limit_policy(&security),
            )),
            credential_rotation: security.credential_rotation.clone(),
            credential_rotation_states: Arc::new(Mutex::new(credential_rotation_states)),
            tee: build_tee_registry(&security),
            persistence,
        }
    }

    pub(crate) fn use_external_query_worker(&self) -> bool {
        self.settings.external_query_worker && self.persistence.is_some()
    }
}

pub fn build_router(settings: ApiSettings) -> Router {
    let state = Arc::new(ApiState::new(settings));
    build_router_from_state(state)
}

pub fn build_router_with_settings(settings: AppSettings) -> Router {
    let state = Arc::new(ApiState::from_app_settings(settings));
    build_router_from_state(state)
}

pub async fn build_persistent_router(
    settings: AppSettings,
) -> Result<Router, persistence::PersistenceError> {
    let state = Arc::new(ApiState::new_persistent(settings).await?);
    if state.use_external_query_worker() {
        phase2::spawn_persistent_task_sync(state.clone());
    }
    if state.persistence.is_some() {
        stage7_governance::spawn_governance_runtime(state.clone());
        stage11_ueba::spawn_ueba_runtime(state.clone());
        spawn_credential_rotation_runtime(state.clone());
        phase8::spawn_key_rotation_runtime(state.clone());
        tokio::spawn(run_audit_retention(state.clone()));
    }
    Ok(build_router_from_state(state))
}

fn build_router_from_state(state: Arc<ApiState>) -> Router {
    let protected_project = Router::new()
        .route("/project-context", get(project_context_handler))
        .route(
            "/permissions/applications",
            post(phase2::permission_application_handler),
        )
        .route(
            "/permissions/grants/active/{data_source_id}",
            get(phase2::active_grant_handler),
        )
        .route(
            "/datasources/adapters",
            post(phase2::register_adapter_handler),
        )
        .route(
            "/datasources/adapters/health",
            get(phase2::adapter_health_handler),
        )
        .route(
            "/datasources/adapters/{data_source_id}/start",
            post(phase2::start_adapter_handler),
        )
        .route(
            "/datasources/adapters/{data_source_id}/stop",
            post(phase2::stop_adapter_handler),
        )
        .route(
            "/permissions/grants",
            get(stage7_governance::permission_grants_handler),
        )
        .route(
            "/approvals/tasks",
            get(stage7_governance::approval_tasks_handler),
        )
        .route(
            "/approvals/callback",
            post(stage7_governance::approval_callback_handler),
        )
        .route(
            "/approvals/approver-resolution",
            post(stage7_governance::approver_resolution_handler),
        )
        .route("/queries", post(phase2::submit_query_handler))
        .route("/tasks/{task_id}/status", get(phase2::task_status_handler))
        .route(
            "/tasks/{task_id}/cancel",
            delete(phase2::cancel_task_handler),
        )
        .route("/tasks/{task_id}/ws", get(phase2::task_stream_handler))
        .route(
            "/snapshots/{snapshot_id}/metadata",
            get(phase2::snapshot_metadata_handler),
        )
        .route(
            "/snapshots/{snapshot_id}/page",
            get(phase4::snapshot_page_handler),
        )
        .route(
            "/snapshots/{snapshot_id}/delete",
            post(phase8::soft_delete_snapshot_handler),
        )
        .route(
            "/snapshots/{snapshot_id}/restore",
            post(phase8::restore_snapshot_handler),
        )
        .route(
            "/snapshots/{snapshot_id}/refresh",
            post(phase8::refresh_snapshot_handler),
        )
        .route(
            "/snapshots/{snapshot_id}/tombstone",
            get(phase8::snapshot_tombstone_handler),
        )
        .route(
            "/snapshots/{snapshot_id}",
            delete(phase8::purge_snapshot_handler),
        )
        .route(
            "/classification/policies/{data_source_id}",
            get(phase9::list_classification_policies_handler),
        )
        .route(
            "/classification/policies/{data_source_id}/confirm",
            post(phase9::confirm_classification_policies_handler),
        )
        .route(
            "/classification/catalog/{data_source_id}",
            get(phase9::list_classification_catalog_handler),
        )
        .route(
            "/classification/rule-versions/{data_source_id}",
            get(phase9::list_classification_rule_versions_handler)
                .post(phase9::create_classification_rule_version_handler),
        )
        .route(
            "/classification/rule-versions/{data_source_id}/{rule_version_id}/activate",
            post(phase9::activate_classification_rule_version_handler),
        )
        .route(
            "/classification/rule-versions/{data_source_id}/{rule_version_id}/retire",
            post(phase9::retire_classification_rule_version_handler),
        )
        .route("/analysis/pivot", post(phase4::pivot_analysis_handler))
        .route(
            "/analysis/pivot/drilldown",
            post(phase4::pivot_drilldown_handler),
        )
        .route(
            "/analysis/templates",
            get(phase4::list_analysis_templates_handler)
                .post(phase4::create_analysis_template_handler),
        )
        .route(
            "/analysis/templates/{template_id}",
            get(phase4::get_analysis_template_handler)
                .put(phase4::update_analysis_template_handler)
                .delete(phase4::delete_analysis_template_handler),
        )
        .route(
            "/analysis/templates/{template_id}/publish",
            post(phase4::publish_analysis_template_handler),
        )
        .route(
            "/analysis/templates/{template_id}/unpublish",
            post(phase4::unpublish_analysis_template_handler),
        )
        .route("/exports/evidence", post(phase5::export_evidence_handler))
        .route(
            "/exports/tasks/{task_id}",
            get(phase5::export_task_status_handler),
        )
        .route(
            "/exports/tasks/{task_id}/refresh-anchor",
            post(phase5::refresh_export_anchor_handler),
        )
        .route(
            "/exports/tasks/{task_id}/authorize-download",
            post(phase5::authorize_export_download_handler),
        )
        .route(
            "/exports/download/{download_token}",
            get(phase5::download_export_handler),
        )
        .route("/watermarks/detect", post(phase5::watermark_detect_handler))
        .route("/watermarks/verify", post(phase5::watermark_verify_handler))
        .route(
            "/watermarks/batch_scan",
            post(phase5::watermark_batch_scan_handler),
        )
        .route(
            "/watermarks/dlp/evaluate",
            post(phase5::watermark_dlp_evaluate_handler),
        )
        .route("/audit/events/search", get(phase7::audit_search_handler))
        .route("/ueba/alerts", get(phase6::ueba_alerts_handler))
        .route("/ueba/baselines", get(phase6::ueba_baselines_handler))
        .route(
            "/ueba/rules",
            get(phase6::ueba_rules_handler).post(phase6::create_ueba_rule_handler),
        )
        .route(
            "/ueba/rules/{rule_version_id}/activate",
            post(phase6::activate_ueba_rule_handler),
        )
        .route(
            "/ueba/rules/{rule_version_id}/enable",
            post(phase6::enable_ueba_rule_handler),
        )
        .route(
            "/ueba/rules/{rule_version_id}/disable",
            post(phase6::disable_ueba_rule_handler),
        )
        .route(
            "/ueba/rules/{rule_version_id}/retire",
            post(phase6::retire_ueba_rule_handler),
        )
        .route(
            "/ueba/rules/{rule_version_id}/tune",
            post(phase6::tune_ueba_rule_handler),
        )
        .route("/ueba/replays", post(phase6::create_ueba_replay_handler))
        .route(
            "/ueba/replays/{run_id}",
            get(phase6::get_ueba_replay_handler),
        )
        .route(
            "/ueba/tuning/proposals",
            post(phase6::create_ueba_tuning_proposal_handler),
        )
        .route(
            "/ueba/tuning/proposals/{proposal_id}/apply",
            post(phase6::apply_ueba_tuning_proposal_handler),
        )
        .route(
            "/ueba/calibrations",
            post(phase6::create_ueba_calibration_handler),
        )
        .route(
            "/ueba/calibrations/{calibration_id}",
            get(phase6::get_ueba_calibration_handler),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            tee_attestation_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            project_context_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            tenant_context_middleware,
        ));

    let protected_tenant = Router::new()
        .route(
            "/projects",
            get(projects_list_handler).post(project_create_handler),
        )
        .route(
            "/projects/{project_id}/state",
            post(project_state_change_handler),
        )
        .route("/projects/{project_id}", delete(project_delete_handler))
        .route("/admin/config-drift", get(config_drift_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            tenant_context_middleware,
        ));

    let protected_admin = Router::new()
        .route("/admin/config-change", post(config_change_handler))
        .route(
            "/admin/credential-rotations",
            get(credential_rotation_states_handler),
        )
        .route(
            "/admin/credential-rotations/run",
            post(credential_rotation_run_handler),
        )
        .route(
            "/admin/key-rotations",
            get(phase8::key_rotation_states_handler),
        )
        .route(
            "/admin/key-rotations/run",
            post(phase8::key_rotation_run_handler),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            tenant_context_middleware,
        ));

    let integration_public = Router::new()
        .route("/auth/scim/sync", post(scim_provider_sync_handler))
        .route("/auth/scim/users", post(scim_user_sync_handler))
        .route("/auth/scim/groups", post(scim_group_sync_handler))
        .route(
            "/integrations/hr/events",
            post(stage7_governance::hr_event_handler),
        )
        .route(
            "/integrations/hr/feishu/snapshot",
            post(stage7_governance::feishu_snapshot_sync_handler),
        )
        .route(
            "/integrations/hr/feishu/poll",
            post(stage7_governance::feishu_event_poll_handler),
        )
        .route(
            "/integrations/hr/feishu/webhook",
            post(stage7_governance::feishu_webhook_handler),
        )
        .route(
            "/integrations/hr/workday/snapshot",
            post(stage7_governance::workday_snapshot_sync_handler),
        )
        .route(
            "/integrations/hr/workday/poll",
            post(stage7_governance::workday_event_poll_handler),
        )
        .route(
            "/integrations/hr/workday/webhook",
            post(stage7_governance::workday_webhook_handler),
        )
        .route(
            "/integrations/hr/sap-successfactors/snapshot",
            post(stage7_governance::sap_successfactors_snapshot_sync_handler),
        )
        .route(
            "/integrations/hr/sap-successfactors/poll",
            post(stage7_governance::sap_successfactors_event_poll_handler),
        )
        .route(
            "/integrations/hr/sap-successfactors/webhook",
            post(stage7_governance::sap_successfactors_webhook_handler),
        )
        .route(
            "/integrations/hr/ldap/snapshot",
            post(stage7_governance::ldap_snapshot_sync_handler),
        )
        .route(
            "/integrations/hr/ldap/poll",
            post(stage7_governance::ldap_incremental_poll_handler),
        )
        .route(
            "/integrations/audit/permission-transitions",
            post(stage7_governance::audit_permission_transition_handler),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            integration_security_middleware,
        ));

    Router::new()
        .route("/healthz", get(health_handler))
        .route("/readyz", get(ready_handler))
        .route("/metrics", get(metrics_handler))
        .route("/auth/login", post(login_handler))
        .route("/auth/sso/start", post(sso_start_handler))
        .route("/auth/sso/callback", post(sso_callback_handler))
        .route("/auth/mfa/verify", post(mfa_verify_handler))
        .route("/auth/device-posture", post(device_posture_handler))
        .route("/auth/step-up/verify", post(step_up_verify_handler))
        .route("/auth/refresh", post(refresh_handler))
        .route("/auth/logout", post(logout_handler))
        .merge(integration_public)
        .nest(
            "/v1",
            protected_project
                .merge(protected_tenant)
                .merge(protected_admin),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            request_observability_middleware,
        ))
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(state)
}

pub fn health_payload(settings: &ApiSettings) -> ServiceHealth {
    ServiceHealth::ready(settings.service_name.clone(), PHASE0_MILESTONE)
}

pub async fn run(settings: AppSettings) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", settings.api.host, settings.api.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("sdqp-api listening on {}", addr);
    axum::serve(listener, build_persistent_router(settings).await?).await?;
    Ok(())
}

async fn health_handler(State(state): State<Arc<ApiState>>) -> Json<ServiceHealth> {
    Json(health_payload(&state.settings))
}

async fn ready_handler(State(state): State<Arc<ApiState>>) -> Json<ServiceHealth> {
    Json(health_payload(&state.settings))
}

async fn metrics_handler(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state
            .metrics
            .render_prometheus(&state.settings.service_name),
    )
}

async fn login_handler(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Response {
    let Some(account) = lookup_user_by_username(&state, &payload.username) else {
        append_login_audit(
            &state,
            "anonymous",
            "anonymous",
            ActionResult::Denied,
            "unknown user",
        )
        .await;
        return json_error(StatusCode::UNAUTHORIZED, "invalid credentials");
    };

    if !account.active {
        append_login_audit(
            &state,
            &account.user_id,
            &account.tenant_id,
            ActionResult::Denied,
            "inactive account",
        )
        .await;
        return json_error(StatusCode::FORBIDDEN, "account disabled");
    }

    if account.auth_source != TrustedAuthenticationSource::LocalPassword {
        append_login_audit(
            &state,
            &account.user_id,
            &account.tenant_id,
            ActionResult::Denied,
            "account requires sso login",
        )
        .await;
        return json_error(StatusCode::FORBIDDEN, "account requires sso login");
    }

    if account.password != payload.password {
        append_login_audit(
            &state,
            &account.user_id,
            &account.tenant_id,
            ActionResult::Denied,
            "invalid password",
        )
        .await;
        return json_error(StatusCode::UNAUTHORIZED, "invalid credentials");
    }

    if enforce_separation_of_duties(&account.roles).is_err() {
        append_login_audit(
            &state,
            &account.user_id,
            &account.tenant_id,
            ActionResult::Denied,
            "role combination violates separation of duties",
        )
        .await;
        return json_error(
            StatusCode::FORBIDDEN,
            "role combination violates separation of duties",
        );
    }

    let pending_session_id = ulid::Ulid::new().to_string();
    let binding = SessionBinding {
        ip_address: extract_ip_address(&headers),
        device_fingerprint: payload.device_fingerprint,
    };
    let Some(registration) = account_mfa_registration(&account) else {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing mfa registration",
        );
    };
    let challenge = match state
        .mfa
        .begin_challenge(registration, Some("login authentication".into()))
    {
        Ok(challenge) => challenge,
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to issue mfa challenge",
            );
        }
    };

    state
        .sessions
        .lock()
        .expect("session registry")
        .pending
        .insert(
            pending_session_id.clone(),
            PendingSession {
                account: account.clone(),
                binding,
                challenge: challenge.clone(),
                auth_source: TrustedAuthenticationSource::LocalPassword,
            },
        );

    let pending = state
        .sessions
        .lock()
        .expect("session registry")
        .pending
        .get(&pending_session_id)
        .cloned()
        .expect("pending session");
    if let Some(persistence) = &state.persistence
        && persistence
            .save_pending_session(&pending_session_id, &pending)
            .await
            .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist pending session",
        );
    }

    append_login_audit(
        &state,
        &account.user_id,
        &account.tenant_id,
        ActionResult::Success,
        "login initiated via local password",
    )
    .await;

    Json(LoginResponse {
        pending_session_id,
        mfa_required: true,
        method: format!("{:?}", account.mfa_method).to_lowercase(),
        challenge_id: Some(challenge.challenge_id.clone()),
        challenge: Some(mfa_challenge_response(&challenge)),
        auth_source: Some("local_password".into()),
    })
    .into_response()
}

async fn sso_start_handler(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<SsoStartRequest>,
) -> Response {
    let protocol = match parse_sso_protocol(&payload.protocol) {
        Some(protocol) => protocol,
        None => return json_error(StatusCode::BAD_REQUEST, "unsupported sso protocol"),
    };

    let initiation = match state.sso.start_auth(
        protocol,
        &payload.login_hint,
        &state.identity_provider.redirect_url,
    ) {
        Ok(initiation) => initiation,
        Err(error) => return sso_error_response(error, false),
    };
    Json(SsoStartResponse {
        authorization_url: initiation.authorization_url,
        relay_state: initiation.relay_state,
        mock_code: initiation.mock_code,
    })
    .into_response()
}

async fn sso_callback_handler(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(payload): Json<SsoCallbackRequest>,
) -> Response {
    let protocol = match parse_sso_protocol(&payload.protocol) {
        Some(protocol) => protocol,
        None => return json_error(StatusCode::BAD_REQUEST, "unsupported sso protocol"),
    };
    let claims = match state
        .sso
        .exchange_code(
            protocol,
            &payload.code,
            &state.identity_provider.redirect_url,
        )
        .await
    {
        Ok(claims) => claims,
        Err(error) => return sso_error_response(error, true),
    };

    let account = match lookup_user_by_username(&state, &claims.username) {
        Some(existing) => existing,
        None => {
            let account = account_from_sso_claims(&claims, &state);
            if let Err(response) = upsert_user_account(&state, account.clone()).await {
                return response;
            }
            account
        }
    };

    if !account.active {
        return json_error(StatusCode::FORBIDDEN, "account disabled");
    }

    let pending_session_id = ulid::Ulid::new().to_string();
    let Some(registration) = account_mfa_registration(&account) else {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing mfa registration",
        );
    };
    let challenge = match state
        .mfa
        .begin_challenge(registration, Some("sso authentication".into()))
    {
        Ok(challenge) => challenge,
        Err(_) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to issue mfa challenge",
            );
        }
    };
    let binding = SessionBinding {
        ip_address: extract_ip_address(&headers),
        device_fingerprint: payload.device_fingerprint,
    };

    state
        .sessions
        .lock()
        .expect("session registry")
        .pending
        .insert(
            pending_session_id.clone(),
            PendingSession {
                account: account.clone(),
                binding,
                challenge: challenge.clone(),
                auth_source: claims.auth_source.clone(),
            },
        );

    let pending = state
        .sessions
        .lock()
        .expect("session registry")
        .pending
        .get(&pending_session_id)
        .cloned()
        .expect("pending session");
    if let Some(persistence) = &state.persistence
        && persistence
            .save_pending_session(&pending_session_id, &pending)
            .await
            .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist sso pending session",
        );
    }

    append_login_audit(
        &state,
        &account.user_id,
        &account.tenant_id,
        ActionResult::Success,
        &format!("sso callback initiated via {}", payload.protocol),
    )
    .await;

    Json(LoginResponse {
        pending_session_id,
        mfa_required: true,
        method: format!("{:?}", account.mfa_method).to_lowercase(),
        challenge_id: Some(challenge.challenge_id.clone()),
        challenge: Some(mfa_challenge_response(&challenge)),
        auth_source: Some(format!("{:?}", claims.auth_source).to_lowercase()),
    })
    .into_response()
}

async fn mfa_verify_handler(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<MfaVerifyRequest>,
) -> Response {
    let pending = state
        .sessions
        .lock()
        .expect("session registry")
        .pending
        .get(&payload.pending_session_id)
        .cloned();

    let Some(pending) = pending else {
        return json_error(StatusCode::NOT_FOUND, "pending session not found");
    };

    let Some(registration) = account_mfa_registration(&pending.account) else {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing mfa registration",
        );
    };
    if state
        .mfa
        .verify_challenge(
            registration,
            &pending.challenge,
            &MfaVerification {
                code: payload.code.clone(),
                webauthn_assertion: payload.webauthn_assertion.clone(),
            },
        )
        .is_err()
    {
        return json_error(StatusCode::UNAUTHORIZED, "invalid mfa proof");
    }

    let pending = {
        let mut sessions = state.sessions.lock().expect("session registry");
        sessions.pending.remove(&payload.pending_session_id)
    };

    let Some(pending) = pending else {
        return json_error(StatusCode::NOT_FOUND, "pending session not found");
    };
    if let Some(persistence) = &state.persistence
        && persistence
            .remove_pending_session(&payload.pending_session_id)
            .await
            .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to clear pending session",
        );
    }

    let request_context = RequestContext::new(
        TenantId::new(pending.account.tenant_id.clone()).expect("tenant id"),
        UserId::new(pending.account.user_id.clone()).expect("user id"),
    );
    let claims = SessionPolicy { ttl_minutes: 15 }.issue(&request_context, pending.binding);
    let refresh_token = issue_refresh_token();
    let access_token = match issue_access_token(&claims, API_TOKEN_SECRET) {
        Ok(token) => token,
        Err(_) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to issue token"),
    };

    state
        .sessions
        .lock()
        .expect("session registry")
        .active
        .insert(
            claims.session_id.clone(),
            ActiveSession {
                claims: claims.clone(),
                refresh_token: refresh_token.clone(),
                previous_refresh_token_fingerprint: None,
                roles: pending.account.roles.clone(),
                mfa_method: pending.account.mfa_method.clone(),
                auth_source: pending.auth_source,
                risk_score: 0,
                device_posture: None,
                revoked: false,
                step_up_required: false,
                step_up_challenge: None,
            },
        );
    if let Some(persistence) = &state.persistence {
        let active = state
            .sessions
            .lock()
            .expect("session registry")
            .active
            .get(&claims.session_id)
            .cloned()
            .expect("active session");
        if persistence.save_active_session(&active).await.is_err() {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist active session",
            );
        }
    }

    append_login_audit(
        &state,
        &pending.account.user_id,
        &pending.account.tenant_id,
        ActionResult::Success,
        "mfa verified",
    )
    .await;

    Json(TokenPairResponse {
        access_token,
        refresh_token,
        session_id: claims.session_id,
    })
    .into_response()
}

async fn device_posture_handler(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<DevicePostureRequest>,
) -> Response {
    let (updated_session, assessment) = match apply_device_posture_assessment(&state, &payload) {
        Some(result) => result,
        None => return json_error(StatusCode::UNAUTHORIZED, "refresh token not found"),
    };

    if let Some(persistence) = &state.persistence
        && persistence
            .save_active_session(&updated_session)
            .await
            .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist device posture state",
        );
    }

    Json(DevicePostureResponse {
        risk_score: assessment.score.score.round() as u8,
        action: format!("{:?}", assessment.score.recommended_action).to_lowercase(),
        compliant: updated_session
            .device_posture
            .as_ref()
            .map(|report| report.compliant)
            .unwrap_or(true),
        reasons: assessment.reasons,
        step_up_required: updated_session.step_up_required,
        step_up_challenge: updated_session
            .step_up_challenge
            .as_ref()
            .map(step_up_challenge_response),
        session_revoked: updated_session.revoked,
    })
    .into_response()
}

async fn step_up_verify_handler(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<StepUpVerifyRequest>,
) -> Response {
    let (session_id, active, access_token, new_refresh_token) = {
        let mut sessions = state.sessions.lock().expect("session registry");
        let Some((session_id, active)) = sessions
            .active
            .iter_mut()
            .find(|(_, active)| active.refresh_token == payload.refresh_token && !active.revoked)
        else {
            return json_error(StatusCode::UNAUTHORIZED, "refresh token not found");
        };

        if !active.step_up_required {
            return json_error(StatusCode::BAD_REQUEST, "step-up not required");
        }

        let Some(challenge) = active.step_up_challenge.clone() else {
            return json_error(StatusCode::BAD_REQUEST, "step-up challenge not found");
        };
        let Some(account) = lookup_user_by_user_id(&state, &active.claims.user_id) else {
            return json_error(StatusCode::NOT_FOUND, "user account not found");
        };
        let Some(registration) = account_mfa_registration(&account) else {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "missing mfa registration",
            );
        };
        if state
            .mfa
            .verify_challenge(
                registration,
                &challenge.as_mfa_challenge(),
                &MfaVerification {
                    code: payload.code.clone(),
                    webauthn_assertion: payload.webauthn_assertion.clone(),
                },
            )
            .is_err()
        {
            return json_error(StatusCode::UNAUTHORIZED, "invalid step-up proof");
        }

        let new_refresh_token =
            match rotate_refresh_token(&payload.refresh_token, &active.refresh_token) {
                Ok(token) => token,
                Err(_) => return json_error(StatusCode::UNAUTHORIZED, "step-up rotation failed"),
            };
        let issued_at = chrono::Utc::now();
        active.previous_refresh_token_fingerprint =
            Some(refresh_token_fingerprint(&active.refresh_token));
        active.refresh_token = new_refresh_token.clone();
        active.claims.issued_at = issued_at;
        active.claims.expires_at = issued_at + chrono::Duration::minutes(15);
        active.step_up_required = false;
        active.step_up_challenge = None;
        active.risk_score = active.risk_score.min(25);

        let access_token = match issue_access_token(&active.claims, API_TOKEN_SECRET) {
            Ok(token) => token,
            Err(_) => {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to issue token");
            }
        };

        (
            session_id.to_string(),
            active.clone(),
            access_token,
            new_refresh_token,
        )
    };

    if let Some(persistence) = &state.persistence
        && persistence.save_active_session(&active).await.is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist step-up session",
        );
    }

    Json(TokenPairResponse {
        access_token,
        refresh_token: new_refresh_token,
        session_id,
    })
    .into_response()
}

async fn refresh_handler(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<RefreshRequest>,
) -> Response {
    let replayed_session = {
        let mut sessions = state.sessions.lock().expect("session registry");
        let token_fingerprint = refresh_token_fingerprint(&payload.refresh_token);
        if let Some((_, active)) = sessions.active.iter_mut().find(|(_, active)| {
            active.previous_refresh_token_fingerprint.as_deref() == Some(token_fingerprint.as_str())
                && !active.revoked
        }) {
            active.revoked = true;
            Some(active.clone())
        } else {
            None
        }
    };

    if let Some(replayed_session) = replayed_session {
        if let Some(persistence) = &state.persistence {
            let _ = persistence.save_active_session(&replayed_session).await;
        }
        return json_error(StatusCode::UNAUTHORIZED, "refresh token replay detected");
    }

    let (session_id, active, access_token, new_refresh_token) = {
        let mut sessions = state.sessions.lock().expect("session registry");
        let Some((session_id, active)) = sessions
            .active
            .iter_mut()
            .find(|(_, active)| active.refresh_token == payload.refresh_token && !active.revoked)
        else {
            return json_error(StatusCode::UNAUTHORIZED, "refresh token not found");
        };

        if active.step_up_required {
            return json_step_up_required(active.step_up_challenge.as_ref());
        }

        let new_refresh_token =
            match rotate_refresh_token(&payload.refresh_token, &active.refresh_token) {
                Ok(token) => token,
                Err(_) => {
                    return json_error(StatusCode::UNAUTHORIZED, "refresh token rotation failed");
                }
            };
        let issued_at = chrono::Utc::now();
        active.previous_refresh_token_fingerprint =
            Some(refresh_token_fingerprint(&active.refresh_token));
        active.claims.issued_at = issued_at;
        active.claims.expires_at = issued_at + chrono::Duration::minutes(15);
        active.refresh_token = new_refresh_token.clone();

        let access_token = match issue_access_token(&active.claims, API_TOKEN_SECRET) {
            Ok(token) => token,
            Err(_) => {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, "failed to issue token");
            }
        };

        (
            session_id.to_string(),
            active.clone(),
            access_token,
            new_refresh_token,
        )
    };

    if let Some(persistence) = &state.persistence
        && persistence.save_active_session(&active).await.is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist refreshed session",
        );
    }

    Json(TokenPairResponse {
        access_token,
        refresh_token: new_refresh_token,
        session_id,
    })
    .into_response()
}

async fn logout_handler(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<RefreshRequest>,
) -> Response {
    let active =
        {
            let mut sessions = state.sessions.lock().expect("session registry");
            let Some((_, active)) = sessions.active.iter_mut().find(|(_, active)| {
                active.refresh_token == payload.refresh_token && !active.revoked
            }) else {
                return json_error(StatusCode::UNAUTHORIZED, "refresh token not found");
            };
            active.revoked = true;
            active.clone()
        };
    if let Some(persistence) = &state.persistence
        && persistence.save_active_session(&active).await.is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist revoked session",
        );
    }
    Json(LogoutResponse { revoked: true }).into_response()
}

async fn scim_user_sync_handler(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(payload): Json<ScimUserPatch>,
) -> Response {
    if !authorize_scim_request(&state, &headers) {
        return json_error(StatusCode::UNAUTHORIZED, "invalid scim token");
    }

    match apply_scim_user_patch(&state, payload).await {
        Ok(summary) => Json(summary).into_response(),
        Err(response) => response,
    }
}

async fn scim_group_sync_handler(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(payload): Json<ScimGroupPatch>,
) -> Response {
    if !authorize_scim_request(&state, &headers) {
        return json_error(StatusCode::UNAUTHORIZED, "invalid scim token");
    }

    match apply_scim_group_patch(&state, payload).await {
        Ok(summary) => Json(summary).into_response(),
        Err(response) => response,
    }
}

async fn scim_provider_sync_handler(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(payload): Json<ScimProviderSyncRequest>,
) -> Response {
    if !authorize_scim_request(&state, &headers) {
        return json_error(StatusCode::UNAUTHORIZED, "invalid scim token");
    }

    let previous_cursor = state.scim_cursor.lock().expect("scim cursor").clone();
    let provider_snapshot = match state.scim.pull_snapshot(previous_cursor.as_ref()).await {
        Ok(snapshot) => snapshot,
        Err(error) => return scim_sync_error_response(error),
    };
    let current_users = scim_users_from_state(&state);
    let current_groups = scim_groups_from_state(&state);
    let plan = build_scim_sync_plan(
        &current_users,
        &current_groups,
        provider_snapshot,
        scim_lifecycle_policy(state.scim.sync_config(), &payload),
    );

    if !payload.dry_run
        && let Err(response) = apply_scim_sync_plan(&state, &plan).await
    {
        return response;
    }

    Json(ScimProviderSyncResponse {
        provider: state.scim.provider_name().to_string(),
        dry_run: payload.dry_run,
        summary: plan.summary,
        cursor: plan.cursor,
        user_patches: plan.user_patches.len(),
        group_patches: plan.group_patches.len(),
        membership_changes: plan.membership_changes,
    })
    .into_response()
}

async fn apply_scim_sync_plan(state: &ApiState, plan: &ScimSyncPlan) -> Result<(), Response> {
    for patch in &plan.group_patches {
        apply_scim_group_patch(state, patch.clone()).await?;
    }
    for patch in &plan.user_patches {
        apply_scim_user_patch(state, patch.clone()).await?;
    }
    {
        let mut cursor = state.scim_cursor.lock().expect("scim cursor");
        *cursor = Some(plan.cursor.clone());
    }
    if let Some(persistence) = &state.persistence
        && persistence
            .save_scim_sync_cursor(&plan.cursor)
            .await
            .is_err()
    {
        return Err(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist scim sync cursor",
        ));
    }
    Ok(())
}

async fn apply_scim_user_patch(
    state: &ApiState,
    payload: ScimUserPatch,
) -> Result<ScimSyncSummary, Response> {
    let mut summary = ScimSyncSummary::default();
    match payload {
        ScimUserPatch::Upsert { user } => {
            let memberships = user.groups.len();
            let disabled = !user.active;
            let account = account_from_scim_user(state, &user);
            upsert_user_account(state, account).await?;
            summary.users_changed = 1;
            if disabled {
                summary.users_disabled = 1;
            }
            summary.memberships_changed = memberships;
        }
        ScimUserPatch::Patch {
            external_id,
            user_name,
            display_name,
            email,
            active,
            groups,
        } => {
            let Some(account) = patch_user_by_external_id(
                state,
                &external_id,
                user_name,
                display_name,
                email,
                active,
                groups,
            )
            .await
            else {
                return Err(json_error(StatusCode::NOT_FOUND, "scim user not found"));
            };
            if let Some(persistence) = &state.persistence
                && persistence.save_user_account(&account).await.is_err()
            {
                return Err(json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to persist scim user",
                ));
            }
            summary.users_changed = 1;
            if !account.active {
                summary.users_disabled = 1;
            }
        }
        ScimUserPatch::Disable { external_id } => {
            let Some(account) = disable_user_by_external_id(state, &external_id).await else {
                return Err(json_error(StatusCode::NOT_FOUND, "scim user not found"));
            };
            if let Some(persistence) = &state.persistence
                && persistence.save_user_account(&account).await.is_err()
            {
                return Err(json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to persist scim user",
                ));
            }
            summary.users_disabled = 1;
        }
        ScimUserPatch::Delete { external_id } => {
            if remove_user_by_external_id(state, &external_id)
                .await
                .is_none()
            {
                return Err(json_error(StatusCode::NOT_FOUND, "scim user not found"));
            }
            if let Some(persistence) = &state.persistence
                && persistence.delete_user_account(&external_id).await.is_err()
            {
                return Err(json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to delete scim user",
                ));
            }
            summary.users_changed = 1;
        }
    }
    Ok(summary)
}

async fn apply_scim_group_patch(
    state: &ApiState,
    payload: ScimGroupPatch,
) -> Result<ScimSyncSummary, Response> {
    let mut summary = ScimSyncSummary::default();
    match payload {
        ScimGroupPatch::Upsert { mut group } => {
            group.members.sort();
            group.members.dedup();
            let previous = state
                .scim_groups
                .lock()
                .expect("scim groups")
                .insert(group.external_id.clone(), group.clone());
            let previous_members = previous.map(|group| group.members).unwrap_or_default();
            summary.memberships_changed = membership_diff_count(&previous_members, &group.members);
            if previous_members.is_empty() {
                summary.memberships_changed = group.members.len();
            }
            if let Some(persistence) = &state.persistence
                && persistence.save_scim_group(&group).await.is_err()
            {
                return Err(json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to persist scim group",
                ));
            }
            summary.groups_changed = 1;
        }
        ScimGroupPatch::Patch {
            external_id,
            display_name,
            active,
        } => {
            let group = {
                let mut groups = state.scim_groups.lock().expect("scim groups");
                let Some(group) = groups.get_mut(&external_id) else {
                    return Err(json_error(StatusCode::NOT_FOUND, "scim group not found"));
                };
                if let Some(display_name) = display_name {
                    group.display_name = display_name;
                }
                if let Some(active) = active {
                    group.active = active;
                }
                group.clone()
            };
            if let Some(persistence) = &state.persistence
                && persistence.save_scim_group(&group).await.is_err()
            {
                return Err(json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to persist scim group",
                ));
            }
            summary.groups_changed = 1;
            if !group.active {
                summary.groups_disabled = 1;
            }
        }
        ScimGroupPatch::PatchMembers {
            external_id,
            add_members,
            remove_members,
        } => {
            let (group, changed) = {
                let mut groups = state.scim_groups.lock().expect("scim groups");
                let Some(group) = groups.get_mut(&external_id) else {
                    return Err(json_error(StatusCode::NOT_FOUND, "scim group not found"));
                };
                let mut members = group
                    .members
                    .iter()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>();
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
                (group.clone(), changed)
            };
            if let Some(persistence) = &state.persistence
                && persistence.save_scim_group(&group).await.is_err()
            {
                return Err(json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to persist scim group",
                ));
            }
            summary.groups_changed = 1;
            summary.memberships_changed = changed;
        }
        ScimGroupPatch::Disable { external_id } => {
            let group = {
                let mut groups = state.scim_groups.lock().expect("scim groups");
                let Some(group) = groups.get_mut(&external_id) else {
                    return Err(json_error(StatusCode::NOT_FOUND, "scim group not found"));
                };
                group.active = false;
                group.clone()
            };
            if let Some(persistence) = &state.persistence
                && persistence.save_scim_group(&group).await.is_err()
            {
                return Err(json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to persist scim group",
                ));
            }
            summary.groups_disabled = 1;
        }
        ScimGroupPatch::Delete { external_id } => {
            if state
                .scim_groups
                .lock()
                .expect("scim groups")
                .remove(&external_id)
                .is_none()
            {
                return Err(json_error(StatusCode::NOT_FOUND, "scim group not found"));
            }
            if let Some(persistence) = &state.persistence
                && persistence.delete_scim_group(&external_id).await.is_err()
            {
                return Err(json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to delete scim group",
                ));
            }
            summary.groups_changed = 1;
        }
    }
    Ok(summary)
}

fn authorize_scim_request(state: &ApiState, headers: &HeaderMap) -> bool {
    let token = extract_bearer_token(headers).or_else(|| parse_header(headers, "x-scim-token"));
    token
        .as_deref()
        .map(|token| state.scim.authorize(token).is_ok())
        .unwrap_or(false)
}

fn scim_lifecycle_policy(
    config: &ScimSyncConfig,
    request: &ScimProviderSyncRequest,
) -> ScimLifecyclePolicy {
    ScimLifecyclePolicy {
        disable_missing_users: request
            .disable_missing_users
            .unwrap_or(config.disable_missing_users),
        disable_missing_groups: request
            .disable_missing_groups
            .unwrap_or(config.disable_missing_groups),
        delete_missing_users: request
            .delete_missing_users
            .unwrap_or(config.delete_missing_users),
        delete_missing_groups: request
            .delete_missing_groups
            .unwrap_or(config.delete_missing_groups),
    }
}

fn scim_users_from_state(state: &ApiState) -> Vec<ScimUser> {
    let groups = scim_groups_from_state(state);
    let mut memberships = HashMap::<String, Vec<String>>::new();
    for group in groups.iter().filter(|group| group.active) {
        for member in &group.members {
            memberships
                .entry(member.clone())
                .or_default()
                .push(group.external_id.clone());
        }
    }

    state
        .users
        .lock()
        .expect("users")
        .values()
        .filter(|account| account.auth_source == TrustedAuthenticationSource::Scim)
        .filter_map(|account| {
            let external_id = account.external_id.clone()?;
            let mut groups = memberships.remove(&external_id).unwrap_or_default();
            groups.sort();
            groups.dedup();
            Some(ScimUser {
                external_id,
                tenant_id: account.tenant_id.clone(),
                user_name: account.username.clone(),
                display_name: account.display_name.clone(),
                email: account.email.clone(),
                active: account.active,
                groups,
            })
        })
        .collect()
}

fn scim_groups_from_state(state: &ApiState) -> Vec<ScimGroup> {
    state
        .scim_groups
        .lock()
        .expect("scim groups")
        .values()
        .cloned()
        .collect()
}

fn membership_diff_count(left: &[String], right: &[String]) -> usize {
    let left = left
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let right = right
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    left.symmetric_difference(&right).count()
}

fn scim_sync_error_response(error: ScimSyncError) -> Response {
    match error {
        ScimSyncError::InvalidToken => json_error(
            StatusCode::BAD_GATEWAY,
            "scim provider rejected configured token",
        ),
        ScimSyncError::UnknownProvider(_) | ScimSyncError::UnsupportedProvider(_) => {
            json_error(StatusCode::BAD_REQUEST, &error.to_string())
        }
        ScimSyncError::ProviderConfiguration(_) => {
            json_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
        ScimSyncError::ProviderStatus { .. }
        | ScimSyncError::ProviderRequest(_)
        | ScimSyncError::ProviderParse(_) => {
            json_error(StatusCode::BAD_GATEWAY, &error.to_string())
        }
        ScimSyncError::NotFound(_) => json_error(StatusCode::NOT_FOUND, &error.to_string()),
    }
}

fn sso_error_response(error: SsoError, is_callback: bool) -> Response {
    match error {
        SsoError::InvalidCallbackCode => {
            json_error(StatusCode::UNAUTHORIZED, "invalid sso callback code")
        }
        SsoError::ProviderConfiguration(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid sso provider configuration",
        ),
        SsoError::UnknownProvider(_)
        | SsoError::ProviderProtocol(_)
        | SsoError::ProviderRequest(_) => {
            let message = if is_callback {
                "sso provider exchange failed"
            } else {
                "sso provider initiation failed"
            };
            json_error(StatusCode::BAD_GATEWAY, message)
        }
    }
}

fn parse_sso_protocol(value: &str) -> Option<SsoProtocol> {
    match value.to_ascii_lowercase().as_str() {
        "oidc" => Some(SsoProtocol::Oidc),
        "saml" => Some(SsoProtocol::Saml),
        _ => None,
    }
}

fn lookup_user_by_username(state: &ApiState, username: &str) -> Option<UserAccount> {
    state.users.lock().expect("users").get(username).cloned()
}

fn lookup_user_by_user_id(state: &ApiState, user_id: &str) -> Option<UserAccount> {
    state
        .users
        .lock()
        .expect("users")
        .values()
        .find(|account| account.user_id == user_id)
        .cloned()
}

fn account_from_sso_claims(
    claims: &sdqp_system_security::SsoCallbackClaims,
    state: &ApiState,
) -> UserAccount {
    let roles = roles_from_group_ids(&claims.groups);
    bootstrap_user_account(
        state,
        UserAccount {
            username: claims.username.clone(),
            display_name: claims.display_name.clone(),
            email: claims.email.clone(),
            password: "__sso_only__".into(),
            user_id: format!("user-{}", claims.username),
            tenant_id: "tenant-alpha".into(),
            external_id: Some(claims.subject.clone()),
            active: true,
            auth_source: claims.auth_source.clone(),
            roles: roles.clone(),
            mfa_method: mfa_method_for_roles(&roles),
            mfa_registration: None,
        },
    )
}

fn account_from_scim_user(state: &ApiState, user: &ScimUser) -> UserAccount {
    let roles = roles_from_group_ids(&user.groups);
    bootstrap_user_account(
        state,
        UserAccount {
            username: user.user_name.clone(),
            display_name: user.display_name.clone(),
            email: user.email.clone(),
            password: "__scim_managed__".into(),
            user_id: format!("user-{}", user.user_name),
            tenant_id: user.tenant_id.clone(),
            external_id: Some(user.external_id.clone()),
            active: user.active,
            auth_source: TrustedAuthenticationSource::Scim,
            roles: roles.clone(),
            mfa_method: mfa_method_for_roles(&roles),
            mfa_registration: None,
        },
    )
}

fn bootstrap_user_account(state: &ApiState, mut account: UserAccount) -> UserAccount {
    if account.mfa_registration.is_none() {
        account.mfa_registration = Some(state.mfa.bootstrap_registration(
            &account.tenant_id,
            &account.user_id,
            &account.username,
            &account.mfa_method,
        ));
    }
    account
}

fn hydrate_user_directory(
    users: HashMap<String, UserAccount>,
    security: &SecuritySettings,
) -> HashMap<String, UserAccount> {
    let registry = build_mfa_registry(security);
    users
        .into_iter()
        .map(|(username, mut account)| {
            if account.mfa_registration.is_none() {
                account.mfa_registration = Some(registry.bootstrap_registration(
                    &account.tenant_id,
                    &account.user_id,
                    &account.username,
                    &account.mfa_method,
                ));
            }
            (username, account)
        })
        .collect()
}

fn account_mfa_registration(account: &UserAccount) -> Option<&MfaRegistration> {
    account.mfa_registration.as_ref()
}

fn mfa_challenge_response(challenge: &MfaChallenge) -> MfaChallengeResponse {
    MfaChallengeResponse {
        challenge_id: challenge.challenge_id.clone(),
        method: format!("{:?}", challenge.method).to_lowercase(),
        reason: challenge.reason.clone(),
        expires_at: challenge.expires_at,
        webauthn_request: match challenge.challenge_payload.as_ref() {
            Some(MfaChallengePayload::WebAuthn(WebAuthnRequestOptions {
                challenge,
                rp_id,
                origin,
                credential_id,
                timeout_ms,
                user_verification,
            })) => Some(WebAuthnRequestResponse {
                challenge: challenge.clone(),
                rp_id: rp_id.clone(),
                origin: origin.clone(),
                credential_id: credential_id.clone(),
                timeout_ms: *timeout_ms,
                user_verification: user_verification.clone(),
            }),
            _ => None,
        },
    }
}

fn step_up_challenge_response(challenge: &StepUpChallenge) -> MfaChallengeResponse {
    mfa_challenge_response(&challenge.as_mfa_challenge())
}

fn roles_from_group_ids(groups: &[String]) -> Vec<Role> {
    let mut roles = Vec::new();
    for group in groups {
        let group = group.to_ascii_lowercase();
        if group.contains("admin") && !roles.contains(&Role::SystemAdmin) {
            roles.push(Role::SystemAdmin);
        } else if group.contains("project-admin") && !roles.contains(&Role::ProjectAdmin) {
            roles.push(Role::ProjectAdmin);
        } else if group.contains("owner") && !roles.contains(&Role::DataOwner) {
            roles.push(Role::DataOwner);
        } else if group.contains("auditor") && !roles.contains(&Role::Auditor) {
            roles.push(Role::Auditor);
        } else if group.contains("approver") && !roles.contains(&Role::Approver) {
            roles.push(Role::Approver);
        } else if group.contains("analyst") && !roles.contains(&Role::Analyst) {
            roles.push(Role::Analyst);
        }
    }

    if roles.is_empty() {
        roles.push(Role::Analyst);
    }

    roles
}

fn mfa_method_for_roles(roles: &[Role]) -> MfaMethod {
    if roles.iter().any(|role| {
        matches!(
            role,
            Role::SystemAdmin
                | Role::ProjectAdmin
                | Role::DataOwner
                | Role::Auditor
                | Role::Approver
        )
    }) {
        MfaMethod::WebAuthn
    } else {
        MfaMethod::Totp
    }
}

async fn upsert_user_account(state: &ApiState, account: UserAccount) -> Result<(), Response> {
    let mut account = account;
    let previous = account.external_id.as_ref().and_then(|external_id| {
        let mut users = state.users.lock().expect("users");
        let username = users
            .iter()
            .find(|(_, existing)| existing.external_id.as_deref() == Some(external_id.as_str()))
            .map(|(username, _)| username.clone())?;
        users.remove(&username)
    });
    if let Some(previous) = previous {
        account.user_id = previous.user_id;
        account.mfa_registration = previous.mfa_registration;
    }
    let account = bootstrap_user_account(state, account);
    state
        .users
        .lock()
        .expect("users")
        .insert(account.username.clone(), account.clone());
    if !account.active {
        revoke_sessions_for_user(state, &account.user_id);
    }
    if let Some(persistence) = &state.persistence
        && persistence.save_user_account(&account).await.is_err()
    {
        return Err(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist user account",
        ));
    }
    Ok(())
}

async fn patch_user_by_external_id(
    state: &ApiState,
    external_id: &str,
    user_name: Option<String>,
    display_name: Option<String>,
    email: Option<String>,
    active: Option<bool>,
    groups: Option<Vec<String>>,
) -> Option<UserAccount> {
    let account = {
        let mut users = state.users.lock().expect("users");
        let username = users
            .iter()
            .find(|(_, account)| account.external_id.as_deref() == Some(external_id))
            .map(|(username, _)| username.clone())?;
        let mut account = users.remove(&username)?;
        if let Some(user_name) = user_name {
            account.username = user_name;
        }
        if let Some(display_name) = display_name {
            account.display_name = display_name;
        }
        if let Some(email) = email {
            account.email = email;
        }
        if let Some(active) = active {
            account.active = active;
        }
        if let Some(groups) = groups {
            account.roles = roles_from_group_ids(&groups);
            account.mfa_method = mfa_method_for_roles(&account.roles);
        }
        users.insert(account.username.clone(), account.clone());
        account
    };
    if !account.active {
        revoke_sessions_for_user(state, &account.user_id);
    }
    Some(account)
}

async fn disable_user_by_external_id(state: &ApiState, external_id: &str) -> Option<UserAccount> {
    let account = {
        let mut users = state.users.lock().expect("users");
        let username = users
            .iter()
            .find(|(_, account)| account.external_id.as_deref() == Some(external_id))
            .map(|(username, _)| username.clone())?;
        let account = users.get_mut(&username)?;
        account.active = false;
        account.clone()
    };
    revoke_sessions_for_user(state, &account.user_id);
    Some(account)
}

async fn remove_user_by_external_id(state: &ApiState, external_id: &str) -> Option<UserAccount> {
    let account = {
        let mut users = state.users.lock().expect("users");
        let username = users
            .iter()
            .find(|(_, account)| account.external_id.as_deref() == Some(external_id))
            .map(|(username, _)| username.clone())?;
        users.remove(&username)?
    };
    revoke_sessions_for_user(state, &account.user_id);
    Some(account)
}

fn revoke_sessions_for_user(state: &ApiState, user_id: &str) {
    for active in state
        .sessions
        .lock()
        .expect("session registry")
        .active
        .values_mut()
    {
        if active.claims.user_id == user_id {
            active.revoked = true;
        }
    }
}

fn apply_device_posture_assessment(
    state: &ApiState,
    payload: &DevicePostureRequest,
) -> Option<(ActiveSession, sdqp_system_security::RiskAssessment)> {
    let mut sessions = state.sessions.lock().expect("session registry");
    let (_, active) = sessions
        .active
        .iter_mut()
        .find(|(_, active)| active.refresh_token == payload.refresh_token && !active.revoked)?;

    let posture = state.device_posture.collect(
        &active.claims.binding.device_fingerprint,
        payload.profile.as_deref(),
    );
    let assessment = state.risk.assess(&ContinuousAccessSignal {
        query_burst: payload.query_burst.unwrap_or_default(),
        denied_burst: payload.denied_burst.unwrap_or_default(),
        export_burst: payload.export_burst.unwrap_or_default(),
        ip_drift: payload.ip_drift,
        impossible_travel: payload.impossible_travel,
        exfiltration_hint: payload.exfiltration_hint,
        device_posture: Some(posture.clone()),
    });

    active.device_posture = Some(posture);
    active.risk_score = assessment.score.score.round() as u8;
    match assessment.score.recommended_action {
        AdaptiveResponse::Allow => {
            active.step_up_required = false;
            active.step_up_challenge = None;
        }
        AdaptiveResponse::StepUpAuth => {
            let account = lookup_user_by_user_id(state, &active.claims.user_id)?;
            let registration = account_mfa_registration(&account)?;
            let challenge = state
                .mfa
                .begin_challenge(
                    registration,
                    Some("continuous risk assessment requires step-up".into()),
                )
                .ok()?;
            active.step_up_required = true;
            active.step_up_challenge = Some(StepUpChallenge::from_mfa_challenge(
                &challenge,
                "continuous risk assessment requires step-up",
            ));
        }
        AdaptiveResponse::TerminateSession => {
            active.revoked = true;
            active.step_up_required = false;
            active.step_up_challenge = None;
        }
    }

    Some((active.clone(), assessment))
}

async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    response
}

fn build_mfa_registry(security: &SecuritySettings) -> MfaProviderRegistry {
    MfaProviderRegistry::new(MfaProviderConfig {
        bootstrap_seed: security.mfa_bootstrap_seed.clone(),
        challenge_ttl_secs: security.mfa_challenge_ttl_secs,
        totp: sdqp_system_security::TotpProviderConfig {
            issuer: security.totp_issuer.clone(),
            period_secs: security.totp_period_secs,
            digits: security.totp_digits,
            allowed_drift_steps: security.totp_allowed_drift_steps,
        },
        webauthn: sdqp_system_security::WebAuthnProviderConfig {
            rp_id: security.webauthn_rp_id.clone(),
            origin: security.webauthn_origin.clone(),
            timeout_ms: security.webauthn_timeout_ms,
            challenge_ttl_secs: security.mfa_challenge_ttl_secs,
            require_user_verification: security.webauthn_require_user_verification,
        },
    })
}

fn build_checkpoint_signers(audit: &AuditSettings) -> CheckpointSignerRegistry {
    build_checkpoint_signer_registry(&CheckpointSignerConfig {
        provider: CheckpointSignerProvider::parse(&audit.checkpoint.provider)
            .unwrap_or(CheckpointSignerProvider::Mock),
        key_id: audit.checkpoint.key_id.clone(),
        key_version: if audit.checkpoint.key_version.trim().is_empty() {
            None
        } else {
            Some(audit.checkpoint.key_version.clone())
        },
        endpoint: if audit.checkpoint.endpoint.trim().is_empty() {
            None
        } else {
            Some(audit.checkpoint.endpoint.clone())
        },
        region: if audit.checkpoint.region.trim().is_empty() {
            None
        } else {
            Some(audit.checkpoint.region.clone())
        },
        key_ring: if audit.checkpoint.key_ring.trim().is_empty() {
            None
        } else {
            Some(audit.checkpoint.key_ring.clone())
        },
        auth_token: if audit.checkpoint.auth_token.trim().is_empty() {
            None
        } else {
            Some(audit.checkpoint.auth_token.clone())
        },
    })
    .unwrap_or_else(|_| {
        build_checkpoint_signer_registry(&CheckpointSignerConfig::default())
            .expect("default checkpoint signer registry")
    })
}

fn build_audit_forwarder(audit: &AuditSettings) -> AuditForwarderRegistry {
    build_audit_forwarder_registry(&AuditForwarderConfig {
        enabled: audit.forwarder.enabled,
        provider: AuditForwarderProvider::parse(&audit.forwarder.provider)
            .unwrap_or(AuditForwarderProvider::Disabled),
        timeout_ms: audit.forwarder.timeout_ms,
        webhook: WebhookAuditForwarderConfig {
            endpoint: audit.forwarder.webhook_url.clone(),
            auth_header: if audit.forwarder.auth_header.trim().is_empty() {
                None
            } else {
                Some(audit.forwarder.auth_header.clone())
            },
            auth_token: if audit.forwarder.auth_token.trim().is_empty() {
                None
            } else {
                Some(audit.forwarder.auth_token.clone())
            },
            headers: std::collections::BTreeMap::new(),
        },
        kafka: KafkaAuditForwarderConfig {
            brokers: if audit.forwarder.kafka_brokers.is_empty() {
                vec![]
            } else {
                audit.forwarder.kafka_brokers.clone()
            },
            topic: audit.forwarder.kafka_topic.clone(),
        },
        syslog: SyslogAuditForwarderConfig {
            endpoint: audit.forwarder.syslog_endpoint.clone(),
            hostname: audit.forwarder.syslog_hostname.clone(),
            app_name: audit.forwarder.syslog_app_name.clone(),
        },
    })
    .unwrap_or_else(|_| {
        build_audit_forwarder_registry(&AuditForwarderConfig::default())
            .expect("default audit forwarder registry")
    })
}

fn build_audit_retention_config(audit: &AuditSettings) -> AuditRetentionConfig {
    AuditRetentionConfig {
        enabled: audit.retention.enabled,
        archive_after_secs: audit.retention.archive_after_secs,
        access_log_retention_secs: audit.retention.access_log_retention_secs,
        permission_lifecycle_retention_secs: audit.retention.permission_lifecycle_retention_secs,
        evidence_retention_secs: audit.retention.evidence_retention_secs,
        system_management_retention_secs: audit.retention.system_management_retention_secs,
    }
}

fn build_rate_limit_policy(security: &SecuritySettings) -> RateLimitPolicy {
    RateLimitPolicy {
        max_requests: security.integration_rate_limit.max_requests,
        window_secs: security.integration_rate_limit.window_secs,
    }
}

fn build_integration_security_policy(security: &SecuritySettings) -> IntegrationSecurityPolicy {
    IntegrationSecurityPolicy::new(IntegrationSecurityConfig {
        api_keys: security
            .integration_api_keys
            .iter()
            .map(|key| ApiKeyRecord {
                key_id: key.key_id.clone(),
                secret: key.secret.clone(),
                scopes: key.scopes.clone(),
                allowed_ips: key.allowed_ips.clone(),
            })
            .collect(),
        ip_allowlist: security.integration_ip_allowlist.clone(),
        mtls: MtlsPolicy {
            required_subjects: security.integration_mtls_subjects.clone(),
        },
        rate_limit: build_rate_limit_policy(security),
    })
}

fn build_tee_registry(security: &SecuritySettings) -> TeeProviderRegistry {
    TeeProviderRegistry::from_config(TeeProviderConfig {
        provider: security.tee.provider.clone(),
        attestation_url: security.tee.attestation_url.clone(),
        expected_measurements: security.tee.expected_measurements.clone(),
    })
    .unwrap_or_else(|_| {
        TeeProviderRegistry::from_config(TeeProviderConfig::default())
            .expect("default tee registry")
    })
}

async fn integration_security_middleware(
    State(state): State<Arc<ApiState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let (scope, require_mtls) = if path.starts_with("/integrations/hr") {
        ("hr.events", true)
    } else if path.starts_with("/integrations/audit/permission-transitions") {
        ("audit.permission_lifecycle", false)
    } else {
        ("scim.sync", false)
    };
    let request_context = IntegrationRequestContext {
        client_ip: extract_ip_address(request.headers()),
        api_key: parse_header(request.headers(), "x-api-key")
            .or_else(|| parse_header(request.headers(), "x-sdqp-api-key")),
        mtls_subject: parse_header(request.headers(), "x-client-cert-subject"),
    };
    let authorized = match state
        .integration_security
        .lock()
        .expect("integration security")
        .authorize(scope, require_mtls, &request_context)
    {
        Ok(authorized) => authorized,
        Err(error) => return integration_security_error_response(error),
    };
    if let Err(error) = state.integration_rate_limiter.check(&format!(
        "{scope}:{}:{}",
        authorized.key_id, authorized.client_ip
    )) {
        return integration_security_error_response(error);
    }
    request.extensions_mut().insert(authorized);
    next.run(request).await
}

fn integration_security_error_response(error: IntegrationSecurityError) -> Response {
    match error {
        IntegrationSecurityError::MissingApiKey | IntegrationSecurityError::InvalidApiKey => {
            json_error(StatusCode::UNAUTHORIZED, &error.to_string())
        }
        IntegrationSecurityError::RateLimited => {
            json_error(StatusCode::TOO_MANY_REQUESTS, &error.to_string())
        }
        _ => json_error(StatusCode::FORBIDDEN, &error.to_string()),
    }
}

fn spawn_credential_rotation_runtime(state: Arc<ApiState>) {
    if !state.credential_rotation.enabled {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let actor = ActorInfo {
                user_id: "system-credential-rotation".into(),
                session_id: "runtime-job".into(),
                ip_address: "127.0.0.1".into(),
            };
            let _ = run_credential_rotation_cycle(
                state.clone(),
                actor,
                "system".into(),
                None,
                CredentialRotationRunRequest {
                    force: false,
                    credential_id: None,
                },
                false,
            )
            .await;
        }
    });
}

async fn run_credential_rotation_cycle(
    state: Arc<ApiState>,
    actor: ActorInfo,
    tenant_id: String,
    project_id: Option<String>,
    request: CredentialRotationRunRequest,
    emit_noop_audit: bool,
) -> CredentialRotationRunResponse {
    let now = chrono::Utc::now();
    let policies = build_credential_rotation_policies(&state);
    let mut results = Vec::new();
    let mut skipped = 0;
    {
        let mut states = state
            .credential_rotation_states
            .lock()
            .expect("credential rotation states");
        for policy in &policies {
            let entry = states
                .entry(policy.credential_id.clone())
                .or_insert_with(|| CredentialRotationState::new_due(policy, now));
            entry.refresh_due_status(now);
        }
    }

    for policy in policies {
        if request
            .credential_id
            .as_deref()
            .is_some_and(|requested| requested != policy.credential_id)
        {
            continue;
        }

        let state_snapshot = state
            .credential_rotation_states
            .lock()
            .expect("credential rotation states")
            .get(&policy.credential_id)
            .cloned()
            .unwrap_or_else(|| CredentialRotationState::new_due(&policy, now));

        if !request.force && !state_snapshot.is_due(&policy, now) {
            skipped += 1;
            continue;
        }

        let result = rotate_single_credential(state.clone(), &policy, state_snapshot, now).await;
        let checkpoint = append_credential_rotation_audit(
            &state,
            actor.clone(),
            &tenant_id,
            project_id.as_deref(),
            &result,
        )
        .await;
        results.push((result, checkpoint.checkpoint_id));
    }

    let mut audit_checkpoint_id = results
        .last()
        .map(|(_, checkpoint_id)| checkpoint_id.clone())
        .unwrap_or_default();
    if audit_checkpoint_id.is_empty() && emit_noop_audit {
        let checkpoint = record_audit_event_from_parts_with_fields(
            &state,
            actor,
            ActionType::ConfigChange,
            TargetRef {
                tenant_id,
                project_id,
                resource_id: "credential-rotation".into(),
            },
            "credential rotation run found no due credentials",
            AuditContextFields::builder()
                .field("force", request.force)
                .field("skipped", skipped)
                .build(),
            ActionResult::Success,
            None,
        )
        .await;
        audit_checkpoint_id = checkpoint.checkpoint_id;
    }

    let results = results
        .into_iter()
        .map(|(result, _)| result)
        .collect::<Vec<_>>();
    let rotated = results.iter().filter(|result| result.rotated).count();
    let failed = results.iter().filter(|result| result.retryable).count();
    let manual_intervention = results
        .iter()
        .filter(|result| result.manual_intervention_required)
        .count();

    CredentialRotationRunResponse {
        evaluated: results.len(),
        rotated,
        failed,
        manual_intervention,
        skipped,
        audit_checkpoint_id,
        results,
    }
}

async fn rotate_single_credential(
    state: Arc<ApiState>,
    policy: &CredentialRotationPolicy,
    mut rotation_state: CredentialRotationState,
    now: DateTime<chrono::Utc>,
) -> CredentialRotationAttemptResponse {
    rotation_state.start_attempt(now);
    persist_rotation_state(&state, &rotation_state).await;

    if !policy.repo_local_automation {
        rotation_state.mark_externally_managed(
            now,
            "credential requires external IdP or certificate authority rotation",
        );
        persist_rotation_state(&state, &rotation_state).await;
        return credential_rotation_attempt_response(
            &rotation_state,
            policy,
            false,
            None,
            None,
            rotation_state.last_error.clone(),
        );
    }

    match policy.kind {
        CredentialKind::IntegrationApiKey => {
            let current_record = state
                .integration_security
                .lock()
                .expect("integration security")
                .api_key_record(&policy.credential_id);
            let Some(mut record) = current_record else {
                rotation_state.mark_failure(policy, now, "integration api key not found");
                persist_rotation_state(&state, &rotation_state).await;
                return credential_rotation_attempt_response(
                    &rotation_state,
                    policy,
                    false,
                    None,
                    None,
                    rotation_state.last_error.clone(),
                );
            };

            let generated = generate_integration_api_key_secret(&policy.credential_id, now);
            record.secret = generated.secret.clone();
            if let Some(persistence) = &state.persistence
                && let Err(error) = persistence.save_integration_api_key(&record).await
            {
                rotation_state.mark_failure(
                    policy,
                    now,
                    format!("failed to persist rotated api key: {error}"),
                );
                persist_rotation_state(&state, &rotation_state).await;
                return credential_rotation_attempt_response(
                    &rotation_state,
                    policy,
                    false,
                    None,
                    None,
                    rotation_state.last_error.clone(),
                );
            }

            state
                .integration_security
                .lock()
                .expect("integration security")
                .upsert_api_key(record);
            rotation_state.mark_success(policy, now, generated.version.clone());
            persist_rotation_state(&state, &rotation_state).await;
            credential_rotation_attempt_response(
                &rotation_state,
                policy,
                true,
                Some(generated.version),
                Some(generated.secret),
                None,
            )
        }
        _ => {
            rotation_state.mark_externally_managed(
                now,
                "credential kind is modeled but not repo-locally rotatable",
            );
            persist_rotation_state(&state, &rotation_state).await;
            credential_rotation_attempt_response(
                &rotation_state,
                policy,
                false,
                None,
                None,
                rotation_state.last_error.clone(),
            )
        }
    }
}

async fn persist_rotation_state(state: &Arc<ApiState>, rotation_state: &CredentialRotationState) {
    {
        state
            .credential_rotation_states
            .lock()
            .expect("credential rotation states")
            .insert(rotation_state.credential_id.clone(), rotation_state.clone());
    }
    if let Some(persistence) = &state.persistence
        && let Err(error) = persistence
            .save_credential_rotation_state(rotation_state)
            .await
    {
        tracing::warn!(?error, "failed to persist credential rotation state");
    }
}

fn ensure_credential_rotation_states(
    state: &Arc<ApiState>,
    now: DateTime<chrono::Utc>,
) -> Vec<CredentialRotationState> {
    let policies = build_credential_rotation_policies(state);
    let mut states = state
        .credential_rotation_states
        .lock()
        .expect("credential rotation states");
    for policy in policies {
        let entry = states
            .entry(policy.credential_id.clone())
            .or_insert_with(|| CredentialRotationState::new_due(&policy, now));
        entry.refresh_due_status(now);
    }

    let mut states = states.values().cloned().collect::<Vec<_>>();
    states.sort_by(|left, right| left.credential_id.cmp(&right.credential_id));
    states
}

fn build_credential_rotation_policies(state: &ApiState) -> Vec<CredentialRotationPolicy> {
    if !state.credential_rotation.enabled {
        return Vec::new();
    }
    let config = state
        .integration_security
        .lock()
        .expect("integration security")
        .config();
    config
        .api_keys
        .iter()
        .map(|key| {
            CredentialRotationPolicy::integration_api_key(
                key.key_id.clone(),
                state.credential_rotation.interval_secs,
                state.credential_rotation.retry_backoff_secs,
                state.credential_rotation.max_attempts,
                state.credential_rotation.manual_intervention_after_attempts,
            )
        })
        .collect()
}

fn credential_rotation_state_response(
    state: CredentialRotationState,
) -> CredentialRotationStateResponse {
    CredentialRotationStateResponse {
        credential_id: state.credential_id,
        kind: state.kind.as_str().into(),
        status: state.status.as_str().into(),
        last_rotated_at: state.last_rotated_at,
        next_rotation_due_at: state.next_rotation_due_at,
        last_attempt_at: state.last_attempt_at,
        attempts: state.attempts,
        active_version: state.active_version,
        last_error: state.last_error,
        manual_intervention_reason: state.manual_intervention_reason,
    }
}

fn credential_rotation_attempt_response(
    state: &CredentialRotationState,
    policy: &CredentialRotationPolicy,
    rotated: bool,
    new_version: Option<String>,
    new_secret: Option<String>,
    error: Option<String>,
) -> CredentialRotationAttemptResponse {
    let retryable = state.status == CredentialRotationStatus::FailedRetryable;
    let manual_intervention_required = matches!(
        state.status,
        CredentialRotationStatus::ManualInterventionRequired
            | CredentialRotationStatus::ExternallyManaged
    );
    CredentialRotationAttemptResponse {
        credential_id: state.credential_id.clone(),
        kind: state.kind.as_str().into(),
        status: state.status.as_str().into(),
        rotated,
        repo_local_automation: policy.repo_local_automation,
        retryable,
        manual_intervention_required,
        new_version,
        new_secret,
        next_rotation_due_at: state.next_rotation_due_at,
        error,
    }
}

async fn append_credential_rotation_audit(
    state: &Arc<ApiState>,
    actor: ActorInfo,
    tenant_id: &str,
    project_id: Option<&str>,
    result: &CredentialRotationAttemptResponse,
) -> AuditCheckpoint {
    let action_result = if result.rotated {
        ActionResult::Success
    } else if result.retryable || result.manual_intervention_required {
        ActionResult::Failure
    } else {
        ActionResult::Denied
    };
    record_audit_event_from_parts_with_fields(
        state,
        actor,
        ActionType::ConfigChange,
        TargetRef {
            tenant_id: tenant_id.to_string(),
            project_id: project_id.map(str::to_string),
            resource_id: format!("credential-rotation/{}", result.credential_id),
        },
        format!(
            "credential rotation {} for {}",
            result.status, result.credential_id
        ),
        AuditContextFields::builder()
            .field("credential_id", result.credential_id.clone())
            .field("credential_kind", result.kind.clone())
            .field("status", result.status.clone())
            .field("repo_local_automation", result.repo_local_automation)
            .field("rotated", result.rotated)
            .field("retryable", result.retryable)
            .field(
                "manual_intervention_required",
                result.manual_intervention_required,
            )
            .field(
                "new_version",
                result.new_version.clone().unwrap_or_else(|| "none".into()),
            )
            .build(),
        action_result,
        None,
    )
    .await
}

fn actor_from_session(session: Option<&AuthenticatedSession>) -> ActorInfo {
    match session {
        Some(session) => ActorInfo {
            user_id: session.claims.user_id.clone(),
            session_id: session.claims.session_id.clone(),
            ip_address: session.claims.binding.ip_address.clone(),
        },
        None => ActorInfo {
            user_id: "system".into(),
            session_id: "system".into(),
            ip_address: "127.0.0.1".into(),
        },
    }
}

async fn tee_attestation_middleware(
    State(state): State<Arc<ApiState>>,
    request: Request,
    next: Next,
) -> Response {
    if state
        .tee
        .enforce_secure_workload("protected-project-routes")
        .await
        .is_err()
    {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "tee attestation unavailable for protected project routes",
        );
    }
    next.run(request).await
}

async fn request_observability_middleware(
    State(state): State<Arc<ApiState>>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let request_id = parse_header(request.headers(), "x-request-id")
        .unwrap_or_else(|| ulid::Ulid::new().to_string());
    let span_id = ulid::Ulid::new().to_string();

    let span = tracing::info_span!(
        "http.request",
        request_id = %request_id,
        span_id = %span_id,
        method = %method,
        path = %path
    );

    let mut response = next.run(request).instrument(span).await;
    state.metrics.record(response.status());

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    if let Ok(value) = HeaderValue::from_str(&span_id) {
        response.headers_mut().insert("x-sdqp-span-id", value);
    }

    response
}

async fn tenant_context_middleware(
    State(state): State<Arc<ApiState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let claims = match extract_authenticated_claims(&state, &request) {
        Ok(session) => session,
        Err(response) => {
            append_request_audit(
                &state,
                None,
                None,
                ActionType::View,
                ActionResult::Denied,
                request.uri().path(),
                "authentication failed",
            )
            .await;
            return *response;
        }
    };

    let tenant_id = match parse_scoped_request_value(&request, "x-tenant-id", "tenant_id") {
        Some(value) if value == claims.claims.tenant_id => value,
        _ => {
            append_request_audit(
                &state,
                Some(&claims),
                None,
                ActionType::View,
                ActionResult::Denied,
                request.uri().path(),
                "tenant mismatch",
            )
            .await;
            return json_error(StatusCode::FORBIDDEN, "tenant mismatch");
        }
    };

    let tenant_id = TenantId::new(tenant_id).expect("tenant id");
    let user_id = UserId::new(claims.claims.user_id.clone()).expect("user id");
    let request_context = RequestContext::new(tenant_id.clone(), user_id);

    request
        .extensions_mut()
        .insert(TenantContext::new(tenant_id));
    request.extensions_mut().insert(request_context);
    request.extensions_mut().insert(claims);

    next.run(request).await
}

async fn project_context_middleware(
    State(state): State<Arc<ApiState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(request_context) = request.extensions().get::<RequestContext>().cloned() else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "missing request context");
    };

    let project_id = match parse_scoped_request_value(&request, "x-project-id", "project_id") {
        Some(value) => value,
        None => return json_error(StatusCode::BAD_REQUEST, "missing x-project-id header"),
    };

    let Some(project) = state
        .projects
        .lock()
        .expect("projects")
        .get(&project_id)
        .cloned()
    else {
        append_request_audit(
            &state,
            request.extensions().get::<AuthenticatedSession>(),
            Some(project_id.as_str()),
            ActionType::View,
            ActionResult::Denied,
            request.uri().path(),
            "unknown project",
        )
        .await;
        return json_error(StatusCode::NOT_FOUND, "project not found");
    };

    let scoped_request = request_context
        .clone()
        .with_project(ProjectId::new(project_id).expect("project id"));

    if let Err(error) = TenantIsolationGuard::assert_request_in_project(&scoped_request, &project) {
        let context = match error {
            IsolationError::ProjectInvisible => "project not visible",
            IsolationError::ProjectUnavailable => "project unavailable",
            IsolationError::ScopeMismatch => "project scope mismatch",
        };
        append_request_audit(
            &state,
            request.extensions().get::<AuthenticatedSession>(),
            scoped_request
                .project_id
                .as_ref()
                .map(|project_id| project_id.as_str()),
            ActionType::View,
            ActionResult::Denied,
            request.uri().path(),
            context,
        )
        .await;
        return match error {
            IsolationError::ProjectInvisible | IsolationError::ProjectUnavailable => {
                json_error(StatusCode::NOT_FOUND, "project not found")
            }
            IsolationError::ScopeMismatch => {
                json_error(StatusCode::FORBIDDEN, "project scope mismatch")
            }
        };
    }

    request.extensions_mut().insert(scoped_request);
    request.extensions_mut().insert(project);
    next.run(request).await
}

async fn project_context_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(project_context): Extension<ProjectContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    append_request_audit(
        &state,
        Some(&session),
        request_context
            .project_id
            .as_ref()
            .map(|project_id| project_id.as_str()),
        ActionType::View,
        ActionResult::Success,
        "project-context",
        "project access granted",
    )
    .await;

    let audit = state.audit.lock().expect("audit");
    Json(ProjectAccessResponse {
        scope_key: request_context.project_scope_key(),
        project_state: format!("{:?}", project_context.state).to_lowercase(),
        audit_chain_valid: audit.chain_valid(),
        audit_events: audit.event_count(),
    })
    .into_response()
}

async fn projects_list_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    append_request_audit(
        &state,
        Some(&session),
        None,
        ActionType::View,
        ActionResult::Success,
        "projects",
        "project catalog listed",
    )
    .await;

    let mut projects = state
        .projects
        .lock()
        .expect("projects")
        .values()
        .filter(|project| project.tenant_id == request_context.tenant_id)
        .filter(|project| project.state.is_externally_visible())
        .map(project_summary_from_context)
        .collect::<Vec<_>>();
    projects.sort_by(|left, right| left.project_id.cmp(&right.project_id));

    Json(ProjectsListResponse { projects }).into_response()
}

async fn project_create_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<ProjectCreateRequest>,
) -> Response {
    if !can_manage_projects(&session.roles) {
        append_request_audit(
            &state,
            Some(&session),
            Some(payload.project_id.as_str()),
            ActionType::ConfigChange,
            ActionResult::Denied,
            "projects",
            "missing project management role",
        )
        .await;
        return json_error(StatusCode::FORBIDDEN, "project admin role required");
    }

    let project_id = match ProjectId::new(payload.project_id.trim()) {
        Ok(project_id) => project_id,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "invalid project id"),
    };
    let tenant_id = request_context.tenant_id.clone();
    let initial_state = match payload.initial_state.as_deref() {
        None => ProjectState::Created,
        Some(value) => match parse_project_state_label(value) {
            Some(ProjectState::Created | ProjectState::Active) => {
                parse_project_state_label(value).expect("parsed")
            }
            _ => return json_error(StatusCode::BAD_REQUEST, "unsupported initial project state"),
        },
    };
    let project_key = project_id.as_str().to_string();

    let project = {
        let mut projects = state.projects.lock().expect("projects");
        if projects.contains_key(&project_key) {
            return json_error(StatusCode::CONFLICT, "project already exists");
        }

        let project = ProjectContext::new_with_namespace(
            tenant_id.clone(),
            project_id,
            initial_state,
            ProjectObjectNamespace::for_project(
                state.snapshot_bucket.clone(),
                &tenant_id,
                &ProjectId::new(project_key.clone()).expect("project id"),
            ),
        )
        .with_created_by(session.claims.user_id.clone());
        projects.insert(project_key.clone(), project.clone());
        project
    };

    if let Some(persistence) = &state.persistence
        && persistence.save_project_context(&project).await.is_err()
    {
        state
            .projects
            .lock()
            .expect("projects")
            .remove(&project_key);
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist project",
        );
    }

    let checkpoint = record_audit_event_from_parts_with_fields(
        &state,
        ActorInfo {
            user_id: session.claims.user_id.clone(),
            session_id: session.claims.session_id.clone(),
            ip_address: session.claims.binding.ip_address.clone(),
        },
        ActionType::ConfigChange,
        TargetRef {
            tenant_id: request_context.tenant_id.as_str().to_string(),
            project_id: Some(project.project_id.as_str().to_string()),
            resource_id: format!("projects/{}", project.project_id.as_str()),
        },
        "project created through runtime lifecycle",
        AuditContextFields::builder()
            .field("runtime_created", true)
            .field("project_state", project_state_label(project.state))
            .field(
                "object_bucket",
                project.object_namespace.object_bucket.clone(),
            )
            .field("object_prefix", project.object_namespace.key_prefix.clone())
            .build(),
        ActionResult::Success,
        None,
    )
    .await;

    Json(ProjectCreateResponse {
        project: project_summary_from_context(&project),
        checkpoint_id: checkpoint.checkpoint_id,
        runtime_created: true,
    })
    .into_response()
}

async fn project_state_change_handler(
    State(state): State<Arc<ApiState>>,
    axum::extract::Path(project_id): axum::extract::Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<ProjectStateChangeRequest>,
) -> Response {
    if !can_manage_projects(&session.roles) {
        append_request_audit(
            &state,
            Some(&session),
            Some(project_id.as_str()),
            ActionType::ConfigChange,
            ActionResult::Denied,
            &format!("projects/{project_id}/state"),
            "missing project management role",
        )
        .await;
        return json_error(StatusCode::FORBIDDEN, "project admin role required");
    }

    let Some(next_state) = parse_project_state_label(&payload.next_state) else {
        append_request_audit(
            &state,
            Some(&session),
            Some(project_id.as_str()),
            ActionType::ConfigChange,
            ActionResult::Denied,
            &format!("projects/{project_id}/state"),
            "unsupported project state",
        )
        .await;
        return json_error(StatusCode::BAD_REQUEST, "unsupported project state");
    };

    let (previous_state, updated_project) = {
        let mut projects = state.projects.lock().expect("projects");
        let Some(project) = projects.get_mut(&project_id) else {
            return json_error(StatusCode::NOT_FOUND, "project not found");
        };
        if project.tenant_id != request_context.tenant_id {
            return json_error(StatusCode::NOT_FOUND, "project not found");
        }
        if project.state == ProjectState::Deleted {
            return json_error(StatusCode::NOT_FOUND, "project not found");
        }

        let previous_state = project.state;
        let mut lifecycle = ProjectLifecycle::new(project.state);
        if lifecycle.transition_to(next_state).is_err() {
            return json_error(StatusCode::BAD_REQUEST, "invalid project transition");
        }

        project.state = lifecycle.state();
        if project.state == ProjectState::Deleted {
            project.deletion_reason = payload.reason.clone();
        }
        (previous_state, project.clone())
    };

    let revoked_permissions = match updated_project.state {
        ProjectState::Archived | ProjectState::Deleted => state
            .permissions
            .lock()
            .expect("permission registry")
            .revoke_grants_for_project(&project_id),
        ProjectState::Frozen => {
            state
                .permissions
                .lock()
                .expect("permission registry")
                .suspend_grants_for_project(&project_id);
            0
        }
        ProjectState::Active if previous_state == ProjectState::Frozen => {
            state
                .permissions
                .lock()
                .expect("permission registry")
                .resume_grants_for_project(&project_id);
            0
        }
        _ => 0,
    };

    let cleanup = if matches!(
        updated_project.state,
        ProjectState::Archived | ProjectState::Deleted
    ) {
        match purge_project_snapshots_and_cache(&state, &project_id).await {
            Ok(cleanup) => cleanup,
            Err(response) => return response,
        }
    } else {
        ProjectSnapshotCleanup::default()
    };

    if let Some(persistence) = &state.persistence {
        if persistence
            .save_project_context(&updated_project)
            .await
            .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist project state",
            );
        }
        if stage7_governance::persist_project_grant_state(
            state.clone(),
            &project_id,
            updated_project.state,
        )
        .await
        .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist project permission lifecycle",
            );
        }
        if cleanup.deleted_snapshots > 0
            && persistence
                .delete_snapshots_for_project(&project_id)
                .await
                .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to remove archived project snapshots",
            );
        }
    }

    let checkpoint = append_request_audit(
        &state,
        Some(&session),
        Some(project_id.as_str()),
        ActionType::ConfigChange,
        ActionResult::Success,
        &format!("projects/{project_id}/state"),
        &format!(
            "transitioned {} -> {} ({})",
            project_state_label(previous_state),
            project_state_label(updated_project.state),
            payload.reason.as_deref().unwrap_or("no reason provided")
        ),
    )
    .await;

    Json(ProjectStateChangeResponse {
        project_id,
        previous_state: project_state_label(previous_state).into(),
        current_state: project_state_label(updated_project.state).into(),
        revoked_permissions,
        deleted_snapshots: cleanup.deleted_snapshots,
        deleted_objects: cleanup.deleted_objects,
        checkpoint_id: checkpoint.checkpoint_id,
    })
    .into_response()
}

async fn project_delete_handler(
    State(state): State<Arc<ApiState>>,
    axum::extract::Path(project_id): axum::extract::Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    if !can_manage_projects(&session.roles) {
        append_request_audit(
            &state,
            Some(&session),
            Some(project_id.as_str()),
            ActionType::ConfigChange,
            ActionResult::Denied,
            &format!("projects/{project_id}"),
            "missing project management role",
        )
        .await;
        return json_error(StatusCode::FORBIDDEN, "project admin role required");
    }

    let (previous_state, updated_project) = {
        let mut projects = state.projects.lock().expect("projects");
        let Some(project) = projects.get_mut(&project_id) else {
            return json_error(StatusCode::NOT_FOUND, "project not found");
        };
        if project.tenant_id != request_context.tenant_id || project.state == ProjectState::Deleted
        {
            return json_error(StatusCode::NOT_FOUND, "project not found");
        }

        let previous_state = project.state;
        let mut lifecycle = ProjectLifecycle::new(project.state);
        if lifecycle.transition_to(ProjectState::Deleted).is_err() {
            return json_error(StatusCode::BAD_REQUEST, "invalid project transition");
        }

        project.mark_deleted("project deleted through runtime lifecycle");
        (previous_state, project.clone())
    };

    let revoked_permissions = state
        .permissions
        .lock()
        .expect("permission registry")
        .revoke_grants_for_project(&project_id);

    let cleanup = match purge_project_snapshots_and_cache(&state, &project_id).await {
        Ok(cleanup) => cleanup,
        Err(response) => return response,
    };

    if let Some(persistence) = &state.persistence {
        if persistence
            .save_project_context(&updated_project)
            .await
            .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist project deletion",
            );
        }
        if stage7_governance::persist_project_grant_state(
            state.clone(),
            &project_id,
            updated_project.state,
        )
        .await
        .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist project permission lifecycle",
            );
        }
        if cleanup.deleted_snapshots > 0
            && persistence
                .delete_snapshots_for_project(&project_id)
                .await
                .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist project snapshot cleanup",
            );
        }
    }

    let checkpoint = record_audit_event_from_parts_with_fields(
        &state,
        ActorInfo {
            user_id: session.claims.user_id.clone(),
            session_id: session.claims.session_id.clone(),
            ip_address: session.claims.binding.ip_address.clone(),
        },
        ActionType::ConfigChange,
        TargetRef {
            tenant_id: request_context.tenant_id.as_str().to_string(),
            project_id: Some(project_id.clone()),
            resource_id: format!("projects/{project_id}"),
        },
        "project deleted through runtime lifecycle",
        AuditContextFields::builder()
            .field("previous_state", project_state_label(previous_state))
            .field("current_state", project_state_label(updated_project.state))
            .field("revoked_permissions", revoked_permissions as i64)
            .field("deleted_snapshots", cleanup.deleted_snapshots as i64)
            .field("deleted_objects", cleanup.deleted_objects as i64)
            .field(
                "object_bucket",
                updated_project.object_namespace.object_bucket.clone(),
            )
            .field(
                "object_prefix",
                updated_project.object_namespace.key_prefix.clone(),
            )
            .build(),
        ActionResult::Success,
        None,
    )
    .await;

    Json(ProjectDeleteResponse {
        project_id,
        previous_state: project_state_label(previous_state).into(),
        current_state: project_state_label(updated_project.state).into(),
        object_bucket: updated_project.object_namespace.object_bucket,
        object_prefix: updated_project.object_namespace.key_prefix,
        revoked_permissions,
        deleted_snapshots: cleanup.deleted_snapshots,
        deleted_objects: cleanup.deleted_objects,
        checkpoint_id: checkpoint.checkpoint_id,
    })
    .into_response()
}

async fn config_drift_handler(
    State(state): State<Arc<ApiState>>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    if !session.roles.iter().any(|role| role == &Role::SystemAdmin) {
        return json_error(StatusCode::FORBIDDEN, "system admin role required");
    }

    let baseline = if let Some(persistence) = &state.persistence {
        match persistence.load_runtime_config().await {
            Ok(config) => config,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to load approved config baseline",
                );
            }
        }
    } else {
        state.runtime_config.lock().expect("runtime config").clone()
    };
    let runtime = state.runtime_config.lock().expect("runtime config").clone();
    let drifts = detect_config_drift(&baseline, &runtime)
        .into_iter()
        .map(config_drift_response)
        .collect::<Vec<_>>();

    Json(ConfigDriftResponse { drifts }).into_response()
}

async fn config_change_handler(
    State(state): State<Arc<ApiState>>,
    Extension(session): Extension<AuthenticatedSession>,
    Extension(request_context): Extension<RequestContext>,
    Json(payload): Json<ConfigChangeRequest>,
) -> Response {
    if !session.roles.iter().any(|role| role == &Role::SystemAdmin) {
        append_request_audit(
            &state,
            Some(&session),
            request_context
                .project_id
                .as_ref()
                .map(|project_id| project_id.as_str()),
            ActionType::ConfigChange,
            ActionResult::Denied,
            "config-change",
            "missing system admin role",
        )
        .await;
        return json_error(StatusCode::FORBIDDEN, "system admin role required");
    }

    if enforce_separation_of_duties(&session.roles).is_err() {
        append_request_audit(
            &state,
            Some(&session),
            request_context
                .project_id
                .as_ref()
                .map(|project_id| project_id.as_str()),
            ActionType::ConfigChange,
            ActionResult::Denied,
            "config-change",
            "separation of duties violation",
        )
        .await;
        return json_error(StatusCode::FORBIDDEN, "separation of duties violation");
    }

    state
        .runtime_config
        .lock()
        .expect("runtime config")
        .insert(payload.key.clone(), payload.value.clone());

    let checkpoint = append_request_audit(
        &state,
        Some(&session),
        request_context
            .project_id
            .as_ref()
            .map(|project_id| project_id.as_str()),
        ActionType::ConfigChange,
        ActionResult::Success,
        &payload.key,
        &format!("{}={}", payload.key, payload.value),
    )
    .await;
    let mut version = ConfigVersion::new(&payload.key, &payload.value);
    version.approved_by_user_id = Some(session.claims.user_id.clone());
    if let Some(persistence) = &state.persistence
        && persistence
            .save_config_version(
                &version,
                &payload.value,
                &checkpoint.checkpoint_id,
                "system-admin-direct",
            )
            .await
            .is_err()
    {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist config version",
        );
    }

    let audit_events = state.audit.lock().expect("audit").event_count();

    let _ = request_context;
    Json(ConfigChangeResponse {
        accepted: true,
        version_id: version.version_id,
        checkpoint_id: checkpoint.checkpoint_id,
        audit_events,
    })
    .into_response()
}

async fn credential_rotation_states_handler(
    State(state): State<Arc<ApiState>>,
    Extension(session): Extension<AuthenticatedSession>,
    Extension(request_context): Extension<RequestContext>,
) -> Response {
    if !session.roles.iter().any(|role| role == &Role::SystemAdmin) {
        append_request_audit(
            &state,
            Some(&session),
            request_context
                .project_id
                .as_ref()
                .map(|project_id| project_id.as_str()),
            ActionType::ConfigChange,
            ActionResult::Denied,
            "credential-rotation",
            "missing system admin role",
        )
        .await;
        return json_error(StatusCode::FORBIDDEN, "system admin role required");
    }

    let states = ensure_credential_rotation_states(&state, chrono::Utc::now());
    Json(CredentialRotationStatesResponse {
        states: states
            .into_iter()
            .map(credential_rotation_state_response)
            .collect(),
    })
    .into_response()
}

async fn credential_rotation_run_handler(
    State(state): State<Arc<ApiState>>,
    Extension(session): Extension<AuthenticatedSession>,
    Extension(request_context): Extension<RequestContext>,
    Json(payload): Json<CredentialRotationRunRequest>,
) -> Response {
    if !session.roles.iter().any(|role| role == &Role::SystemAdmin) {
        append_request_audit(
            &state,
            Some(&session),
            request_context
                .project_id
                .as_ref()
                .map(|project_id| project_id.as_str()),
            ActionType::ConfigChange,
            ActionResult::Denied,
            "credential-rotation",
            "missing system admin role",
        )
        .await;
        return json_error(StatusCode::FORBIDDEN, "system admin role required");
    }

    if enforce_separation_of_duties(&session.roles).is_err() {
        append_request_audit(
            &state,
            Some(&session),
            request_context
                .project_id
                .as_ref()
                .map(|project_id| project_id.as_str()),
            ActionType::ConfigChange,
            ActionResult::Denied,
            "credential-rotation",
            "separation of duties violation",
        )
        .await;
        return json_error(StatusCode::FORBIDDEN, "separation of duties violation");
    }

    let actor = actor_from_session(Some(&session));
    let tenant_id = request_context.tenant_id.as_str().to_string();
    let project_id = request_context
        .project_id
        .as_ref()
        .map(|project_id| project_id.as_str().to_string());
    let response =
        run_credential_rotation_cycle(state, actor, tenant_id, project_id, payload, true).await;
    Json(response).into_response()
}

fn extract_authenticated_claims(
    state: &ApiState,
    request: &Request,
) -> Result<AuthenticatedSession, ApiErrorResponse> {
    let Some(token) = extract_request_access_token(request) else {
        return Err(Box::new(json_error(
            StatusCode::UNAUTHORIZED,
            "missing bearer token",
        )));
    };

    let claims = parse_access_token(&token, API_TOKEN_SECRET)
        .map_err(|_| Box::new(json_error(StatusCode::UNAUTHORIZED, "invalid access token")))?;

    if claims.is_expired_at(chrono::Utc::now()) {
        return Err(Box::new(json_error(
            StatusCode::UNAUTHORIZED,
            "access token expired",
        )));
    }

    let sessions = state.sessions.lock().expect("session registry");
    let Some(active) = sessions.active.get(&claims.session_id) else {
        return Err(Box::new(json_error(
            StatusCode::UNAUTHORIZED,
            "session not found",
        )));
    };

    if active.revoked {
        return Err(Box::new(json_error(
            StatusCode::UNAUTHORIZED,
            "session revoked",
        )));
    }

    if active.step_up_required {
        return Err(Box::new(json_step_up_required(
            active.step_up_challenge.as_ref(),
        )));
    }

    let request_ip = extract_ip_address(request.headers());
    let request_device = parse_header(request.headers(), "x-device-fingerprint")
        .unwrap_or_else(|| claims.binding.device_fingerprint.clone());
    if !claims.is_bound_to(&request_ip, &request_device) {
        return Err(Box::new(json_error(
            StatusCode::UNAUTHORIZED,
            "session binding mismatch",
        )));
    }

    Ok(AuthenticatedSession {
        claims,
        roles: active.roles.clone(),
    })
}

async fn append_login_audit(
    state: &Arc<ApiState>,
    user_id: &str,
    tenant_id: &str,
    result: ActionResult,
    context: &str,
) -> AuditCheckpoint {
    record_audit_event_from_parts(
        state,
        ActorInfo {
            user_id: user_id.to_string(),
            session_id: "pre-auth".into(),
            ip_address: "127.0.0.1".into(),
        },
        ActionType::Login,
        TargetRef {
            tenant_id: tenant_id.to_string(),
            project_id: None,
            resource_id: "auth/login".into(),
        },
        context,
        result,
        None,
    )
    .await
}

async fn append_request_audit(
    state: &Arc<ApiState>,
    session: Option<&AuthenticatedSession>,
    project_id: Option<&str>,
    action: ActionType,
    result: ActionResult,
    resource_id: &str,
    context: &str,
) -> AuditCheckpoint {
    let actor = match session {
        Some(session) => ActorInfo {
            user_id: session.claims.user_id.clone(),
            session_id: session.claims.session_id.clone(),
            ip_address: session.claims.binding.ip_address.clone(),
        },
        None => ActorInfo {
            user_id: "anonymous".into(),
            session_id: "anonymous".into(),
            ip_address: "127.0.0.1".into(),
        },
    };
    let target = TargetRef {
        tenant_id: session
            .map(|session| session.claims.tenant_id.clone())
            .unwrap_or_else(|| "unknown".into()),
        project_id: project_id.map(str::to_string),
        resource_id: resource_id.to_string(),
    };
    record_audit_event_from_parts(state, actor, action, target, context, result, None).await
}

pub(crate) async fn record_audit_event_from_parts(
    state: &Arc<ApiState>,
    actor: ActorInfo,
    action: ActionType,
    target: TargetRef,
    context: impl Into<String>,
    result: ActionResult,
    data_fingerprint: Option<String>,
) -> AuditCheckpoint {
    record_audit_event_from_parts_with_fields(
        state,
        actor,
        action,
        target,
        context,
        AuditContextFields::default(),
        result,
        data_fingerprint,
    )
    .await
}

pub(crate) async fn record_audit_event_from_parts_with_fields(
    state: &Arc<ApiState>,
    actor: ActorInfo,
    action: ActionType,
    target: TargetRef,
    context: impl Into<String>,
    context_fields: AuditContextFields,
    result: ActionResult,
    data_fingerprint: Option<String>,
) -> AuditCheckpoint {
    let context = context.into();
    let signer = state
        .audit_signers
        .active_signer()
        .expect("audit checkpoint signer")
        .clone();
    let (event, checkpoint, trail) = {
        let mut audit = state.audit.lock().expect("audit");
        let event = AuditEvent::new_with_fields(
            actor,
            action,
            target,
            context,
            context_fields,
            result,
            data_fingerprint,
            audit.latest_event_hash(),
        );
        let checkpoint = audit.append_with_signer(event.clone(), signer.as_ref());
        (event, checkpoint, audit.clone())
    };

    finalize_audit_event(state, event, checkpoint, trail).await
}

async fn finalize_audit_event(
    state: &Arc<ApiState>,
    event: AuditEvent,
    checkpoint: AuditCheckpoint,
    trail: sdqp_audit::AuditTrail,
) -> AuditCheckpoint {
    if let Some(persistence) = &state.persistence
        && let Err(error) = persistence
            .persist_audit_append(&event, &checkpoint, &trail)
            .await
    {
        tracing::error!(?error, "failed to persist audit append");
    }

    tokio::spawn(stage11_ueba::publish_audit_event(
        state.clone(),
        event.clone(),
    ));
    tokio::spawn(publish_external_audit_forward(
        state.clone(),
        event,
        checkpoint.clone(),
    ));
    tokio::spawn(run_audit_retention(state.clone()));

    checkpoint
}

async fn publish_external_audit_forward(
    state: Arc<ApiState>,
    event: AuditEvent,
    checkpoint: AuditCheckpoint,
) {
    let request = AuditForwardRequest::new(event.clone(), checkpoint.clone());
    let delivery = match state.audit_forwarder.forward_active(&request).await {
        Ok(Some(receipt)) => Some(persistence::StoredAuditForwardDelivery {
            delivery_id: receipt.delivery_id,
            event_id: event.event_id.clone(),
            checkpoint_id: checkpoint.checkpoint_id.clone(),
            provider: receipt.provider,
            destination: receipt.destination,
            status: "success".into(),
            payload_bytes: receipt.payload_bytes,
            error_message: None,
            delivered_at: receipt.delivered_at,
        }),
        Ok(None) => None,
        Err(error) => Some(persistence::StoredAuditForwardDelivery {
            delivery_id: ulid::Ulid::new().to_string(),
            event_id: event.event_id.clone(),
            checkpoint_id: checkpoint.checkpoint_id.clone(),
            provider: state.audit_forwarder.active_provider().to_string(),
            destination: state.audit_forwarder.active_destination(),
            status: "failed".into(),
            payload_bytes: 0,
            error_message: Some(error.to_string()),
            delivered_at: chrono::Utc::now(),
        }),
    };

    if let Some(persistence) = &state.persistence
        && let Some(delivery) = delivery
        && let Err(error) = persistence.save_audit_forward_delivery(&delivery).await
    {
        tracing::warn!(?error, "failed to persist audit forward delivery");
    }
}

async fn run_audit_retention(state: Arc<ApiState>) {
    if !state.audit_retention.enabled {
        return;
    }

    let Some(persistence) = state.persistence.clone() else {
        return;
    };

    if state.audit_retention_running.swap(true, Ordering::AcqRel) {
        return;
    }

    let now = chrono::Utc::now();
    let mut run = persistence::StoredAuditRetentionRun {
        run_id: ulid::Ulid::new().to_string(),
        archived_bundle_id: None,
        archived_events: 0,
        archived_checkpoints: 0,
        purged_bundles: 0,
        archive_path: None,
        status: "success".into(),
        error_message: None,
        created_at: now,
    };

    let result = async {
        let plan = {
            let audit = state.audit.lock().expect("audit");
            build_archive_plan(
                audit.anchor_checkpoint(),
                audit.events(),
                audit.checkpoints(),
                &state.audit_retention,
                now,
            )
        };

        if let Some(plan) = plan {
            if !verify_archive_bundle(&plan.bundle) {
                return Err("generated audit archive bundle failed verification".to_string());
            }

            let archive_path = persistence
                .apply_audit_archive(&plan.bundle)
                .await
                .map_err(|error| error.to_string())?;

            run.archived_bundle_id = Some(plan.bundle.bundle_id.clone());
            run.archived_events = plan.archived_event_count;
            run.archived_checkpoints = plan.archived_checkpoint_count;
            run.archive_path = Some(archive_path.to_string_lossy().to_string());

            let hot_trail = {
                let mut audit = state.audit.lock().expect("audit");
                audit.apply_archive_boundary(plan.bundle.boundary_checkpoint.clone());
                audit.clone()
            };
            persistence
                .persist_audit_replica(&hot_trail)
                .map_err(|error| error.to_string())?;
        }

        run.purged_bundles = persistence
            .cleanup_expired_audit_archives(now)
            .await
            .map_err(|error| error.to_string())?;

        Ok::<(), String>(())
    }
    .await;

    if let Err(error) = result {
        run.status = "failed".into();
        run.error_message = Some(error);
    }

    if (run.archived_bundle_id.is_some() || run.purged_bundles > 0 || run.status != "success")
        && let Err(error) = persistence.save_audit_retention_run(&run).await
    {
        tracing::warn!(?error, "failed to persist audit retention run");
    }

    state
        .audit_retention_running
        .store(false, Ordering::Release);
}

fn build_sso_registry(identity_provider: &IdentityProviderSettings) -> SsoProviderRegistry {
    let saml_entity_id = if identity_provider.saml_entity_id.trim().is_empty() {
        identity_provider.client_id.clone()
    } else {
        identity_provider.saml_entity_id.clone()
    };
    let saml_audience = if identity_provider.saml_audience.trim().is_empty() {
        saml_entity_id.clone()
    } else {
        identity_provider.saml_audience.clone()
    };

    SsoProviderRegistry::from_configs(
        OidcProviderConfig {
            provider: identity_provider.oidc_provider.clone(),
            issuer_url: identity_provider.issuer_url.clone(),
            client_id: identity_provider.client_id.clone(),
            client_secret: identity_provider.client_secret.clone(),
            authorize_url: provider_url(
                &identity_provider.oidc_authorize_url,
                &identity_provider.issuer_url,
                "authorize",
            ),
            token_url: provider_url(
                &identity_provider.oidc_token_url,
                &identity_provider.issuer_url,
                "token",
            ),
            userinfo_url: provider_url(
                &identity_provider.oidc_userinfo_url,
                &identity_provider.issuer_url,
                "userinfo",
            ),
        },
        SamlProviderConfig {
            provider: identity_provider.saml_provider.clone(),
            issuer_url: identity_provider.issuer_url.clone(),
            entity_id: saml_entity_id,
            audience: saml_audience,
            sso_url: provider_url(
                &identity_provider.saml_sso_url,
                &identity_provider.issuer_url,
                "saml/sso",
            ),
            exchange_url: provider_url(
                &identity_provider.saml_exchange_url,
                &identity_provider.issuer_url,
                "saml/exchange",
            ),
        },
    )
    .expect("valid sso provider config")
}

fn build_scim_registry(identity_provider: &IdentityProviderSettings) -> ScimDirectoryRegistry {
    ScimDirectoryRegistry::from_sync_config(ScimSyncConfig {
        provider: identity_provider.scim_provider.clone(),
        base_url: identity_provider.scim_base_url.clone(),
        token: identity_provider.scim_token.clone(),
        tenant_id: identity_provider.scim_tenant_id.clone(),
        page_size: identity_provider.scim_page_size as usize,
        timeout_ms: identity_provider.scim_timeout_ms,
        retry_attempts: identity_provider.scim_retry_attempts as usize,
        retry_backoff_ms: identity_provider.scim_retry_backoff_ms,
        disable_missing_users: identity_provider.scim_disable_missing_users,
        disable_missing_groups: identity_provider.scim_disable_missing_groups,
        delete_missing_users: identity_provider.scim_delete_missing_users,
        delete_missing_groups: identity_provider.scim_delete_missing_groups,
    })
    .expect("valid scim provider config")
}

fn provider_url(explicit: &str, issuer_url: &str, suffix: &str) -> String {
    if explicit.trim().is_empty() {
        format!(
            "{}/{}",
            issuer_url.trim_end_matches('/'),
            suffix.trim_start_matches('/')
        )
    } else {
        explicit.to_string()
    }
}

fn build_runtime_config(settings: &AppSettings) -> HashMap<String, String> {
    HashMap::from([
        (
            "observability.log_filter".into(),
            settings.observability.log_filter.clone(),
        ),
        (
            "identity_provider.oidc_provider".into(),
            settings.identity_provider.oidc_provider.clone(),
        ),
        (
            "identity_provider.saml_provider".into(),
            settings.identity_provider.saml_provider.clone(),
        ),
        (
            "identity_provider.scim_provider".into(),
            settings.identity_provider.scim_provider.clone(),
        ),
        (
            "identity_provider.scim_tenant_id".into(),
            settings.identity_provider.scim_tenant_id.clone(),
        ),
        (
            "identity_provider.scim_page_size".into(),
            settings.identity_provider.scim_page_size.to_string(),
        ),
        (
            "identity_provider.scim_timeout_ms".into(),
            settings.identity_provider.scim_timeout_ms.to_string(),
        ),
        (
            "identity_provider.scim_retry_attempts".into(),
            settings.identity_provider.scim_retry_attempts.to_string(),
        ),
        (
            "identity_provider.scim_retry_backoff_ms".into(),
            settings.identity_provider.scim_retry_backoff_ms.to_string(),
        ),
        (
            "identity_provider.scim_disable_missing_users".into(),
            settings
                .identity_provider
                .scim_disable_missing_users
                .to_string(),
        ),
        (
            "identity_provider.scim_disable_missing_groups".into(),
            settings
                .identity_provider
                .scim_disable_missing_groups
                .to_string(),
        ),
        (
            "identity_provider.scim_delete_missing_users".into(),
            settings
                .identity_provider
                .scim_delete_missing_users
                .to_string(),
        ),
        (
            "identity_provider.scim_delete_missing_groups".into(),
            settings
                .identity_provider
                .scim_delete_missing_groups
                .to_string(),
        ),
        (
            "classification.default_retention_days".into(),
            settings.classification.default_retention_days.to_string(),
        ),
        (
            "classification.restricted_retention_days".into(),
            settings
                .classification
                .restricted_retention_days
                .to_string(),
        ),
        (
            "classification.manual_confirmation_required_level".into(),
            settings
                .classification
                .manual_confirmation_required_level
                .clone(),
        ),
        (
            "classification.default_regulations".into(),
            settings.classification.default_regulations.join(","),
        ),
        (
            "identity_provider.issuer_url".into(),
            settings.identity_provider.issuer_url.clone(),
        ),
        (
            "identity_provider.oidc_authorize_url".into(),
            settings.identity_provider.oidc_authorize_url.clone(),
        ),
        (
            "identity_provider.saml_sso_url".into(),
            settings.identity_provider.saml_sso_url.clone(),
        ),
        (
            "identity_provider.client_id".into(),
            settings.identity_provider.client_id.clone(),
        ),
        ("kms.provider".into(), settings.kms.provider.clone()),
        (
            "kms.master_key_id".into(),
            settings.kms.master_key_id.clone(),
        ),
        ("kms.key_version".into(), settings.kms.key_version.clone()),
        (
            "kms.rotation.enabled".into(),
            settings.kms.rotation.enabled.to_string(),
        ),
        (
            "kms.rotation.cycle_interval_secs".into(),
            settings.kms.rotation.cycle_interval_secs.to_string(),
        ),
        (
            "kms.rotation.batch_limit".into(),
            settings.kms.rotation.batch_limit.to_string(),
        ),
        (
            "kms.rotation.dek_rotation_days".into(),
            settings.kms.rotation.dek_rotation_days.to_string(),
        ),
        (
            "kms.rotation.kek_rotation_days".into(),
            settings.kms.rotation.kek_rotation_days.to_string(),
        ),
        (
            "kms.rotation.allow_dek_rotation".into(),
            settings.kms.rotation.allow_dek_rotation.to_string(),
        ),
        (
            "kms.rotation.allow_kek_rewrap".into(),
            settings.kms.rotation.allow_kek_rewrap.to_string(),
        ),
        (
            "database.clickhouse.http_url".into(),
            settings.database.clickhouse.http_url.clone(),
        ),
        (
            "integrations.tsa.provider".into(),
            settings.integrations.tsa.provider.clone(),
        ),
        (
            "integrations.tsa.authority".into(),
            settings.integrations.tsa.authority.clone(),
        ),
        (
            "integrations.tsa.require_external".into(),
            settings.integrations.tsa.require_external.to_string(),
        ),
        (
            "integrations.blockchain_anchor.provider".into(),
            settings.integrations.blockchain_anchor.provider.clone(),
        ),
        (
            "integrations.blockchain_anchor.network".into(),
            settings.integrations.blockchain_anchor.network.clone(),
        ),
        (
            "integrations.blockchain_anchor.require_external".into(),
            settings
                .integrations
                .blockchain_anchor
                .require_external
                .to_string(),
        ),
        (
            "integrations.dlp.provider".into(),
            settings.integrations.dlp.provider.clone(),
        ),
        (
            "integrations.dlp.provider_id".into(),
            settings.integrations.dlp.provider_id.clone(),
        ),
        (
            "integrations.dlp.default_action".into(),
            settings.integrations.dlp.default_action.clone(),
        ),
        (
            "integrations.hr.provider".into(),
            settings.integrations.hr.provider.clone(),
        ),
        (
            "integrations.hr.approver_resolution.system_fallback_user_id".into(),
            settings
                .integrations
                .hr
                .approver_resolution
                .system_fallback_user_id
                .clone(),
        ),
        (
            "integrations.hr.approver_resolution.escalation_user_ids".into(),
            settings
                .integrations
                .hr
                .approver_resolution
                .escalation_user_ids
                .join(","),
        ),
        (
            "integrations.hr.approver_resolution.max_manager_hops".into(),
            settings
                .integrations
                .hr
                .approver_resolution
                .max_manager_hops
                .to_string(),
        ),
        (
            "integrations.hr.approver_resolution.allow_delegation".into(),
            settings
                .integrations
                .hr
                .approver_resolution
                .allow_delegation
                .to_string(),
        ),
        (
            "integrations.hr.feishu.provider_id".into(),
            settings.integrations.hr.feishu.provider_id.clone(),
        ),
        (
            "integrations.hr.feishu.tenant_key".into(),
            settings.integrations.hr.feishu.tenant_key.clone(),
        ),
        (
            "integrations.hr.feishu.base_url".into(),
            settings.integrations.hr.feishu.base_url.clone(),
        ),
        (
            "integrations.hr.feishu.auth_mode".into(),
            settings.integrations.hr.feishu.auth_mode.clone(),
        ),
        (
            "integrations.hr.feishu.users_path".into(),
            settings.integrations.hr.feishu.users_path.clone(),
        ),
        (
            "integrations.hr.feishu.events_path".into(),
            settings.integrations.hr.feishu.events_path.clone(),
        ),
        (
            "integrations.hr.feishu.timeout_ms".into(),
            settings.integrations.hr.feishu.timeout_ms.to_string(),
        ),
        (
            "integrations.hr.feishu.page_size".into(),
            settings.integrations.hr.feishu.page_size.to_string(),
        ),
        (
            "integrations.hr.workday.provider_id".into(),
            settings.integrations.hr.workday.provider_id.clone(),
        ),
        (
            "integrations.hr.workday.tenant".into(),
            settings.integrations.hr.workday.tenant.clone(),
        ),
        (
            "integrations.hr.workday.base_url".into(),
            settings.integrations.hr.workday.base_url.clone(),
        ),
        (
            "integrations.hr.workday.auth_mode".into(),
            settings.integrations.hr.workday.auth_mode.clone(),
        ),
        (
            "integrations.hr.workday.snapshot_path".into(),
            settings.integrations.hr.workday.snapshot_path.clone(),
        ),
        (
            "integrations.hr.workday.events_path".into(),
            settings.integrations.hr.workday.events_path.clone(),
        ),
        (
            "integrations.hr.workday.timeout_ms".into(),
            settings.integrations.hr.workday.timeout_ms.to_string(),
        ),
        (
            "integrations.hr.workday.page_size".into(),
            settings.integrations.hr.workday.page_size.to_string(),
        ),
        (
            "integrations.hr.sap_successfactors.provider_id".into(),
            settings
                .integrations
                .hr
                .sap_successfactors
                .provider_id
                .clone(),
        ),
        (
            "integrations.hr.sap_successfactors.company_id".into(),
            settings
                .integrations
                .hr
                .sap_successfactors
                .company_id
                .clone(),
        ),
        (
            "integrations.hr.sap_successfactors.base_url".into(),
            settings.integrations.hr.sap_successfactors.base_url.clone(),
        ),
        (
            "integrations.hr.sap_successfactors.auth_mode".into(),
            settings
                .integrations
                .hr
                .sap_successfactors
                .auth_mode
                .clone(),
        ),
        (
            "integrations.hr.sap_successfactors.users_path".into(),
            settings
                .integrations
                .hr
                .sap_successfactors
                .users_path
                .clone(),
        ),
        (
            "integrations.hr.sap_successfactors.events_path".into(),
            settings
                .integrations
                .hr
                .sap_successfactors
                .events_path
                .clone(),
        ),
        (
            "integrations.hr.sap_successfactors.timeout_ms".into(),
            settings
                .integrations
                .hr
                .sap_successfactors
                .timeout_ms
                .to_string(),
        ),
        (
            "integrations.hr.sap_successfactors.page_size".into(),
            settings
                .integrations
                .hr
                .sap_successfactors
                .page_size
                .to_string(),
        ),
        (
            "integrations.hr.ldap.provider_id".into(),
            settings.integrations.hr.ldap.provider_id.clone(),
        ),
        (
            "integrations.hr.ldap.url".into(),
            settings.integrations.hr.ldap.url.clone(),
        ),
        (
            "integrations.hr.ldap.auth_mode".into(),
            settings.integrations.hr.ldap.auth_mode.clone(),
        ),
        (
            "integrations.hr.ldap.tls_mode".into(),
            settings.integrations.hr.ldap.tls_mode.clone(),
        ),
        (
            "integrations.hr.ldap.base_dn".into(),
            settings.integrations.hr.ldap.base_dn.clone(),
        ),
        (
            "integrations.hr.ldap.search_filter".into(),
            settings.integrations.hr.ldap.search_filter.clone(),
        ),
        (
            "integrations.hr.ldap.search_scope".into(),
            settings.integrations.hr.ldap.search_scope.clone(),
        ),
        (
            "integrations.hr.ldap.changed_since_attribute".into(),
            settings
                .integrations
                .hr
                .ldap
                .changed_since_attribute
                .clone(),
        ),
        (
            "integrations.hr.ldap.page_size".into(),
            settings.integrations.hr.ldap.page_size.to_string(),
        ),
        (
            "integrations.hr.ldap.ldapsearch_binary".into(),
            settings.integrations.hr.ldap.ldapsearch_binary.clone(),
        ),
        (
            "security.credential_rotation.enabled".into(),
            settings.security.credential_rotation.enabled.to_string(),
        ),
        (
            "security.credential_rotation.interval_secs".into(),
            settings
                .security
                .credential_rotation
                .interval_secs
                .to_string(),
        ),
        (
            "security.credential_rotation.retry_backoff_secs".into(),
            settings
                .security
                .credential_rotation
                .retry_backoff_secs
                .to_string(),
        ),
        (
            "security.credential_rotation.max_attempts".into(),
            settings
                .security
                .credential_rotation
                .max_attempts
                .to_string(),
        ),
    ])
}

fn can_manage_projects(roles: &[Role]) -> bool {
    roles
        .iter()
        .any(|role| matches!(role, Role::SystemAdmin | Role::ProjectAdmin))
}

fn project_summary_from_context(project: &ProjectContext) -> ProjectSummaryResponse {
    ProjectSummaryResponse {
        project_id: project.project_id.as_str().into(),
        tenant_id: project.tenant_id.as_str().into(),
        state: project_state_label(project.state).into(),
        object_bucket: project.object_namespace.object_bucket.clone(),
        object_prefix: project.object_namespace.key_prefix.clone(),
        can_accept_new_permissions: project.state.can_accept_new_permissions(),
        can_export: project.state.can_export(),
        read_only: project.state.is_read_only(),
    }
}

fn parse_project_state_label(value: &str) -> Option<ProjectState> {
    match value.trim().to_ascii_lowercase().as_str() {
        "created" => Some(ProjectState::Created),
        "active" => Some(ProjectState::Active),
        "frozen" => Some(ProjectState::Frozen),
        "archived" => Some(ProjectState::Archived),
        "deleted" => Some(ProjectState::Deleted),
        _ => None,
    }
}

fn project_state_label(state: ProjectState) -> &'static str {
    match state {
        ProjectState::Created => "created",
        ProjectState::Active => "active",
        ProjectState::Frozen => "frozen",
        ProjectState::Archived => "archived",
        ProjectState::Deleted => "deleted",
    }
}

fn config_drift_response(drift: ConfigDrift) -> ConfigDriftEntryResponse {
    ConfigDriftEntryResponse {
        key: drift.key,
        expected: drift.expected,
        actual: drift.actual,
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ProjectSnapshotCleanup {
    deleted_snapshots: usize,
    deleted_objects: usize,
}

async fn purge_project_snapshots_and_cache(
    state: &ApiState,
    project_id: &str,
) -> Result<ProjectSnapshotCleanup, Response> {
    let purged_records = state
        .snapshots
        .lock()
        .expect("snapshot store")
        .purge_project_snapshots(project_id, "project lifecycle namespace purge", Utc::now());
    if purged_records.is_empty() {
        return Ok(ProjectSnapshotCleanup::default());
    }

    let purged_snapshot_ids = purged_records
        .iter()
        .map(|record| record.snapshot_id.clone())
        .collect::<Vec<_>>();
    state
        .cache_index
        .lock()
        .expect("cache index")
        .retain(|_, snapshot_id| {
            !purged_snapshot_ids
                .iter()
                .any(|deleted| deleted == snapshot_id)
        });

    let mut deleted_objects = 0usize;
    for record in &purged_records {
        let exists = state
            .snapshot_objects
            .exists(&record.lifecycle.object_bucket, &record.storage_key)
            .await
            .map_err(|error| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("failed to inspect project snapshot object: {error}"),
                )
            })?;
        if exists {
            state
                .snapshot_objects
                .delete_object(&record.lifecycle.object_bucket, &record.storage_key)
                .await
                .map_err(|error| {
                    json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("failed to purge project snapshot object: {error}"),
                    )
                })?;
            deleted_objects += 1;
        }
    }

    Ok(ProjectSnapshotCleanup {
        deleted_snapshots: purged_records.len(),
        deleted_objects,
    })
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.to_string(),
            step_up_required: None,
            step_up_challenge: None,
        }),
    )
        .into_response()
}

fn json_step_up_required(challenge: Option<&StepUpChallenge>) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            error: "step-up authentication required".into(),
            step_up_required: Some(true),
            step_up_challenge: challenge.map(step_up_challenge_response),
        }),
    )
        .into_response()
}

fn extract_ip_address(headers: &HeaderMap) -> String {
    parse_header(headers, "x-forwarded-for").unwrap_or_else(|| "127.0.0.1".into())
}

fn parse_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)?
        .to_str()
        .ok()
        .map(|value| value.to_string())
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(str::to_string)
}

fn extract_request_access_token(request: &Request) -> Option<String> {
    extract_bearer_token(request.headers()).or_else(|| {
        if is_websocket_upgrade(request.headers()) {
            parse_query_param(request.uri().query(), "access_token")
        } else {
            None
        }
    })
}

fn parse_scoped_request_value(
    request: &Request,
    header_name: &str,
    query_name: &str,
) -> Option<String> {
    parse_header(request.headers(), header_name).or_else(|| {
        if is_websocket_upgrade(request.headers()) {
            parse_query_param(request.uri().query(), query_name)
        } else {
            None
        }
    })
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
        || headers.contains_key("sec-websocket-key")
}

fn parse_query_param(query: Option<&str>, target: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next()?;
        if key != target {
            return None;
        }
        Some(parts.next().unwrap_or_default().to_string())
    })
}

pub(crate) fn build_user_directory(security: &SecuritySettings) -> HashMap<String, UserAccount> {
    let registry = build_mfa_registry(security);
    HashMap::from([
        (
            "sysadmin".into(),
            UserAccount {
                username: "sysadmin".into(),
                display_name: "System Administrator".into(),
                email: "sysadmin@example.internal".into(),
                password: "password123".into(),
                user_id: "user-sysadmin".into(),
                tenant_id: "tenant-alpha".into(),
                external_id: None,
                active: true,
                auth_source: TrustedAuthenticationSource::LocalPassword,
                roles: vec![Role::SystemAdmin],
                mfa_method: MfaMethod::WebAuthn,
                mfa_registration: Some(registry.bootstrap_registration(
                    "tenant-alpha",
                    "user-sysadmin",
                    "sysadmin",
                    &MfaMethod::WebAuthn,
                )),
            },
        ),
        (
            "analyst".into(),
            UserAccount {
                username: "analyst".into(),
                display_name: "Primary Analyst".into(),
                email: "analyst@example.internal".into(),
                password: "password123".into(),
                user_id: "user-analyst".into(),
                tenant_id: "tenant-alpha".into(),
                external_id: None,
                active: true,
                auth_source: TrustedAuthenticationSource::LocalPassword,
                roles: vec![Role::Analyst],
                mfa_method: MfaMethod::Totp,
                mfa_registration: Some(registry.bootstrap_registration(
                    "tenant-alpha",
                    "user-analyst",
                    "analyst",
                    &MfaMethod::Totp,
                )),
            },
        ),
        (
            "mixed".into(),
            UserAccount {
                username: "mixed".into(),
                display_name: "Mixed Role User".into(),
                email: "mixed@example.internal".into(),
                password: "password123".into(),
                user_id: "user-mixed".into(),
                tenant_id: "tenant-alpha".into(),
                external_id: None,
                active: true,
                auth_source: TrustedAuthenticationSource::LocalPassword,
                roles: vec![Role::SystemAdmin, Role::Analyst],
                mfa_method: MfaMethod::Totp,
                mfa_registration: Some(registry.bootstrap_registration(
                    "tenant-alpha",
                    "user-mixed",
                    "mixed",
                    &MfaMethod::Totp,
                )),
            },
        ),
        (
            "manager".into(),
            UserAccount {
                username: "manager".into(),
                display_name: "Primary Manager".into(),
                email: "manager@example.internal".into(),
                password: "password123".into(),
                user_id: "user-manager-a".into(),
                tenant_id: "tenant-alpha".into(),
                external_id: Some("feishu-manager-a".into()),
                active: true,
                auth_source: TrustedAuthenticationSource::LocalPassword,
                roles: vec![Role::Approver],
                mfa_method: MfaMethod::Totp,
                mfa_registration: Some(registry.bootstrap_registration(
                    "tenant-alpha",
                    "user-manager-a",
                    "manager",
                    &MfaMethod::Totp,
                )),
            },
        ),
        (
            "security".into(),
            UserAccount {
                username: "security".into(),
                display_name: "Security Approver".into(),
                email: "security@example.internal".into(),
                password: "password123".into(),
                user_id: "user-security-a".into(),
                tenant_id: "tenant-alpha".into(),
                external_id: Some("ldap-security-a".into()),
                active: true,
                auth_source: TrustedAuthenticationSource::LocalPassword,
                roles: vec![Role::Approver, Role::Auditor],
                mfa_method: MfaMethod::Totp,
                mfa_registration: Some(registry.bootstrap_registration(
                    "tenant-alpha",
                    "user-security-a",
                    "security",
                    &MfaMethod::Totp,
                )),
            },
        ),
        (
            "delegate".into(),
            UserAccount {
                username: "delegate".into(),
                display_name: "Delegated Approver".into(),
                email: "delegate@example.internal".into(),
                password: "password123".into(),
                user_id: "user-security-b".into(),
                tenant_id: "tenant-alpha".into(),
                external_id: Some("csv-security-b".into()),
                active: true,
                auth_source: TrustedAuthenticationSource::LocalPassword,
                roles: vec![Role::Approver],
                mfa_method: MfaMethod::Totp,
                mfa_registration: Some(registry.bootstrap_registration(
                    "tenant-alpha",
                    "user-security-b",
                    "delegate",
                    &MfaMethod::Totp,
                )),
            },
        ),
    ])
}

pub(crate) fn build_project_registry() -> HashMap<String, ProjectContext> {
    HashMap::from([
        (
            "project-alpha".into(),
            ProjectContext::new(
                TenantId::new("tenant-alpha").expect("tenant"),
                ProjectId::new("project-alpha").expect("project"),
                ProjectState::Active,
            ),
        ),
        (
            "project-archive".into(),
            ProjectContext::new(
                TenantId::new("tenant-alpha").expect("tenant"),
                ProjectId::new("project-archive").expect("project"),
                ProjectState::Archived,
            ),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::observability::HttpMetrics;
    use super::{API_TOKEN_SECRET, ApiState, build_user_directory, health_payload};
    use sdqp_config::AppSettings;
    use sdqp_contracts::HealthStatus;
    use sdqp_core::{RequestContext, TenantId, UserId};
    use sdqp_system_security::{
        SessionBinding, SessionPolicy, issue_access_token, parse_access_token,
    };

    #[test]
    fn health_payload_uses_ready_status() {
        let settings = AppSettings::local_dev();
        let payload = health_payload(&settings.api);
        assert_eq!(payload.service, "sdqp-api");
        assert_eq!(payload.status, HealthStatus::Ready);
        assert_eq!(payload.phase, "phase0");
    }

    #[test]
    fn user_directory_contains_expected_accounts() {
        let directory = build_user_directory(&AppSettings::local_dev().security);
        assert!(directory.contains_key("sysadmin"));
        assert!(directory.contains_key("analyst"));
    }

    #[test]
    fn api_state_bootstraps_projects() {
        let state = ApiState::new(AppSettings::local_dev().api);
        assert!(
            state
                .projects
                .lock()
                .expect("projects")
                .contains_key("project-alpha")
        );
    }

    #[test]
    fn access_tokens_round_trip_through_security_helpers() {
        let request = RequestContext::new(
            TenantId::new("tenant-alpha").expect("tenant"),
            UserId::new("user-analyst").expect("user"),
        );
        let claims = SessionPolicy { ttl_minutes: 15 }.issue(
            &request,
            SessionBinding {
                ip_address: "127.0.0.1".into(),
                device_fingerprint: "device-a".into(),
            },
        );

        let token = issue_access_token(&claims, API_TOKEN_SECRET).expect("token");
        let parsed = parse_access_token(&token, API_TOKEN_SECRET).expect("parsed");
        assert_eq!(parsed.user_id, "user-analyst");
    }

    #[test]
    fn metrics_payload_counts_responses() {
        let metrics = HttpMetrics::default();
        metrics.record(http::StatusCode::OK);
        metrics.record(http::StatusCode::FORBIDDEN);

        let payload = metrics.render_prometheus("sdqp-api");
        assert!(payload.contains("sdqp_http_requests_total{service=\"sdqp-api\"} 2"));
        assert!(payload.contains("sdqp_http_responses_2xx_total{service=\"sdqp-api\"} 1"));
        assert!(payload.contains("sdqp_http_responses_4xx_total{service=\"sdqp-api\"} 1"));
    }
}
