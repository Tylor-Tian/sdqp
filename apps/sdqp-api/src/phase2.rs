use std::{sync::Arc, time::Duration};

use axum::{
    Extension, Json,
    extract::{
        Path, Query as QueryParams, State,
        ws::{Message, WebSocketUpgrade},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{Duration as ChronoDuration, Utc};
use sdqp_audit::{
    ActionResult, ActionType, ActorInfo, AuditContextFields, AuditContextValue, TargetRef,
};
use sdqp_config::AppSettings;
use sdqp_core::{
    FieldSelector, Pagination, ProjectId, RequestContext, TenantId, UserId, compute_sha256_hex,
};
use sdqp_data_classification::{ClassificationStatus, classify_fields};
use sdqp_data_view::encode_rows_to_parquet;
use sdqp_datasource_adapter::{
    AdapterHealthSnapshot, AdapterLifecycleScheduler, AdapterRegistry, AdapterSchedulerConfig,
    AdapterSchedulerErrorKind, DataSourceConfig, ExecutionMode, QueryTaskRegistry,
    ScheduledQueryRequest, SourceType, StoredQueryTask, UnifiedQuery,
    task::{QueryTaskSnapshot, QueryTaskState},
};
use sdqp_encryption::{
    DecryptionPipelineConfig, EnvelopeCipher, InMemorySnapshotStore, KmsClientConfig, KmsProvider,
    ProviderEnvelopeCipher, SnapshotStore, SnapshotWriteRequest, build_kms_service_registry,
};
use sdqp_permission_engine::{
    FieldPermission, PermissionGrant, PermissionRegistry, apply_grant_to_query,
};
use sdqp_tenant_isolation::{ProjectContext, ProjectObjectNamespace};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::{ApiErrorResponse, ApiState, AuthenticatedSession, json_error, stage7_governance};

#[derive(Debug, Clone)]
pub(crate) struct TaskScope {
    pub project_scope_key: String,
    pub tenant_id: String,
    pub project_id: String,
    pub user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionApplicationRequest {
    pub data_source_id: String,
    pub requested_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveGrantResponse {
    pub grant_id: String,
    pub fields: Vec<String>,
    pub condition_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuerySubmitRequest {
    pub data_source_id: String,
    pub source_type: String,
    pub fields: Vec<String>,
    #[serde(default)]
    pub priority: Option<QueryPriorityLevel>,
    pub timeout_secs: Option<u64>,
    pub page_size: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryPriorityLevel {
    Low,
    Normal,
    High,
    Critical,
}

impl QueryPriorityLevel {
    fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    fn value(self) -> i32 {
        match self {
            Self::Low => 25,
            Self::Normal => 50,
            Self::High => 75,
            Self::Critical => 100,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryPriorityResponse {
    pub label: String,
    pub value: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRuntimeControlSurface {
    pub can_cancel: bool,
    pub can_retry: bool,
    pub can_access_snapshot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryWorkbenchRuntimeState {
    pub task_id: String,
    pub priority: QueryPriorityResponse,
    pub runtime_state: String,
    pub adapter_runtime_state: Option<String>,
    pub adapter_availability: Option<String>,
    pub secure_snapshot_access: String,
    pub controls: QueryRuntimeControlSurface,
}

impl QueryWorkbenchRuntimeState {
    pub(crate) fn from_snapshot(priority_value: i32, snapshot: &QueryTaskSnapshot) -> Self {
        Self::from_snapshot_with_adapter(priority_value, snapshot, None)
    }

    fn from_snapshot_with_adapter(
        priority_value: i32,
        snapshot: &QueryTaskSnapshot,
        adapter_runtime: Option<&AdapterHealthSnapshot>,
    ) -> Self {
        let runtime_state = query_task_state_label(&snapshot.state);
        let can_cancel = matches!(
            snapshot.state,
            QueryTaskState::Pending | QueryTaskState::Running
        );
        let can_retry = matches!(
            snapshot.state,
            QueryTaskState::Failed | QueryTaskState::Cancelled
        );
        let can_access_snapshot =
            matches!(snapshot.state, QueryTaskState::Completed) && snapshot.snapshot_id.is_some();
        let secure_snapshot_access = if can_access_snapshot {
            if snapshot.cache_hit {
                "authorized_cache_snapshot"
            } else {
                "authorized_encrypted_snapshot"
            }
        } else {
            match snapshot.state {
                QueryTaskState::Pending | QueryTaskState::Running => "pending_encrypted_snapshot",
                QueryTaskState::Failed => "blocked_failed_task",
                QueryTaskState::Cancelled => "blocked_cancelled_task",
                QueryTaskState::Completed => "blocked_missing_snapshot",
            }
        }
        .to_string();

        Self {
            task_id: snapshot.task_id.clone(),
            priority: QueryPriorityResponse {
                label: query_priority_label(priority_value).to_string(),
                value: priority_value,
            },
            runtime_state,
            adapter_runtime_state: adapter_runtime
                .map(|runtime| format!("{:?}", runtime.lifecycle_state)),
            adapter_availability: adapter_runtime
                .map(|runtime| format!("{:?}", runtime.availability)),
            secure_snapshot_access,
            controls: QueryRuntimeControlSurface {
                can_cancel,
                can_retry,
                can_access_snapshot,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuerySubmitResponse {
    pub task_id: String,
    pub status: String,
    pub websocket_path: String,
    pub priority: QueryPriorityResponse,
    pub runtime: QueryWorkbenchRuntimeState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTaskStatusResponse {
    pub task_id: String,
    pub state: String,
    pub snapshot_id: Option<String>,
    pub cache_hit: bool,
    pub error: Option<String>,
    pub priority: QueryPriorityResponse,
    pub runtime: QueryWorkbenchRuntimeState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelTaskResponse {
    pub task_id: String,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterRegistrationRequest {
    pub data_source_id: String,
    pub source_type: String,
    pub connection_uri: String,
    #[serde(default)]
    pub adapter_config: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterHealthResponse {
    pub adapters: Vec<AdapterHealthSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadataResponse {
    pub snapshot_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub owner_user_id: String,
    pub grant_id: String,
    pub storage_key: String,
    pub data_source_id: String,
    pub row_count: usize,
    pub encrypted: bool,
    pub dek_id: String,
    pub kek_id: String,
    pub kms_provider: String,
    pub key_version: Option<String>,
    pub algorithm: String,
    pub payload_format: String,
    pub columns: Vec<String>,
    pub data_fingerprint: String,
    pub retention_until: chrono::DateTime<chrono::Utc>,
    pub delete_state: String,
    pub last_rewrapped_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheKeyParts {
    project_scope_key: String,
    grant_id: String,
    data_source_id: String,
    source_type: String,
    fields: Vec<String>,
    timeout_secs: u64,
    page_size: Option<usize>,
    cursor: Option<String>,
}

#[derive(Debug, Clone)]
struct PreparedQueryExecution {
    task_id: String,
    cache_key: String,
    grant_id: String,
    grant_valid_until: chrono::DateTime<chrono::Utc>,
    data_source_id: String,
    source_type: SourceType,
    query: UnifiedQuery,
    stored_task: StoredQueryTask,
    session: AuthenticatedSession,
    request_context: RequestContext,
    storage_namespace: ProjectObjectNamespace,
}

pub(crate) fn build_permission_registry() -> PermissionRegistry {
    let mut registry = PermissionRegistry::default();

    registry.register_grant(PermissionGrant::active(
        "user-analyst",
        "project-alpha",
        "datasource-rest",
        vec![
            FieldPermission {
                field_name: "employee_id".into(),
                denied: false,
            },
            FieldPermission {
                field_name: "department".into(),
                denied: false,
            },
        ],
        vec![sdqp_core::FilterCondition {
            field: "department".into(),
            operator: sdqp_core::FilterOperator::Eq,
            value: "fraud".into(),
        }],
    ));
    registry.register_grant(PermissionGrant::active(
        "user-analyst",
        "project-alpha",
        "datasource-rpc",
        vec![FieldPermission {
            field_name: "employee_id".into(),
            denied: false,
        }],
        Vec::new(),
    ));
    registry.register_grant(PermissionGrant::active(
        "user-analyst",
        "project-alpha",
        "datasource-hive",
        vec![
            FieldPermission {
                field_name: "employee_id".into(),
                denied: false,
            },
            FieldPermission {
                field_name: "department".into(),
                denied: false,
            },
        ],
        Vec::new(),
    ));

    registry
}

pub(crate) type QueryRuntime = (
    PermissionRegistry,
    QueryTaskRegistry,
    InMemorySnapshotStore,
    std::collections::HashMap<String, String>,
    std::collections::HashMap<String, TaskScope>,
    AdapterLifecycleScheduler,
    Arc<AdapterRegistry>,
    Arc<dyn EnvelopeCipher>,
    DecryptionPipelineConfig,
);

pub(crate) fn build_query_runtime(settings: &AppSettings) -> QueryRuntime {
    let pipeline = DecryptionPipelineConfig {
        require_masking: true,
        require_watermark: true,
    };
    pipeline.validate().expect("phase2 pipeline must be valid");

    let cipher = build_kms_cipher(settings);

    let adapter_registry = Arc::new(AdapterRegistry::development());
    let adapter_scheduler = AdapterLifecycleScheduler::from_started_configs(
        adapter_registry.clone(),
        default_adapter_configs(),
        AdapterSchedulerConfig::default(),
    );

    (
        build_permission_registry(),
        QueryTaskRegistry::default(),
        InMemorySnapshotStore::default(),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        adapter_scheduler,
        adapter_registry,
        cipher,
        pipeline,
    )
}

fn default_adapter_configs() -> Vec<DataSourceConfig> {
    vec![
        DataSourceConfig {
            data_source_id: "datasource-rest".into(),
            source_type: SourceType::Rest,
            connection_uri: "mock://rest".into(),
            adapter_config: serde_json::json!({"max_concurrent_tasks": 8}),
        },
        DataSourceConfig {
            data_source_id: "datasource-rpc".into(),
            source_type: SourceType::Rpc,
            connection_uri: "mock://rpc".into(),
            adapter_config: serde_json::json!({"max_concurrent_tasks": 8}),
        },
        default_hive_adapter_config(),
    ]
}

fn default_hive_adapter_config() -> DataSourceConfig {
    let connection_uri =
        std::env::var("SDQP_HIVE_CONNECTION_URI").unwrap_or_else(|_| "mock://hive".into());
    if connection_uri.starts_with("mock://") {
        return DataSourceConfig {
            data_source_id: "datasource-hive".into(),
            source_type: SourceType::Hive,
            connection_uri,
            adapter_config: serde_json::json!({"max_concurrent_tasks": 2}),
        };
    }

    let mut adapter_config = serde_json::json!({
        "provider": std::env::var("SDQP_HIVE_PROVIDER").unwrap_or_else(|_| "beeline".into()),
        "command": std::env::var("SDQP_HIVE_COMMAND").unwrap_or_else(|_| "beeline".into()),
        "username": std::env::var("SDQP_HIVE_USERNAME").unwrap_or_else(|_| "hive".into()),
        "table": std::env::var("SDQP_HIVE_TABLE").unwrap_or_else(|_| "sdqp_fixture_employees".into()),
        "max_concurrent_tasks": env_u64("SDQP_HIVE_MAX_CONCURRENT_TASKS", 2),
        "poll_interval_ms": env_u64("SDQP_HIVE_POLL_INTERVAL_MS", 100)
    });
    if let Ok(password) = std::env::var("SDQP_HIVE_PASSWORD")
        && !password.trim().is_empty()
    {
        adapter_config["password"] = serde_json::Value::String(password);
    }
    if let Ok(args_json) = std::env::var("SDQP_HIVE_COMMAND_ARGS_JSON")
        && let Ok(args) = serde_json::from_str::<serde_json::Value>(&args_json)
    {
        adapter_config["command_args"] = args;
    }

    DataSourceConfig {
        data_source_id: "datasource-hive".into(),
        source_type: SourceType::Hive,
        connection_uri,
        adapter_config,
    }
}

fn env_u64(key: &str, default_value: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default_value)
}

fn build_kms_cipher(settings: &AppSettings) -> Arc<dyn EnvelopeCipher> {
    let provider =
        KmsProvider::parse(&settings.kms.provider).expect("phase2 kms provider must be valid");
    let registry = build_kms_service_registry(&KmsClientConfig {
        provider,
        endpoint: non_empty_option(&settings.kms.endpoint),
        master_key_id: settings.kms.master_key_id.clone(),
        key_ring: non_empty_option(&settings.kms.key_ring),
        auth_token: non_empty_option(&settings.kms.auth_token),
        region: non_empty_option(&settings.kms.region),
        key_version: non_empty_option(&settings.kms.key_version),
    })
    .expect("phase2 kms registry must build");
    let (active_provider, services) = registry.into_parts();
    Arc::new(ProviderEnvelopeCipher::new(active_provider, services))
}

fn non_empty_option(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub async fn permission_application_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(project_context): Extension<ProjectContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<PermissionApplicationRequest>,
) -> Response {
    if !project_context.state.can_accept_new_permissions() {
        append_phase2_audit(
            &state,
            &session,
            &request_context,
            ActionType::PermissionApply,
            ActionResult::Denied,
            "permission-application",
            "project does not accept new permissions",
            None,
        )
        .await;
        return json_error(
            StatusCode::FORBIDDEN,
            "project does not accept new permissions",
        );
    }

    let project_id = request_context
        .project_id
        .as_ref()
        .expect("project middleware must inject project context")
        .as_str()
        .to_string();

    let application = if state.persistence.is_some() {
        match stage7_governance::submit_persistent_permission_application(
            state.clone(),
            &session,
            &project_id,
            payload.data_source_id,
            payload.requested_fields,
        )
        .await
        {
            Ok(application) => application,
            Err(error) => {
                append_phase2_audit(
                    &state,
                    &session,
                    &request_context,
                    ActionType::PermissionApply,
                    error.audit_result(),
                    "permission-application",
                    error.message(),
                    None,
                )
                .await;
                return json_error(error.status(), error.message());
            }
        }
    } else {
        state
            .permissions
            .lock()
            .expect("permission registry")
            .submit_application(
                session.claims.user_id.clone(),
                project_id,
                payload.data_source_id,
                payload.requested_fields,
            )
    };

    append_phase2_audit(
        &state,
        &session,
        &request_context,
        ActionType::PermissionApply,
        ActionResult::Success,
        &application.application_id,
        "permission application submitted",
        None,
    )
    .await;

    Json(application).into_response()
}

pub async fn active_grant_handler(
    State(state): State<Arc<ApiState>>,
    Path(data_source_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let Some(project_id) = request_context.project_id.as_ref().map(|id| id.as_str()) else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "missing project scope");
    };

    let grant = state
        .permissions
        .lock()
        .expect("permission registry")
        .merged_active_grant(&session.claims.user_id, project_id, &data_source_id);

    let Some(grant) = grant else {
        append_phase2_audit(
            &state,
            &session,
            &request_context,
            ActionType::Query,
            ActionResult::Denied,
            &data_source_id,
            "active permission grant not found",
            None,
        )
        .await;
        return json_error(StatusCode::NOT_FOUND, "active permission grant not found");
    };

    let condition_count = grant.condition_count();
    Json(ActiveGrantResponse {
        grant_id: grant.grant_id,
        fields: grant
            .fields
            .into_iter()
            .filter(|field| !field.denied)
            .map(|field| field.field_name)
            .collect(),
        condition_count,
    })
    .into_response()
}

pub async fn adapter_health_handler(State(state): State<Arc<ApiState>>) -> Response {
    Json(AdapterHealthResponse {
        adapters: state.adapter_scheduler.refresh_all_health().await,
    })
    .into_response()
}

pub async fn register_adapter_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<AdapterRegistrationRequest>,
) -> Response {
    let Some(source_type) = parse_source_type(&payload.source_type) else {
        return json_error(StatusCode::BAD_REQUEST, "unsupported source_type");
    };
    let data_source_id = payload.data_source_id.clone();
    let config = DataSourceConfig {
        data_source_id: payload.data_source_id,
        source_type,
        connection_uri: payload.connection_uri,
        adapter_config: payload.adapter_config,
    };
    match state.adapter_scheduler.register_adapter(config).await {
        Ok(snapshot) => {
            append_phase2_audit(
                &state,
                &session,
                &request_context,
                ActionType::Query,
                ActionResult::Success,
                &data_source_id,
                "adapter runtime registered",
                None,
            )
            .await;
            Json(snapshot).into_response()
        }
        Err(error) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &error),
    }
}

pub async fn start_adapter_handler(
    State(state): State<Arc<ApiState>>,
    Path(data_source_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    match state.adapter_scheduler.start_adapter(&data_source_id).await {
        Ok(snapshot) => {
            append_phase2_audit(
                &state,
                &session,
                &request_context,
                ActionType::Query,
                ActionResult::Success,
                &data_source_id,
                "adapter runtime started",
                None,
            )
            .await;
            Json(snapshot).into_response()
        }
        Err(error) => json_error(StatusCode::NOT_FOUND, &error),
    }
}

pub async fn stop_adapter_handler(
    State(state): State<Arc<ApiState>>,
    Path(data_source_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    match state.adapter_scheduler.stop_adapter(&data_source_id).await {
        Ok(snapshot) => {
            append_phase2_audit(
                &state,
                &session,
                &request_context,
                ActionType::Query,
                ActionResult::Success,
                &data_source_id,
                "adapter runtime stopped",
                None,
            )
            .await;
            Json(snapshot).into_response()
        }
        Err(error) => json_error(StatusCode::NOT_FOUND, &error),
    }
}

pub async fn submit_query_handler(
    State(state): State<Arc<ApiState>>,
    Extension(request_context): Extension<RequestContext>,
    Extension(project_context): Extension<ProjectContext>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(payload): Json<QuerySubmitRequest>,
) -> Response {
    let data_source_id = payload.data_source_id.clone();
    let source_type = payload.source_type.clone();
    let requested_fields = payload.fields.clone();
    let prepared = match prepare_query_execution(
        &state,
        &request_context,
        &project_context,
        &session,
        payload,
    ) {
        Ok(prepared) => prepared,
        Err(response) => {
            let result = if response.status() == StatusCode::FORBIDDEN {
                ActionResult::Denied
            } else {
                ActionResult::Failure
            };
            append_query_audit(
                &state,
                &session,
                &request_context,
                QueryAuditDetails {
                    result,
                    resource_id: &data_source_id,
                    context: "query preparation failed",
                    data_source_id: &data_source_id,
                    source_type: &source_type,
                    requested_fields: requested_fields.clone(),
                    query_state: "prepare_failed",
                    extra_fields: Vec::new(),
                    data_fingerprint: None,
                },
            )
            .await;
            return *response;
        }
    };
    let task_id = prepared.task_id.clone();
    if let Some(persistence) = &state.persistence {
        let pending_snapshot = state
            .tasks
            .lock()
            .expect("task registry")
            .snapshot(&task_id)
            .expect("pending snapshot");
        if persistence
            .save_task(&prepared.stored_task, &pending_snapshot)
            .await
            .is_err()
        {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to persist query task",
            );
        }
    }

    if state.use_external_query_worker() {
        append_query_audit(
            &state,
            &session,
            &request_context,
            QueryAuditDetails {
                result: ActionResult::Success,
                resource_id: &task_id,
                context: "query submitted",
                data_source_id: &prepared.data_source_id,
                source_type: source_type_label(&prepared.source_type),
                requested_fields: prepared
                    .query
                    .fields
                    .iter()
                    .map(|field| field.as_str().to_string())
                    .collect::<Vec<_>>(),
                query_state: "submitted_pending_worker",
                extra_fields: vec![
                    ("task_id".to_string(), prepared.task_id.clone().into()),
                    ("external_worker".to_string(), true.into()),
                ],
                data_fingerprint: None,
            },
        )
        .await;

        return Json(query_submit_response(&state, &task_id, "pending")).into_response();
    }

    let existing_snapshot = {
        state
            .cache_index
            .lock()
            .expect("cache index")
            .get(&prepared.cache_key)
            .cloned()
    };
    if let Some(snapshot_id) = existing_snapshot {
        state.tasks.lock().expect("task registry").mark_completed(
            &prepared.task_id,
            snapshot_id.clone(),
            true,
        );
        persist_task_state(&state, &prepared.task_id).await;

        append_query_audit(
            &state,
            &session,
            &request_context,
            QueryAuditDetails {
                result: ActionResult::Success,
                resource_id: &task_id,
                context: "query completed from encrypted snapshot cache",
                data_source_id: &prepared.data_source_id,
                source_type: source_type_label(&prepared.source_type),
                requested_fields: prepared
                    .query
                    .fields
                    .iter()
                    .map(|field| field.as_str().to_string())
                    .collect::<Vec<_>>(),
                query_state: "completed_cache_hit",
                extra_fields: vec![
                    ("task_id".to_string(), prepared.task_id.clone().into()),
                    ("snapshot_id".to_string(), snapshot_id.into()),
                    ("cache_hit".to_string(), true.into()),
                ],
                data_fingerprint: None,
            },
        )
        .await;

        sync_workbench_runtime_for_task(&state, &prepared.task_id, None);

        return Json(query_submit_response(&state, &task_id, "completed")).into_response();
    }

    state
        .tasks
        .lock()
        .expect("task registry")
        .mark_running(&prepared.task_id);
    sync_workbench_runtime_for_task(&state, &prepared.task_id, None);
    persist_task_state(&state, &prepared.task_id).await;

    append_query_audit(
        &state,
        &session,
        &request_context,
        QueryAuditDetails {
            result: ActionResult::Success,
            resource_id: &task_id,
            context: "query submitted",
            data_source_id: &prepared.data_source_id,
            source_type: source_type_label(&prepared.source_type),
            requested_fields: prepared
                .query
                .fields
                .iter()
                .map(|field| field.as_str().to_string())
                .collect::<Vec<_>>(),
            query_state: "submitted_running",
            extra_fields: vec![
                ("task_id".to_string(), prepared.task_id.clone().into()),
                ("external_worker".to_string(), false.into()),
            ],
            data_fingerprint: None,
        },
    )
    .await;

    tokio::spawn(run_query_task(state.clone(), prepared));

    Json(query_submit_response(&state, &task_id, "running")).into_response()
}

pub async fn task_status_handler(
    State(state): State<Arc<ApiState>>,
    Path(task_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    match task_scope_match(&state, &task_id, &request_context, &session) {
        Some(true) => {}
        Some(false) => return json_error(StatusCode::FORBIDDEN, "task scope mismatch"),
        None => return json_error(StatusCode::NOT_FOUND, "task not found"),
    }

    let Some(snapshot) = state
        .tasks
        .lock()
        .expect("task registry")
        .snapshot(&task_id)
    else {
        return json_error(StatusCode::NOT_FOUND, "task not found");
    };

    Json(task_status_response(&state, snapshot)).into_response()
}

pub async fn cancel_task_handler(
    State(state): State<Arc<ApiState>>,
    Path(task_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    match task_scope_match(&state, &task_id, &request_context, &session) {
        Some(true) => {}
        Some(false) => return json_error(StatusCode::FORBIDDEN, "task scope mismatch"),
        None => return json_error(StatusCode::NOT_FOUND, "task not found"),
    }

    let task_registry_cancelled = {
        let mut tasks = state.tasks.lock().expect("task registry");
        let Some(snapshot) = tasks.snapshot(&task_id) else {
            return json_error(StatusCode::NOT_FOUND, "task not found");
        };
        if matches!(
            snapshot.state,
            QueryTaskState::Completed | QueryTaskState::Failed | QueryTaskState::Cancelled
        ) {
            return (
                StatusCode::CONFLICT,
                Json(CancelTaskResponse {
                    task_id,
                    cancelled: false,
                }),
            )
                .into_response();
        }

        tasks.cancel(&task_id)
    };
    let scheduler_cancelled = state.adapter_scheduler.cancel_task(&task_id).await;
    let cancelled = task_registry_cancelled || scheduler_cancelled;
    sync_workbench_runtime_for_task(&state, &task_id, None);
    persist_task_state(&state, &task_id).await;

    append_phase2_audit(
        &state,
        &session,
        &request_context,
        ActionType::Query,
        ActionResult::Success,
        &task_id,
        "query task cancelled",
        None,
    )
    .await;

    Json(CancelTaskResponse { task_id, cancelled }).into_response()
}

pub async fn snapshot_metadata_handler(
    State(state): State<Arc<ApiState>>,
    Path(snapshot_id): Path<String>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    let cached_record = {
        state
            .snapshots
            .lock()
            .expect("snapshot store")
            .get(&snapshot_id)
            .ok()
    };
    let record = match cached_record {
        Some(record) => record,
        None => {
            let Some(persistence) = &state.persistence else {
                return json_error(StatusCode::NOT_FOUND, "snapshot not found");
            };
            match persistence.load_snapshot(&snapshot_id).await {
                Ok(Some(record)) => {
                    state
                        .snapshots
                        .lock()
                        .expect("snapshot store")
                        .restore_record(record.clone());
                    record
                }
                _ => return json_error(StatusCode::NOT_FOUND, "snapshot not found"),
            }
        }
    };

    if record.tenant_id != request_context.tenant_id.as_str()
        || record.project_id
            != request_context
                .project_id
                .as_ref()
                .expect("project scope")
                .as_str()
    {
        append_phase2_audit(
            &state,
            &session,
            &request_context,
            ActionType::View,
            ActionResult::Denied,
            &snapshot_id,
            "snapshot scope mismatch",
            None,
        )
        .await;
        return json_error(StatusCode::FORBIDDEN, "snapshot scope mismatch");
    }

    append_phase2_audit_with_fields(
        &state,
        &session,
        &request_context,
        ActionType::View,
        ActionResult::Success,
        &snapshot_id,
        "snapshot metadata read",
        Phase2AuditDetails::new(snapshot_encryption_audit_fields(&record), None),
    )
    .await;

    Json(SnapshotMetadataResponse {
        snapshot_id: record.snapshot_id,
        tenant_id: record.tenant_id,
        project_id: record.project_id,
        owner_user_id: record.lifecycle.owner_user_id,
        grant_id: record.lifecycle.grant_id,
        storage_key: record.storage_key,
        data_source_id: record.data_source_id,
        row_count: record.row_count,
        encrypted: true,
        dek_id: record.encrypted_payload.dek_id,
        kek_id: record.encrypted_payload.kek_id,
        kms_provider: record.encrypted_payload.kms_provider,
        key_version: record.encrypted_payload.key_version,
        algorithm: record.encrypted_payload.algorithm,
        payload_format: record.payload_format.as_str().to_string(),
        columns: record.columns,
        data_fingerprint: record.lifecycle.data_fingerprint,
        retention_until: record.lifecycle.retention_until,
        delete_state: record.lifecycle.delete_state.as_str().to_string(),
        last_rewrapped_at: record.lifecycle.last_rewrapped_at,
        created_at: record.created_at,
    })
    .into_response()
}

pub(crate) fn snapshot_encryption_audit_fields(
    record: &sdqp_encryption::EncryptedSnapshotRecord,
) -> AuditContextFields {
    let mut fields = AuditContextFields::builder()
        .field("grant_id", record.lifecycle.grant_id.clone())
        .field("storage_key", record.storage_key.clone())
        .field("payload_format", record.payload_format.as_str())
        .field("delete_state", record.lifecycle.delete_state.as_str())
        .field(
            "kms_provider",
            record.encrypted_payload.kms_provider.clone(),
        )
        .field("kek_id", record.encrypted_payload.kek_id.clone())
        .build();

    if let Some(key_version) = &record.encrypted_payload.key_version {
        fields.insert("key_version", key_version.clone());
    }
    if let Some(last_rewrapped_at) = record.lifecycle.last_rewrapped_at {
        fields.insert("last_rewrapped_at", last_rewrapped_at.to_rfc3339());
    }

    fields
}

#[derive(Debug, Deserialize)]
pub struct TaskStreamParams {
    pub replay_last: Option<bool>,
}

pub async fn task_stream_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<ApiState>>,
    Path(task_id): Path<String>,
    QueryParams(params): QueryParams<TaskStreamParams>,
    Extension(request_context): Extension<RequestContext>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Response {
    match task_scope_match(&state, &task_id, &request_context, &session) {
        Some(true) => {}
        Some(false) => return json_error(StatusCode::FORBIDDEN, "task scope mismatch"),
        None => return json_error(StatusCode::NOT_FOUND, "task not found"),
    }

    let receiver = {
        state
            .tasks
            .lock()
            .expect("task registry")
            .subscribe(&task_id)
    };
    let Some(mut receiver) = receiver else {
        return json_error(StatusCode::NOT_FOUND, "task not found");
    };
    let replay_last = params.replay_last.unwrap_or(true);
    let initial_snapshot = if replay_last {
        state
            .tasks
            .lock()
            .expect("task registry")
            .snapshot(&task_id)
    } else {
        None
    };

    ws.on_upgrade(move |mut socket| async move {
        if let Some(snapshot) = initial_snapshot
            && send_snapshot(&mut socket, task_status_response(&state, snapshot))
                .await
                .is_err()
        {
            return;
        }

        while let Ok(event) = receiver.recv().await {
            let status = task_status_response(
                &state,
                QueryTaskSnapshot {
                    task_id: event.task_id.clone(),
                    state: event.state.clone(),
                    snapshot_id: event.snapshot_id.clone(),
                    cache_hit: event.cache_hit,
                    error: event.error.clone(),
                },
            );

            if send_snapshot(&mut socket, status).await.is_err() {
                break;
            }
            if is_terminal(&event.state) {
                break;
            }
        }
    })
    .into_response()
}

fn parse_source_type(value: &str) -> Option<SourceType> {
    match value.to_ascii_lowercase().as_str() {
        "rest" => Some(SourceType::Rest),
        "rpc" => Some(SourceType::Rpc),
        "hive" => Some(SourceType::Hive),
        "rdbms" => Some(SourceType::Rdbms),
        _ => None,
    }
}

fn prepare_query_execution(
    state: &Arc<ApiState>,
    request_context: &RequestContext,
    project_context: &ProjectContext,
    session: &AuthenticatedSession,
    payload: QuerySubmitRequest,
) -> Result<PreparedQueryExecution, ApiErrorResponse> {
    let Some(project_id) = request_context.project_id.as_ref().map(|id| id.as_str()) else {
        return Err(Box::new(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing project scope",
        )));
    };
    let Some(source_type) = parse_source_type(&payload.source_type) else {
        return Err(Box::new(json_error(
            StatusCode::BAD_REQUEST,
            "unsupported source_type",
        )));
    };

    let requested_fields = payload
        .fields
        .iter()
        .map(FieldSelector::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Box::new(json_error(StatusCode::BAD_REQUEST, "invalid query field")))?;

    let grant = state
        .permissions
        .lock()
        .expect("permission registry")
        .merged_active_grant(&session.claims.user_id, project_id, &payload.data_source_id)
        .ok_or_else(|| {
            Box::new(json_error(
                StatusCode::FORBIDDEN,
                "active permission grant not found",
            ))
        })?;

    let mut query = apply_grant_to_query(&grant, &requested_fields)
        .map_err(|error| Box::new(json_error(StatusCode::FORBIDDEN, &error.to_string())))?;
    query.execution_mode = ExecutionMode::Snapshot;
    if let Some(timeout_secs) = payload.timeout_secs {
        query.timeout_secs = timeout_secs;
    }
    if let Some(page_size) = payload.page_size {
        query.pagination = Some(
            Pagination::bounded(page_size, payload.cursor.clone())
                .map_err(|_| Box::new(json_error(StatusCode::BAD_REQUEST, "invalid pagination")))?,
        );
    }

    let task_id = {
        let mut tasks = state.tasks.lock().expect("task registry");
        let task_id = tasks.create_task();
        let scope = task_scope_for_request(request_context, session);
        state
            .task_scope
            .lock()
            .expect("task scope")
            .insert(task_id.clone(), scope.clone());
        task_id
    };
    let cache_key = build_cache_key(request_context, &payload, &grant.grant_id);
    let task_scope = task_scope_for_request(request_context, session);
    let priority = resolve_query_priority(payload.priority, &source_type);
    sync_workbench_runtime_for_task_with_priority(state, &task_id, priority, None);
    let data_source_id = payload.data_source_id.clone();
    let stored_source_type = source_type.clone();
    let stored_query = query.clone();

    Ok(PreparedQueryExecution {
        task_id: task_id.clone(),
        cache_key: cache_key.clone(),
        grant_id: grant.grant_id.clone(),
        grant_valid_until: grant.valid_until,
        data_source_id: data_source_id.clone(),
        source_type,
        query,
        stored_task: StoredQueryTask {
            task_id,
            tenant_id: task_scope.tenant_id.clone(),
            project_id: task_scope.project_id.clone(),
            user_id: task_scope.user_id.clone(),
            project_scope_key: task_scope.project_scope_key.clone(),
            grant_id: grant.grant_id.clone(),
            grant_valid_until: grant.valid_until,
            data_source_id,
            source_type: stored_source_type,
            query: stored_query,
            cache_key,
            priority,
            attempt_count: 0,
            max_attempts: 2,
        },
        session: session.clone(),
        request_context: request_context.clone(),
        storage_namespace: project_context.object_namespace.clone(),
    })
}

fn build_cache_key(
    request_context: &RequestContext,
    payload: &QuerySubmitRequest,
    grant_id: &str,
) -> String {
    serde_json::to_string(&CacheKeyParts {
        project_scope_key: request_context.project_scope_key(),
        grant_id: grant_id.to_string(),
        data_source_id: payload.data_source_id.clone(),
        source_type: payload.source_type.to_ascii_lowercase(),
        fields: payload.fields.clone(),
        timeout_secs: payload.timeout_secs.unwrap_or(30),
        page_size: payload.page_size,
        cursor: payload.cursor.clone(),
    })
    .expect("cache key parts must serialize")
}

fn task_scope_for_request(
    request_context: &RequestContext,
    session: &AuthenticatedSession,
) -> TaskScope {
    TaskScope {
        project_scope_key: request_context.project_scope_key(),
        tenant_id: request_context.tenant_id.as_str().to_string(),
        project_id: request_context
            .project_id
            .as_ref()
            .expect("project scope")
            .as_str()
            .to_string(),
        user_id: session.claims.user_id.clone(),
    }
}

fn default_query_priority(source_type: &SourceType) -> i32 {
    match source_type {
        SourceType::Rest => 50,
        SourceType::Rpc => 60,
        SourceType::Rdbms => 80,
        SourceType::Hive => 100,
    }
}

fn resolve_query_priority(priority: Option<QueryPriorityLevel>, source_type: &SourceType) -> i32 {
    priority
        .map(QueryPriorityLevel::value)
        .unwrap_or_else(|| default_query_priority(source_type))
}

fn query_priority_label(priority_value: i32) -> &'static str {
    match priority_value {
        value if value <= 35 => QueryPriorityLevel::Low.label(),
        value if value <= 65 => QueryPriorityLevel::Normal.label(),
        value if value <= 90 => QueryPriorityLevel::High.label(),
        _ => QueryPriorityLevel::Critical.label(),
    }
}

async fn run_query_task(state: Arc<ApiState>, prepared: PreparedQueryExecution) {
    if is_cancelled(&state, &prepared.task_id) {
        return;
    }

    let result = state
        .adapter_scheduler
        .execute_query(ScheduledQueryRequest {
            task_id: prepared.task_id.clone(),
            data_source_id: prepared.data_source_id.clone(),
            source_type: prepared.source_type.clone(),
            query: prepared.query.clone(),
            priority: prepared.stored_task.priority,
        })
        .await;

    match result {
        Ok(scheduled_result) => {
            let query_result = scheduled_result.result;
            if state.pipeline.validate().is_err() {
                state
                    .tasks
                    .lock()
                    .expect("task registry")
                    .mark_failed(&prepared.task_id, "decryption pipeline invalid".into());
                persist_task_state(&state, &prepared.task_id).await;
                return;
            }
            let plaintext = match serde_json::to_string(&query_result.rows) {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    state
                        .tasks
                        .lock()
                        .expect("task registry")
                        .mark_failed(&prepared.task_id, "failed to serialize query result".into());
                    persist_task_state(&state, &prepared.task_id).await;
                    return;
                }
            };
            let data_fingerprint = compute_sha256_hex(&plaintext);
            let projected_fields = prepared
                .query
                .fields
                .iter()
                .map(|field| field.as_str().to_string())
                .collect::<Vec<_>>();
            let encoded_snapshot =
                match encode_rows_to_parquet(&query_result.rows, Some(&projected_fields)) {
                    Ok(encoded) => encoded,
                    Err(_) => {
                        state.tasks.lock().expect("task registry").mark_failed(
                            &prepared.task_id,
                            "failed to encode columnar snapshot".into(),
                        );
                        persist_task_state(&state, &prepared.task_id).await;
                        return;
                    }
                };
            let encrypted_payload = match state.cipher.encrypt(&encoded_snapshot.payload) {
                Ok(payload) => payload,
                Err(_) => {
                    state
                        .tasks
                        .lock()
                        .expect("task registry")
                        .mark_failed(&prepared.task_id, "failed to encrypt snapshot".into());
                    persist_task_state(&state, &prepared.task_id).await;
                    return;
                }
            };
            let snapshot = state.snapshots.lock().expect("snapshot store").put(
                SnapshotWriteRequest {
                    tenant_id: prepared.request_context.tenant_id.as_str().to_string(),
                    project_id: prepared
                        .request_context
                        .project_id
                        .as_ref()
                        .expect("project scope")
                        .as_str()
                        .to_string(),
                    owner_user_id: prepared.session.claims.user_id.clone(),
                    grant_id: prepared.grant_id.clone(),
                    grant_expires_at: prepared.grant_valid_until,
                    retention_until: prepared
                        .grant_valid_until
                        .min(Utc::now() + ChronoDuration::hours(24)),
                    data_source_id: prepared.data_source_id.clone(),
                    object_bucket: prepared.storage_namespace.object_bucket.clone(),
                    data_fingerprint: data_fingerprint.clone(),
                    columns: encoded_snapshot.columns,
                    payload_format: encoded_snapshot.format,
                },
                encrypted_payload,
                query_result.rows.len(),
            );
            let mut snapshot = snapshot;
            if !prepared
                .storage_namespace
                .contains_key(&snapshot.lifecycle.object_bucket, &snapshot.storage_key)
            {
                state.tasks.lock().expect("task registry").mark_failed(
                    &prepared.task_id,
                    "snapshot object escaped project namespace".into(),
                );
                persist_task_state(&state, &prepared.task_id).await;
                return;
            }
            let object_metadata = match state
                .snapshot_objects
                .put_ciphertext(
                    &snapshot.lifecycle.object_bucket,
                    &snapshot.storage_key,
                    &snapshot.encrypted_payload.ciphertext_b64,
                )
                .await
            {
                Ok(metadata) => metadata,
                Err(error) => {
                    state.tasks.lock().expect("task registry").mark_failed(
                        &prepared.task_id,
                        format!("failed to persist encrypted snapshot object: {error}"),
                    );
                    persist_task_state(&state, &prepared.task_id).await;
                    return;
                }
            };
            snapshot.lifecycle.object_size_bytes = object_metadata.size_bytes;
            state
                .snapshots
                .lock()
                .expect("snapshot store")
                .restore_record(snapshot.clone());

            state
                .cache_index
                .lock()
                .expect("cache index")
                .insert(prepared.cache_key.clone(), snapshot.snapshot_id.clone());
            state.tasks.lock().expect("task registry").mark_completed(
                &prepared.task_id,
                snapshot.snapshot_id.clone(),
                false,
            );
            sync_workbench_runtime_for_task(
                &state,
                &prepared.task_id,
                Some(&scheduled_result.runtime),
            );
            if let Some(persistence) = &state.persistence {
                if persistence.save_snapshot(&snapshot).await.is_ok() {
                    let project_id = prepared
                        .request_context
                        .project_id
                        .as_ref()
                        .expect("project scope")
                        .as_str()
                        .to_string();
                    let existing = persistence
                        .load_classification_policies(
                            &project_id,
                            &prepared.data_source_id,
                            &projected_fields,
                        )
                        .await
                        .unwrap_or_default();
                    let existing_status = existing
                        .into_iter()
                        .map(|policy| (policy.field_name, policy.status))
                        .collect::<std::collections::HashMap<_, _>>();
                    if let Ok(Some(rule_version)) = persistence
                        .load_active_classification_rule_version(
                            &project_id,
                            &prepared.data_source_id,
                        )
                        .await
                    {
                        let row_maps = query_rows_to_maps(&query_result.rows);
                        let policies =
                            classify_fields(&rule_version, &row_maps, &projected_fields, None)
                                .into_iter()
                                .filter(|policy| {
                                    !matches!(
                                        existing_status.get(&policy.field_name),
                                        Some(ClassificationStatus::Confirmed)
                                    )
                                })
                                .collect::<Vec<_>>();
                        if !policies.is_empty()
                            && let Ok(detection_run_id) = persistence
                                .save_classification_detection_run(
                                    &snapshot.snapshot_id,
                                    &project_id,
                                    &prepared.data_source_id,
                                    &rule_version,
                                    &policies,
                                )
                                .await
                        {
                            append_phase2_audit_with_fields(
                                &state,
                                &prepared.session,
                                &prepared.request_context,
                                ActionType::Query,
                                ActionResult::Success,
                                &detection_run_id,
                                "classification detection run persisted",
                                Phase2AuditDetails::new(
                                    AuditContextFields::builder()
                                        .field("task_id", prepared.task_id.clone())
                                        .field("snapshot_id", snapshot.snapshot_id.clone())
                                        .field("data_source_id", prepared.data_source_id.clone())
                                        .field(
                                            "rule_version_id",
                                            rule_version.rule_version_id.clone(),
                                        )
                                        .field("policy_count", policies.len())
                                        .field(
                                            "catalog_entry_count",
                                            rule_version.catalog_entries.len(),
                                        )
                                        .build(),
                                    None,
                                ),
                            )
                            .await;
                        }
                    }
                }
                let _ = persistence
                    .save_cache_entry(&prepared.cache_key, &snapshot.snapshot_id)
                    .await;
            }
            persist_task_state(&state, &prepared.task_id).await;

            append_query_audit(
                &state,
                &prepared.session,
                &prepared.request_context,
                QueryAuditDetails {
                    result: ActionResult::Success,
                    resource_id: &snapshot.snapshot_id,
                    context: "encrypted snapshot persisted",
                    data_source_id: &prepared.data_source_id,
                    source_type: source_type_label(&prepared.source_type),
                    requested_fields: projected_fields.clone(),
                    query_state: "completed_snapshot_persisted",
                    extra_fields: vec![
                        ("task_id".to_string(), prepared.task_id.clone().into()),
                        (
                            "snapshot_id".to_string(),
                            snapshot.snapshot_id.clone().into(),
                        ),
                        ("cache_hit".to_string(), false.into()),
                        ("row_count".to_string(), query_result.rows.len().into()),
                        (
                            "adapter_attempts".to_string(),
                            (scheduled_result.attempts as usize).into(),
                        ),
                        (
                            "adapter_runtime_state".to_string(),
                            format!("{:?}", scheduled_result.runtime.lifecycle_state).into(),
                        ),
                        (
                            "adapter_availability".to_string(),
                            format!("{:?}", scheduled_result.runtime.availability).into(),
                        ),
                    ],
                    data_fingerprint: Some(data_fingerprint),
                },
            )
            .await;
        }
        Err(error) if error.kind == AdapterSchedulerErrorKind::Cancelled => {
            state
                .tasks
                .lock()
                .expect("task registry")
                .cancel(&prepared.task_id);
            sync_workbench_runtime_for_task(&state, &prepared.task_id, error.runtime.as_ref());
            persist_task_state(&state, &prepared.task_id).await;
        }
        Err(error) => {
            state
                .tasks
                .lock()
                .expect("task registry")
                .mark_failed(&prepared.task_id, error.message.clone());
            sync_workbench_runtime_for_task(&state, &prepared.task_id, error.runtime.as_ref());
            persist_task_state(&state, &prepared.task_id).await;
            let query_state = match error.kind {
                AdapterSchedulerErrorKind::Unavailable => "failed_adapter_unavailable",
                AdapterSchedulerErrorKind::Timeout => "failed_timeout",
                AdapterSchedulerErrorKind::ExecutionFailed => "failed_execution",
                AdapterSchedulerErrorKind::Cancelled => "cancelled",
            };

            append_query_audit(
                &state,
                &prepared.session,
                &prepared.request_context,
                QueryAuditDetails {
                    result: ActionResult::Failure,
                    resource_id: &prepared.task_id,
                    context: &format!("query failed: {}", error.message),
                    data_source_id: &prepared.data_source_id,
                    source_type: source_type_label(&prepared.source_type),
                    requested_fields: prepared
                        .query
                        .fields
                        .iter()
                        .map(|field| field.as_str().to_string())
                        .collect::<Vec<_>>(),
                    query_state,
                    extra_fields: scheduler_error_audit_fields(&prepared.task_id, &error),
                    data_fingerprint: None,
                },
            )
            .await;
        }
    }
}

fn task_scope_match(
    state: &Arc<ApiState>,
    task_id: &str,
    request_context: &RequestContext,
    session: &AuthenticatedSession,
) -> Option<bool> {
    let scope = state
        .task_scope
        .lock()
        .expect("task scope")
        .get(task_id)
        .cloned()?;

    Some(
        scope.project_scope_key == request_context.project_scope_key()
            && scope.tenant_id == request_context.tenant_id.as_str()
            && scope.project_id
                == request_context
                    .project_id
                    .as_ref()
                    .expect("project scope")
                    .as_str()
            && scope.user_id == session.claims.user_id,
    )
}

fn query_submit_response(
    state: &Arc<ApiState>,
    task_id: &str,
    status: &str,
) -> QuerySubmitResponse {
    let snapshot = state
        .tasks
        .lock()
        .expect("task registry")
        .snapshot(task_id)
        .unwrap_or_else(|| QueryTaskSnapshot {
            task_id: task_id.to_string(),
            state: QueryTaskState::Pending,
            snapshot_id: None,
            cache_hit: false,
            error: None,
        });
    let runtime = workbench_runtime_response(state, &snapshot);
    QuerySubmitResponse {
        task_id: task_id.to_string(),
        status: status.to_string(),
        websocket_path: format!("/v1/tasks/{task_id}/ws"),
        priority: runtime.priority.clone(),
        runtime,
    }
}

fn task_status_response(
    state: &Arc<ApiState>,
    snapshot: QueryTaskSnapshot,
) -> QueryTaskStatusResponse {
    let runtime = workbench_runtime_response(state, &snapshot);
    QueryTaskStatusResponse {
        task_id: snapshot.task_id.clone(),
        state: query_task_state_label(&snapshot.state),
        snapshot_id: snapshot.snapshot_id.clone(),
        cache_hit: snapshot.cache_hit,
        error: snapshot.error.clone(),
        priority: runtime.priority.clone(),
        runtime,
    }
}

fn workbench_runtime_response(
    state: &Arc<ApiState>,
    snapshot: &QueryTaskSnapshot,
) -> QueryWorkbenchRuntimeState {
    state
        .query_runtime
        .lock()
        .expect("query runtime")
        .get(&snapshot.task_id)
        .cloned()
        .unwrap_or_else(|| QueryWorkbenchRuntimeState::from_snapshot(50, snapshot))
}

fn sync_workbench_runtime_for_task_with_priority(
    state: &Arc<ApiState>,
    task_id: &str,
    priority_value: i32,
    adapter_runtime: Option<&AdapterHealthSnapshot>,
) {
    let Some(snapshot) = state.tasks.lock().expect("task registry").snapshot(task_id) else {
        return;
    };
    let mut runtime = QueryWorkbenchRuntimeState::from_snapshot_with_adapter(
        priority_value,
        &snapshot,
        adapter_runtime,
    );
    let mut runtimes = state.query_runtime.lock().expect("query runtime");
    if adapter_runtime.is_none()
        && let Some(existing) = runtimes.get(task_id)
    {
        runtime.adapter_runtime_state = existing.adapter_runtime_state.clone();
        runtime.adapter_availability = existing.adapter_availability.clone();
    }
    runtimes.insert(task_id.to_string(), runtime);
}

fn sync_workbench_runtime_for_task(
    state: &Arc<ApiState>,
    task_id: &str,
    adapter_runtime: Option<&AdapterHealthSnapshot>,
) {
    let priority_value = state
        .query_runtime
        .lock()
        .expect("query runtime")
        .get(task_id)
        .map(|runtime| runtime.priority.value)
        .unwrap_or(50);
    sync_workbench_runtime_for_task_with_priority(state, task_id, priority_value, adapter_runtime);
}

fn query_task_state_label(state: &QueryTaskState) -> String {
    match state {
        QueryTaskState::Pending => "pending",
        QueryTaskState::Running => "running",
        QueryTaskState::Completed => "completed",
        QueryTaskState::Failed => "failed",
        QueryTaskState::Cancelled => "cancelled",
    }
    .into()
}

fn source_type_label(source_type: &SourceType) -> &'static str {
    match source_type {
        SourceType::Rest => "rest",
        SourceType::Rpc => "rpc",
        SourceType::Hive => "hive",
        SourceType::Rdbms => "rdbms",
    }
}

fn is_terminal(state: &QueryTaskState) -> bool {
    matches!(
        state,
        QueryTaskState::Completed | QueryTaskState::Failed | QueryTaskState::Cancelled
    )
}

fn is_cancelled(state: &Arc<ApiState>, task_id: &str) -> bool {
    matches!(
        state.tasks.lock().expect("task registry").state(task_id),
        Some(QueryTaskState::Cancelled)
    )
}

fn query_rows_to_maps(
    rows: &[Vec<sdqp_datasource_adapter::FieldQueryResult>],
) -> Vec<std::collections::HashMap<String, String>> {
    rows.iter()
        .map(|row| {
            row.iter()
                .map(|field| (field.field.clone(), field.value.clone()))
                .collect::<std::collections::HashMap<_, _>>()
        })
        .collect()
}

fn scheduler_error_audit_fields(
    task_id: &str,
    error: &sdqp_datasource_adapter::AdapterSchedulerError,
) -> Vec<(String, AuditContextValue)> {
    let mut fields = vec![
        ("task_id".to_string(), task_id.to_string().into()),
        ("error".to_string(), error.message.clone().into()),
        (
            "adapter_attempts".to_string(),
            (error.attempts as usize).into(),
        ),
        (
            "adapter_error_kind".to_string(),
            format!("{:?}", error.kind).into(),
        ),
    ];
    if let Some(runtime) = &error.runtime {
        fields.push((
            "adapter_runtime_state".to_string(),
            format!("{:?}", runtime.lifecycle_state).into(),
        ));
        fields.push((
            "adapter_availability".to_string(),
            format!("{:?}", runtime.availability).into(),
        ));
        fields.push((
            "adapter_circuit_open".to_string(),
            runtime.circuit_open.into(),
        ));
        fields.push((
            "adapter_consecutive_failures".to_string(),
            (runtime.consecutive_failures as usize).into(),
        ));
    }
    fields
}

async fn persist_task_state(state: &Arc<ApiState>, task_id: &str) {
    sync_workbench_runtime_for_task(state, task_id, None);
    let Some(persistence) = &state.persistence else {
        return;
    };
    let Some(scope) = state
        .task_scope
        .lock()
        .expect("task scope")
        .get(task_id)
        .cloned()
    else {
        return;
    };
    let Some(snapshot) = state.tasks.lock().expect("task registry").snapshot(task_id) else {
        return;
    };
    let _ = persistence.save_task_state(&scope, &snapshot).await;
}

async fn send_snapshot(
    socket: &mut axum::extract::ws::WebSocket,
    payload: QueryTaskStatusResponse,
) -> Result<(), ()> {
    let text = serde_json::to_string(&payload).map_err(|_| ())?;
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|_| ())
}

pub(crate) fn spawn_persistent_task_sync(state: Arc<ApiState>) {
    tokio::spawn(async move {
        loop {
            sync_persisted_task_registry(&state).await;
            audit_terminal_task_completions(&state).await;
            sleep(Duration::from_millis(25)).await;
        }
    });
}

async fn sync_persisted_task_registry(state: &Arc<ApiState>) {
    let Some(persistence) = &state.persistence else {
        return;
    };
    let Ok(tasks) = persistence.load_query_tasks().await else {
        return;
    };

    let mut task_scope = state.task_scope.lock().expect("task scope");
    let mut registry = state.tasks.lock().expect("task registry");
    for (scope, snapshot) in tasks {
        task_scope.insert(snapshot.task_id.clone(), scope);
        registry.upsert_snapshot(snapshot);
    }
}

async fn audit_terminal_task_completions(state: &Arc<ApiState>) {
    let Some(persistence) = &state.persistence else {
        return;
    };
    let Ok(tasks) = persistence.load_unaudited_terminal_tasks().await else {
        return;
    };

    for task in tasks {
        let request_context = RequestContext::new(
            TenantId::new(task.scope.tenant_id.clone()).expect("tenant"),
            UserId::new(task.scope.user_id.clone()).expect("user"),
        )
        .with_project(ProjectId::new(task.scope.project_id.clone()).expect("project"));
        let (result, resource_id, context, query_state, extra_fields) = match task.snapshot.state {
            QueryTaskState::Completed => (
                ActionResult::Success,
                task.snapshot
                    .snapshot_id
                    .clone()
                    .unwrap_or_else(|| task.snapshot.task_id.clone()),
                if task.snapshot.cache_hit {
                    "query completed from persisted cache"
                } else {
                    "query completed by worker"
                },
                if task.snapshot.cache_hit {
                    "completed_cache_hit"
                } else {
                    "completed_worker"
                },
                vec![
                    ("task_id".to_string(), task.snapshot.task_id.clone().into()),
                    ("cache_hit".to_string(), task.snapshot.cache_hit.into()),
                    (
                        "snapshot_id".to_string(),
                        task.snapshot
                            .snapshot_id
                            .clone()
                            .unwrap_or_else(|| task.snapshot.task_id.clone())
                            .into(),
                    ),
                ],
            ),
            QueryTaskState::Cancelled => (
                ActionResult::Success,
                task.snapshot.task_id.clone(),
                "query task cancelled",
                "cancelled",
                vec![("task_id".to_string(), task.snapshot.task_id.clone().into())],
            ),
            QueryTaskState::Failed => (
                ActionResult::Failure,
                task.snapshot.task_id.clone(),
                task.snapshot
                    .error
                    .as_deref()
                    .map(|_| "query failed in worker")
                    .unwrap_or("query failed in worker"),
                "failed_worker",
                vec![
                    ("task_id".to_string(), task.snapshot.task_id.clone().into()),
                    (
                        "error".to_string(),
                        task.snapshot
                            .error
                            .clone()
                            .unwrap_or_else(|| "unknown".into())
                            .into(),
                    ),
                ],
            ),
            QueryTaskState::Pending | QueryTaskState::Running => continue,
        };
        super::record_audit_event_from_parts_with_fields(
            state,
            ActorInfo {
                user_id: task.scope.user_id.clone(),
                session_id: format!("worker-task-{}", task.snapshot.task_id),
                ip_address: "127.0.0.1".into(),
            },
            ActionType::Query,
            TargetRef {
                tenant_id: task.scope.tenant_id.clone(),
                project_id: Some(task.scope.project_id.clone()),
                resource_id,
            },
            context,
            extend_audit_fields(
                query_audit_fields(&task.data_source_id, "worker", &Vec::new(), query_state),
                extra_fields,
            ),
            result,
            None,
        )
        .await;
        let _ = persistence
            .mark_task_completion_audited(&task.snapshot.task_id)
            .await;
        let _ = request_context;
    }
}

pub(crate) async fn append_phase2_audit(
    state: &Arc<ApiState>,
    session: &AuthenticatedSession,
    request_context: &RequestContext,
    action: ActionType,
    result: ActionResult,
    resource_id: &str,
    context: &str,
    data_fingerprint: Option<String>,
) {
    append_phase2_audit_with_fields(
        state,
        session,
        request_context,
        action,
        result,
        resource_id,
        context,
        Phase2AuditDetails::new(AuditContextFields::default(), data_fingerprint),
    )
    .await;
}

#[derive(Default)]
pub(crate) struct Phase2AuditDetails {
    context_fields: AuditContextFields,
    data_fingerprint: Option<String>,
}

impl Phase2AuditDetails {
    pub(crate) fn new(
        context_fields: AuditContextFields,
        data_fingerprint: Option<String>,
    ) -> Self {
        Self {
            context_fields,
            data_fingerprint,
        }
    }
}

pub(crate) async fn append_phase2_audit_with_fields(
    state: &Arc<ApiState>,
    session: &AuthenticatedSession,
    request_context: &RequestContext,
    action: ActionType,
    result: ActionResult,
    resource_id: &str,
    context: &str,
    details: Phase2AuditDetails,
) {
    let Phase2AuditDetails {
        context_fields,
        data_fingerprint,
    } = details;
    let actor = ActorInfo {
        user_id: session.claims.user_id.clone(),
        session_id: session.claims.session_id.clone(),
        ip_address: session.claims.binding.ip_address.clone(),
    };
    let target = TargetRef {
        tenant_id: request_context.tenant_id.as_str().to_string(),
        project_id: request_context
            .project_id
            .as_ref()
            .map(|project_id| project_id.as_str().to_string()),
        resource_id: resource_id.to_string(),
    };
    super::record_audit_event_from_parts_with_fields(
        state,
        actor,
        action,
        target,
        context,
        context_fields,
        result,
        data_fingerprint,
    )
    .await;
}

fn query_audit_fields(
    data_source_id: &str,
    source_type: &str,
    requested_fields: &[String],
    query_state: &str,
) -> AuditContextFields {
    AuditContextFields::builder()
        .field("data_source_id", data_source_id)
        .field("source_type", source_type)
        .field("requested_fields", requested_fields.to_vec())
        .field("field_count", requested_fields.len())
        .field("query_state", query_state)
        .build()
}

fn extend_audit_fields(
    mut base: AuditContextFields,
    entries: impl IntoIterator<Item = (String, AuditContextValue)>,
) -> AuditContextFields {
    for (key, value) in entries {
        base.insert(key, value);
    }
    base
}

struct QueryAuditDetails<'a> {
    result: ActionResult,
    resource_id: &'a str,
    context: &'a str,
    data_source_id: &'a str,
    source_type: &'a str,
    requested_fields: Vec<String>,
    query_state: &'a str,
    extra_fields: Vec<(String, AuditContextValue)>,
    data_fingerprint: Option<String>,
}

async fn append_query_audit(
    state: &Arc<ApiState>,
    session: &AuthenticatedSession,
    request_context: &RequestContext,
    details: QueryAuditDetails<'_>,
) {
    let QueryAuditDetails {
        result,
        resource_id,
        context,
        data_source_id,
        source_type,
        requested_fields,
        query_state,
        extra_fields,
        data_fingerprint,
    } = details;
    append_phase2_audit_with_fields(
        state,
        session,
        request_context,
        ActionType::Query,
        result,
        resource_id,
        context,
        Phase2AuditDetails::new(
            extend_audit_fields(
                query_audit_fields(data_source_id, source_type, &requested_fields, query_state),
                extra_fields,
            ),
            data_fingerprint,
        ),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::{
        QueryPriorityLevel, QuerySubmitRequest, QueryWorkbenchRuntimeState, build_cache_key,
        build_query_runtime, is_terminal, parse_source_type, query_task_state_label,
        resolve_query_priority,
    };
    use sdqp_config::AppSettings;
    use sdqp_core::{ProjectId, RequestContext, TenantId, UserId};
    use sdqp_datasource_adapter::task::{QueryTaskSnapshot, QueryTaskState};
    use sdqp_encryption::EnvelopeCipher;

    #[test]
    fn parse_source_type_accepts_lower_and_upper_case_values() {
        assert!(parse_source_type("REST").is_some());
        assert!(parse_source_type("hive").is_some());
        assert!(parse_source_type("unknown").is_none());
    }

    #[test]
    fn cache_key_is_stable_for_identical_query_inputs() {
        let context = RequestContext::new(
            TenantId::new("tenant-alpha").expect("tenant"),
            UserId::new("user-analyst").expect("user"),
        )
        .with_project(ProjectId::new("project-alpha").expect("project"));
        let request = QuerySubmitRequest {
            data_source_id: "datasource-rest".into(),
            source_type: "rest".into(),
            fields: vec!["employee_id".into()],
            priority: None,
            timeout_secs: Some(30),
            page_size: Some(50),
            cursor: Some("cursor-a".into()),
        };

        assert_eq!(
            build_cache_key(&context, &request, "grant-alpha"),
            build_cache_key(&context, &request, "grant-alpha")
        );
    }

    #[test]
    fn runtime_bootstrap_provisions_valid_pipeline_and_security_artifacts() {
        let (_, _, _, _, task_scope, _adapter_scheduler, _, cipher, pipeline) =
            build_query_runtime(&AppSettings::local_dev());
        assert!(task_scope.is_empty());
        assert!(pipeline.validate().is_ok());
        let encrypted = cipher.encrypt(b"phase2").expect("encrypted");
        assert_eq!(encrypted.kms_provider, "mock");
    }

    #[tokio::test]
    async fn runtime_bootstrap_exposes_default_adapter_scheduler_health() {
        let (_, _, _, _, _, adapter_scheduler, _, _, _) =
            build_query_runtime(&AppSettings::local_dev());
        let health = adapter_scheduler.health_snapshots().await;

        assert_eq!(health.len(), 3);
        assert!(
            health
                .iter()
                .any(|snapshot| snapshot.data_source_id == "datasource-hive")
        );
    }

    #[test]
    fn runtime_bootstrap_honors_explicit_kms_provider_selection() {
        let mut settings = AppSettings::local_dev();
        settings.kms.provider = "aws".into();
        settings.kms.region = "cn-test-1".into();
        settings.kms.key_version = "4".into();

        let (_, _, _, _, _, _, _, cipher, _) = build_query_runtime(&settings);
        let encrypted = cipher.encrypt(b"phase2").expect("encrypted");

        assert_eq!(encrypted.kms_provider, "aws");
        assert_eq!(encrypted.key_version.as_deref(), Some("4"));
    }

    #[test]
    fn terminal_state_and_labels_match_public_api_contract() {
        assert_eq!(query_task_state_label(&QueryTaskState::Running), "running");
        assert!(is_terminal(&QueryTaskState::Completed));
        assert!(!is_terminal(&QueryTaskState::Pending));
    }

    #[test]
    fn explicit_query_priority_overrides_source_default_priority() {
        assert_eq!(
            resolve_query_priority(
                Some(QueryPriorityLevel::Critical),
                &sdqp_datasource_adapter::SourceType::Rest
            ),
            100
        );
        assert_eq!(
            resolve_query_priority(None, &sdqp_datasource_adapter::SourceType::Hive),
            100
        );
    }

    #[test]
    fn workbench_runtime_state_exposes_controls_and_secure_snapshot_access() {
        let running = QueryTaskSnapshot {
            task_id: "task-running".into(),
            state: QueryTaskState::Running,
            snapshot_id: None,
            cache_hit: false,
            error: None,
        };
        let running_runtime = QueryWorkbenchRuntimeState::from_snapshot(75, &running);
        assert_eq!(running_runtime.priority.label, "high");
        assert!(running_runtime.controls.can_cancel);
        assert!(!running_runtime.controls.can_retry);
        assert_eq!(
            running_runtime.secure_snapshot_access,
            "pending_encrypted_snapshot"
        );

        let completed = QueryTaskSnapshot {
            task_id: "task-completed".into(),
            state: QueryTaskState::Completed,
            snapshot_id: Some("snapshot-a".into()),
            cache_hit: false,
            error: None,
        };
        let completed_runtime = QueryWorkbenchRuntimeState::from_snapshot(50, &completed);
        assert!(completed_runtime.controls.can_access_snapshot);
        assert_eq!(
            completed_runtime.secure_snapshot_access,
            "authorized_encrypted_snapshot"
        );
    }
}
