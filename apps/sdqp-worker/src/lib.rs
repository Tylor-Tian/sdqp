mod observability;
mod persistence;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Extension, Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use observability::HttpMetrics;
use sdqp_audit::{
    ActionResult, ActionType, ActorInfo, AuditCheckpoint, AuditEvent, TargetRef, create_checkpoint,
    verify_chain,
};
use sdqp_config::{AppSettings, WorkerSettings};
use sdqp_contracts::{PHASE0_MILESTONE, ServiceHealth};
use sdqp_core::{ProjectId, RequestContext, TenantId, UserId, compute_sha256_hex};
use sdqp_data_classification::{ClassificationStatus, classify_fields};
use sdqp_data_view::encode_rows_to_parquet;
use sdqp_datasource_adapter::{AdapterRegistry, CircuitBreaker, StoredQueryTask};
use sdqp_encryption::{
    EnvelopeCipher, InMemorySnapshotObjectStore, KmsClientConfig, KmsProvider,
    ProviderEnvelopeCipher, S3CompatibleObjectStore, SnapshotObjectStore, SnapshotStore,
    SnapshotWriteRequest, build_kms_service_registry,
};
use sdqp_system_security::{SessionClaims, parse_access_token};
use sdqp_tenant_isolation::{ProjectContext, ProjectState, TenantContext, TenantIsolationGuard};
use serde::{Deserialize, Serialize};
use tracing::Instrument;

const WORKER_TOKEN_SECRET: &str = "sdqp-phase1-dev-secret";
const QUERY_METRIC_OUTCOMES: [&str; 5] =
    ["completed", "cache_hit", "cancelled", "failed", "retried"];

#[derive(Clone)]
pub struct WorkerRuntime {
    settings: WorkerSettings,
    phase0_queues: Vec<String>,
    projects: HashMap<String, ProjectContext>,
    audit: Arc<Mutex<WorkerAuditLedger>>,
    metrics: Arc<HttpMetrics>,
    query_metrics: Arc<Mutex<QueryWorkerMetrics>>,
    persistence: Option<Arc<persistence::WorkerPersistence>>,
    adapters: Arc<AdapterRegistry>,
    cipher: Arc<dyn EnvelopeCipher>,
    snapshot_objects: Arc<dyn SnapshotObjectStore>,
    snapshot_bucket: String,
    circuit_breaker: Arc<Mutex<CircuitBreaker>>,
    worker_id: String,
}

#[derive(Debug, Default)]
struct WorkerAuditLedger {
    events: Vec<AuditEvent>,
    checkpoints: Vec<AuditCheckpoint>,
}

#[derive(Debug, Default)]
struct QueryWorkerMetrics {
    outcomes: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
struct AuthenticatedWorkerRequest {
    claims: SessionClaims,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerProjectResponse {
    pub queue_count: usize,
    pub project_state: String,
    pub audit_chain_valid: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
}

impl WorkerRuntime {
    pub fn new(settings: WorkerSettings) -> Self {
        let app_settings = AppSettings::local_dev();
        Self::with_runtime(
            settings,
            default_projects(),
            None,
            Arc::new(AdapterRegistry::development()),
            build_worker_cipher(&app_settings),
            Arc::new(InMemorySnapshotObjectStore::default()),
            app_settings.object_store.bucket_snapshots,
        )
    }

    async fn new_persistent(
        settings: AppSettings,
    ) -> Result<Self, persistence::WorkerPersistenceError> {
        let persistence = persistence::WorkerPersistence::initialize(&settings).await?;
        let projects = persistence.load_projects().await?;
        let adapters = AdapterRegistry::from_configs(persistence.load_data_source_configs().await?);
        let cipher = build_worker_cipher(&settings);
        let snapshot_objects = Arc::new(S3CompatibleObjectStore::new(
            settings.object_store.endpoint.clone(),
            settings.object_store.region.clone(),
            settings.object_store.access_key.clone(),
            settings.object_store.secret_key.clone(),
        ));
        Ok(Self::with_runtime(
            settings.worker,
            if projects.is_empty() {
                default_projects()
            } else {
                projects
            },
            Some(persistence),
            Arc::new(adapters),
            cipher,
            snapshot_objects,
            settings.object_store.bucket_snapshots,
        ))
    }

    fn with_runtime(
        settings: WorkerSettings,
        projects: HashMap<String, ProjectContext>,
        persistence: Option<Arc<persistence::WorkerPersistence>>,
        adapters: Arc<AdapterRegistry>,
        cipher: Arc<dyn EnvelopeCipher>,
        snapshot_objects: Arc<dyn SnapshotObjectStore>,
        snapshot_bucket: String,
    ) -> Self {
        Self {
            settings,
            phase0_queues: vec!["audit-checkpoints".into(), "query-task-polling".into()],
            projects,
            audit: Arc::new(Mutex::new(WorkerAuditLedger::default())),
            metrics: Arc::new(HttpMetrics::default()),
            query_metrics: Arc::new(Mutex::new(QueryWorkerMetrics::default())),
            persistence,
            adapters,
            cipher,
            snapshot_objects,
            snapshot_bucket,
            circuit_breaker: Arc::new(Mutex::new(CircuitBreaker::new(2))),
            worker_id: ulid::Ulid::new().to_string(),
        }
    }

    pub fn health(&self) -> ServiceHealth {
        let mut health = ServiceHealth::ready(self.settings.service_name.clone(), PHASE0_MILESTONE);
        health
            .details
            .insert("queues".into(), self.phase0_queues.join(","));
        health
    }

    pub fn queue_count(&self) -> usize {
        self.phase0_queues.len()
    }
}

impl WorkerAuditLedger {
    fn append(&mut self, event: AuditEvent) {
        self.events.push(event);
        let checkpoint = create_checkpoint(&self.events).expect("checkpoint");
        self.checkpoints.push(checkpoint);
    }

    fn chain_valid(&self) -> bool {
        verify_chain(&self.events)
    }
}

impl QueryWorkerMetrics {
    fn record(&mut self, outcome: &str) {
        *self.outcomes.entry(outcome.to_string()).or_insert(0) += 1;
    }

    fn render_prometheus(&self, service_name: &str, breaker: &CircuitBreaker) -> String {
        let mut lines = String::new();
        for outcome in QUERY_METRIC_OUTCOMES {
            let count = self.outcomes.get(outcome).copied().unwrap_or(0);
            lines.push_str(&format!(
                "sdqp_query_tasks_total{{service=\"{service_name}\",result=\"{outcome}\"}} {count}\n"
            ));
        }
        for (outcome, count) in self
            .outcomes
            .iter()
            .filter(|(outcome, _)| !QUERY_METRIC_OUTCOMES.contains(&outcome.as_str()))
        {
            lines.push_str(&format!(
                "sdqp_query_tasks_total{{service=\"{service_name}\",result=\"{outcome}\"}} {count}\n"
            ));
        }
        for (source_id, failures) in breaker.snapshot() {
            let open = if breaker.allow(&source_id) { 0 } else { 1 };
            lines.push_str(&format!(
                "sdqp_datasource_circuit_failures{{service=\"{service_name}\",data_source_id=\"{source_id}\"}} {failures}\n"
            ));
            lines.push_str(&format!(
                "sdqp_datasource_circuit_open{{service=\"{service_name}\",data_source_id=\"{source_id}\"}} {open}\n"
            ));
        }
        lines
    }
}

fn build_worker_cipher(settings: &AppSettings) -> Arc<dyn EnvelopeCipher> {
    let provider =
        KmsProvider::parse(&settings.kms.provider).expect("worker kms provider must be valid");
    let registry = build_kms_service_registry(&KmsClientConfig {
        provider,
        endpoint: non_empty_option(&settings.kms.endpoint),
        master_key_id: settings.kms.master_key_id.clone(),
        key_ring: non_empty_option(&settings.kms.key_ring),
        auth_token: non_empty_option(&settings.kms.auth_token),
        region: non_empty_option(&settings.kms.region),
        key_version: non_empty_option(&settings.kms.key_version),
    })
    .expect("worker kms registry must build");
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

pub fn build_router(settings: WorkerSettings) -> Router {
    let state = Arc::new(WorkerRuntime::new(settings));
    build_router_from_state(state)
}

pub async fn build_persistent_router(
    settings: AppSettings,
) -> Result<Router, persistence::WorkerPersistenceError> {
    let state = Arc::new(WorkerRuntime::new_persistent(settings).await?);
    spawn_query_polling_loop(state.clone());
    Ok(build_router_from_state(state))
}

fn build_router_from_state(state: Arc<WorkerRuntime>) -> Router {
    let protected = Router::new()
        .route("/worker/project-queue", get(project_queue_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            project_context_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            tenant_context_middleware,
        ));

    Router::new()
        .route("/healthz", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .merge(Router::new().nest("/v1", protected))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            request_observability_middleware,
        ))
        .with_state(state)
}

pub async fn run(settings: AppSettings) -> Result<(), Box<dyn std::error::Error>> {
    let addr = settings.worker.socket_addr();
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("sdqp-worker listening on {}", addr);
    axum::serve(listener, build_persistent_router(settings).await?).await?;
    Ok(())
}

fn spawn_query_polling_loop(state: Arc<WorkerRuntime>) {
    tokio::spawn(async move {
        loop {
            let Some(persistence) = &state.persistence else {
                return;
            };
            match persistence
                .claim_next_query_task(&state.worker_id, state.settings.query_lease_secs)
                .await
            {
                Ok(Some(task)) => process_query_task(state.clone(), task).await,
                Ok(None) => {
                    tokio::time::sleep(Duration::from_millis(state.settings.query_poll_interval_ms))
                        .await
                }
                Err(error) => {
                    tracing::warn!("worker task polling failed: {error}");
                    tokio::time::sleep(Duration::from_millis(
                        state.settings.query_poll_interval_ms,
                    ))
                    .await;
                }
            }
        }
    });
}

async fn process_query_task(state: Arc<WorkerRuntime>, task: StoredQueryTask) {
    let Some(persistence) = &state.persistence else {
        return;
    };
    if matches!(
        persistence.load_task_state(&task.task_id).await,
        Ok(Some(sdqp_datasource_adapter::QueryTaskState::Cancelled))
    ) {
        state
            .query_metrics
            .lock()
            .expect("query metrics")
            .record("cancelled");
        return;
    }

    if let Ok(Some(snapshot_id)) = persistence.load_cache_entry(&task.cache_key).await {
        let _ = persistence
            .complete_task(&task.task_id, &snapshot_id, true)
            .await;
        state
            .query_metrics
            .lock()
            .expect("query metrics")
            .record("cache_hit");
        return;
    }

    let allow = state
        .circuit_breaker
        .lock()
        .expect("circuit breaker")
        .allow(&task.data_source_id);
    if !allow {
        let _ = persistence
            .fail_task(&task.task_id, "circuit breaker open")
            .await;
        state
            .query_metrics
            .lock()
            .expect("query metrics")
            .record("failed");
        return;
    }

    let result = tokio::time::timeout(
        task.query.timeout(),
        state
            .adapters
            .execute_query(&task.data_source_id, &task.source_type, task.query.clone()),
    )
    .await;

    if matches!(
        persistence.load_task_state(&task.task_id).await,
        Ok(Some(sdqp_datasource_adapter::QueryTaskState::Cancelled))
    ) {
        state
            .query_metrics
            .lock()
            .expect("query metrics")
            .record("cancelled");
        return;
    }

    match result {
        Ok(Ok(query_result)) => {
            let plaintext = match serde_json::to_string(&query_result.rows) {
                Ok(payload) => payload,
                Err(error) => {
                    handle_task_failure(
                        state,
                        task,
                        &format!("failed to serialize query result: {error}"),
                    )
                    .await;
                    return;
                }
            };
            let data_fingerprint = compute_sha256_hex(&plaintext);
            let projected_fields = task
                .query
                .fields
                .iter()
                .map(|field| field.as_str().to_string())
                .collect::<Vec<_>>();
            let encoded_snapshot =
                match encode_rows_to_parquet(&query_result.rows, Some(&projected_fields)) {
                    Ok(encoded) => encoded,
                    Err(error) => {
                        handle_task_failure(
                            state,
                            task,
                            &format!("failed to encode columnar snapshot: {error}"),
                        )
                        .await;
                        return;
                    }
                };
            let encrypted_payload = match state.cipher.encrypt(&encoded_snapshot.payload) {
                Ok(payload) => payload,
                Err(error) => {
                    handle_task_failure(
                        state,
                        task,
                        &format!("failed to encrypt query result: {error}"),
                    )
                    .await;
                    return;
                }
            };
            let mut snapshot_store = sdqp_encryption::InMemorySnapshotStore::default();
            let mut snapshot = snapshot_store.put(
                SnapshotWriteRequest {
                    tenant_id: task.tenant_id.clone(),
                    project_id: task.project_id.clone(),
                    owner_user_id: task.user_id.clone(),
                    grant_id: task.grant_id.clone(),
                    grant_expires_at: task.grant_valid_until,
                    retention_until: task.grant_valid_until,
                    data_source_id: task.data_source_id.clone(),
                    object_bucket: state.snapshot_bucket.clone(),
                    data_fingerprint,
                    columns: encoded_snapshot.columns,
                    payload_format: encoded_snapshot.format,
                },
                encrypted_payload,
                query_result.rows.len(),
            );

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
                    handle_task_failure(
                        state,
                        task,
                        &format!("failed to persist encrypted snapshot object: {error}"),
                    )
                    .await;
                    return;
                }
            };
            snapshot.lifecycle.object_size_bytes = object_metadata.size_bytes;

            if persistence.save_snapshot(&snapshot).await.is_ok() {
                let existing = persistence
                    .load_classification_policies(
                        &task.project_id,
                        &task.data_source_id,
                        &projected_fields,
                    )
                    .await
                    .unwrap_or_default();
                let existing_status = existing
                    .into_iter()
                    .map(|policy| (policy.field_name, policy.status))
                    .collect::<HashMap<_, _>>();
                if let Ok(Some(rule_version)) = persistence
                    .load_active_classification_rule_version(&task.project_id, &task.data_source_id)
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
                    if !policies.is_empty() {
                        let _ = persistence
                            .save_classification_detection_run(
                                &snapshot.snapshot_id,
                                &task.project_id,
                                &task.data_source_id,
                                &rule_version,
                                &policies,
                            )
                            .await;
                    }
                }
            }
            let _ = persistence
                .save_cache_entry(&task.cache_key, &snapshot.snapshot_id)
                .await;
            let _ = persistence
                .complete_task(&task.task_id, &snapshot.snapshot_id, false)
                .await;
            state
                .circuit_breaker
                .lock()
                .expect("circuit breaker")
                .record_success(&task.data_source_id);
            state
                .query_metrics
                .lock()
                .expect("query metrics")
                .record("completed");
        }
        Ok(Err(error)) => handle_task_failure(state, task, &error).await,
        Err(_) => handle_task_failure(state, task, "query timed out").await,
    }
}

async fn handle_task_failure(state: Arc<WorkerRuntime>, task: StoredQueryTask, error: &str) {
    let Some(persistence) = &state.persistence else {
        return;
    };
    state
        .circuit_breaker
        .lock()
        .expect("circuit breaker")
        .record_failure(&task.data_source_id);

    if task.attempt_count < task.max_attempts {
        let _ = persistence.reset_task_for_retry(&task.task_id, error).await;
        state
            .query_metrics
            .lock()
            .expect("query metrics")
            .record("retried");
    } else {
        let _ = persistence.fail_task(&task.task_id, error).await;
        state
            .query_metrics
            .lock()
            .expect("query metrics")
            .record("failed");
    }
}

fn default_projects() -> HashMap<String, ProjectContext> {
    HashMap::from([(
        "project-alpha".into(),
        ProjectContext::new(
            TenantId::new("tenant-alpha").expect("tenant"),
            ProjectId::new("project-alpha").expect("project"),
            ProjectState::Active,
        ),
    )])
}

async fn health_handler(State(state): State<Arc<WorkerRuntime>>) -> Json<ServiceHealth> {
    Json(state.health())
}

async fn metrics_handler(State(state): State<Arc<WorkerRuntime>>) -> impl IntoResponse {
    let http_metrics = state
        .metrics
        .render_prometheus(&state.settings.service_name);
    let query_metrics = state
        .query_metrics
        .lock()
        .expect("query metrics")
        .render_prometheus(
            &state.settings.service_name,
            &state.circuit_breaker.lock().expect("circuit breaker"),
        );

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        format!("{http_metrics}{query_metrics}"),
    )
}

async fn tenant_context_middleware(
    State(state): State<Arc<WorkerRuntime>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(token) = extract_bearer_token(request.headers()) else {
        append_worker_audit(
            &state,
            None,
            ActionType::View,
            ActionResult::Denied,
            "worker/project-queue",
            "missing token",
        );
        return json_error(StatusCode::UNAUTHORIZED, "missing bearer token");
    };

    let claims = match parse_access_token(&token, WORKER_TOKEN_SECRET) {
        Ok(claims) => claims,
        Err(_) => {
            append_worker_audit(
                &state,
                None,
                ActionType::View,
                ActionResult::Denied,
                "worker/project-queue",
                "invalid token",
            );
            return json_error(StatusCode::UNAUTHORIZED, "invalid token");
        }
    };

    let tenant = match parse_header(request.headers(), "x-tenant-id") {
        Some(tenant) if tenant == claims.tenant_id => tenant,
        _ => {
            append_worker_audit(
                &state,
                None,
                ActionType::View,
                ActionResult::Denied,
                "worker/project-queue",
                "tenant mismatch",
            );
            return json_error(StatusCode::FORBIDDEN, "tenant mismatch");
        }
    };

    let request_context = RequestContext::new(
        TenantId::new(tenant.clone()).expect("tenant"),
        UserId::new(claims.user_id.clone()).expect("user"),
    );

    request
        .extensions_mut()
        .insert(TenantContext::new(TenantId::new(tenant).expect("tenant")));
    request.extensions_mut().insert(request_context);
    request
        .extensions_mut()
        .insert(AuthenticatedWorkerRequest { claims });

    next.run(request).await
}

async fn project_context_middleware(
    State(state): State<Arc<WorkerRuntime>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(request_context) = request.extensions().get::<RequestContext>().cloned() else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "missing request context");
    };

    let Some(project_id) = parse_header(request.headers(), "x-project-id") else {
        return json_error(StatusCode::BAD_REQUEST, "missing x-project-id header");
    };

    let Some(project_context) = state.projects.get(&project_id).cloned() else {
        append_worker_audit(
            &state,
            request.extensions().get::<AuthenticatedWorkerRequest>(),
            ActionType::View,
            ActionResult::Denied,
            "worker/project-queue",
            "project not found",
        );
        return json_error(StatusCode::NOT_FOUND, "project not found");
    };

    let scoped_request = request_context
        .clone()
        .with_project(ProjectId::new(project_id).expect("project"));

    if TenantIsolationGuard::assert_request_in_project(&scoped_request, &project_context).is_err() {
        append_worker_audit(
            &state,
            request.extensions().get::<AuthenticatedWorkerRequest>(),
            ActionType::View,
            ActionResult::Denied,
            "worker/project-queue",
            "project scope mismatch",
        );
        return json_error(StatusCode::FORBIDDEN, "project scope mismatch");
    }

    request.extensions_mut().insert(scoped_request);
    request.extensions_mut().insert(project_context);
    next.run(request).await
}

async fn project_queue_handler(
    State(state): State<Arc<WorkerRuntime>>,
    Extension(project_context): Extension<ProjectContext>,
    Extension(auth): Extension<AuthenticatedWorkerRequest>,
) -> Json<WorkerProjectResponse> {
    append_worker_audit(
        &state,
        Some(&auth),
        ActionType::View,
        ActionResult::Success,
        "worker/project-queue",
        "worker queue inspection",
    );
    let audit = state.audit.lock().expect("audit");
    Json(WorkerProjectResponse {
        queue_count: state.queue_count(),
        project_state: format!("{:?}", project_context.state).to_lowercase(),
        audit_chain_valid: audit.chain_valid(),
    })
}

fn append_worker_audit(
    state: &WorkerRuntime,
    auth: Option<&AuthenticatedWorkerRequest>,
    action: ActionType,
    result: ActionResult,
    resource_id: &str,
    context: &str,
) {
    let actor = auth.map_or(
        ActorInfo {
            user_id: "anonymous".into(),
            session_id: "anonymous".into(),
            ip_address: "127.0.0.1".into(),
        },
        |auth| ActorInfo {
            user_id: auth.claims.user_id.clone(),
            session_id: auth.claims.session_id.clone(),
            ip_address: auth.claims.binding.ip_address.clone(),
        },
    );
    let target = TargetRef {
        tenant_id: auth
            .map(|auth| auth.claims.tenant_id.clone())
            .unwrap_or_else(|| "unknown".into()),
        project_id: None,
        resource_id: resource_id.into(),
    };
    let prev_hash = state
        .audit
        .lock()
        .expect("audit")
        .events
        .last()
        .map(|event| event.event_hash.clone());
    let event = AuditEvent::new(actor, action, target, context, result, None, prev_hash);
    state.audit.lock().expect("audit").append(event);
}

fn parse_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name)?.to_str().ok().map(str::to_string)
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(str::to_string)
}

fn query_rows_to_maps(
    rows: &[Vec<sdqp_datasource_adapter::FieldQueryResult>],
) -> Vec<HashMap<String, String>> {
    rows.iter()
        .map(|row| {
            row.iter()
                .map(|field| (field.field.clone(), field.value.clone()))
                .collect::<HashMap<_, _>>()
        })
        .collect()
}

async fn request_observability_middleware(
    State(state): State<Arc<WorkerRuntime>>,
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

    if let Ok(value) = http::HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    if let Ok(value) = http::HeaderValue::from_str(&span_id) {
        response.headers_mut().insert("x-sdqp-span-id", value);
    }

    response
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.to_string(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{
        QUERY_METRIC_OUTCOMES, QueryWorkerMetrics, WORKER_TOKEN_SECRET, WorkerRuntime,
        observability::HttpMetrics,
    };
    use sdqp_config::AppSettings;
    use sdqp_core::{RequestContext, TenantId, UserId};
    use sdqp_datasource_adapter::CircuitBreaker;
    use sdqp_system_security::{SessionBinding, SessionPolicy, issue_access_token};

    #[test]
    fn worker_runtime_starts_with_phase0_queues() {
        let runtime = WorkerRuntime::new(AppSettings::local_dev().worker);
        assert_eq!(runtime.queue_count(), 2);
    }

    #[test]
    fn worker_tokens_can_be_issued_for_phase1_routes() {
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
        let token = issue_access_token(&claims, WORKER_TOKEN_SECRET).expect("token");
        assert!(token.contains('.'));
    }

    #[test]
    fn worker_metrics_payload_counts_responses() {
        let metrics = HttpMetrics::default();
        metrics.record(http::StatusCode::OK);
        metrics.record(http::StatusCode::BAD_REQUEST);

        let payload = metrics.render_prometheus("sdqp-worker");
        assert!(payload.contains("sdqp_http_requests_total{service=\"sdqp-worker\"} 2"));
        assert!(payload.contains("sdqp_http_responses_2xx_total{service=\"sdqp-worker\"} 1"));
        assert!(payload.contains("sdqp_http_responses_4xx_total{service=\"sdqp-worker\"} 1"));
    }

    #[test]
    fn query_metrics_render_known_outcomes_with_zero_defaults() {
        let metrics = QueryWorkerMetrics::default();
        let breaker = CircuitBreaker::new(2);

        let payload = metrics.render_prometheus("sdqp-worker", &breaker);
        for outcome in QUERY_METRIC_OUTCOMES {
            assert!(payload.contains(&format!(
                "sdqp_query_tasks_total{{service=\"sdqp-worker\",result=\"{outcome}\"}} 0"
            )));
        }
    }
}
