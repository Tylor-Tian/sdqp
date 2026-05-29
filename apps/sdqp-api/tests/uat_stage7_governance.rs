use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Path, Query, State},
    http::{Method, Request, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use chrono::Utc;
use http::Response;
use sdqp_api::{
    ApprovalTasksResponse, ApproverResolutionResponse, FeishuHrRuntimeResponse,
    LdapHrRuntimeResponse, LoginResponse, PermissionGrantsResponse, QuerySubmitResponse,
    QueryTaskStatusResponse, SapSuccessFactorsHrRuntimeResponse, TokenPairResponse,
    WorkdayHrRuntimeResponse, build_persistent_router,
};
use sdqp_config::AppSettings;
use serde_json::Value;
use sqlx::{Executor, Row, types::Json as SqlJson};
use sqlx_postgres::PgPoolOptions;
use tokio::{net::TcpListener, sync::oneshot};
use tower::ServiceExt;

fn stage7_enabled() -> bool {
    std::env::var("SDQP_ENABLE_STAGE7_TESTS").ok().as_deref() == Some("1")
}

fn admin_dsn() -> String {
    std::env::var("SDQP_STAGE3_ADMIN_DSN")
        .unwrap_or_else(|_| "postgres://sdqp:sdqp@127.0.0.1:15432/postgres".into())
}

fn test_settings(database_name: &str, receiver_base_url: &str) -> AppSettings {
    let mut settings = AppSettings::local_dev();
    settings.database.postgres.dsn =
        format!("postgres://sdqp:sdqp@127.0.0.1:15432/{database_name}");
    settings.database.clickhouse.http_url = "http://127.0.0.1:18123".into();
    settings.database.clickhouse.native_url = "tcp://127.0.0.1:19000".into();
    settings.object_store.endpoint = "http://127.0.0.1:19002".into();
    settings.integrations.notifications.feishu_webhook_url =
        format!("{receiver_base_url}/notify/feishu");
    settings.integrations.notifications.slack_webhook_url =
        format!("{receiver_base_url}/notify/slack");
    settings.integrations.notifications.email_api_url = format!("{receiver_base_url}/notify/email");
    settings.integrations.notifications.telegram_bot_api_url =
        format!("{receiver_base_url}/notify/telegram");
    settings.integrations.notifications.dingtalk_webhook_url =
        format!("{receiver_base_url}/notify/dingtalk");
    settings.integrations.notifications.retry_backoff_ms = 50;
    settings.integrations.hr.token = "stage7-hr-token".into();
    settings
}

async fn create_database(database_name: &str) {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_dsn())
        .await
        .expect("admin postgres");
    admin
        .execute(format!(r#"DROP DATABASE IF EXISTS "{database_name}""#).as_str())
        .await
        .expect("drop database if exists");
    admin
        .execute(format!(r#"CREATE DATABASE "{database_name}""#).as_str())
        .await
        .expect("create database");
}

async fn drop_database(database_name: &str) {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_dsn())
        .await
        .expect("admin postgres");
    admin
        .execute(
            format!(
                r#"
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = '{database_name}' AND pid <> pg_backend_pid()
                "#,
            )
            .as_str(),
        )
        .await
        .expect("terminate sessions");
    admin
        .execute(format!(r#"DROP DATABASE IF EXISTS "{database_name}""#).as_str())
        .await
        .expect("drop database");
}

async fn json_request(
    app: Router,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
    headers: &[(&str, &str)],
) -> Response<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }

    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
        None => builder.body(Body::empty()).expect("request"),
    };

    app.oneshot(request).await.expect("response")
}

async fn decode_json<T: serde::de::DeserializeOwned>(response: Response<Body>) -> T {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

async fn user_tokens(app: Router, username: &str) -> TokenPairResponse {
    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            Some(serde_json::json!({
                "username": username,
                "password": "password123",
                "device_fingerprint": format!("stage7-{username}")
            })),
            &[("x-forwarded-for", "127.0.0.1")],
        )
        .await,
    )
    .await;

    decode_json(
        json_request(
            app,
            Method::POST,
            "/auth/mfa/verify",
            Some(serde_json::json!({
                "pending_session_id": login.pending_session_id,
                "code": "000000"
            })),
            &[],
        )
        .await,
    )
    .await
}

fn scoped_headers(token: &str) -> [(&str, &str); 3] {
    [
        ("authorization", token),
        ("x-tenant-id", "tenant-alpha"),
        ("x-project-id", "project-alpha"),
    ]
}

async fn wait_for_task_state(
    app: Router,
    token: &str,
    task_id: &str,
    expected: &str,
) -> QueryTaskStatusResponse {
    for _ in 0..120 {
        let status: QueryTaskStatusResponse = decode_json(
            json_request(
                app.clone(),
                Method::GET,
                &format!("/v1/tasks/{task_id}/status"),
                None,
                &scoped_headers(token),
            )
            .await,
        )
        .await;
        if status.state == expected {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("task {task_id} did not reach {expected}");
}

async fn wait_for_grant_field(
    app: Router,
    token: &str,
    field_name: &str,
) -> PermissionGrantsResponse {
    for _ in 0..120 {
        let grants: PermissionGrantsResponse = decode_json(
            json_request(
                app.clone(),
                Method::GET,
                "/v1/permissions/grants",
                None,
                &scoped_headers(token),
            )
            .await,
        )
        .await;
        if grants.grants.iter().any(|grant| {
            grant.status == "active" && grant.fields.iter().any(|field| field == field_name)
        }) {
            return grants;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("field grant {field_name} did not become active");
}

async fn wait_for_all_grants_revoked(app: Router, token: &str) -> PermissionGrantsResponse {
    for _ in 0..120 {
        let grants: PermissionGrantsResponse = decode_json(
            json_request(
                app.clone(),
                Method::GET,
                "/v1/permissions/grants",
                None,
                &scoped_headers(token),
            )
            .await,
        )
        .await;
        if grants.grants.iter().all(|grant| grant.status != "active") {
            return grants;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("active grants were not revoked");
}

#[derive(Debug, Clone)]
struct ReceivedNotification {
    delivery_id: String,
    instance_id: Option<String>,
    channel: String,
    recipient: String,
    message: String,
    payload: Value,
}

#[derive(Debug, Default)]
struct ReceiverState {
    attempts_by_channel: Mutex<HashMap<String, usize>>,
    notifications: Mutex<Vec<ReceivedNotification>>,
}

async fn receiver_handler(
    Path(channel): Path<String>,
    State(state): State<Arc<ReceiverState>>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let Ok(payload) = normalize_received_notification(&channel, payload) else {
        return StatusCode::BAD_REQUEST;
    };
    let attempt = {
        let mut attempts = state.attempts_by_channel.lock().expect("attempts");
        let next = attempts.entry(channel.clone()).or_insert(0);
        *next += 1;
        *next
    };
    if channel == "slack" && attempt == 1 {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    state
        .notifications
        .lock()
        .expect("notifications")
        .push(payload);
    StatusCode::OK
}

struct MockReceiver {
    base_url: String,
    state: Arc<ReceiverState>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl MockReceiver {
    async fn start() -> Self {
        let state = Arc::new(ReceiverState::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let app = Router::new()
            .route("/notify/{channel}", post(receiver_handler))
            .with_state(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("receiver");
        });
        Self {
            base_url: format!("http://{address}"),
            state,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    fn notifications(&self) -> Vec<ReceivedNotification> {
        self.state
            .notifications
            .lock()
            .expect("notifications")
            .clone()
    }

    fn notification_for(&self, channel: &str, recipient: &str) -> Option<ReceivedNotification> {
        self.notifications()
            .into_iter()
            .find(|item| item.channel == channel && item.recipient == recipient)
    }

    fn attempts_for(&self, channel: &str) -> usize {
        self.state
            .attempts_by_channel
            .lock()
            .expect("attempts")
            .get(channel)
            .copied()
            .unwrap_or_default()
    }
}

impl Drop for MockReceiver {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
    }
}

#[derive(Clone)]
struct FeishuProviderState {
    tenant_access_token: String,
    requests: Arc<Mutex<Vec<String>>>,
}

async fn feishu_token_handler(State(state): State<FeishuProviderState>) -> Json<Value> {
    state
        .requests
        .lock()
        .expect("feishu requests")
        .push("token".into());
    Json(serde_json::json!({
        "tenant_access_token": state.tenant_access_token,
        "code": 0,
        "msg": "ok"
    }))
}

async fn feishu_users_handler(
    State(state): State<FeishuProviderState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response<Body> {
    if !feishu_authorized(&headers, &state.tenant_access_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    state
        .requests
        .lock()
        .expect("feishu requests")
        .push(format!(
            "users:{}",
            query.get("tenant_key").cloned().unwrap_or_default()
        ));
    Json(serde_json::json!({
        "data": {
            "items": [
                {
                    "user_id": "user-manager-a",
                    "department_ids": ["dept-risk"],
                    "leader_user_id": null,
                    "status": { "is_activated": true, "is_resigned": false }
                },
                {
                    "user_id": "user-analyst",
                    "department_ids": ["dept-risk"],
                    "leader_user_id": "user-manager-a",
                    "status": { "is_activated": true, "is_resigned": false }
                }
            ],
            "page_token": "snapshot-cursor-feishu-001"
        }
    }))
    .into_response()
}

async fn feishu_events_handler(
    State(state): State<FeishuProviderState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response<Body> {
    if !feishu_authorized(&headers, &state.tenant_access_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    state
        .requests
        .lock()
        .expect("feishu requests")
        .push(format!(
            "events:{}",
            query.get("cursor").cloned().unwrap_or_default()
        ));
    Json(serde_json::json!({
        "data": {
            "items": [
                {
                    "event_id": "evt-feishu-poll-001",
                    "user_id": "user-analyst",
                    "event_type": "user_deleted",
                    "department_id": "dept-risk",
                    "leader_user_id": "user-manager-a",
                    "occurred_at": Utc::now().to_rfc3339()
                }
            ],
            "page_token": "evt-feishu-poll-001"
        }
    }))
    .into_response()
}

fn feishu_authorized(headers: &axum::http::HeaderMap, token: &str) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value == format!("Bearer {token}"))
        .unwrap_or(false)
}

struct MockFeishuProvider {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockFeishuProvider {
    async fn start() -> Self {
        let state = FeishuProviderState {
            tenant_access_token: "feishu-tenant-access-token".into(),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let app = Router::new()
            .route(
                "/open-apis/auth/v3/tenant_access_token/internal",
                post(feishu_token_handler),
            )
            .route("/open-apis/contact/v3/users", get(feishu_users_handler))
            .route("/open-apis/contact/v3/events", get(feishu_events_handler))
            .with_state(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("feishu provider");
        });
        Self {
            base_url: format!("http://{address}"),
            requests: state.requests,
        }
    }

    fn observed_requests(&self) -> Vec<String> {
        self.requests.lock().expect("feishu requests").clone()
    }
}

#[derive(Clone)]
struct WorkdayProviderState {
    bearer_token: String,
    requests: Arc<Mutex<Vec<String>>>,
}

async fn workday_token_handler(State(state): State<WorkdayProviderState>) -> Json<Value> {
    state
        .requests
        .lock()
        .expect("workday requests")
        .push("token".into());
    Json(serde_json::json!({
        "access_token": state.bearer_token,
        "token_type": "Bearer",
        "expires_in": 300
    }))
}

async fn workday_workers_handler(
    State(state): State<WorkdayProviderState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response<Body> {
    if !workday_authorized(&headers, &state.bearer_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    state
        .requests
        .lock()
        .expect("workday requests")
        .push(format!(
            "workers:{}",
            query.get("tenant").cloned().unwrap_or_default()
        ));
    Json(serde_json::json!({
        "workers": [
            {
                "worker_id": "user-manager-a",
                "supervisory_org_id": "dept-risk",
                "manager_worker_id": null,
                "active": true
            },
            {
                "worker_id": "user-analyst",
                "supervisory_org_id": "dept-risk",
                "manager_worker_id": "user-manager-a",
                "active": true
            }
        ],
        "next_cursor": "snapshot-cursor-001"
    }))
    .into_response()
}

async fn workday_events_handler(
    State(state): State<WorkdayProviderState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response<Body> {
    if !workday_authorized(&headers, &state.bearer_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    state
        .requests
        .lock()
        .expect("workday requests")
        .push(format!(
            "events:{}",
            query.get("cursor").cloned().unwrap_or_default()
        ));
    Json(serde_json::json!({
        "events": [
            {
                "event_id": "evt-workday-poll-001",
                "worker_id": "user-analyst",
                "event_type": "Termination",
                "supervisory_org_id": "dept-risk",
                "manager_worker_id": "user-manager-a",
                "occurred_at": Utc::now().to_rfc3339()
            }
        ],
        "next_cursor": "evt-workday-poll-001"
    }))
    .into_response()
}

fn workday_authorized(headers: &axum::http::HeaderMap, token: &str) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value == format!("Bearer {token}"))
        .unwrap_or(false)
}

struct MockWorkdayProvider {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockWorkdayProvider {
    async fn start() -> Self {
        let state = WorkdayProviderState {
            bearer_token: "workday-access-token".into(),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let app = Router::new()
            .route("/oauth2/token", post(workday_token_handler))
            .route("/workday/workers", get(workday_workers_handler))
            .route("/workday/events", get(workday_events_handler))
            .with_state(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("workday provider");
        });
        Self {
            base_url: format!("http://{address}"),
            requests: state.requests,
        }
    }

    fn observed_requests(&self) -> Vec<String> {
        self.requests.lock().expect("workday requests").clone()
    }
}

#[derive(Clone)]
struct SapSuccessFactorsProviderState {
    bearer_token: String,
    requests: Arc<Mutex<Vec<String>>>,
}

async fn sap_successfactors_token_handler(
    State(state): State<SapSuccessFactorsProviderState>,
) -> Json<Value> {
    state
        .requests
        .lock()
        .expect("sap successfactors requests")
        .push("token".into());
    Json(serde_json::json!({
        "access_token": state.bearer_token,
        "token_type": "Bearer",
        "expires_in": 300
    }))
}

async fn sap_successfactors_users_handler(
    State(state): State<SapSuccessFactorsProviderState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response<Body> {
    if !sap_successfactors_authorized(&headers, &state.bearer_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    state
        .requests
        .lock()
        .expect("sap successfactors requests")
        .push(format!(
            "users:{}",
            query.get("companyId").cloned().unwrap_or_default()
        ));
    Json(serde_json::json!({
        "d": {
            "results": [
                {
                    "personIdExternal": "user-manager-a",
                    "departmentExternalCode": "dept-risk",
                    "managerPersonIdExternal": null,
                    "employmentStatus": "Active"
                },
                {
                    "personIdExternal": "user-analyst",
                    "departmentExternalCode": "dept-risk",
                    "managerPersonIdExternal": "user-manager-a",
                    "employmentStatus": "Active"
                }
            ],
            "__next": "snapshot-cursor-sap-001"
        }
    }))
    .into_response()
}

async fn sap_successfactors_events_handler(
    State(state): State<SapSuccessFactorsProviderState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response<Body> {
    if !sap_successfactors_authorized(&headers, &state.bearer_token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    state
        .requests
        .lock()
        .expect("sap successfactors requests")
        .push(format!(
            "events:{}",
            query.get("$skiptoken").cloned().unwrap_or_default()
        ));
    Json(serde_json::json!({
        "d": {
            "results": [
                {
                    "eventId": "evt-sap-poll-001",
                    "personIdExternal": "user-analyst",
                    "eventType": "Termination",
                    "departmentExternalCode": "dept-risk",
                    "managerPersonIdExternal": "user-manager-a",
                    "occurredAt": Utc::now().to_rfc3339()
                }
            ],
            "__next": "evt-sap-poll-001"
        }
    }))
    .into_response()
}

fn sap_successfactors_authorized(headers: &axum::http::HeaderMap, token: &str) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value == format!("Bearer {token}"))
        .unwrap_or(false)
}

struct MockSapSuccessFactorsProvider {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockSapSuccessFactorsProvider {
    async fn start() -> Self {
        let state = SapSuccessFactorsProviderState {
            bearer_token: "sap-successfactors-access-token".into(),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let app = Router::new()
            .route("/oauth/token", post(sap_successfactors_token_handler))
            .route("/odata/v2/User", get(sap_successfactors_users_handler))
            .route("/odata/v2/EmpJob", get(sap_successfactors_events_handler))
            .with_state(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("sap successfactors provider");
        });
        Self {
            base_url: format!("http://{address}"),
            requests: state.requests,
        }
    }

    fn observed_requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("sap successfactors requests")
            .clone()
    }
}

struct MockLdapSearchBinary {
    path: PathBuf,
    dir: PathBuf,
}

impl MockLdapSearchBinary {
    fn create() -> Self {
        let dir = std::env::temp_dir().join(format!("sdqp-ldapsearch-{}", ulid::Ulid::new()));
        fs::create_dir_all(&dir).expect("ldapsearch temp dir");
        let path = dir.join(if cfg!(windows) {
            "ldapsearch.cmd"
        } else {
            "ldapsearch"
        });
        let mut file = fs::File::create(&path).expect("ldapsearch script");
        if cfg!(windows) {
            writeln!(file, "@echo off").expect("script");
            writeln!(file, "echo %* | findstr /C:\"modifyTimestamp\" >nul").expect("script");
            writeln!(file, "if %errorlevel%==0 (").expect("script");
            write_ldap_poll_cmd(&mut file);
            writeln!(file, ") else (").expect("script");
            write_ldap_snapshot_cmd(&mut file);
            writeln!(file, ")").expect("script");
        } else {
            writeln!(file, "#!/bin/sh").expect("script");
            writeln!(file, "case \"$*\" in").expect("script");
            writeln!(file, "  *modifyTimestamp*)").expect("script");
            writeln!(file, "cat <<'LDIF'").expect("script");
            write_ldap_poll_ldif(&mut file);
            writeln!(file, "LDIF").expect("script");
            writeln!(file, ";;").expect("script");
            writeln!(file, "  *)").expect("script");
            writeln!(file, "cat <<'LDIF'").expect("script");
            write_ldap_snapshot_ldif(&mut file);
            writeln!(file, "LDIF").expect("script");
            writeln!(file, ";;").expect("script");
            writeln!(file, "esac").expect("script");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&path).expect("metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).expect("permissions");
        }
        Self { path, dir }
    }
}

impl Drop for MockLdapSearchBinary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn write_ldap_snapshot_ldif(file: &mut fs::File) {
    writeln!(
        file,
        "dn: uid=user-manager-a,ou=People,dc=example,dc=internal\nuid: user-manager-a\ndepartmentNumber: dept-risk\nemployeeStatus: active\nmodifyTimestamp: 20260426090000Z\n\ndn: uid=user-analyst,ou=People,dc=example,dc=internal\nuid: user-analyst\ndepartmentNumber: dept-risk\nmanager: uid=user-manager-a,ou=People,dc=example,dc=internal\nemployeeStatus: active\nmodifyTimestamp: 20260426090000Z\n"
    )
    .expect("ldif");
}

fn write_ldap_poll_ldif(file: &mut fs::File) {
    writeln!(
        file,
        "dn: uid=user-analyst,ou=People,dc=example,dc=internal\nuid: user-analyst\ndepartmentNumber: dept-risk\nmanager: uid=user-manager-a,ou=People,dc=example,dc=internal\nemployeeStatus: departed\nmodifyTimestamp: 20260426100000Z\n"
    )
    .expect("ldif");
}

fn write_ldap_snapshot_cmd(file: &mut fs::File) {
    for line in [
        "dn: uid=user-manager-a,ou=People,dc=example,dc=internal",
        "uid: user-manager-a",
        "departmentNumber: dept-risk",
        "employeeStatus: active",
        "modifyTimestamp: 20260426090000Z",
        "",
        "dn: uid=user-analyst,ou=People,dc=example,dc=internal",
        "uid: user-analyst",
        "departmentNumber: dept-risk",
        "manager: uid=user-manager-a,ou=People,dc=example,dc=internal",
        "employeeStatus: active",
        "modifyTimestamp: 20260426090000Z",
    ] {
        if line.is_empty() {
            writeln!(file, "echo.").expect("script");
        } else {
            writeln!(file, "echo {line}").expect("script");
        }
    }
}

fn write_ldap_poll_cmd(file: &mut fs::File) {
    for line in [
        "dn: uid=user-analyst,ou=People,dc=example,dc=internal",
        "uid: user-analyst",
        "departmentNumber: dept-risk",
        "manager: uid=user-manager-a,ou=People,dc=example,dc=internal",
        "employeeStatus: departed",
        "modifyTimestamp: 20260426100000Z",
    ] {
        writeln!(file, "echo {line}").expect("script");
    }
}

async fn wait_for_notification(
    receiver: &MockReceiver,
    recipient: &str,
    min_slack_attempts: usize,
) {
    for _ in 0..120 {
        let notifications = receiver.notifications();
        if ["feishu", "slack", "email", "telegram", "dingtalk"]
            .iter()
            .all(|channel| {
                notifications
                    .iter()
                    .any(|item| item.recipient == recipient && item.channel == *channel)
            })
            && receiver.attempts_for("slack") >= min_slack_attempts
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("notification for {recipient} was not observed");
}

fn normalize_received_notification(
    channel: &str,
    payload: Value,
) -> Result<ReceivedNotification, ()> {
    let metadata = payload.get("sdqp_metadata").ok_or(())?;
    let recipient = metadata
        .get("recipient")
        .and_then(Value::as_str)
        .ok_or(())?
        .to_string();
    let message = metadata
        .get("message")
        .and_then(Value::as_str)
        .ok_or(())?
        .to_string();
    Ok(ReceivedNotification {
        delivery_id: metadata
            .get("delivery_id")
            .and_then(Value::as_str)
            .ok_or(())?
            .to_string(),
        instance_id: metadata
            .get("instance_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        channel: channel.to_string(),
        recipient,
        message,
        payload,
    })
}

fn assert_actionable_notification_contracts(
    receiver: &MockReceiver,
    recipient: &str,
    expected_kind: &str,
) {
    let feishu = receiver
        .notification_for("feishu", recipient)
        .expect("feishu notification");
    assert!(!feishu.delivery_id.is_empty());
    assert!(feishu.instance_id.is_some());
    assert!(!feishu.message.is_empty());
    assert_eq!(feishu.payload["msg_type"].as_str(), Some("interactive"));
    assert!(feishu.payload["card"]["elements"].is_array());
    assert_eq!(
        feishu.payload["sdqp_metadata"]["kind"].as_str(),
        Some(expected_kind)
    );
    assert_eq!(
        feishu.payload["sdqp_metadata"]["callback"]["path"].as_str(),
        Some("/v1/approvals/callback")
    );
    assert_eq!(
        feishu.payload["sdqp_metadata"]["callback"]["actions"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );

    let slack = receiver
        .notification_for("slack", recipient)
        .expect("slack notification");
    assert_eq!(slack.payload["channel"].as_str(), Some(recipient));
    assert!(slack.payload["blocks"].is_array());
    assert_eq!(
        slack.payload["sdqp_metadata"]["kind"].as_str(),
        Some(expected_kind)
    );
    assert_eq!(
        slack.payload["sdqp_metadata"]["callback"]["path"].as_str(),
        Some("/v1/approvals/callback")
    );

    let email = receiver
        .notification_for("email", recipient)
        .expect("email notification");
    assert_eq!(email.payload["to"].as_str(), Some(recipient));
    assert!(email.payload["actions"].is_array());
    assert!(
        email.payload["html"]
            .as_str()
            .expect("email html")
            .contains("/v1/approvals/callback")
    );
    assert_eq!(
        email.payload["sdqp_metadata"]["kind"].as_str(),
        Some(expected_kind)
    );

    let telegram = receiver
        .notification_for("telegram", recipient)
        .expect("telegram notification");
    assert_eq!(telegram.payload["chat_id"].as_str(), Some(recipient));
    assert_eq!(telegram.payload["parse_mode"].as_str(), Some("Markdown"));
    assert!(telegram.payload["reply_markup"]["inline_keyboard"].is_array());
    assert_eq!(
        telegram.payload["sdqp_metadata"]["kind"].as_str(),
        Some(expected_kind)
    );
    assert_eq!(
        telegram.payload["sdqp_metadata"]["callback"]["path"].as_str(),
        Some("/v1/approvals/callback")
    );

    let dingtalk = receiver
        .notification_for("dingtalk", recipient)
        .expect("dingtalk notification");
    assert_eq!(dingtalk.payload["msgtype"].as_str(), Some("actionCard"));
    assert!(dingtalk.payload["actionCard"]["btns"].is_array());
    assert_eq!(
        dingtalk.payload["sdqp_metadata"]["kind"].as_str(),
        Some(expected_kind)
    );
    assert_eq!(
        dingtalk.payload["sdqp_metadata"]["callback"]["path"].as_str(),
        Some("/v1/approvals/callback")
    );
}

async fn wait_for_delivery_statuses(
    database_dsn: &str,
    instance_id: &str,
    recipient: &str,
    min_slack_attempts: i32,
) {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_dsn)
        .await
        .expect("postgres");
    for _ in 0..120 {
        let rows = sqlx::query(
            r#"
            SELECT channel, status, attempt_count, last_error
            FROM notification_deliveries
            WHERE instance_id = $1 AND recipient = $2
            "#,
        )
        .bind(instance_id)
        .bind(recipient)
        .fetch_all(&pool)
        .await
        .expect("notification deliveries");
        if rows.len() == 5
            && rows.iter().all(|row| {
                row.try_get::<String, _>("status").unwrap() == "sent"
                    && row
                        .try_get::<Option<String>, _>("last_error")
                        .unwrap()
                        .is_none()
            })
            && rows.iter().any(|row| {
                row.try_get::<String, _>("channel").unwrap() == "slack"
                    && row.try_get::<i32, _>("attempt_count").unwrap() >= min_slack_attempts
            })
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("notification delivery status for {recipient} was not persisted as sent");
}

async fn force_instance_due(database_dsn: &str, instance_id: &str) {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_dsn)
        .await
        .expect("postgres");
    let row = sqlx::query("SELECT step_states_json FROM approval_instances WHERE instance_id = $1")
        .bind(instance_id)
        .fetch_one(&pool)
        .await
        .expect("instance row");
    let mut step_states = row
        .try_get::<SqlJson<Vec<serde_json::Value>>, _>("step_states_json")
        .expect("step states")
        .0;
    step_states[0]["due_at"] =
        serde_json::Value::String((Utc::now() - chrono::Duration::seconds(5)).to_rfc3339());
    sqlx::query("UPDATE approval_instances SET step_states_json = $2 WHERE instance_id = $1")
        .bind(instance_id)
        .bind(SqlJson(step_states))
        .execute(&pool)
        .await
        .expect("update step states");
}

#[tokio::test]
async fn uat_stage7_request_approval_effective_and_hr_revocation_flow() {
    if !stage7_enabled() {
        return;
    }

    let receiver = MockReceiver::start().await;
    let database_name = format!("sdqp_stage7_flow_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let settings = test_settings(&database_name, &receiver.base_url);
    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent api router");

    let analyst = user_tokens(app.clone(), "analyst").await;
    let manager = user_tokens(app.clone(), "manager").await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);
    let manager_bearer = format!("Bearer {}", manager.access_token);

    let denied_before = json_request(
        app.clone(),
        Method::POST,
        "/v1/queries",
        Some(serde_json::json!({
            "data_source_id": "datasource-rest",
            "source_type": "rest",
            "fields": ["employee_email"]
        })),
        &scoped_headers(&analyst_bearer),
    )
    .await;
    assert_eq!(denied_before.status(), StatusCode::FORBIDDEN);

    let application: serde_json::Value = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/permissions/applications",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "requested_fields": ["employee_email"]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(application["status"], "Pending");
    let application_id = application["application_id"]
        .as_str()
        .expect("application id");
    let instance_id = application["approval_instance_id"]
        .as_str()
        .expect("instance id");

    let duplicate: serde_json::Value = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/permissions/applications",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "requested_fields": ["employee_email"]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(duplicate["application_id"], application["application_id"]);

    let manager_tasks: ApprovalTasksResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/approvals/tasks",
            None,
            &scoped_headers(&manager_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(manager_tasks.tasks.len(), 1);
    assert_eq!(manager_tasks.tasks[0].application_id, application_id);

    let approval_response = json_request(
        app.clone(),
        Method::POST,
        "/v1/approvals/callback",
        Some(serde_json::json!({
            "instance_id": instance_id,
            "action": "approve"
        })),
        &scoped_headers(&manager_bearer),
    )
    .await;
    assert_eq!(approval_response.status(), StatusCode::OK);

    let grants = wait_for_grant_field(app.clone(), &analyst_bearer, "employee_email").await;
    assert!(grants.grants.iter().any(|grant| grant.status == "active"));

    let submit: QuerySubmitResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "source_type": "rest",
                "fields": ["employee_email"]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    let status =
        wait_for_task_state(app.clone(), &analyst_bearer, &submit.task_id, "completed").await;
    assert_eq!(status.state, "completed");

    let hr_response = json_request(
        app.clone(),
        Method::POST,
        "/integrations/hr/events",
        Some(serde_json::json!({
            "source": "feishu",
            "event_id": format!("evt-{}", ulid::Ulid::new()),
            "user_id": "user-analyst",
            "event_type": "departure"
        })),
        &[("x-sdqp-hr-token", settings.integrations.hr.token.as_str())],
    )
    .await;
    assert_eq!(hr_response.status(), StatusCode::OK);

    let grants_after = wait_for_all_grants_revoked(app.clone(), &analyst_bearer).await;
    assert!(
        grants_after
            .grants
            .iter()
            .all(|grant| grant.status != "active")
    );

    let denied_after = json_request(
        app,
        Method::POST,
        "/v1/queries",
        Some(serde_json::json!({
            "data_source_id": "datasource-rest",
            "source_type": "rest",
            "fields": ["employee_id"]
        })),
        &scoped_headers(&analyst_bearer),
    )
    .await;
    assert_eq!(denied_after.status(), StatusCode::FORBIDDEN);

    drop_database(&database_name).await;
}

#[tokio::test]
async fn uat_stage7_feishu_provider_snapshot_poll_and_webhook_runtime_closure() {
    if !stage7_enabled() {
        return;
    }

    let receiver = MockReceiver::start().await;
    let feishu = MockFeishuProvider::start().await;
    let database_name = format!("sdqp_stage7_feishu_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let mut settings = test_settings(&database_name, &receiver.base_url);
    settings.integrations.hr.provider = "feishu".into();
    settings.integrations.hr.feishu.provider_id = "feishu-primary".into();
    settings.integrations.hr.feishu.tenant_key = "tenant-alpha".into();
    settings.integrations.hr.feishu.base_url = feishu.base_url.clone();
    settings.integrations.hr.feishu.auth_mode = "app_credentials".into();
    settings.integrations.hr.feishu.token_url = format!(
        "{}/open-apis/auth/v3/tenant_access_token/internal",
        feishu.base_url
    );
    settings.integrations.hr.feishu.app_id = "cli_a".into();
    settings.integrations.hr.feishu.app_secret = "feishu-secret".into();
    settings.integrations.hr.feishu.users_path = "/open-apis/contact/v3/users".into();
    settings.integrations.hr.feishu.events_path = "/open-apis/contact/v3/events".into();
    settings.integrations.hr.feishu.webhook_verification_token = "feishu-webhook-token".into();
    settings.integrations.hr.feishu.page_size = 2;
    settings.integrations.hr.feishu.timeout_ms = 3_000;
    let database_dsn = settings.database.postgres.dsn.clone();
    let integration_key = settings.security.integration_api_keys[0].secret.clone();
    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent api router");

    let integration_headers = [
        ("x-api-key", integration_key.as_str()),
        ("x-client-cert-subject", "CN=sdqp-integration"),
        ("x-forwarded-for", "127.0.0.1"),
    ];
    let snapshot: FeishuHrRuntimeResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/integrations/hr/feishu/snapshot",
            None,
            &integration_headers,
        )
        .await,
    )
    .await;
    assert_eq!(snapshot.provider_id, "feishu-primary");
    assert_eq!(snapshot.runtime_mode, "real_http_openapi");
    assert_eq!(snapshot.auth_mode, "app_credentials");
    assert_eq!(snapshot.synced_user_count, 2);
    assert_eq!(
        snapshot.snapshot_cursor_after.as_deref(),
        Some("snapshot-cursor-feishu-001")
    );

    let analyst = user_tokens(app.clone(), "analyst").await;
    let manager = user_tokens(app.clone(), "manager").await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);
    let manager_bearer = format!("Bearer {}", manager.access_token);

    let application: serde_json::Value = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/permissions/applications",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "requested_fields": ["employee_email"]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    let instance_id = application["approval_instance_id"]
        .as_str()
        .expect("instance id");

    let approval_response = json_request(
        app.clone(),
        Method::POST,
        "/v1/approvals/callback",
        Some(serde_json::json!({
            "instance_id": instance_id,
            "action": "approve"
        })),
        &scoped_headers(&manager_bearer),
    )
    .await;
    assert_eq!(approval_response.status(), StatusCode::OK);
    let _ = wait_for_grant_field(app.clone(), &analyst_bearer, "employee_email").await;

    let poll: FeishuHrRuntimeResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/integrations/hr/feishu/poll",
            None,
            &integration_headers,
        )
        .await,
    )
    .await;
    assert_eq!(poll.operation, "event_poll");
    assert_eq!(poll.received_event_count, 1);
    assert_eq!(poll.applied_event_count, 1);
    assert_eq!(
        poll.checkpoint_after.as_deref(),
        Some("evt-feishu-poll-001")
    );
    assert!(poll.revoked_grants >= 1);
    let _ = wait_for_all_grants_revoked(app.clone(), &analyst_bearer).await;

    let webhook_headers = [
        ("x-api-key", integration_key.as_str()),
        ("x-client-cert-subject", "CN=sdqp-integration"),
        ("x-forwarded-for", "127.0.0.1"),
        ("x-feishu-webhook-token", "feishu-webhook-token"),
    ];
    let webhook: FeishuHrRuntimeResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/integrations/hr/feishu/webhook",
            Some(serde_json::json!({
                "events": [
                    {
                        "event_id": "evt-feishu-webhook-001",
                        "user_id": "user-manager-a",
                        "event_type": "manager_change",
                        "department_id": "dept-risk",
                        "leader_user_id": null,
                        "occurred_at": Utc::now().to_rfc3339()
                    }
                ],
                "next_cursor": "evt-feishu-webhook-001"
            })),
            &webhook_headers,
        )
        .await,
    )
    .await;
    assert_eq!(webhook.operation, "webhook");
    assert_eq!(webhook.applied_event_count, 1);
    assert_eq!(
        webhook.checkpoint_after.as_deref(),
        Some("evt-feishu-webhook-001")
    );
    assert!(!webhook.audit_checkpoint_id.is_empty());

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_dsn)
        .await
        .expect("postgres");
    let checkpoint_row = sqlx::query(
        "SELECT source, event_cursor, snapshot_cursor, auth_mode FROM hr_sync_checkpoints WHERE provider_id = 'feishu-primary'",
    )
    .fetch_one(&pool)
    .await
    .expect("checkpoint");
    assert_eq!(
        checkpoint_row.try_get::<String, _>("source").unwrap(),
        "feishu"
    );
    assert_eq!(
        checkpoint_row.try_get::<String, _>("event_cursor").unwrap(),
        "evt-feishu-webhook-001"
    );
    assert_eq!(
        checkpoint_row
            .try_get::<String, _>("snapshot_cursor")
            .unwrap(),
        "snapshot-cursor-feishu-001"
    );
    assert_eq!(
        checkpoint_row.try_get::<String, _>("auth_mode").unwrap(),
        "app_credentials"
    );
    let event_count = sqlx::query(
        "SELECT COUNT(*)::BIGINT AS count FROM hr_sync_events WHERE provider_id = 'feishu-primary'",
    )
    .fetch_one(&pool)
    .await
    .expect("event count")
    .try_get::<i64, _>("count")
    .unwrap();
    assert_eq!(event_count, 2);
    assert!(
        feishu
            .observed_requests()
            .iter()
            .any(|request| request == "users:tenant-alpha")
    );

    drop_database(&database_name).await;
}

#[tokio::test]
async fn uat_stage7_workday_provider_snapshot_poll_and_webhook_runtime_closure() {
    if !stage7_enabled() {
        return;
    }

    let receiver = MockReceiver::start().await;
    let workday = MockWorkdayProvider::start().await;
    let database_name = format!("sdqp_stage7_workday_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let mut settings = test_settings(&database_name, &receiver.base_url);
    settings.integrations.hr.provider = "workday".into();
    settings.integrations.hr.workday.provider_id = "workday-primary".into();
    settings.integrations.hr.workday.tenant = "tenant-alpha".into();
    settings.integrations.hr.workday.base_url = workday.base_url.clone();
    settings.integrations.hr.workday.auth_mode = "oauth_client_credentials".into();
    settings.integrations.hr.workday.token_url = format!("{}/oauth2/token", workday.base_url);
    settings.integrations.hr.workday.client_id = "workday-client".into();
    settings.integrations.hr.workday.client_secret = "workday-secret".into();
    settings.integrations.hr.workday.scope = "workers events".into();
    settings.integrations.hr.workday.snapshot_path = "/workday/workers".into();
    settings.integrations.hr.workday.events_path = "/workday/events".into();
    settings.integrations.hr.workday.webhook_secret = "workday-webhook-secret".into();
    settings.integrations.hr.workday.page_size = 2;
    settings.integrations.hr.workday.timeout_ms = 3_000;
    let database_dsn = settings.database.postgres.dsn.clone();
    let integration_key = settings.security.integration_api_keys[0].secret.clone();
    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent api router");

    let integration_headers = [
        ("x-api-key", integration_key.as_str()),
        ("x-client-cert-subject", "CN=sdqp-integration"),
        ("x-forwarded-for", "127.0.0.1"),
    ];
    let snapshot: WorkdayHrRuntimeResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/integrations/hr/workday/snapshot",
            None,
            &integration_headers,
        )
        .await,
    )
    .await;
    assert_eq!(snapshot.provider_id, "workday-primary");
    assert_eq!(snapshot.runtime_mode, "real_http");
    assert_eq!(snapshot.auth_mode, "oauth_client_credentials");
    assert_eq!(snapshot.synced_user_count, 2);
    assert_eq!(
        snapshot.snapshot_cursor_after.as_deref(),
        Some("snapshot-cursor-001")
    );

    let analyst = user_tokens(app.clone(), "analyst").await;
    let manager = user_tokens(app.clone(), "manager").await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);
    let manager_bearer = format!("Bearer {}", manager.access_token);

    let application: serde_json::Value = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/permissions/applications",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "requested_fields": ["employee_email"]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    let instance_id = application["approval_instance_id"]
        .as_str()
        .expect("instance id");

    let approval_response = json_request(
        app.clone(),
        Method::POST,
        "/v1/approvals/callback",
        Some(serde_json::json!({
            "instance_id": instance_id,
            "action": "approve"
        })),
        &scoped_headers(&manager_bearer),
    )
    .await;
    assert_eq!(approval_response.status(), StatusCode::OK);
    let _ = wait_for_grant_field(app.clone(), &analyst_bearer, "employee_email").await;

    let poll: WorkdayHrRuntimeResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/integrations/hr/workday/poll",
            None,
            &integration_headers,
        )
        .await,
    )
    .await;
    assert_eq!(poll.operation, "event_poll");
    assert_eq!(poll.received_event_count, 1);
    assert_eq!(poll.applied_event_count, 1);
    assert_eq!(
        poll.checkpoint_after.as_deref(),
        Some("evt-workday-poll-001")
    );
    assert!(poll.revoked_grants >= 1);
    let _ = wait_for_all_grants_revoked(app.clone(), &analyst_bearer).await;

    let webhook_headers = [
        ("x-api-key", integration_key.as_str()),
        ("x-client-cert-subject", "CN=sdqp-integration"),
        ("x-forwarded-for", "127.0.0.1"),
        ("x-workday-webhook-secret", "workday-webhook-secret"),
    ];
    let webhook: WorkdayHrRuntimeResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/integrations/hr/workday/webhook",
            Some(serde_json::json!({
                "events": [
                    {
                        "event_id": "evt-workday-webhook-001",
                        "worker_id": "user-manager-a",
                        "event_type": "ManagerChange",
                        "supervisory_org_id": "dept-risk",
                        "manager_worker_id": null,
                        "occurred_at": Utc::now().to_rfc3339()
                    }
                ],
                "next_cursor": "evt-workday-webhook-001"
            })),
            &webhook_headers,
        )
        .await,
    )
    .await;
    assert_eq!(webhook.operation, "webhook");
    assert_eq!(webhook.applied_event_count, 1);
    assert_eq!(
        webhook.checkpoint_after.as_deref(),
        Some("evt-workday-webhook-001")
    );
    assert!(!webhook.audit_checkpoint_id.is_empty());

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_dsn)
        .await
        .expect("postgres");
    let checkpoint_row = sqlx::query(
        "SELECT source, event_cursor, snapshot_cursor, auth_mode FROM hr_sync_checkpoints WHERE provider_id = 'workday-primary'",
    )
    .fetch_one(&pool)
    .await
    .expect("checkpoint");
    assert_eq!(
        checkpoint_row.try_get::<String, _>("source").unwrap(),
        "workday"
    );
    assert_eq!(
        checkpoint_row.try_get::<String, _>("event_cursor").unwrap(),
        "evt-workday-webhook-001"
    );
    assert_eq!(
        checkpoint_row
            .try_get::<String, _>("snapshot_cursor")
            .unwrap(),
        "snapshot-cursor-001"
    );
    assert_eq!(
        checkpoint_row.try_get::<String, _>("auth_mode").unwrap(),
        "oauth_client_credentials"
    );
    let event_count = sqlx::query(
        "SELECT COUNT(*)::BIGINT AS count FROM hr_sync_events WHERE provider_id = 'workday-primary'",
    )
    .fetch_one(&pool)
    .await
    .expect("event count")
    .try_get::<i64, _>("count")
    .unwrap();
    assert_eq!(event_count, 2);
    assert!(
        workday
            .observed_requests()
            .iter()
            .any(|request| request == "workers:tenant-alpha")
    );

    drop_database(&database_name).await;
}

#[tokio::test]
async fn uat_stage7_sap_successfactors_provider_snapshot_poll_and_webhook_runtime_closure() {
    if !stage7_enabled() {
        return;
    }

    let receiver = MockReceiver::start().await;
    let sap = MockSapSuccessFactorsProvider::start().await;
    let database_name = format!("sdqp_stage7_sap_sf_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let mut settings = test_settings(&database_name, &receiver.base_url);
    settings.integrations.hr.provider = "sap_successfactors".into();
    settings.integrations.hr.sap_successfactors.provider_id = "sap-successfactors-primary".into();
    settings.integrations.hr.sap_successfactors.company_id = "company-alpha".into();
    settings.integrations.hr.sap_successfactors.base_url = sap.base_url.clone();
    settings.integrations.hr.sap_successfactors.auth_mode = "oauth_client_credentials".into();
    settings.integrations.hr.sap_successfactors.token_url = format!("{}/oauth/token", sap.base_url);
    settings.integrations.hr.sap_successfactors.client_id = "sap-client".into();
    settings.integrations.hr.sap_successfactors.client_secret = "sap-secret".into();
    settings.integrations.hr.sap_successfactors.scope = "odata.read events.read".into();
    settings.integrations.hr.sap_successfactors.users_path = "/odata/v2/User".into();
    settings.integrations.hr.sap_successfactors.events_path = "/odata/v2/EmpJob".into();
    settings.integrations.hr.sap_successfactors.webhook_secret =
        "sap-successfactors-webhook-secret".into();
    settings.integrations.hr.sap_successfactors.page_size = 2;
    settings.integrations.hr.sap_successfactors.timeout_ms = 3_000;
    let database_dsn = settings.database.postgres.dsn.clone();
    let integration_key = settings.security.integration_api_keys[0].secret.clone();
    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent api router");

    let integration_headers = [
        ("x-api-key", integration_key.as_str()),
        ("x-client-cert-subject", "CN=sdqp-integration"),
        ("x-forwarded-for", "127.0.0.1"),
    ];
    let snapshot: SapSuccessFactorsHrRuntimeResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/integrations/hr/sap-successfactors/snapshot",
            None,
            &integration_headers,
        )
        .await,
    )
    .await;
    assert_eq!(snapshot.provider_id, "sap-successfactors-primary");
    assert_eq!(snapshot.runtime_mode, "real_http_odata");
    assert_eq!(snapshot.auth_mode, "oauth_client_credentials");
    assert_eq!(snapshot.synced_user_count, 2);
    assert_eq!(
        snapshot.snapshot_cursor_after.as_deref(),
        Some("snapshot-cursor-sap-001")
    );

    let analyst = user_tokens(app.clone(), "analyst").await;
    let manager = user_tokens(app.clone(), "manager").await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);
    let manager_bearer = format!("Bearer {}", manager.access_token);

    let application: serde_json::Value = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/permissions/applications",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "requested_fields": ["employee_email"]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    let instance_id = application["approval_instance_id"]
        .as_str()
        .expect("instance id");

    let approval_response = json_request(
        app.clone(),
        Method::POST,
        "/v1/approvals/callback",
        Some(serde_json::json!({
            "instance_id": instance_id,
            "action": "approve"
        })),
        &scoped_headers(&manager_bearer),
    )
    .await;
    assert_eq!(approval_response.status(), StatusCode::OK);
    let _ = wait_for_grant_field(app.clone(), &analyst_bearer, "employee_email").await;

    let poll: SapSuccessFactorsHrRuntimeResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/integrations/hr/sap-successfactors/poll",
            None,
            &integration_headers,
        )
        .await,
    )
    .await;
    assert_eq!(poll.operation, "event_poll");
    assert_eq!(poll.received_event_count, 1);
    assert_eq!(poll.applied_event_count, 1);
    assert_eq!(poll.checkpoint_after.as_deref(), Some("evt-sap-poll-001"));
    assert!(poll.revoked_grants >= 1);
    let _ = wait_for_all_grants_revoked(app.clone(), &analyst_bearer).await;

    let webhook_headers = [
        ("x-api-key", integration_key.as_str()),
        ("x-client-cert-subject", "CN=sdqp-integration"),
        ("x-forwarded-for", "127.0.0.1"),
        (
            "x-sap-successfactors-webhook-secret",
            "sap-successfactors-webhook-secret",
        ),
    ];
    let webhook: SapSuccessFactorsHrRuntimeResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/integrations/hr/sap-successfactors/webhook",
            Some(serde_json::json!({
                "events": [
                    {
                        "event_id": "evt-sap-webhook-001",
                        "person_id_external": "user-manager-a",
                        "event_type": "ManagerChange",
                        "department_external_code": "dept-risk",
                        "manager_person_id_external": null,
                        "occurred_at": Utc::now().to_rfc3339()
                    }
                ],
                "next_cursor": "evt-sap-webhook-001"
            })),
            &webhook_headers,
        )
        .await,
    )
    .await;
    assert_eq!(webhook.operation, "webhook");
    assert_eq!(webhook.applied_event_count, 1);
    assert_eq!(
        webhook.checkpoint_after.as_deref(),
        Some("evt-sap-webhook-001")
    );
    assert!(!webhook.audit_checkpoint_id.is_empty());

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_dsn)
        .await
        .expect("postgres");
    let checkpoint_row = sqlx::query(
        "SELECT source, event_cursor, snapshot_cursor, auth_mode FROM hr_sync_checkpoints WHERE provider_id = 'sap-successfactors-primary'",
    )
    .fetch_one(&pool)
    .await
    .expect("checkpoint");
    assert_eq!(
        checkpoint_row.try_get::<String, _>("source").unwrap(),
        "sap_successfactors"
    );
    assert_eq!(
        checkpoint_row.try_get::<String, _>("event_cursor").unwrap(),
        "evt-sap-webhook-001"
    );
    assert_eq!(
        checkpoint_row
            .try_get::<String, _>("snapshot_cursor")
            .unwrap(),
        "snapshot-cursor-sap-001"
    );
    assert_eq!(
        checkpoint_row.try_get::<String, _>("auth_mode").unwrap(),
        "oauth_client_credentials"
    );
    let event_count = sqlx::query(
        "SELECT COUNT(*)::BIGINT AS count FROM hr_sync_events WHERE provider_id = 'sap-successfactors-primary'",
    )
    .fetch_one(&pool)
    .await
    .expect("event count")
    .try_get::<i64, _>("count")
    .unwrap();
    assert_eq!(event_count, 2);
    assert!(
        sap.observed_requests()
            .iter()
            .any(|request| request == "users:company-alpha")
    );

    drop_database(&database_name).await;
}

#[tokio::test]
async fn uat_stage7_ldap_provider_snapshot_and_incremental_poll_runtime_closure() {
    if !stage7_enabled() {
        return;
    }

    let receiver = MockReceiver::start().await;
    let ldapsearch = MockLdapSearchBinary::create();
    let database_name = format!("sdqp_stage7_ldap_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let mut settings = test_settings(&database_name, &receiver.base_url);
    settings.integrations.hr.provider = "ldap".into();
    settings.integrations.hr.ldap.provider_id = "ldap-primary".into();
    settings.integrations.hr.ldap.url = "ldap://ldap.example.internal:389".into();
    settings.integrations.hr.ldap.auth_mode = "simple_bind".into();
    settings.integrations.hr.ldap.bind_dn = "cn=sdqp-sync,ou=svc,dc=example,dc=internal".into();
    settings.integrations.hr.ldap.bind_password = "ldap-secret".into();
    settings.integrations.hr.ldap.tls_mode = "start_tls".into();
    settings.integrations.hr.ldap.base_dn = "ou=People,dc=example,dc=internal".into();
    settings.integrations.hr.ldap.search_filter =
        "(&(objectClass=person)(employeeType=employee))".into();
    settings.integrations.hr.ldap.search_scope = "sub".into();
    settings.integrations.hr.ldap.user_id_attribute = "uid".into();
    settings.integrations.hr.ldap.department_attribute = "departmentNumber".into();
    settings.integrations.hr.ldap.manager_attribute = "manager".into();
    settings.integrations.hr.ldap.status_attribute = "employeeStatus".into();
    settings.integrations.hr.ldap.changed_since_attribute = "modifyTimestamp".into();
    settings.integrations.hr.ldap.active_status_values = vec!["active".into()];
    settings.integrations.hr.ldap.departed_status_values = vec!["departed".into()];
    settings.integrations.hr.ldap.page_size = 2;
    settings.integrations.hr.ldap.timeout_ms = 3_000;
    settings.integrations.hr.ldap.ldapsearch_binary = ldapsearch.path.to_string_lossy().to_string();
    let database_dsn = settings.database.postgres.dsn.clone();
    let integration_key = settings.security.integration_api_keys[0].secret.clone();
    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent api router");

    let integration_headers = [
        ("x-api-key", integration_key.as_str()),
        ("x-client-cert-subject", "CN=sdqp-integration"),
        ("x-forwarded-for", "127.0.0.1"),
    ];
    let snapshot: LdapHrRuntimeResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/integrations/hr/ldap/snapshot",
            None,
            &integration_headers,
        )
        .await,
    )
    .await;
    assert_eq!(snapshot.provider_id, "ldap-primary");
    assert_eq!(snapshot.runtime_mode, "real_ldap_directory_sync");
    assert_eq!(snapshot.auth_mode, "simple_bind");
    assert_eq!(snapshot.tls_mode, "start_tls");
    assert_eq!(snapshot.page_size, 2);
    assert_eq!(snapshot.estimated_page_count, 1);
    assert_eq!(snapshot.synced_user_count, 2);
    assert_eq!(
        snapshot.snapshot_cursor_after.as_deref(),
        Some("20260426090000Z")
    );

    let analyst = user_tokens(app.clone(), "analyst").await;
    let manager = user_tokens(app.clone(), "manager").await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);
    let manager_bearer = format!("Bearer {}", manager.access_token);

    let application: serde_json::Value = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/permissions/applications",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "requested_fields": ["employee_email"]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    let instance_id = application["approval_instance_id"]
        .as_str()
        .expect("instance id");

    let approval_response = json_request(
        app.clone(),
        Method::POST,
        "/v1/approvals/callback",
        Some(serde_json::json!({
            "instance_id": instance_id,
            "action": "approve"
        })),
        &scoped_headers(&manager_bearer),
    )
    .await;
    assert_eq!(approval_response.status(), StatusCode::OK);
    let _ = wait_for_grant_field(app.clone(), &analyst_bearer, "employee_email").await;

    let poll: LdapHrRuntimeResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/integrations/hr/ldap/poll",
            None,
            &integration_headers,
        )
        .await,
    )
    .await;
    assert_eq!(poll.operation, "incremental_poll");
    assert_eq!(poll.received_event_count, 1);
    assert_eq!(poll.applied_event_count, 1);
    assert_eq!(poll.checkpoint_after.as_deref(), Some("20260426100000Z"));
    assert!(poll.revoked_grants >= 1);
    let _ = wait_for_all_grants_revoked(app.clone(), &analyst_bearer).await;

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_dsn)
        .await
        .expect("postgres");
    let checkpoint_row = sqlx::query(
        "SELECT source, event_cursor, snapshot_cursor, auth_mode, last_webhook_at FROM hr_sync_checkpoints WHERE provider_id = 'ldap-primary'",
    )
    .fetch_one(&pool)
    .await
    .expect("checkpoint");
    assert_eq!(
        checkpoint_row.try_get::<String, _>("source").unwrap(),
        "ldap"
    );
    assert_eq!(
        checkpoint_row.try_get::<String, _>("event_cursor").unwrap(),
        "20260426100000Z"
    );
    assert_eq!(
        checkpoint_row
            .try_get::<String, _>("snapshot_cursor")
            .unwrap(),
        "20260426090000Z"
    );
    assert_eq!(
        checkpoint_row.try_get::<String, _>("auth_mode").unwrap(),
        "simple_bind"
    );
    assert!(
        checkpoint_row
            .try_get::<Option<chrono::DateTime<Utc>>, _>("last_webhook_at")
            .unwrap()
            .is_none()
    );
    let event_count = sqlx::query(
        "SELECT COUNT(*)::BIGINT AS count FROM hr_sync_events WHERE provider_id = 'ldap-primary' AND source = 'ldap'",
    )
    .fetch_one(&pool)
    .await
    .expect("event count")
    .try_get::<i64, _>("count")
    .unwrap();
    assert_eq!(event_count, 1);

    drop_database(&database_name).await;
}

#[tokio::test]
async fn uat_stage7_notification_retry_escalation_and_delegation() {
    if !stage7_enabled() {
        return;
    }

    let receiver = MockReceiver::start().await;
    let database_name = format!("sdqp_stage7_notify_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let settings = test_settings(&database_name, &receiver.base_url);
    let database_dsn = settings.database.postgres.dsn.clone();
    let app = build_persistent_router(settings)
        .await
        .expect("persistent api router");

    let analyst = user_tokens(app.clone(), "analyst").await;
    let security = user_tokens(app.clone(), "security").await;
    let delegate = user_tokens(app.clone(), "delegate").await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);
    let security_bearer = format!("Bearer {}", security.access_token);
    let delegate_bearer = format!("Bearer {}", delegate.access_token);

    let application: serde_json::Value = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/permissions/applications",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "requested_fields": ["employee_email"]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    let instance_id = application["approval_instance_id"]
        .as_str()
        .expect("instance id")
        .to_string();

    force_instance_due(&database_dsn, &instance_id).await;
    wait_for_notification(&receiver, "user-security-a", 2).await;
    assert_actionable_notification_contracts(&receiver, "user-security-a", "approval_escalated");
    wait_for_delivery_statuses(&database_dsn, &instance_id, "user-security-a", 2).await;

    let security_tasks: ApprovalTasksResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/approvals/tasks",
            None,
            &scoped_headers(&security_bearer),
        )
        .await,
    )
    .await;
    assert!(
        security_tasks
            .tasks
            .iter()
            .any(|task| task.instance_id == instance_id)
    );

    let delegate_response = json_request(
        app.clone(),
        Method::POST,
        "/v1/approvals/callback",
        Some(serde_json::json!({
            "instance_id": instance_id,
            "action": "delegate",
            "delegate_to": "user-security-b"
        })),
        &scoped_headers(&security_bearer),
    )
    .await;
    assert_eq!(delegate_response.status(), StatusCode::OK);

    wait_for_notification(&receiver, "user-security-b", 2).await;
    assert_actionable_notification_contracts(&receiver, "user-security-b", "approval_delegated");
    wait_for_delivery_statuses(&database_dsn, &instance_id, "user-security-b", 1).await;

    let delegate_tasks: ApprovalTasksResponse = decode_json(
        json_request(
            app,
            Method::GET,
            "/v1/approvals/tasks",
            None,
            &scoped_headers(&delegate_bearer),
        )
        .await,
    )
    .await;
    assert!(delegate_tasks.tasks.iter().any(|task| {
        task.instance_id == instance_id && task.delegated_to.as_deref() == Some("user-security-b")
    }));
    assert!(receiver.attempts_for("slack") >= 2);

    drop_database(&database_name).await;
}

#[tokio::test]
async fn uat_stage7_unavailable_manager_routes_to_delegate_before_escalation() {
    if !stage7_enabled() {
        return;
    }

    let receiver = MockReceiver::start().await;
    let database_name = format!("sdqp_stage7_delegate_first_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let settings = test_settings(&database_name, &receiver.base_url);
    let app = build_persistent_router(settings)
        .await
        .expect("persistent api router");

    let hr_profile_response = json_request(
        app.clone(),
        Method::POST,
        "/integrations/hr/events",
        Some(serde_json::json!({
            "source": "feishu",
            "event_id": format!("evt-{}", ulid::Ulid::new()),
            "user_id": "user-manager-a",
            "event_type": "manager_change",
            "approver_availability": "unavailable",
            "delegate_user_id": "user-security-b"
        })),
        &[("x-sdqp-hr-token", "stage7-hr-token")],
    )
    .await;
    assert_eq!(hr_profile_response.status(), StatusCode::OK);

    let analyst = user_tokens(app.clone(), "analyst").await;
    let manager = user_tokens(app.clone(), "manager").await;
    let delegate = user_tokens(app.clone(), "delegate").await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);
    let manager_bearer = format!("Bearer {}", manager.access_token);
    let delegate_bearer = format!("Bearer {}", delegate.access_token);

    let application: serde_json::Value = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/permissions/applications",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "requested_fields": ["employee_email"]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    let instance_id = application["approval_instance_id"]
        .as_str()
        .expect("instance id");

    wait_for_notification(&receiver, "user-security-b", 0).await;

    let manager_tasks: ApprovalTasksResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/approvals/tasks",
            None,
            &scoped_headers(&manager_bearer),
        )
        .await,
    )
    .await;
    assert!(
        manager_tasks
            .tasks
            .iter()
            .all(|task| task.instance_id != instance_id)
    );

    let delegate_tasks: ApprovalTasksResponse = decode_json(
        json_request(
            app,
            Method::GET,
            "/v1/approvals/tasks",
            None,
            &scoped_headers(&delegate_bearer),
        )
        .await,
    )
    .await;
    assert!(delegate_tasks.tasks.iter().any(|task| {
        task.instance_id == instance_id && task.delegated_to.as_deref() == Some("user-security-b")
    }));

    drop_database(&database_name).await;
}

#[tokio::test]
async fn uat_stage7_approver_availability_delegation_escalation_closure() {
    if !stage7_enabled() {
        return;
    }

    let receiver = MockReceiver::start().await;
    let database_name = format!("sdqp_stage7_approver_closure_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let mut settings = test_settings(&database_name, &receiver.base_url);
    settings
        .integrations
        .hr
        .approver_resolution
        .system_fallback_user_id = "user-sysadmin".into();
    settings
        .integrations
        .hr
        .approver_resolution
        .escalation_user_ids = vec!["user-security-a".into()];
    settings
        .integrations
        .hr
        .approver_resolution
        .max_manager_hops = 2;
    settings
        .integrations
        .hr
        .approver_resolution
        .allow_delegation = true;
    let app = build_persistent_router(settings)
        .await
        .expect("persistent api router");

    let security = user_tokens(app.clone(), "security").await;
    let analyst = user_tokens(app.clone(), "analyst").await;
    let sysadmin = user_tokens(app.clone(), "sysadmin").await;
    let security_bearer = format!("Bearer {}", security.access_token);
    let analyst_bearer = format!("Bearer {}", analyst.access_token);
    let sysadmin_bearer = format!("Bearer {}", sysadmin.access_token);

    let manager_profile = json_request(
        app.clone(),
        Method::POST,
        "/integrations/hr/events",
        Some(serde_json::json!({
            "source": "workday",
            "event_id": format!("evt-workday-{}", ulid::Ulid::new()),
            "user_id": "user-manager-a",
            "event_type": "manager_change",
            "approver_availability": "unavailable",
            "delegate_user_id": "user-security-b"
        })),
        &[("x-sdqp-hr-token", "stage7-hr-token")],
    )
    .await;
    assert_eq!(manager_profile.status(), StatusCode::OK);

    let delegated: ApproverResolutionResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/approvals/approver-resolution",
            Some(serde_json::json!({
                "requested_user_id": "user-manager-a"
            })),
            &scoped_headers(&security_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(delegated.route_kind, "delegated");
    assert_eq!(delegated.resolved_user_id, "user-security-b");
    assert_eq!(delegated.delegated_from.as_deref(), Some("user-manager-a"));
    assert!(
        delegated
            .unavailable_user_ids
            .iter()
            .any(|user_id| user_id == "user-manager-a")
    );

    let delegate_unavailable = json_request(
        app.clone(),
        Method::POST,
        "/integrations/hr/events",
        Some(serde_json::json!({
            "source": "sap_successfactors",
            "event_id": format!("evt-sap-{}", ulid::Ulid::new()),
            "user_id": "user-security-b",
            "event_type": "manager_change",
            "approver_availability": "unavailable"
        })),
        &[("x-sdqp-hr-token", "stage7-hr-token")],
    )
    .await;
    assert_eq!(delegate_unavailable.status(), StatusCode::OK);

    let escalated: ApproverResolutionResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/approvals/approver-resolution",
            Some(serde_json::json!({
                "requested_user_id": "user-manager-a"
            })),
            &scoped_headers(&security_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(escalated.route_kind, "escalated_to_configured_target");
    assert_eq!(escalated.resolved_user_id, "user-security-a");
    assert!(
        escalated
            .unavailable_user_ids
            .iter()
            .any(|user_id| user_id == "user-security-b")
    );

    let escalation_unavailable = json_request(
        app.clone(),
        Method::POST,
        "/integrations/hr/events",
        Some(serde_json::json!({
            "source": "ldap",
            "event_id": format!("evt-ldap-{}", ulid::Ulid::new()),
            "user_id": "user-security-a",
            "event_type": "manager_change",
            "approver_availability": "unavailable"
        })),
        &[("x-sdqp-hr-token", "stage7-hr-token")],
    )
    .await;
    assert_eq!(escalation_unavailable.status(), StatusCode::OK);

    let fallback: ApproverResolutionResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/approvals/approver-resolution",
            Some(serde_json::json!({
                "requested_user_id": "user-manager-a"
            })),
            &scoped_headers(&security_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(fallback.route_kind, "system_fallback");
    assert_eq!(fallback.resolved_user_id, "user-sysadmin");
    assert!(fallback.used_system_fallback);
    assert!(
        fallback
            .unavailable_user_ids
            .iter()
            .any(|user_id| user_id == "user-security-a")
    );

    let application: serde_json::Value = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/permissions/applications",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "requested_fields": ["employee_email"]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    let instance_id = application["approval_instance_id"]
        .as_str()
        .expect("instance id");

    wait_for_notification(&receiver, "user-sysadmin", 0).await;
    let sysadmin_tasks: ApprovalTasksResponse = decode_json(
        json_request(
            app,
            Method::GET,
            "/v1/approvals/tasks",
            None,
            &scoped_headers(&sysadmin_bearer),
        )
        .await,
    )
    .await;
    let task = sysadmin_tasks
        .tasks
        .iter()
        .find(|task| task.instance_id == instance_id)
        .expect("sysadmin fallback task");
    assert_eq!(task.escalation_target.as_deref(), Some("user-sysadmin"));
    assert!(
        task.routing
            .iter()
            .any(|trace| trace.used_system_fallback && trace.resolved_user_id == "user-sysadmin")
    );

    drop_database(&database_name).await;
}
