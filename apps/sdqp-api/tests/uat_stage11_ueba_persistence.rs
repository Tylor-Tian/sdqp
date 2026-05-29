use std::{collections::BTreeMap, time::Duration};

use axum::body::{Body, to_bytes};
use chrono::{TimeZone, Utc};
use http::{Method, Request, StatusCode, header};
use reqwest::Client;
use rskafka::{
    client::{
        ClientBuilder,
        partition::{Compression, UnknownTopicHandling},
    },
    record::Record,
};
use sdqp_api::{
    EvidenceExportResponse, LoginResponse, QuerySubmitResponse, TokenPairResponse,
    UebaAlertsResponse, UebaBaselinesResponse, build_persistent_router,
};
use sdqp_audit::{ActionResult, ActionType, ActorInfo, AuditEvent, TargetRef};
use sdqp_config::AppSettings;
use sqlx::Executor;
use sqlx_postgres::PgPoolOptions;
use tower::ServiceExt;

fn stage11_enabled() -> bool {
    std::env::var("SDQP_ENABLE_STAGE11_TESTS").ok().as_deref() == Some("1")
}

fn admin_dsn() -> String {
    std::env::var("SDQP_STAGE3_ADMIN_DSN")
        .unwrap_or_else(|_| "postgres://sdqp:sdqp@127.0.0.1:15432/postgres".into())
}

fn test_settings(database_name: &str) -> AppSettings {
    let mut settings = AppSettings::local_dev();
    settings.database.postgres.dsn =
        format!("postgres://sdqp:sdqp@127.0.0.1:15432/{database_name}");
    settings.database.clickhouse.http_url = "http://127.0.0.1:18123".into();
    settings.database.clickhouse.native_url = "tcp://127.0.0.1:19000".into();
    settings.object_store.endpoint = "http://127.0.0.1:19002".into();
    settings.kafka.brokers = vec!["127.0.0.1:19092".into()];
    settings.kafka.audit_topic = format!("sdqp.audit.events.{database_name}");
    settings.kafka.ueba_topic = format!("sdqp.ueba.events.{database_name}");
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
                "#
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
    app: axum::Router,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
    headers: &[(&str, &str)],
) -> http::Response<Body> {
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

async fn decode_json<T: serde::de::DeserializeOwned>(response: http::Response<Body>) -> T {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

async fn user_tokens(app: axum::Router, username: &str) -> TokenPairResponse {
    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            Some(serde_json::json!({
                "username": username,
                "password": "password123",
                "device_fingerprint": format!("stage11-{username}")
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

async fn clickhouse_count(http_url: &str, query: &str) -> i64 {
    Client::new()
        .post(format!(
            "{}/?wait_end_of_query=1",
            http_url.trim_end_matches('/')
        ))
        .body(query.to_string())
        .send()
        .await
        .expect("clickhouse request")
        .error_for_status()
        .expect("clickhouse status")
        .text()
        .await
        .expect("clickhouse text")
        .trim()
        .parse()
        .expect("count")
}

async fn clickhouse_execute(http_url: &str, query: &str) {
    Client::new()
        .post(format!(
            "{}/?wait_end_of_query=1",
            http_url.trim_end_matches('/')
        ))
        .body(query.to_string())
        .send()
        .await
        .expect("clickhouse request")
        .error_for_status()
        .expect("clickhouse status");
}

async fn reset_clickhouse(settings: &AppSettings) {
    for table in [
        "sdqp.audit_events",
        "sdqp.audit_checkpoints",
        "sdqp.ueba_user_baselines",
        "sdqp.ueba_entity_baselines",
        "sdqp.ueba_alerts",
        "sdqp.ueba_rule_hits",
    ] {
        clickhouse_execute(
            &settings.database.clickhouse.http_url,
            &format!("TRUNCATE TABLE {table}"),
        )
        .await;
    }
}

async fn await_alerts(app: axum::Router, admin_bearer: &str) -> UebaAlertsResponse {
    for _ in 0..120 {
        let response = json_request(
            app.clone(),
            Method::GET,
            "/v1/ueba/alerts",
            None,
            &scoped_headers(admin_bearer),
        )
        .await;
        if response.status() != StatusCode::OK {
            panic!(
                "{}",
                String::from_utf8(
                    to_bytes(response.into_body(), usize::MAX)
                        .await
                        .expect("alert error body")
                        .to_vec(),
                )
                .expect("alert error text")
            );
        }
        let alerts: UebaAlertsResponse = decode_json(response).await;
        if !alerts.alerts.is_empty() {
            return alerts;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("ueba alerts were not persisted in time")
}

async fn await_alert_rule(app: axum::Router, admin_bearer: &str, rule: &str) -> UebaAlertsResponse {
    for _ in 0..120 {
        let alerts = await_alerts(app.clone(), admin_bearer).await;
        if alerts.alerts.iter().any(|alert| alert.rule == rule) {
            return alerts;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("ueba alert {rule} was not persisted in time")
}

async fn completed_snapshot(app: axum::Router, token: &str) -> String {
    let response = json_request(
        app.clone(),
        Method::POST,
        "/v1/queries",
        Some(serde_json::json!({
            "data_source_id": "datasource-rest",
            "source_type": "rest",
            "fields": ["employee_id"]
        })),
        &scoped_headers(token),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let submit: QuerySubmitResponse = decode_json(response).await;

    for _ in 0..60 {
        let status = json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/tasks/{}/status", submit.task_id),
            None,
            &scoped_headers(token),
        )
        .await;
        let payload: sdqp_api::QueryTaskStatusResponse = decode_json(status).await;
        if payload.state == "completed" {
            return payload.snapshot_id.expect("snapshot id");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!("snapshot not ready")
}

async fn publish_audit_event(settings: &AppSettings, event: &AuditEvent) {
    let client = ClientBuilder::new(settings.kafka.brokers.clone())
        .build()
        .await
        .expect("kafka client");
    if let Ok(controller) = client.controller_client() {
        let _ = controller
            .create_topic(&settings.kafka.audit_topic, 1, 1, 5_000)
            .await;
    }
    let partition_client = client
        .partition_client(
            settings.kafka.audit_topic.clone(),
            0,
            UnknownTopicHandling::Retry,
        )
        .await
        .expect("partition client");
    partition_client
        .produce(
            vec![Record {
                key: Some(event.event_id.as_bytes().to_vec()),
                value: Some(serde_json::to_vec(event).expect("audit event json")),
                headers: BTreeMap::new(),
                timestamp: event.timestamp,
            }],
            Compression::default(),
        )
        .await
        .expect("produce audit event");
}

fn synthetic_audit_event(
    user_id: &str,
    session_id: &str,
    action: ActionType,
    result: ActionResult,
    context: &str,
    hour: u32,
) -> AuditEvent {
    let mut event = AuditEvent::new(
        ActorInfo {
            user_id: user_id.into(),
            session_id: session_id.into(),
            ip_address: "127.0.0.1".into(),
        },
        action,
        TargetRef {
            tenant_id: "tenant-alpha".into(),
            project_id: Some("project-alpha".into()),
            resource_id: "stage11-synthetic".into(),
        },
        context,
        result,
        None,
        None,
    );
    event.timestamp = Utc
        .with_ymd_and_hms(2026, 3, 29, hour, 30, 0)
        .single()
        .expect("timestamp");
    event.event_hash = event.recompute_hash();
    event
}

async fn lookup_user_id(settings: &AppSettings, username: &str) -> String {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&settings.database.postgres.dsn)
        .await
        .expect("postgres");
    sqlx::query_scalar("SELECT user_id FROM users WHERE username = $1")
        .bind(username)
        .fetch_one(&pool)
        .await
        .expect("user id")
}

async fn assert_stream_offset_advanced(settings: &AppSettings) {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&settings.database.postgres.dsn)
        .await
        .expect("postgres");
    let offset: i64 = sqlx::query_scalar(
        "SELECT next_offset FROM stream_offsets WHERE stream_name = $1 AND partition_id = 0",
    )
    .bind(&settings.kafka.audit_topic)
    .fetch_one(&pool)
    .await
    .expect("stream offset");
    assert!(offset > 0);
}

async fn analyst_and_admin_tokens(
    app: axum::Router,
) -> (TokenPairResponse, String, TokenPairResponse, String) {
    let analyst = user_tokens(app.clone(), "analyst").await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);
    let admin = user_tokens(app, "sysadmin").await;
    let admin_bearer = format!("Bearer {}", admin.access_token);
    (analyst, analyst_bearer, admin, admin_bearer)
}

#[tokio::test]
async fn uat_stage11_streams_query_burst_to_step_up_and_persists_baselines() {
    if !stage11_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage11_query_{}", ulid::Ulid::new());
    create_database(&database_name).await;
    let settings = test_settings(&database_name);
    reset_clickhouse(&settings).await;

    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent router");
    let (_, analyst_bearer, _, admin_bearer) = analyst_and_admin_tokens(app.clone()).await;

    for _ in 0..5 {
        let response = json_request(
            app.clone(),
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
        assert_eq!(response.status(), StatusCode::OK);
        let _: QuerySubmitResponse = decode_json(response).await;
    }

    let alerts = await_alert_rule(app.clone(), &admin_bearer, "HighFrequencyQuery").await;
    assert!(alerts.step_up_sessions > 0);

    let baselines: UebaBaselinesResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/ueba/baselines",
            None,
            &scoped_headers(&admin_bearer),
        )
        .await,
    )
    .await;
    assert!(!baselines.user_baselines.is_empty());
    assert!(
        baselines
            .entity_baselines
            .iter()
            .any(|baseline| baseline.entity_type == "role")
    );
    assert!(
        baselines
            .entity_baselines
            .iter()
            .any(|baseline| baseline.entity_type == "project")
    );

    assert_stream_offset_advanced(&settings).await;

    drop(app);
    drop_database(&database_name).await;
}

#[tokio::test]
async fn uat_stage11_streams_denied_query_burst_to_permission_revocation() {
    if !stage11_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage11_denied_{}", ulid::Ulid::new());
    create_database(&database_name).await;
    let settings = test_settings(&database_name);
    reset_clickhouse(&settings).await;

    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent router");
    let (_, analyst_bearer, _, admin_bearer) = analyst_and_admin_tokens(app.clone()).await;

    for _ in 0..2 {
        let response = json_request(
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
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    let alerts = await_alert_rule(app.clone(), &admin_bearer, "UnauthorizedQueryBurst").await;
    assert!(alerts.permissions_revoked > 0);

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&settings.database.postgres.dsn)
        .await
        .expect("postgres");
    let analyst_user_id = lookup_user_id(&settings, "analyst").await;
    let revoked_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM permission_grants WHERE applicant_user_id = $1 AND status = 'revoked'",
    )
    .bind(&analyst_user_id)
    .fetch_one(&pool)
    .await
    .expect("revoked grants");
    assert!(revoked_count > 0);

    drop(app);
    drop(pool);
    drop_database(&database_name).await;
}

#[tokio::test]
async fn uat_stage11_streams_export_spike_to_session_termination() {
    if !stage11_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage11_export_{}", ulid::Ulid::new());
    create_database(&database_name).await;
    let settings = test_settings(&database_name);
    reset_clickhouse(&settings).await;

    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent router");
    let (_, analyst_bearer, _, admin_bearer) = analyst_and_admin_tokens(app.clone()).await;
    let snapshot_id = completed_snapshot(app.clone(), &analyst_bearer).await;

    for _ in 0..3 {
        let response: EvidenceExportResponse = decode_json(
            json_request(
                app.clone(),
                Method::POST,
                "/v1/exports/evidence",
                Some(serde_json::json!({
                    "snapshot_id": snapshot_id,
                    "template": "eu"
                })),
                &scoped_headers(&analyst_bearer),
            )
            .await,
        )
        .await;
        assert!(response.verification_ready);
    }

    let alerts = await_alert_rule(app.clone(), &admin_bearer, "ExportSpike").await;
    assert!(alerts.terminated_sessions > 0);

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&settings.database.postgres.dsn)
        .await
        .expect("postgres");
    let revoked_sessions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions WHERE revoked = TRUE AND session_kind = 'active'",
    )
    .fetch_one(&pool)
    .await
    .expect("revoked sessions");
    assert!(revoked_sessions > 0);

    drop(app);
    drop(pool);
    drop_database(&database_name).await;
}

#[tokio::test]
async fn uat_stage11_detects_after_hours_access_from_audit_topic() {
    if !stage11_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage11_after_hours_{}", ulid::Ulid::new());
    create_database(&database_name).await;
    let settings = test_settings(&database_name);
    reset_clickhouse(&settings).await;

    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent router");
    let (analyst, _, _, admin_bearer) = analyst_and_admin_tokens(app.clone()).await;
    let analyst_user_id = lookup_user_id(&settings, "analyst").await;

    publish_audit_event(
        &settings,
        &synthetic_audit_event(
            &analyst_user_id,
            &analyst.session_id,
            ActionType::View,
            ActionResult::Success,
            "after hours access",
            23,
        ),
    )
    .await;

    let alerts = await_alert_rule(app.clone(), &admin_bearer, "AfterHoursAccess").await;
    assert!(
        alerts
            .alerts
            .iter()
            .any(|alert| alert.rule == "AfterHoursAccess")
    );

    drop(app);
    drop_database(&database_name).await;
}

#[tokio::test]
async fn uat_stage11_detects_dns_hidden_channel_from_audit_topic() {
    if !stage11_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage11_dns_{}", ulid::Ulid::new());
    create_database(&database_name).await;
    let settings = test_settings(&database_name);
    reset_clickhouse(&settings).await;

    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent router");
    let (analyst, _, _, admin_bearer) = analyst_and_admin_tokens(app.clone()).await;
    let analyst_user_id = lookup_user_id(&settings, "analyst").await;

    publish_audit_event(
        &settings,
        &synthetic_audit_event(
            &analyst_user_id,
            &analyst.session_id,
            ActionType::View,
            ActionResult::Success,
            "dns://exfil.example TXT base32 chunk",
            13,
        ),
    )
    .await;

    let alerts = await_alert_rule(app.clone(), &admin_bearer, "HiddenChannelDns").await;
    assert!(
        alerts
            .alerts
            .iter()
            .any(|alert| alert.rule == "HiddenChannelDns")
    );

    drop(app);
    drop_database(&database_name).await;
}

#[tokio::test]
async fn uat_stage11_detects_http_hidden_channel_from_audit_topic() {
    if !stage11_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage11_http_{}", ulid::Ulid::new());
    create_database(&database_name).await;
    let settings = test_settings(&database_name);
    reset_clickhouse(&settings).await;

    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent router");
    let (analyst, _, _, admin_bearer) = analyst_and_admin_tokens(app.clone()).await;
    let analyst_user_id = lookup_user_id(&settings, "analyst").await;

    publish_audit_event(
        &settings,
        &synthetic_audit_event(
            &analyst_user_id,
            &analyst.session_id,
            ActionType::View,
            ActionResult::Success,
            "https://exfil.example/pixel.gif?chunk=abc&beacon=true",
            14,
        ),
    )
    .await;

    let alerts = await_alert_rule(app.clone(), &admin_bearer, "HiddenChannelHttp").await;
    assert!(
        alerts
            .alerts
            .iter()
            .any(|alert| alert.rule == "HiddenChannelHttp")
    );

    let alert_count = clickhouse_count(
        &settings.database.clickhouse.http_url,
        "SELECT COUNT() FROM sdqp.ueba_alerts WHERE tenant_id = 'tenant-alpha'",
    )
    .await;
    assert!(alert_count > 0);

    drop(app);
    drop_database(&database_name).await;
}
