use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    routing::post,
};
use http::{Method, Request, StatusCode, header};
use reqwest::Client;
use sdqp_api::{LoginResponse, ProjectsListResponse, TokenPairResponse, build_persistent_router};
use sdqp_audit::{read_archive_bundle_file, verify_archive_bundle};
use sdqp_config::AppSettings;
use sqlx::{Executor, Row};
use sqlx_postgres::{PgPool, PgPoolOptions};
use tower::ServiceExt;

fn stage11_enabled() -> bool {
    std::env::var("SDQP_ENABLE_STAGE11_TESTS").ok().as_deref() == Some("1")
}

fn admin_dsn() -> String {
    std::env::var("SDQP_STAGE3_ADMIN_DSN")
        .unwrap_or_else(|_| "postgres://sdqp:sdqp@127.0.0.1:15432/postgres".into())
}

fn test_settings(database_name: &str, archive_dir: &Path, webhook_url: &str) -> AppSettings {
    let mut settings = AppSettings::local_dev();
    settings.database.postgres.dsn =
        format!("postgres://sdqp:sdqp@127.0.0.1:15432/{database_name}");
    settings.database.clickhouse.http_url = "http://127.0.0.1:18123".into();
    settings.database.clickhouse.native_url = "tcp://127.0.0.1:19000".into();
    settings.object_store.endpoint = "http://127.0.0.1:19002".into();
    settings.kafka.brokers = vec!["127.0.0.1:19092".into()];
    settings.kafka.audit_topic = format!("sdqp.audit.events.{database_name}");
    settings.kafka.ueba_topic = format!("sdqp.ueba.events.{database_name}");
    settings.audit.checkpoint.provider = "vault".into();
    settings.audit.checkpoint.key_id = "audit-root".into();
    settings.audit.checkpoint.key_version = "7".into();
    settings.audit.checkpoint.endpoint = "https://vault.example/v1/transit".into();
    settings.audit.checkpoint.region = "cn-test-1".into();
    settings.audit.checkpoint.key_ring = "audit-stage11".into();
    settings.audit.checkpoint.auth_token = "vault-token".into();
    settings.audit.forwarder.enabled = true;
    settings.audit.forwarder.provider = "webhook".into();
    settings.audit.forwarder.webhook_url = webhook_url.into();
    settings.audit.retention.enabled = true;
    settings.audit.retention.archive_after_secs = 0;
    settings.audit.retention.access_log_retention_secs = 1;
    settings.audit.retention.permission_lifecycle_retention_secs = 1;
    settings.audit.retention.evidence_retention_secs = 1;
    settings.audit.retention.system_management_retention_secs = 1;
    settings.audit.retention.archive_dir = archive_dir.to_string_lossy().to_string();
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
                "device_fingerprint": format!("stage11-audit-{username}")
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
    for table in ["sdqp.audit_events", "sdqp.audit_checkpoints"] {
        clickhouse_execute(
            &settings.database.clickhouse.http_url,
            &format!("TRUNCATE TABLE {table}"),
        )
        .await;
    }
}

async fn connect_pool(dsn: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(dsn)
        .await
        .expect("postgres pool")
}

fn archive_files(archive_dir: &Path) -> Vec<PathBuf> {
    if !archive_dir.exists() {
        return Vec::new();
    }

    let mut files = fs::read_dir(archive_dir)
        .expect("read archive dir")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    files.sort();
    files
}

async fn await_archive_file(archive_dir: &Path) -> PathBuf {
    for _ in 0..120 {
        let files = archive_files(archive_dir);
        if let Some(path) = files.into_iter().next() {
            return path;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("archive bundle was not created");
}

async fn await_forward_delivery(pool: &PgPool) -> (String, String, String) {
    for _ in 0..120 {
        if let Some(row) = sqlx::query(
            r#"
            SELECT provider, destination, status
            FROM audit_forward_deliveries
            ORDER BY delivered_at DESC, delivery_id DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(pool)
        .await
        .expect("load forward delivery")
        {
            let status: String = row.try_get("status").expect("status");
            if status == "success" {
                return (
                    row.try_get("provider").expect("provider"),
                    row.try_get("destination").expect("destination"),
                    status,
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("forward delivery was not persisted");
}

async fn await_active_boundary(pool: &PgPool) -> (String, String, String) {
    for _ in 0..120 {
        if let Some(row) = sqlx::query(
            r#"
            SELECT signer_provider, signer_key_id, COALESCE(signer_key_version, '') AS signer_key_version
            FROM audit_chain_boundaries
            WHERE active = TRUE
            ORDER BY created_at DESC, boundary_id DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(pool)
        .await
        .expect("load active boundary")
        {
            return (
                row.try_get("signer_provider").expect("signer_provider"),
                row.try_get("signer_key_id").expect("signer_key_id"),
                row.try_get("signer_key_version").expect("signer_key_version"),
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("active archive boundary was not persisted");
}

async fn await_retention_run(pool: &PgPool, require_purge: bool) -> (i64, i64, String) {
    for _ in 0..120 {
        if let Some(row) = sqlx::query(
            r#"
            SELECT archived_events, purged_bundles, status
            FROM audit_retention_runs
            ORDER BY created_at DESC, run_id DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(pool)
        .await
        .expect("load retention run")
        {
            let archived_events: i64 = row.try_get("archived_events").expect("archived_events");
            let purged_bundles: i64 = row.try_get("purged_bundles").expect("purged_bundles");
            let status: String = row.try_get("status").expect("status");
            if archived_events > 0 && (!require_purge || purged_bundles > 0) {
                return (archived_events, purged_bundles, status);
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("retention run was not persisted");
}

async fn await_file_removed(path: &Path) {
    for _ in 0..120 {
        if !path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("archive bundle was not purged");
}

#[tokio::test]
async fn uat_stage11_audit_runtime_executes_forwarding_archival_and_cleanup() {
    if !stage11_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage11_audit_runtime_{}", ulid::Ulid::new());
    let archive_dir = std::env::temp_dir().join(format!("sdqp-stage11-audit-{database_name}"));
    let _ = fs::remove_dir_all(&archive_dir);
    create_database(&database_name).await;

    let captured = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind webhook listener");
    let webhook_addr = listener.local_addr().expect("local addr");
    let app_webhook = {
        let captured = captured.clone();
        Router::new().route(
            "/audit/siem",
            post(move |Json(body): Json<serde_json::Value>| {
                let captured = captured.clone();
                async move {
                    captured.lock().expect("captured").push(body);
                    StatusCode::ACCEPTED
                }
            }),
        )
    };
    tokio::spawn(async move {
        axum::serve(listener, app_webhook)
            .await
            .expect("serve webhook");
    });

    let settings = test_settings(
        &database_name,
        &archive_dir,
        &format!("http://{webhook_addr}/audit/siem"),
    );
    reset_clickhouse(&settings).await;
    let pool = connect_pool(&settings.database.postgres.dsn).await;
    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent router");

    let sysadmin = user_tokens(app.clone(), "sysadmin").await;

    let archive_path = await_archive_file(&archive_dir).await;
    let archive_bundle = read_archive_bundle_file(&archive_path).expect("archive bundle");
    assert!(verify_archive_bundle(&archive_bundle));
    assert_eq!(archive_bundle.boundary_checkpoint.signer_provider, "vault");
    assert_eq!(
        archive_bundle.boundary_checkpoint.signer_key_id,
        "audit-root"
    );
    assert_eq!(
        archive_bundle
            .boundary_checkpoint
            .signer_key_version
            .as_deref(),
        Some("7")
    );

    let (provider, destination, status) = await_forward_delivery(&pool).await;
    assert_eq!(provider, "webhook");
    assert_eq!(status, "success");
    assert!(destination.ends_with("/audit/siem"));

    let (signer_provider, signer_key_id, signer_key_version) = await_active_boundary(&pool).await;
    assert_eq!(signer_provider, "vault");
    assert_eq!(signer_key_id, "audit-root");
    assert_eq!(signer_key_version, "7");

    {
        let captured = captured.lock().expect("captured");
        assert!(!captured.is_empty());
        let latest = captured.last().expect("latest webhook payload");
        assert_eq!(latest["checkpoint"]["signer_provider"], "vault");
        assert_eq!(latest["checkpoint"]["signer_key_id"], "audit-root");
        assert_eq!(latest["checkpoint"]["signer_key_version"], "7");
    }

    tokio::time::sleep(Duration::from_secs(2)).await;

    let projects: ProjectsListResponse = decode_json(
        json_request(
            app,
            Method::GET,
            "/v1/projects",
            None,
            &scoped_headers(&sysadmin.access_token),
        )
        .await,
    )
    .await;
    assert!(!projects.projects.is_empty());

    let (archived_events, purged_bundles, retention_status) =
        await_retention_run(&pool, true).await;
    assert!(archived_events > 0);
    assert!(purged_bundles > 0);
    assert_eq!(retention_status, "success");
    await_file_removed(&archive_path).await;

    drop_database(&database_name).await;
    let _ = fs::remove_dir_all(&archive_dir);
}
