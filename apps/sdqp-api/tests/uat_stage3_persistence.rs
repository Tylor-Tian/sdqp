use std::time::Duration;

use axum::body::{Body, to_bytes};
use http::{Method, Request, StatusCode, header};
use sdqp_api::{
    LoginResponse, QueryTaskStatusResponse, TokenPairResponse, build_persistent_router,
};
use sdqp_config::AppSettings;
use sqlx::{Executor, Row};
use sqlx_postgres::{PgPool, PgPoolOptions};
use tower::ServiceExt;

fn stage3_enabled() -> bool {
    std::env::var("SDQP_ENABLE_STAGE3_TESTS").ok().as_deref() == Some("1")
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
    settings
}

async fn json_request(
    app: axum::Router,
    method: Method,
    uri: &str,
    body: serde_json::Value,
    headers: &[(&str, &str)],
) -> http::Response<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }

    app.oneshot(
        builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
    )
    .await
    .expect("response")
}

async fn decode_json<T: serde::de::DeserializeOwned>(response: http::Response<Body>) -> T {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

async fn wait_for_terminal_status(
    app: axum::Router,
    task_id: &str,
    headers: &[(&str, &str)],
) -> QueryTaskStatusResponse {
    for _ in 0..80 {
        let mut builder = Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/tasks/{task_id}/status"));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }

        let response = app
            .clone()
            .oneshot(builder.body(Body::empty()).expect("request"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let status: QueryTaskStatusResponse = decode_json(response).await;
        if matches!(status.state.as_str(), "completed" | "failed" | "cancelled") {
            return status;
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!("task {task_id} did not reach a terminal state");
}

async fn wait_for_persisted_completion(pool: &PgPool, task_id: &str) -> (String, Option<String>) {
    for _ in 0..80 {
        let row = sqlx::query("SELECT state, snapshot_id FROM query_tasks WHERE task_id = $1")
            .bind(task_id)
            .fetch_one(pool)
            .await
            .expect("task row");
        let state = row.try_get::<String, _>("state").expect("state");
        let snapshot_id = row
            .try_get::<Option<String>, _>("snapshot_id")
            .expect("snapshot");
        if state == "completed" && snapshot_id.is_some() {
            return (state, snapshot_id);
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!("task {task_id} did not persist a completed state");
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

#[tokio::test]
async fn uat_persistent_router_seeds_catalog_and_writes_runtime_state() {
    if !stage3_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage3_api_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let settings = test_settings(&database_name);
    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent router");

    let login = json_request(
        app.clone(),
        Method::POST,
        "/auth/login",
        serde_json::json!({
            "username": "analyst",
            "password": "password123",
            "device_fingerprint": "stage3-api"
        }),
        &[("x-forwarded-for", "127.0.0.1")],
    )
    .await;
    assert_eq!(login.status(), StatusCode::OK);
    let login: LoginResponse = decode_json(login).await;

    let mfa = json_request(
        app.clone(),
        Method::POST,
        "/auth/mfa/verify",
        serde_json::json!({
            "pending_session_id": login.pending_session_id,
            "code": "000000"
        }),
        &[],
    )
    .await;
    assert_eq!(mfa.status(), StatusCode::OK);
    let mfa: TokenPairResponse = decode_json(mfa).await;

    let headers = [
        ("authorization", format!("Bearer {}", mfa.access_token)),
        ("x-tenant-id", "tenant-alpha".into()),
        ("x-project-id", "project-alpha".into()),
    ];

    let query = json_request(
        app.clone(),
        Method::POST,
        "/v1/queries",
        serde_json::json!({
            "data_source_id": "datasource-rest",
            "source_type": "rest",
            "fields": ["employee_id", "department"]
        }),
        &[
            ("authorization", headers[0].1.as_str()),
            ("x-tenant-id", headers[1].1.as_str()),
            ("x-project-id", headers[2].1.as_str()),
        ],
    )
    .await;
    assert_eq!(query.status(), StatusCode::OK);
    let query: serde_json::Value = decode_json(query).await;
    let task_id = query["task_id"].as_str().expect("task id").to_string();

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&settings.database.postgres.dsn)
        .await
        .expect("postgres");

    let status = wait_for_terminal_status(
        app.clone(),
        &task_id,
        &[
            ("authorization", headers[0].1.as_str()),
            ("x-tenant-id", headers[1].1.as_str()),
            ("x-project-id", headers[2].1.as_str()),
        ],
    )
    .await;
    assert_eq!(status.state, "completed");

    let (persisted_state, persisted_snapshot_id) =
        wait_for_persisted_completion(&pool, &task_id).await;

    let users_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .expect("users count");
    let projects_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects")
        .fetch_one(&pool)
        .await
        .expect("projects count");
    let sessions_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions WHERE session_kind = 'active' AND revoked = FALSE",
    )
    .fetch_one(&pool)
    .await
    .expect("sessions count");
    let snapshots_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM snapshots")
        .fetch_one(&pool)
        .await
        .expect("snapshots count");
    let cache_entries_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM snapshot_cache_entries")
            .fetch_one(&pool)
            .await
            .expect("cache entries count");

    assert!(users_count >= 3);
    assert!(projects_count >= 2);
    assert_eq!(sessions_count, 1);
    assert_eq!(persisted_state, "completed");
    assert!(persisted_snapshot_id.is_some());
    assert_eq!(snapshots_count, 1);
    assert_eq!(cache_entries_count, 1);

    drop(app);
    drop(pool);
    drop_database(&database_name).await;
}
