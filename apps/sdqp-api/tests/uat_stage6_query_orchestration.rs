use std::time::Duration;

use axum::body::{Body, to_bytes};
use futures_util::StreamExt;
use http::{Method, Request, StatusCode, header};
use sdqp_api::{
    LoginResponse, QuerySubmitResponse, QueryTaskStatusResponse, SnapshotMetadataResponse,
    TokenPairResponse, build_persistent_router,
};
use sdqp_config::AppSettings;
use sdqp_worker::build_persistent_router as build_worker_router;
use sqlx::{Executor, Row};
use sqlx_postgres::PgPoolOptions;
use tokio::{net::TcpListener, sync::oneshot};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tower::ServiceExt;

fn stage6_enabled() -> bool {
    std::env::var("SDQP_ENABLE_STAGE6_TESTS").ok().as_deref() == Some("1")
}

fn admin_dsn() -> String {
    std::env::var("SDQP_STAGE3_ADMIN_DSN")
        .unwrap_or_else(|_| "postgres://sdqp:sdqp@127.0.0.1:15432/postgres".into())
}

fn test_settings(database_name: &str) -> AppSettings {
    let mut settings = AppSettings::local_dev();
    settings.api.external_query_worker = true;
    settings.worker.query_poll_interval_ms = 25;
    settings.worker.query_lease_secs = 30;
    settings.worker.query_max_attempts = 2;
    settings.database.postgres.dsn =
        format!("postgres://sdqp:sdqp@127.0.0.1:15432/{database_name}");
    settings.database.clickhouse.http_url = "http://127.0.0.1:18123".into();
    settings.database.clickhouse.native_url = "tcp://127.0.0.1:19000".into();
    settings.object_store.endpoint = "http://127.0.0.1:19002".into();
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

async fn analyst_tokens(app: axum::Router) -> TokenPairResponse {
    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            Some(serde_json::json!({
                "username": "analyst",
                "password": "password123",
                "device_fingerprint": "stage6-worker"
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

async fn wait_for_terminal_status(
    app: axum::Router,
    token: &str,
    task_id: &str,
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

        if matches!(status.state.as_str(), "completed" | "failed" | "cancelled") {
            return status;
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!("task {task_id} did not reach terminal state");
}

async fn configure_hive_source(settings: &AppSettings, delay_ms: u64) -> sqlx::PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&settings.database.postgres.dsn)
        .await
        .expect("postgres");
    pool.execute(
        r#"
        CREATE TABLE stage6_employee_rows (
            employee_id TEXT NOT NULL,
            department TEXT NOT NULL
        )
        "#,
    )
    .await
    .expect("create table");
    pool.execute(
        r#"
        INSERT INTO stage6_employee_rows (employee_id, department)
        VALUES ('H-100', 'warehouse'), ('H-200', 'ops')
        "#,
    )
    .await
    .expect("insert rows");
    sqlx::query(
        r#"
        UPDATE data_sources
        SET
            connection_uri = $2,
            adapter_config_json = $3
        WHERE data_source_id = 'datasource-hive'
        "#,
    )
    .bind("datasource-hive")
    .bind(&settings.database.postgres.dsn)
    .bind(sqlx::types::Json(serde_json::json!({
        "table": "stage6_employee_rows",
        "delay_ms": delay_ms
    })))
    .execute(&pool)
    .await
    .expect("update datasource");
    pool
}

#[tokio::test]
async fn uat_stage6_worker_processes_persisted_query_tasks_and_syncs_api_status() {
    if !stage6_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage6_api_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let settings = test_settings(&database_name);
    let api = build_persistent_router(settings.clone())
        .await
        .expect("persistent api router");
    let pool = configure_hive_source(&settings, 200).await;
    let worker = build_worker_router(settings.clone())
        .await
        .expect("persistent worker router");

    let tokens = analyst_tokens(api.clone()).await;
    let bearer = format!("Bearer {}", tokens.access_token);

    let first_submit: QuerySubmitResponse = decode_json(
        json_request(
            api.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-hive",
                "source_type": "hive",
                "fields": ["employee_id"]
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert_eq!(first_submit.status, "pending");

    let first_status = wait_for_terminal_status(api.clone(), &bearer, &first_submit.task_id).await;
    assert_eq!(first_status.state, "completed");
    assert!(!first_status.cache_hit);
    let snapshot_id = first_status.snapshot_id.clone().expect("snapshot");

    let metadata = json_request(
        api.clone(),
        Method::GET,
        &format!("/v1/snapshots/{snapshot_id}/metadata"),
        None,
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(metadata.status(), StatusCode::OK);
    let metadata: SnapshotMetadataResponse = decode_json(metadata).await;
    assert_eq!(metadata.data_source_id, "datasource-hive");

    let second_submit: QuerySubmitResponse = decode_json(
        json_request(
            api.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-hive",
                "source_type": "hive",
                "fields": ["employee_id"]
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    let second_status =
        wait_for_terminal_status(api.clone(), &bearer, &second_submit.task_id).await;
    assert_eq!(second_status.state, "completed");
    assert!(second_status.cache_hit);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let api_server = api.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, api_server)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server");
    });

    let ws_submit: QuerySubmitResponse = decode_json(
        json_request(
            api.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-hive",
                "source_type": "hive",
                "fields": ["department"]
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;

    let mut request = format!("ws://{address}/v1/tasks/{}/ws", ws_submit.task_id)
        .into_client_request()
        .expect("ws request");
    request
        .headers_mut()
        .insert(header::AUTHORIZATION, bearer.parse().expect("auth header"));
    request.headers_mut().insert(
        "x-tenant-id",
        "tenant-alpha".parse().expect("tenant header"),
    );
    request.headers_mut().insert(
        "x-project-id",
        "project-alpha".parse().expect("project header"),
    );

    let (mut socket, _) = connect_async(request).await.expect("websocket");
    let first_message = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("first message timeout")
        .expect("first message")
        .expect("ws frame");
    let first_status: QueryTaskStatusResponse =
        serde_json::from_str(&first_message.into_text().expect("text")).expect("status");
    assert!(matches!(first_status.state.as_str(), "pending" | "running"));

    let mut terminal_ws_status = None;
    for _ in 0..3 {
        let message = tokio::time::timeout(Duration::from_secs(3), socket.next())
            .await
            .expect("follow-up message timeout")
            .expect("follow-up message")
            .expect("ws frame");
        let status: QueryTaskStatusResponse =
            serde_json::from_str(&message.into_text().expect("text")).expect("status");
        if status.state == "completed" {
            terminal_ws_status = Some(status);
            break;
        }
    }
    assert_eq!(
        terminal_ws_status
            .expect("completed websocket update")
            .state,
        "completed"
    );
    let _ = socket.close(None).await;
    let _ = shutdown_tx.send(());
    server.await.expect("server join");

    let cancel_submit: QuerySubmitResponse = decode_json(
        json_request(
            api.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-hive",
                "source_type": "hive",
                "fields": ["employee_id", "department"],
                "page_size": 1
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(60)).await;
    let cancel_response = json_request(
        api.clone(),
        Method::DELETE,
        &format!("/v1/tasks/{}/cancel", cancel_submit.task_id),
        None,
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(cancel_response.status(), StatusCode::OK);
    let cancelled = wait_for_terminal_status(api.clone(), &bearer, &cancel_submit.task_id).await;
    assert_eq!(cancelled.state, "cancelled");

    let timeout_submit: QuerySubmitResponse = decode_json(
        json_request(
            api.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-hive",
                "source_type": "hive",
                "fields": ["employee_id"],
                "timeout_secs": 0
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    let timeout_status =
        wait_for_terminal_status(api.clone(), &bearer, &timeout_submit.task_id).await;
    assert_eq!(timeout_status.state, "failed");
    assert_eq!(timeout_status.error.as_deref(), Some("query timed out"));

    let timeout_row =
        sqlx::query("SELECT attempt_count, state FROM query_tasks WHERE task_id = $1")
            .bind(&timeout_submit.task_id)
            .fetch_one(&pool)
            .await
            .expect("timeout row");
    assert_eq!(
        timeout_row
            .try_get::<i32, _>("attempt_count")
            .expect("attempts"),
        2
    );
    assert_eq!(
        timeout_row.try_get::<String, _>("state").expect("state"),
        "failed"
    );

    let breaker_submit: QuerySubmitResponse = decode_json(
        json_request(
            api.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-hive",
                "source_type": "hive",
                "fields": ["department"],
                "timeout_secs": 0,
                "page_size": 2
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    let breaker_status =
        wait_for_terminal_status(api.clone(), &bearer, &breaker_submit.task_id).await;
    assert_eq!(breaker_status.state, "failed");
    assert_eq!(
        breaker_status.error.as_deref(),
        Some("circuit breaker open")
    );

    let worker_metrics = worker
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/metrics")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("worker metrics");
    let metrics_body = to_bytes(worker_metrics.into_body(), usize::MAX)
        .await
        .expect("metrics body");
    let metrics_text = String::from_utf8(metrics_body.to_vec()).expect("metrics text");
    assert!(
        metrics_text
            .contains("sdqp_query_tasks_total{service=\"sdqp-worker\",result=\"completed\"}")
    );
    assert!(
        metrics_text
            .contains("sdqp_query_tasks_total{service=\"sdqp-worker\",result=\"cache_hit\"}")
    );
    assert!(metrics_text.contains(
        "sdqp_datasource_circuit_open{service=\"sdqp-worker\",data_source_id=\"datasource-hive\"} 1"
    ));

    drop(api);
    drop(worker);
    drop(pool);
    drop_database(&database_name).await;
}
