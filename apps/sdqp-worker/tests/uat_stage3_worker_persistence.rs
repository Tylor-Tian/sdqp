use axum::body::{Body, to_bytes};
use http::{Method, Request, StatusCode, header};
use sdqp_config::AppSettings;
use sdqp_core::{RequestContext, TenantId, UserId};
use sdqp_system_security::{SessionBinding, SessionPolicy, issue_access_token};
use sdqp_worker::{WorkerProjectResponse, build_persistent_router};
use sqlx::Executor;
use sqlx_postgres::PgPoolOptions;
use tower::ServiceExt;

fn stage3_enabled() -> bool {
    std::env::var("SDQP_ENABLE_STAGE3_TESTS").ok().as_deref() == Some("1")
}

fn admin_dsn() -> String {
    std::env::var("SDQP_STAGE3_ADMIN_DSN")
        .unwrap_or_else(|_| "postgres://sdqp:sdqp@127.0.0.1:15432/postgres".into())
}

fn worker_token() -> String {
    let request = RequestContext::new(
        TenantId::new("tenant-alpha").expect("tenant"),
        UserId::new("user-analyst").expect("user"),
    );
    let claims = SessionPolicy { ttl_minutes: 15 }.issue(
        &request,
        SessionBinding {
            ip_address: "127.0.0.1".into(),
            device_fingerprint: "stage3-worker".into(),
        },
    );
    issue_access_token(&claims, "sdqp-phase1-dev-secret").expect("token")
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
async fn uat_worker_loads_project_catalog_from_postgres() {
    if !stage3_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage3_worker_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let settings = test_settings(&database_name);
    let _ = sdqp_api::build_persistent_router(settings.clone())
        .await
        .expect("api bootstrap");

    let app = build_persistent_router(settings.clone())
        .await
        .expect("worker persistent router");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/worker/project-queue")
                .header(header::AUTHORIZATION, format!("Bearer {}", worker_token()))
                .header("x-tenant-id", "tenant-alpha")
                .header("x-project-id", "project-alpha")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let payload: WorkerProjectResponse = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(payload.queue_count, 2);
    assert_eq!(payload.project_state, "active");

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&settings.database.postgres.dsn)
        .await
        .expect("postgres");
    let projects_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects")
        .fetch_one(&pool)
        .await
        .expect("projects count");
    assert!(projects_count >= 2);

    drop(app);
    drop(pool);
    drop_database(&database_name).await;
}
