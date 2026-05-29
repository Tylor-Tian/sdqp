use std::{fs, path::PathBuf, time::Duration};

use axum::body::{Body, to_bytes};
use http::{Method, Request, StatusCode, header};
use reqwest::Client;
use sdqp_api::{
    ConfigChangeResponse, ConfigDriftResponse, LoginResponse, ProjectCreateResponse,
    ProjectDeleteResponse, ProjectStateChangeResponse, ProjectsListResponse, QuerySubmitResponse,
    QueryTaskStatusResponse, SnapshotMetadataResponse, TokenPairResponse, build_persistent_router,
};
use sdqp_audit::{read_replica_file, verify_replica};
use sdqp_config::AppSettings;
use sdqp_encryption::{S3CompatibleObjectStore, SnapshotObjectStore};
use serde_json::Value;
use sqlx::{Executor, Row};
use sqlx_postgres::PgPoolOptions;
use tower::ServiceExt;

fn stage5_enabled() -> bool {
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

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("stage5")
        .join(name)
}

fn load_fixture(name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(fixture_path(name)).expect("fixture")).expect("json")
}

fn replica_path(database_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("generated")
        .join("audit")
        .join(format!("{database_name}-replica.json"))
}

async fn json_request(
    app: axum::Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
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

async fn login_tokens(
    app: axum::Router,
    username: &str,
    device_fingerprint: &str,
) -> TokenPairResponse {
    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            Some(serde_json::json!({
                "username": username,
                "password": "password123",
                "device_fingerprint": device_fingerprint,
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
                "code": "000000",
            })),
            &[],
        )
        .await,
    )
    .await
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

async fn wait_for_task_completion(
    app: axum::Router,
    bearer: &str,
    task_id: &str,
) -> QueryTaskStatusResponse {
    for _ in 0..20 {
        let response = json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/tasks/{task_id}/status"),
            None,
            &[
                ("authorization", bearer),
                ("x-tenant-id", "tenant-alpha"),
                ("x-project-id", "project-alpha"),
            ],
        )
        .await;
        if response.status() == StatusCode::OK {
            let payload: QueryTaskStatusResponse = decode_json(response).await;
            if payload.state == "completed" {
                return payload;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("task did not complete in time");
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

#[tokio::test]
async fn uat_stage5_persists_audit_and_enforces_project_lifecycle() {
    if !stage5_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage5_api_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let settings = test_settings(&database_name);
    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent router");

    let analyst = login_tokens(app.clone(), "analyst", "stage5-analyst").await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);
    let admin = login_tokens(app.clone(), "sysadmin", "stage5-admin").await;
    let admin_bearer = format!("Bearer {}", admin.access_token);

    let runtime_project_id = format!("project-runtime-{}", ulid::Ulid::new());
    let created: ProjectCreateResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/projects",
            Some(serde_json::json!({
                "project_id": runtime_project_id,
                "initial_state": "active"
            })),
            &[
                ("authorization", admin_bearer.as_str()),
                ("x-tenant-id", "tenant-alpha"),
            ],
        )
        .await,
    )
    .await;
    assert!(created.runtime_created);
    assert_eq!(created.project.state, "active");
    assert_eq!(
        created.project.object_prefix,
        format!("snapshots/tenant-alpha/{}/", created.project.project_id)
    );

    let runtime_context = json_request(
        app.clone(),
        Method::GET,
        "/v1/project-context",
        None,
        &[
            ("authorization", admin_bearer.as_str()),
            ("x-tenant-id", "tenant-alpha"),
            ("x-project-id", created.project.project_id.as_str()),
        ],
    )
    .await;
    assert_eq!(runtime_context.status(), StatusCode::OK);

    let runtime_deleted: ProjectDeleteResponse = decode_json(
        json_request(
            app.clone(),
            Method::DELETE,
            &format!("/v1/projects/{}", created.project.project_id),
            None,
            &[
                ("authorization", admin_bearer.as_str()),
                ("x-tenant-id", "tenant-alpha"),
            ],
        )
        .await,
    )
    .await;
    assert_eq!(runtime_deleted.current_state, "deleted");
    assert_eq!(runtime_deleted.deleted_snapshots, 0);
    assert_eq!(runtime_deleted.object_prefix, created.project.object_prefix);

    let runtime_deleted_hidden = json_request(
        app.clone(),
        Method::GET,
        "/v1/project-context",
        None,
        &[
            ("authorization", admin_bearer.as_str()),
            ("x-tenant-id", "tenant-alpha"),
            ("x-project-id", created.project.project_id.as_str()),
        ],
    )
    .await;
    assert_eq!(runtime_deleted_hidden.status(), StatusCode::NOT_FOUND);

    let query: QuerySubmitResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "source_type": "rest",
                "fields": ["employee_id", "department"]
            })),
            &[
                ("authorization", analyst_bearer.as_str()),
                ("x-tenant-id", "tenant-alpha"),
                ("x-project-id", "project-alpha"),
            ],
        )
        .await,
    )
    .await;
    let completed = wait_for_task_completion(app.clone(), &analyst_bearer, &query.task_id).await;
    let snapshot_id = completed.snapshot_id.expect("snapshot id");
    let metadata: SnapshotMetadataResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/snapshots/{snapshot_id}/metadata"),
            None,
            &[
                ("authorization", analyst_bearer.as_str()),
                ("x-tenant-id", "tenant-alpha"),
                ("x-project-id", "project-alpha"),
            ],
        )
        .await,
    )
    .await;
    assert!(
        metadata
            .storage_key
            .starts_with("snapshots/tenant-alpha/project-alpha/")
    );
    let object_store = S3CompatibleObjectStore::new(
        settings.object_store.endpoint.clone(),
        settings.object_store.region.clone(),
        settings.object_store.access_key.clone(),
        settings.object_store.secret_key.clone(),
    );
    assert!(
        object_store
            .exists(
                &settings.object_store.bucket_snapshots,
                &metadata.storage_key
            )
            .await
            .expect("snapshot object exists")
    );

    let projects: ProjectsListResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/projects",
            None,
            &[
                ("authorization", admin_bearer.as_str()),
                ("x-tenant-id", "tenant-alpha"),
            ],
        )
        .await,
    )
    .await;
    assert!(
        projects
            .projects
            .iter()
            .any(|project| project.project_id == "project-alpha" && project.state == "active")
    );

    let config: ConfigChangeResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/admin/config-change",
            Some(load_fixture("config-change.json")),
            &[
                ("authorization", admin_bearer.as_str()),
                ("x-tenant-id", "tenant-alpha"),
            ],
        )
        .await,
    )
    .await;
    assert!(config.accepted);
    assert!(!config.version_id.is_empty());

    let drift: ConfigDriftResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/admin/config-drift",
            None,
            &[
                ("authorization", admin_bearer.as_str()),
                ("x-tenant-id", "tenant-alpha"),
            ],
        )
        .await,
    )
    .await;
    assert!(drift.drifts.is_empty());

    let freeze: ProjectStateChangeResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/projects/project-alpha/state",
            Some(load_fixture("project-freeze.json")),
            &[
                ("authorization", admin_bearer.as_str()),
                ("x-tenant-id", "tenant-alpha"),
            ],
        )
        .await,
    )
    .await;
    assert_eq!(freeze.current_state, "frozen");

    let permission_denied = json_request(
        app.clone(),
        Method::POST,
        "/v1/permissions/applications",
        Some(serde_json::json!({
            "data_source_id": "datasource-rest",
            "requested_fields": ["employee_id"]
        })),
        &[
            ("authorization", analyst_bearer.as_str()),
            ("x-tenant-id", "tenant-alpha"),
            ("x-project-id", "project-alpha"),
        ],
    )
    .await;
    assert_eq!(permission_denied.status(), StatusCode::FORBIDDEN);

    let export_denied = json_request(
        app.clone(),
        Method::POST,
        "/v1/exports/evidence",
        Some(serde_json::json!({
            "snapshot_id": snapshot_id,
            "template": "china"
        })),
        &[
            ("authorization", analyst_bearer.as_str()),
            ("x-tenant-id", "tenant-alpha"),
            ("x-project-id", "project-alpha"),
        ],
    )
    .await;
    assert_eq!(export_denied.status(), StatusCode::FORBIDDEN);

    let deleted: ProjectDeleteResponse = decode_json(
        json_request(
            app.clone(),
            Method::DELETE,
            "/v1/projects/project-alpha",
            None,
            &[
                ("authorization", admin_bearer.as_str()),
                ("x-tenant-id", "tenant-alpha"),
            ],
        )
        .await,
    )
    .await;
    assert_eq!(deleted.current_state, "deleted");
    assert!(deleted.deleted_snapshots >= 1);
    assert!(deleted.deleted_objects >= 1);
    assert!(
        !object_store
            .exists(
                &settings.object_store.bucket_snapshots,
                &metadata.storage_key
            )
            .await
            .expect("snapshot object purged")
    );

    let project_denied = json_request(
        app.clone(),
        Method::GET,
        "/v1/project-context",
        None,
        &[
            ("authorization", analyst_bearer.as_str()),
            ("x-tenant-id", "tenant-alpha"),
            ("x-project-id", "project-alpha"),
        ],
    )
    .await;
    assert_eq!(project_denied.status(), StatusCode::NOT_FOUND);

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&settings.database.postgres.dsn)
        .await
        .expect("postgres");
    let config_versions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM config_versions")
        .fetch_one(&pool)
        .await
        .expect("config versions");
    let purged_snapshots: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM snapshots
        WHERE project_id = $1
          AND delete_state = 'purged'
          AND purged_at IS NOT NULL
          AND encrypted_payload_json ->> 'ciphertext_b64' = ''
        "#,
    )
    .bind("project-alpha")
    .fetch_one(&pool)
    .await
    .expect("snapshots");
    let project_state =
        sqlx::query("SELECT state, object_prefix, deleted_at FROM projects WHERE project_id = $1")
            .bind("project-alpha")
            .fetch_one(&pool)
            .await
            .expect("project");

    assert_eq!(config_versions, 1);
    assert!(purged_snapshots >= 1);
    assert_eq!(
        project_state.try_get::<String, _>("state").expect("state"),
        "deleted"
    );
    assert_eq!(
        project_state
            .try_get::<String, _>("object_prefix")
            .expect("object prefix"),
        "snapshots/tenant-alpha/project-alpha/"
    );
    assert!(
        project_state
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("deleted_at")
            .expect("deleted at")
            .is_some()
    );

    let audit_events = clickhouse_count(
        &settings.database.clickhouse.http_url,
        "SELECT COUNT() FROM sdqp.audit_events",
    )
    .await;
    let audit_checkpoints = clickhouse_count(
        &settings.database.clickhouse.http_url,
        "SELECT COUNT() FROM sdqp.audit_checkpoints",
    )
    .await;
    assert!(audit_events >= 8);
    assert!(audit_checkpoints >= audit_events);

    let replica = read_replica_file(replica_path(&database_name)).expect("replica");
    assert!(verify_replica(&replica));
    assert!(replica.events.len() as i64 >= audit_events);

    drop(app);
    drop(pool);
    drop_database(&database_name).await;
}
