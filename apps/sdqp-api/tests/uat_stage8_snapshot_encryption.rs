use axum::body::{Body, to_bytes};
use http::{Method, Request, StatusCode, header};
use sdqp_api::{
    AuditSearchResponse, KeyRotationRunResponse, KeyRotationStatesResponse, LoginResponse,
    QuerySubmitResponse, QueryTaskStatusResponse, SnapshotLifecycleResponse,
    SnapshotMetadataResponse, SnapshotPageResponse, SnapshotRefreshResponse, TokenPairResponse,
    build_persistent_router,
};
use sdqp_config::AppSettings;
use sdqp_encryption::{S3CompatibleObjectStore, SnapshotObjectStore};
use sqlx::{Executor, Row};
use sqlx_postgres::PgPoolOptions;
use tower::ServiceExt;

fn stage8_enabled() -> bool {
    std::env::var("SDQP_ENABLE_STAGE8_TESTS").ok().as_deref() == Some("1")
}

fn admin_dsn() -> String {
    std::env::var("SDQP_STAGE8_ADMIN_DSN")
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

async fn analyst_tokens(app: axum::Router) -> TokenPairResponse {
    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            Some(serde_json::json!({
                "username": "analyst",
                "password": "password123",
                "device_fingerprint": "stage8-api"
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

async fn sysadmin_tokens(app: axum::Router) -> TokenPairResponse {
    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            Some(serde_json::json!({
                "username": "sysadmin",
                "password": "password123",
                "device_fingerprint": "stage8-api-admin"
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

fn audit_context_field(
    response: &AuditSearchResponse,
    context: &str,
    field: &str,
) -> Option<serde_json::Value> {
    response
        .events
        .iter()
        .find(|event| event.context == context)
        .and_then(|event| serde_json::to_value(&event.context_fields).ok())
        .and_then(|fields| fields.get(field).cloned())
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
    for _ in 0..60 {
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

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    panic!("task {task_id} did not reach terminal state");
}

#[tokio::test]
async fn uat_snapshot_lifecycle_persists_object_store_and_delete_restore_flow() {
    if !stage8_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage8_api_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let settings = test_settings(&database_name);
    let object_store = S3CompatibleObjectStore::new(
        settings.object_store.endpoint.clone(),
        settings.object_store.region.clone(),
        settings.object_store.access_key.clone(),
        settings.object_store.secret_key.clone(),
    );
    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent router");
    let tokens = analyst_tokens(app.clone()).await;
    let bearer = format!("Bearer {}", tokens.access_token);

    let submit: QuerySubmitResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "source_type": "rest",
                "fields": ["employee_id", "department"]
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    let status = wait_for_terminal_status(app.clone(), &bearer, &submit.task_id).await;
    assert_eq!(status.state, "completed");
    let snapshot_id = status.snapshot_id.expect("snapshot id");

    let metadata: SnapshotMetadataResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/snapshots/{snapshot_id}/metadata"),
            None,
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert!(metadata.encrypted);
    assert_eq!(metadata.delete_state, "active");
    assert_eq!(metadata.kms_provider, "mock");
    assert_eq!(metadata.key_version.as_deref(), Some("1"));
    assert!(!metadata.kek_id.is_empty());
    assert!(
        object_store
            .exists(
                &settings.object_store.bucket_snapshots,
                &metadata.storage_key
            )
            .await
            .expect("snapshot object exists")
    );

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&settings.database.postgres.dsn)
        .await
        .expect("postgres");
    let task_row =
        sqlx::query("SELECT grant_id, grant_valid_until FROM query_tasks WHERE task_id = $1")
            .bind(&submit.task_id)
            .fetch_one(&pool)
            .await
            .expect("task row");
    assert!(
        !task_row
            .try_get::<String, _>("grant_id")
            .expect("grant id")
            .is_empty()
    );
    assert!(
        task_row
            .try_get::<chrono::DateTime<chrono::Utc>, _>("grant_valid_until")
            .is_ok()
    );

    let deleted: SnapshotLifecycleResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            &format!("/v1/snapshots/{snapshot_id}/delete"),
            None,
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert_eq!(deleted.delete_state, "soft_deleted");
    assert!(deleted.object_present);
    assert_eq!(deleted.kms_provider, metadata.kms_provider);
    assert_eq!(deleted.kek_id, metadata.kek_id);
    assert_eq!(deleted.key_version, metadata.key_version);

    let page = json_request(
        app.clone(),
        Method::GET,
        &format!("/v1/snapshots/{snapshot_id}/page?page_size=1"),
        None,
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(page.status(), StatusCode::NOT_FOUND);

    let restored: SnapshotLifecycleResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            &format!("/v1/snapshots/{snapshot_id}/restore"),
            None,
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert_eq!(restored.delete_state, "active");
    assert!(restored.object_present);
    assert_eq!(restored.kms_provider, metadata.kms_provider);
    assert_eq!(restored.kek_id, metadata.kek_id);
    assert_eq!(restored.key_version, metadata.key_version);

    let page: SnapshotPageResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/snapshots/{snapshot_id}/page?page_size=1"),
            None,
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert_eq!(page.snapshot_id, snapshot_id);
    assert!(!page.rows.is_empty());

    let refreshed: SnapshotRefreshResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            &format!("/v1/snapshots/{snapshot_id}/refresh"),
            None,
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert!(refreshed.refreshed);
    assert_eq!(refreshed.kms_provider, metadata.kms_provider);
    assert_eq!(refreshed.kek_id, metadata.kek_id);
    assert!(refreshed.last_rewrapped_at.is_some());

    let purged: SnapshotLifecycleResponse = decode_json(
        json_request(
            app.clone(),
            Method::DELETE,
            &format!("/v1/snapshots/{snapshot_id}"),
            None,
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert_eq!(purged.delete_state, "purged");
    assert!(!purged.object_present);
    assert_eq!(purged.kms_provider, refreshed.kms_provider);
    assert_eq!(purged.kek_id, refreshed.kek_id);
    assert_eq!(purged.key_version, refreshed.key_version);
    assert!(
        !object_store
            .exists(
                &settings.object_store.bucket_snapshots,
                &metadata.storage_key
            )
            .await
            .expect("snapshot object removed")
    );

    let snapshot_row = sqlx::query(
        "SELECT delete_state, purged_at, last_rewrapped_at, object_size_bytes FROM snapshots WHERE snapshot_id = $1",
    )
    .bind(&snapshot_id)
    .fetch_one(&pool)
    .await
    .expect("snapshot row");
    assert_eq!(
        snapshot_row
            .try_get::<String, _>("delete_state")
            .expect("delete state"),
        "purged"
    );
    assert!(
        snapshot_row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("purged_at")
            .expect("purged_at")
            .is_some()
    );
    assert!(
        snapshot_row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_rewrapped_at")
            .expect("last_rewrapped_at")
            .is_some()
    );
    assert!(
        snapshot_row
            .try_get::<i64, _>("object_size_bytes")
            .expect("object size")
            > 0
    );

    let restore_after_purge = json_request(
        app.clone(),
        Method::POST,
        &format!("/v1/snapshots/{snapshot_id}/restore"),
        None,
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(restore_after_purge.status(), StatusCode::CONFLICT);

    drop(app);
    drop(pool);
    drop_database(&database_name).await;
}

#[tokio::test]
async fn uat_snapshot_refresh_rewraps_persisted_snapshot_across_providers() {
    if !stage8_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage8_api_refresh_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let mut mock_settings = test_settings(&database_name);
    mock_settings.kms.provider = "mock".into();
    let app = build_persistent_router(mock_settings.clone())
        .await
        .expect("persistent router");
    let analyst = analyst_tokens(app.clone()).await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);

    let submit: QuerySubmitResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "source_type": "rest",
                "fields": ["employee_id", "department"]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    let status = wait_for_terminal_status(app.clone(), &analyst_bearer, &submit.task_id).await;
    assert_eq!(status.state, "completed");
    let snapshot_id = status.snapshot_id.expect("snapshot id");

    let initial_metadata: SnapshotMetadataResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/snapshots/{snapshot_id}/metadata"),
            None,
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(initial_metadata.kms_provider, "mock");
    assert_eq!(initial_metadata.key_version.as_deref(), Some("1"));

    drop(app);

    let mut vault_settings = test_settings(&database_name);
    vault_settings.kms.provider = "vault".into();
    vault_settings.kms.key_version = "9".into();
    let app = build_persistent_router(vault_settings)
        .await
        .expect("persistent router");
    let analyst = analyst_tokens(app.clone()).await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);

    let page_before_refresh: SnapshotPageResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/snapshots/{snapshot_id}/page?page_size=1"),
            None,
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(page_before_refresh.snapshot_id, snapshot_id);
    assert!(!page_before_refresh.rows.is_empty());

    let refreshed: SnapshotRefreshResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            &format!("/v1/snapshots/{snapshot_id}/refresh"),
            None,
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    assert!(refreshed.refreshed);
    assert_eq!(refreshed.previous_kms_provider, "mock");
    assert_eq!(refreshed.kms_provider, "vault");
    assert_eq!(refreshed.previous_key_version.as_deref(), Some("1"));
    assert_eq!(refreshed.key_version.as_deref(), Some("9"));
    assert!(refreshed.last_rewrapped_at.is_some());

    let metadata_after_refresh: SnapshotMetadataResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/snapshots/{snapshot_id}/metadata"),
            None,
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(metadata_after_refresh.kms_provider, "vault");
    assert_eq!(metadata_after_refresh.key_version.as_deref(), Some("9"));

    let page_after_refresh: SnapshotPageResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/snapshots/{snapshot_id}/page?page_size=1"),
            None,
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(page_after_refresh.snapshot_id, snapshot_id);
    assert_eq!(page_after_refresh.rows, page_before_refresh.rows);

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&mock_settings.database.postgres.dsn)
        .await
        .expect("postgres");
    let snapshot_row = sqlx::query(
        r#"
        SELECT
            encrypted_payload_json ->> 'kms_provider' AS kms_provider,
            encrypted_payload_json ->> 'key_version' AS key_version,
            last_rewrapped_at
        FROM snapshots
        WHERE snapshot_id = $1
        "#,
    )
    .bind(&snapshot_id)
    .fetch_one(&pool)
    .await
    .expect("snapshot row");
    assert_eq!(
        snapshot_row
            .try_get::<String, _>("kms_provider")
            .expect("kms_provider"),
        "vault"
    );
    assert_eq!(
        snapshot_row
            .try_get::<Option<String>, _>("key_version")
            .expect("key_version")
            .as_deref(),
        Some("9")
    );
    assert!(
        snapshot_row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_rewrapped_at")
            .expect("last_rewrapped_at")
            .is_some()
    );

    let admin = sysadmin_tokens(app.clone()).await;
    let admin_bearer = format!("Bearer {}", admin.access_token);
    let audit: AuditSearchResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/audit/events/search?resource_id_contains={snapshot_id}&limit=20"),
            None,
            &scoped_headers(&admin_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(
        audit_context_field(
            &audit,
            "snapshot key wrap refreshed",
            "previous_kms_provider"
        ),
        Some(serde_json::Value::String("mock".into()))
    );
    assert_eq!(
        audit_context_field(&audit, "snapshot key wrap refreshed", "kms_provider"),
        Some(serde_json::Value::String("vault".into()))
    );
    assert_eq!(
        audit_context_field(
            &audit,
            "snapshot key wrap refreshed",
            "previous_key_version"
        ),
        Some(serde_json::Value::String("1".into()))
    );
    assert_eq!(
        audit_context_field(&audit, "snapshot key wrap refreshed", "key_version"),
        Some(serde_json::Value::String("9".into()))
    );
    assert_eq!(
        audit_context_field(&audit, "snapshot key wrap refreshed", "rotate_kek_wrap_due"),
        Some(serde_json::Value::Bool(false))
    );

    drop(app);
    drop(pool);
    drop_database(&database_name).await;
}

#[tokio::test]
async fn uat_key_rotation_lifecycle_runtime_persists_state_and_rotates_deks() {
    if !stage8_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage8_key_rotation_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let mut mock_settings = test_settings(&database_name);
    mock_settings.kms.provider = "mock".into();
    mock_settings.kms.key_version = "1".into();
    let app = build_persistent_router(mock_settings.clone())
        .await
        .expect("persistent router");
    let analyst = analyst_tokens(app.clone()).await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);

    let submit: QuerySubmitResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "source_type": "rest",
                "fields": ["employee_id", "department"]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    let status = wait_for_terminal_status(app.clone(), &analyst_bearer, &submit.task_id).await;
    assert_eq!(status.state, "completed");
    let snapshot_id = status.snapshot_id.expect("snapshot id");

    let page_before_rotation: SnapshotPageResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/snapshots/{snapshot_id}/page?page_size=1"),
            None,
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&mock_settings.database.postgres.dsn)
        .await
        .expect("postgres");
    let initial_row = sqlx::query(
        r#"
        SELECT
            encrypted_payload_json ->> 'dek_id' AS dek_id,
            encrypted_payload_json ->> 'ciphertext_b64' AS ciphertext_b64
        FROM snapshots
        WHERE snapshot_id = $1
        "#,
    )
    .bind(&snapshot_id)
    .fetch_one(&pool)
    .await
    .expect("initial snapshot row");
    let initial_dek_id: String = initial_row.try_get("dek_id").expect("initial dek id");
    let initial_ciphertext: String = initial_row
        .try_get("ciphertext_b64")
        .expect("initial ciphertext");

    sqlx::query(
        r#"
        UPDATE snapshots
        SET
            created_at = NOW() - INTERVAL '120 days',
            last_rewrapped_at = NOW() - INTERVAL '400 days'
        WHERE snapshot_id = $1
        "#,
    )
    .bind(&snapshot_id)
    .execute(&pool)
    .await
    .expect("age snapshot for rotation");
    drop(app);

    let mut vault_settings = test_settings(&database_name);
    vault_settings.kms.provider = "vault".into();
    vault_settings.kms.key_version = "9".into();
    let app = build_persistent_router(vault_settings)
        .await
        .expect("persistent router");
    let analyst = analyst_tokens(app.clone()).await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);
    let admin = sysadmin_tokens(app.clone()).await;
    let admin_bearer = format!("Bearer {}", admin.access_token);

    let states_before: KeyRotationStatesResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/admin/key-rotations",
            None,
            &scoped_headers(&admin_bearer),
        )
        .await,
    )
    .await;
    let due_state = states_before
        .states
        .iter()
        .find(|state| state.snapshot_id == snapshot_id)
        .expect("snapshot key state");
    assert_eq!(due_state.provider, "mock");
    assert_eq!(due_state.key_version.as_deref(), Some("1"));
    assert_eq!(due_state.due_state, "dek_and_kek_due");
    assert_eq!(due_state.status, "due");
    assert!(due_state.last_rewrapped_at.is_some());

    let rotation: KeyRotationRunResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/admin/key-rotations/run",
            Some(serde_json::json!({
                "snapshot_id": snapshot_id
            })),
            &scoped_headers(&admin_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(rotation.trigger, "manual");
    assert_eq!(rotation.evaluated, 1);
    assert_eq!(rotation.rotated_deks, 1);
    assert_eq!(rotation.rewrapped_keks, 1);
    assert_eq!(rotation.failed, 0);
    let result = rotation.results.first().expect("rotation result");
    assert_eq!(result.snapshot_id, snapshot_id);
    assert_eq!(result.status, "completed");
    assert_eq!(result.operation, "dek_rotation_and_kek_refresh");
    assert_eq!(result.previous_kms_provider, "mock");
    assert_eq!(result.current_kms_provider, "vault");
    assert_eq!(result.current_key_version.as_deref(), Some("9"));
    assert_ne!(result.previous_dek_id, result.current_dek_id);
    assert!(result.last_rewrapped_at.is_some());
    assert!(
        rotation
            .tee_key_release_boundary
            .contains("provider-ready boundary")
    );

    let page_after_rotation: SnapshotPageResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/snapshots/{snapshot_id}/page?page_size=1"),
            None,
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(page_after_rotation.rows, page_before_rotation.rows);

    let snapshot_row = sqlx::query(
        r#"
        SELECT
            encrypted_payload_json ->> 'kms_provider' AS kms_provider,
            encrypted_payload_json ->> 'key_version' AS key_version,
            encrypted_payload_json ->> 'dek_id' AS dek_id,
            encrypted_payload_json ->> 'ciphertext_b64' AS ciphertext_b64,
            last_rewrapped_at
        FROM snapshots
        WHERE snapshot_id = $1
        "#,
    )
    .bind(&snapshot_id)
    .fetch_one(&pool)
    .await
    .expect("rotated snapshot row");
    assert_eq!(
        snapshot_row
            .try_get::<String, _>("kms_provider")
            .expect("kms provider"),
        "vault"
    );
    assert_eq!(
        snapshot_row
            .try_get::<Option<String>, _>("key_version")
            .expect("key version")
            .as_deref(),
        Some("9")
    );
    assert_ne!(
        snapshot_row
            .try_get::<String, _>("dek_id")
            .expect("rotated dek id"),
        initial_dek_id
    );
    assert_ne!(
        snapshot_row
            .try_get::<String, _>("ciphertext_b64")
            .expect("rotated ciphertext"),
        initial_ciphertext
    );
    assert!(
        snapshot_row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_rewrapped_at")
            .expect("last rewrapped")
            .is_some()
    );

    let state_row = sqlx::query(
        r#"
        SELECT provider, key_version, dek_id, last_rewrapped_at, due_state, status, last_operation, last_cycle_id
        FROM key_rotation_state
        WHERE snapshot_id = $1
        "#,
    )
    .bind(&snapshot_id)
    .fetch_one(&pool)
    .await
    .expect("key rotation state row");
    assert_eq!(
        state_row
            .try_get::<String, _>("provider")
            .expect("provider"),
        "vault"
    );
    assert_eq!(
        state_row
            .try_get::<Option<String>, _>("key_version")
            .expect("key version")
            .as_deref(),
        Some("9")
    );
    assert_eq!(
        state_row.try_get::<String, _>("status").expect("status"),
        "completed"
    );
    assert_eq!(
        state_row
            .try_get::<String, _>("last_operation")
            .expect("operation"),
        "dek_rotation_and_kek_refresh"
    );
    assert!(
        state_row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_rewrapped_at")
            .expect("last rewrapped")
            .is_some()
    );
    assert!(
        state_row
            .try_get::<Option<String>, _>("last_cycle_id")
            .expect("cycle id")
            .is_some()
    );

    let audit: AuditSearchResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/audit/events/search?resource_id_contains={snapshot_id}&limit=40"),
            None,
            &scoped_headers(&admin_bearer),
        )
        .await,
    )
    .await;
    let key_rotation_event = audit
        .events
        .iter()
        .find(|event| event.context.contains("key lifecycle rotation completed"))
        .expect("key rotation audit event");
    let audit_fields =
        serde_json::to_value(&key_rotation_event.context_fields).expect("audit fields as json");
    assert_eq!(
        audit_fields.get("operation"),
        Some(&serde_json::Value::String(
            "dek_rotation_and_kek_refresh".into()
        ))
    );
    assert_eq!(
        audit_fields.get("provider"),
        Some(&serde_json::Value::String("vault".into()))
    );
    assert_eq!(
        audit_fields.get("key_version"),
        Some(&serde_json::Value::String("9".into()))
    );
    assert_eq!(
        audit_fields.get("due_state"),
        Some(&serde_json::Value::String("current".into()))
    );

    drop(app);
    drop(pool);
    drop_database(&database_name).await;
}
