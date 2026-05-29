use std::time::Duration;

use axum::{
    Json,
    body::{Body, Bytes, to_bytes},
    extract::State,
    http::HeaderMap,
    routing::post,
};
use http::{Method, Request, StatusCode, header};
use sdqp_api::{
    EvidenceExportResponse, ExportDownloadAuthorizationResponse, LoginResponse,
    QuerySubmitResponse, QueryTaskStatusResponse, TokenPairResponse, build_persistent_router,
};
use sdqp_config::AppSettings;
use sdqp_evidence::{
    AnchorParams, AnchorResult, JsonRpcRequest, JsonRpcResponse, build_rfc3161_reply,
    ethereum_anchor_proof, parse_rfc3161_query,
};
use sha2::{Digest, Sha256};
use sqlx::{Executor, Row};
use sqlx_postgres::PgPoolOptions;
use tower::ServiceExt;

fn stage10_enabled() -> bool {
    std::env::var("SDQP_ENABLE_STAGE10_TESTS").ok().as_deref() == Some("1")
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

#[derive(Clone)]
struct TsaServerState {
    authority: String,
    api_key: String,
}

#[derive(Clone)]
struct AnchorServerState {
    api_key: String,
}

async fn spawn_tsa_server(authority: &str, api_key: &str) -> String {
    async fn handler(
        State(state): State<TsaServerState>,
        headers: HeaderMap,
        body: Bytes,
    ) -> http::Response<Body> {
        assert_eq!(
            headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/timestamp-query")
        );
        assert_eq!(
            headers
                .get("x-api-key")
                .and_then(|value| value.to_str().ok()),
            Some(state.api_key.as_str())
        );

        let query = parse_rfc3161_query(&body).expect("rfc3161 query");
        let reply = build_rfc3161_reply(&query, &state.authority, &state.api_key).expect("reply");

        http::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/timestamp-reply")
            .body(Body::from(reply))
            .expect("tsa response")
    }

    let state = TsaServerState {
        authority: authority.into(),
        api_key: api_key.into(),
    };
    let app = axum::Router::new()
        .route("/", post(handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("tsa bind");
    let addr = listener.local_addr().expect("tsa addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("tsa server");
    });
    format!("http://{addr}/")
}

async fn spawn_anchor_server(api_key: &str) -> String {
    async fn handler(
        State(state): State<AnchorServerState>,
        headers: HeaderMap,
        Json(request): Json<JsonRpcRequest<AnchorParams>>,
    ) -> Json<JsonRpcResponse<AnchorResult>> {
        assert_eq!(
            headers
                .get("x-api-key")
                .and_then(|value| value.to_str().ok()),
            Some(state.api_key.as_str())
        );
        let method = request.method.to_ascii_lowercase();
        let result = if method.contains("anchordigest") {
            let anchored_at = chrono::Utc::now();
            let network = request.params.network;
            let digest = request.params.digest;
            let transaction_id = format!(
                "0x{}",
                hex::encode(Sha256::digest(
                    format!(
                        "{}|{}|{}|{}",
                        network,
                        digest,
                        anchored_at.to_rfc3339(),
                        state.api_key
                    )
                    .as_bytes()
                ))
            );
            AnchorResult {
                transaction_id,
                anchored_at,
                status: "pending".into(),
                block_number: None,
                proof: None,
                confirmed_at: None,
                failure_reason: None,
                network,
                digest,
            }
        } else if method.contains("getreceipt") || method.contains("getanchorreceipt") {
            let confirmed_at = chrono::Utc::now();
            let network = request.params.network;
            let digest = request.params.digest;
            let transaction_id = request
                .params
                .transaction_id
                .expect("transaction id for receipt lookup");
            AnchorResult {
                proof: Some(ethereum_anchor_proof(
                    &network,
                    &digest,
                    &transaction_id,
                    confirmed_at,
                    &state.api_key,
                )),
                transaction_id,
                anchored_at: confirmed_at,
                status: "confirmed".into(),
                block_number: Some(123_456),
                confirmed_at: Some(confirmed_at),
                failure_reason: None,
                network,
                digest,
            }
        } else {
            panic!("unexpected anchor method {}", request.method);
        };

        Json(JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: request.id,
            error: None,
            result: Some(result),
        })
    }

    let app = axum::Router::new()
        .route("/", post(handler))
        .with_state(AnchorServerState {
            api_key: api_key.into(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("anchor bind");
    let addr = listener.local_addr().expect("anchor addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("anchor server");
    });
    format!("http://{addr}/")
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

async fn user_tokens(app: axum::Router, username: &str) -> TokenPairResponse {
    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            Some(serde_json::json!({
                "username": username,
                "password": "password123",
                "device_fingerprint": format!("stage10-{username}")
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
    app: axum::Router,
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

#[tokio::test]
async fn uat_stage10_export_tasks_download_authorization_and_persistence() {
    if !stage10_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage10_api_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let tsa_authority = "stage10-ntsc-tsa";
    let tsa_api_key = "stage10-tsa-key";
    let blockchain_network = "fabric-stage10";
    let blockchain_api_key = "stage10-anchor-key";
    let tsa_url = spawn_tsa_server(tsa_authority, tsa_api_key).await;
    let anchor_url = spawn_anchor_server(blockchain_api_key).await;

    let mut settings = test_settings(&database_name);
    settings.integrations.tsa.provider = "ntsc".into();
    settings.integrations.tsa.base_url = tsa_url;
    settings.integrations.tsa.api_key = tsa_api_key.into();
    settings.integrations.tsa.authority = tsa_authority.into();
    settings.integrations.blockchain_anchor.provider = "fabric".into();
    settings.integrations.blockchain_anchor.base_url = anchor_url;
    settings.integrations.blockchain_anchor.api_key = blockchain_api_key.into();
    settings.integrations.blockchain_anchor.network = blockchain_network.into();
    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent router");

    let analyst = user_tokens(app.clone(), "analyst").await;
    let bearer = format!("Bearer {}", analyst.access_token);

    let submit: QuerySubmitResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "source_type": "rest",
                "fields": ["employee_id"]
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    let completed = wait_for_task_state(app.clone(), &bearer, &submit.task_id, "completed").await;
    let snapshot_id = completed.snapshot_id.expect("snapshot id");

    let export: EvidenceExportResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/exports/evidence",
            Some(serde_json::json!({
                "snapshot_id": snapshot_id,
                "template": "eu"
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert_eq!(export.status, "pending_anchor");
    assert!(!export.download_ready);
    assert!(!export.verification_ready);
    assert!(!export.verified);
    assert!(export.integrity_verified);
    assert_eq!(export.verification_status, "pending_anchor");
    assert_eq!(export.jurisdiction, "European Union");
    assert!(!export.hash_chain_digest.is_empty());
    assert_eq!(export.timestamp_provider, "ntsc");
    assert_eq!(export.timestamp_authority, tsa_authority);
    assert_eq!(export.anchor_provider, "fabric");
    assert_eq!(export.anchor_status, "pending");
    assert_eq!(export.anchor_network, blockchain_network);
    assert!(export.anchor_transaction_id.starts_with("0x"));
    assert_eq!(export.anchor_block_number, None);
    assert_eq!(export.provider_runtime_mode, "external");
    assert!(export.external_final_uat_required);
    assert!(export.refresh_recommended);
    assert_eq!(export.recipient_user_id, "user-analyst");
    assert_eq!(export.audit_extract_event_count, export.audit_event_count);

    let early_download = json_request(
        app.clone(),
        Method::POST,
        &format!("/v1/exports/tasks/{}/authorize-download", export.task_id),
        Some(serde_json::json!({
            "ttl_seconds": 300
        })),
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(early_download.status(), StatusCode::CONFLICT);

    let refreshed: EvidenceExportResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            &format!("/v1/exports/tasks/{}/refresh-anchor", export.task_id),
            None,
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert_eq!(refreshed.status, "completed");
    assert_eq!(refreshed.anchor_status, "confirmed");
    assert_eq!(refreshed.anchor_block_number, Some(123_456));
    assert!(refreshed.anchor_confirmed_at.is_some());
    assert!(refreshed.verified);
    assert!(refreshed.verification_ready);
    assert!(refreshed.download_ready);
    assert_eq!(refreshed.verification_status, "verified");
    assert!(!refreshed.refresh_recommended);

    let download_auth: ExportDownloadAuthorizationResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            &format!("/v1/exports/tasks/{}/authorize-download", refreshed.task_id),
            Some(serde_json::json!({
                "ttl_seconds": 300
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;

    let download = json_request(
        app.clone(),
        Method::GET,
        &format!("/v1/exports/download/{}", download_auth.download_token),
        None,
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(download.status(), StatusCode::OK);
    let downloaded = String::from_utf8(
        to_bytes(download.into_body(), usize::MAX)
            .await
            .expect("download body")
            .to_vec(),
    )
    .expect("download text");
    let downloaded: serde_json::Value =
        serde_json::from_str(&downloaded).expect("downloaded package json");
    assert_eq!(
        downloaded["package_id"].as_str(),
        Some(export.package_id.as_str())
    );
    assert_eq!(
        downloaded["data_payload"]["recipient"]["user_id"].as_str(),
        Some("user-analyst")
    );

    let replay = json_request(
        app.clone(),
        Method::GET,
        &format!("/v1/exports/download/{}", download_auth.download_token),
        None,
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::CONFLICT);

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&settings.database.postgres.dsn)
        .await
        .expect("postgres");

    let evidence_row = sqlx::query(
        r#"
        SELECT task_id, template, file_name, media_type, package_json
        FROM evidence_packages
        WHERE package_id = $1
        "#,
    )
    .bind(&export.package_id)
    .fetch_one(&pool)
    .await
    .expect("evidence package row");
    assert_eq!(
        evidence_row
            .try_get::<String, _>("task_id")
            .expect("task id"),
        export.task_id
    );
    assert_eq!(
        evidence_row
            .try_get::<String, _>("template")
            .expect("template"),
        export.template
    );
    let package_json: serde_json::Value = evidence_row
        .try_get::<sqlx::types::Json<serde_json::Value>, _>("package_json")
        .expect("package json")
        .0;
    assert_eq!(
        package_json["timestamp_receipt"]["provider"].as_str(),
        Some("ntsc")
    );
    assert_eq!(
        package_json["anchor_receipt"]["provider"].as_str(),
        Some("fabric")
    );
    assert_eq!(
        package_json["anchor_receipt"]["status"].as_str(),
        Some("confirmed")
    );
    assert_eq!(
        package_json["anchor_receipt"]["block_number"].as_u64(),
        Some(123_456)
    );
    assert_eq!(
        package_json["manifest"]["verification_status"].as_str(),
        Some("verified")
    );
    assert_eq!(
        package_json["provider_runtime"]["overall_mode"].as_str(),
        Some("external")
    );
    assert!(
        package_json["certificate_of_authenticity"]["serial_number"]
            .as_str()
            .is_some()
    );
    assert!(package_json["metadata_manifest"].is_object());
    assert!(package_json["hash_chain"]["final_digest"].is_string());
    assert!(package_json["jurisdiction_marker"]["standards"].is_array());
    assert!(package_json["manifest"]["metadata_manifest_digest"].is_string());
    assert!(package_json["manifest"]["hash_chain_digest"].is_string());

    let export_task_row = sqlx::query(
        r#"
        SELECT status, package_id, payload_json, verification_status, provider_runtime_mode, refresh_recommended
        FROM export_tasks
        WHERE task_id = $1
        "#,
    )
    .bind(&refreshed.task_id)
    .fetch_one(&pool)
    .await
    .expect("export task row");
    assert_eq!(
        export_task_row
            .try_get::<String, _>("status")
            .expect("status"),
        "completed"
    );
    assert_eq!(
        export_task_row
            .try_get::<String, _>("package_id")
            .expect("package id"),
        export.package_id
    );
    let export_payload: serde_json::Value = export_task_row
        .try_get::<sqlx::types::Json<serde_json::Value>, _>("payload_json")
        .expect("payload json")
        .0;
    assert_eq!(export_payload["anchor_status"].as_str(), Some("confirmed"));
    assert_eq!(export_payload["anchor_provider"].as_str(), Some("fabric"));
    assert_eq!(
        export_task_row
            .try_get::<String, _>("verification_status")
            .expect("verification status"),
        "verified"
    );
    assert_eq!(
        export_task_row
            .try_get::<String, _>("provider_runtime_mode")
            .expect("provider runtime mode"),
        "external"
    );
    assert!(
        !export_task_row
            .try_get::<bool, _>("refresh_recommended")
            .expect("refresh recommended")
    );

    let auth_row = sqlx::query(
        r#"
        SELECT consumed_at
        FROM download_authorizations
        WHERE download_token = $1
        "#,
    )
    .bind(&download_auth.download_token)
    .fetch_one(&pool)
    .await
    .expect("download auth row");
    assert!(
        auth_row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("consumed_at")
            .expect("consumed_at")
            .is_some()
    );

    drop_database(&database_name).await;
}
