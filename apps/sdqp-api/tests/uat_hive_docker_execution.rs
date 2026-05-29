use std::{path::PathBuf, time::Duration};

use axum::body::{Body, to_bytes};
use chrono::Utc;
use http::{Method, Request, StatusCode, header};
use sdqp_api::{
    AdapterHealthResponse, LoginResponse, QuerySubmitResponse, QueryTaskStatusResponse,
    SnapshotMetadataResponse, TokenPairResponse, build_router,
};
use sdqp_config::AppSettings;
use sdqp_system_security::{MfaProviderConfig, MfaProviderRegistry};
use sdqp_test_kit::sample_settings;
use tower::ServiceExt;

fn hive_docker_enabled() -> bool {
    std::env::var("SDQP_ENABLE_HIVE_DOCKER_TESTS")
        .ok()
        .as_deref()
        == Some("1")
}

fn compose_file() -> String {
    std::env::var("SDQP_HIVE_DOCKER_COMPOSE_FILE").unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("docker-compose.hive.yml")
            .to_string_lossy()
            .to_string()
    })
}

fn hive_service() -> String {
    std::env::var("SDQP_HIVE_DOCKER_SERVICE").unwrap_or_else(|_| "hive-server".into())
}

fn hive_jdbc_url() -> String {
    std::env::var("SDQP_HIVE_DOCKER_JDBC_URL")
        .unwrap_or_else(|_| "jdbc:hive2://127.0.0.1:10000/default".into())
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
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let text = String::from_utf8_lossy(&bytes);
    if !status.is_success() {
        panic!("request failed with status {status}: {text}");
    }
    serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!("json decode failed with status {status}: {error}; body={text}")
    })
}

fn mfa_registry(settings: &AppSettings) -> MfaProviderRegistry {
    MfaProviderRegistry::new(MfaProviderConfig {
        bootstrap_seed: settings.security.mfa_bootstrap_seed.clone(),
        challenge_ttl_secs: settings.security.mfa_challenge_ttl_secs,
        totp: sdqp_system_security::TotpProviderConfig {
            issuer: settings.security.totp_issuer.clone(),
            period_secs: settings.security.totp_period_secs,
            digits: settings.security.totp_digits,
            allowed_drift_steps: settings.security.totp_allowed_drift_steps,
        },
        webauthn: sdqp_system_security::WebAuthnProviderConfig {
            rp_id: settings.security.webauthn_rp_id.clone(),
            origin: settings.security.webauthn_origin.clone(),
            timeout_ms: settings.security.webauthn_timeout_ms,
            challenge_ttl_secs: settings.security.mfa_challenge_ttl_secs,
            require_user_verification: settings.security.webauthn_require_user_verification,
        },
    })
}

fn analyst_totp_code(settings: &AppSettings) -> String {
    mfa_registry(settings).bootstrap_totp_code_at(
        "tenant-alpha",
        "user-analyst",
        "analyst",
        Utc::now(),
    )
}

async fn analyst_tokens(app: axum::Router, settings: &AppSettings) -> TokenPairResponse {
    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            Some(serde_json::json!({
                "username": "analyst",
                "password": "password123",
                "device_fingerprint": "hive-docker-uat"
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
                "code": analyst_totp_code(settings)
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
    for _ in 0..160 {
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

async fn build_hive_app(table: &str, poll_interval_ms: u64) -> (axum::Router, String) {
    let settings = sample_settings();
    let app = build_router(settings.api.clone());
    let tokens = analyst_tokens(app.clone(), &settings).await;
    let bearer = format!("Bearer {}", tokens.access_token);
    let command_args = serde_json::json!([
        "compose",
        "-f",
        compose_file(),
        "exec",
        "-T",
        hive_service(),
        "/opt/hive/bin/beeline",
        "-u",
        hive_jdbc_url(),
        "-n",
        "hive",
        "--outputformat=csv2",
        "--showHeader=false",
        "--silent=true",
        "-e",
        "{sql}"
    ]);

    let register = json_request(
        app.clone(),
        Method::POST,
        "/v1/datasources/adapters",
        Some(serde_json::json!({
            "data_source_id": "datasource-hive",
            "source_type": "hive",
            "connection_uri": hive_jdbc_url(),
            "adapter_config": {
                "provider": "beeline",
                "command": "docker",
                "command_args": command_args,
                "username": "hive",
                "table": table,
                "poll_interval_ms": poll_interval_ms,
                "max_concurrent_tasks": 1
            }
        })),
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(register.status(), StatusCode::OK);

    let start = json_request(
        app.clone(),
        Method::POST,
        "/v1/datasources/adapters/datasource-hive/start",
        None,
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(start.status(), StatusCode::OK);

    let health: AdapterHealthResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/datasources/adapters/health",
            None,
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert!(health.adapters.iter().any(|adapter| {
        adapter.data_source_id == "datasource-hive"
            && format!("{:?}", adapter.availability) == "Available"
    }));

    (app, bearer)
}

#[tokio::test]
async fn uat_docker_hive_provider_covers_success_failure_timeout_and_cancellation() {
    if !hive_docker_enabled() {
        return;
    }

    let (success_app, success_bearer) = build_hive_app("sdqp_fixture_employees", 100).await;
    let submit: QuerySubmitResponse = decode_json(
        json_request(
            success_app.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-hive",
                "source_type": "hive",
                "fields": ["employee_id", "department"],
                "timeout_secs": 30
            })),
            &scoped_headers(&success_bearer),
        )
        .await,
    )
    .await;
    let status =
        wait_for_terminal_status(success_app.clone(), &success_bearer, &submit.task_id).await;
    assert_eq!(status.state, "completed");
    let snapshot_id = status.snapshot_id.expect("snapshot");
    let metadata: SnapshotMetadataResponse = decode_json(
        json_request(
            success_app,
            Method::GET,
            &format!("/v1/snapshots/{snapshot_id}/metadata"),
            None,
            &scoped_headers(&success_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(metadata.data_source_id, "datasource-hive");
    assert_eq!(metadata.row_count, 3);

    let (failure_app, failure_bearer) = build_hive_app("sdqp_missing_table", 100).await;
    let failure_submit: QuerySubmitResponse = decode_json(
        json_request(
            failure_app.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-hive",
                "source_type": "hive",
                "fields": ["employee_id"],
                "timeout_secs": 30
            })),
            &scoped_headers(&failure_bearer),
        )
        .await,
    )
    .await;
    let failure_status =
        wait_for_terminal_status(failure_app, &failure_bearer, &failure_submit.task_id).await;
    assert_eq!(failure_status.state, "failed");
    assert!(
        failure_status
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("Hive JDBC command failed")
    );

    let (timeout_app, timeout_bearer) = build_hive_app("sdqp_fixture_employees", 5_000).await;
    let timeout_submit: QuerySubmitResponse = decode_json(
        json_request(
            timeout_app.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-hive",
                "source_type": "hive",
                "fields": ["employee_id"],
                "timeout_secs": 0
            })),
            &scoped_headers(&timeout_bearer),
        )
        .await,
    )
    .await;
    let timeout_status =
        wait_for_terminal_status(timeout_app, &timeout_bearer, &timeout_submit.task_id).await;
    assert_eq!(timeout_status.state, "failed");
    assert_eq!(timeout_status.error.as_deref(), Some("query timed out"));

    let (cancel_app, cancel_bearer) = build_hive_app("sdqp_fixture_employees", 5_000).await;
    let cancel_submit: QuerySubmitResponse = decode_json(
        json_request(
            cancel_app.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-hive",
                "source_type": "hive",
                "fields": ["employee_id"],
                "timeout_secs": 30
            })),
            &scoped_headers(&cancel_bearer),
        )
        .await,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let cancel_response = json_request(
        cancel_app.clone(),
        Method::DELETE,
        &format!("/v1/tasks/{}/cancel", cancel_submit.task_id),
        None,
        &scoped_headers(&cancel_bearer),
    )
    .await;
    assert_eq!(cancel_response.status(), StatusCode::OK);
    let cancelled =
        wait_for_terminal_status(cancel_app, &cancel_bearer, &cancel_submit.task_id).await;
    assert_eq!(cancelled.state, "cancelled");
}
