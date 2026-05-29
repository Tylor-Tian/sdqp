use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use axum::body::{Body, to_bytes};
use futures_util::future::join_all;
use http::{Method, Request, StatusCode, header};
use sdqp_api::{AuditSearchResponse, LoginResponse, TokenPairResponse, build_router};
use sdqp_test_kit::sample_settings;
use serde::Deserialize;
use tower::ServiceExt;

#[derive(Debug, Deserialize)]
struct AuditSearchFixture {
    action: Option<String>,
    result: Option<String>,
    actor_user_id: Option<String>,
    resource_id_contains: Option<String>,
    include_projectless: Option<bool>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AuditSearchBudgetFixture {
    event_requests: usize,
    search_iterations: usize,
    limit: usize,
    max_duration_ms: u64,
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

fn scoped_headers(token: &str) -> [(&str, &str); 3] {
    [
        ("authorization", token),
        ("x-tenant-id", "tenant-alpha"),
        ("x-project-id", "project-alpha"),
    ]
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("phase7")
        .join(name)
}

fn load_search_fixture() -> AuditSearchFixture {
    serde_json::from_str(
        &fs::read_to_string(fixture_path("audit-search-query.json")).expect("fixture"),
    )
    .expect("search fixture")
}

fn load_budget_fixture() -> AuditSearchBudgetFixture {
    serde_json::from_str(
        &fs::read_to_string(fixture_path("audit-search-budget.json")).expect("fixture"),
    )
    .expect("budget fixture")
}

fn build_search_uri(fixture: &AuditSearchFixture, limit_override: Option<usize>) -> String {
    let mut params = Vec::new();
    if let Some(action) = &fixture.action {
        params.push(format!("action={action}"));
    }
    if let Some(result) = &fixture.result {
        params.push(format!("result={result}"));
    }
    if let Some(actor_user_id) = &fixture.actor_user_id {
        params.push(format!("actor_user_id={actor_user_id}"));
    }
    if let Some(resource_id_contains) = &fixture.resource_id_contains {
        params.push(format!("resource_id_contains={resource_id_contains}"));
    }
    if let Some(include_projectless) = fixture.include_projectless {
        params.push(format!("include_projectless={include_projectless}"));
    }

    let limit = limit_override.or(fixture.limit).unwrap_or(10);
    params.push(format!("limit={limit}"));
    format!("/v1/audit/events/search?{}", params.join("&"))
}

async fn create_project_context_events(app: axum::Router, bearer: &str, count: usize) {
    for _ in 0..count {
        let response = json_request(
            app.clone(),
            Method::GET,
            "/v1/project-context",
            None,
            &scoped_headers(bearer),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn uat_audit_search_requires_system_admin_role() {
    let app = build_router(sample_settings().api);
    let analyst_tokens = login_tokens(app.clone(), "analyst", "device-phase7-analyst").await;
    let analyst_bearer = format!("Bearer {}", analyst_tokens.access_token);

    let response = json_request(
        app,
        Method::GET,
        &build_search_uri(&load_search_fixture(), None),
        None,
        &scoped_headers(&analyst_bearer),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn uat_system_admin_can_search_scoped_audit_events() {
    let app = build_router(sample_settings().api);
    let analyst_tokens = login_tokens(app.clone(), "analyst", "device-phase7-analyst").await;
    let analyst_bearer = format!("Bearer {}", analyst_tokens.access_token);
    create_project_context_events(app.clone(), &analyst_bearer, 3).await;

    let admin_tokens = login_tokens(app.clone(), "sysadmin", "device-phase7-admin").await;
    let admin_bearer = format!("Bearer {}", admin_tokens.access_token);

    let response = json_request(
        app,
        Method::GET,
        &build_search_uri(&load_search_fixture(), None),
        None,
        &scoped_headers(&admin_bearer),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let payload: AuditSearchResponse = decode_json(response).await;
    assert!(payload.chain_valid);
    assert!(payload.total_matches >= 3);
    assert!(payload.events.len() >= 3);
    assert!(
        payload
            .events
            .iter()
            .all(|event| event.actor_user_id == "user-analyst")
    );
    assert!(
        payload
            .events
            .iter()
            .all(|event| event.resource_id == "project-context")
    );
    assert!(
        payload
            .events
            .iter()
            .all(|event| event.project_id.as_deref() == Some("project-alpha"))
    );
}

#[tokio::test]
async fn uat_security_headers_are_applied_to_api_responses() {
    let app = build_router(sample_settings().api);
    let analyst_tokens = login_tokens(app.clone(), "analyst", "device-phase7-security").await;
    let analyst_bearer = format!("Bearer {}", analyst_tokens.access_token);

    let response = json_request(
        app,
        Method::GET,
        "/v1/project-context",
        None,
        &scoped_headers(&analyst_bearer),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        response
            .headers()
            .get("x-frame-options")
            .and_then(|value| value.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        response
            .headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
    );
}

#[tokio::test]
async fn perf_smoke_audit_search_stays_within_budget() {
    let budget = load_budget_fixture();
    let search = load_search_fixture();
    let app = build_router(sample_settings().api);

    let analyst_tokens = login_tokens(app.clone(), "analyst", "device-phase7-perf-analyst").await;
    let analyst_bearer = format!("Bearer {}", analyst_tokens.access_token);
    create_project_context_events(app.clone(), &analyst_bearer, budget.event_requests).await;

    let admin_tokens = login_tokens(app.clone(), "sysadmin", "device-phase7-perf-admin").await;
    let admin_bearer = format!("Bearer {}", admin_tokens.access_token);
    let uri = build_search_uri(&search, Some(budget.limit));

    let started = Instant::now();
    for _ in 0..budget.search_iterations {
        let response = json_request(
            app.clone(),
            Method::GET,
            &uri,
            None,
            &scoped_headers(&admin_bearer),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let elapsed = started.elapsed();

    assert!(
        elapsed <= Duration::from_millis(budget.max_duration_ms),
        "audit search exceeded performance budget: {:?}",
        elapsed
    );
}

#[tokio::test]
async fn concurrent_project_context_reads_keep_audit_chain_valid() {
    let app = build_router(sample_settings().api);
    let analyst_tokens =
        login_tokens(app.clone(), "analyst", "device-phase7-concurrent-analyst").await;
    let analyst_bearer = format!("Bearer {}", analyst_tokens.access_token);

    let responses = join_all((0..16).map(|_| {
        let app = app.clone();
        let analyst_bearer = analyst_bearer.clone();
        async move {
            let headers = scoped_headers(&analyst_bearer);
            json_request(app, Method::GET, "/v1/project-context", None, &headers).await
        }
    }))
    .await;
    assert!(
        responses
            .iter()
            .all(|response| response.status() == StatusCode::OK)
    );

    let admin_tokens =
        login_tokens(app.clone(), "sysadmin", "device-phase7-concurrent-admin").await;
    let admin_bearer = format!("Bearer {}", admin_tokens.access_token);
    let response = json_request(
        app,
        Method::GET,
        "/v1/audit/events/search?action=view&actor_user_id=user-analyst&resource_id_contains=project-context&limit=50",
        None,
        &scoped_headers(&admin_bearer),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let payload: AuditSearchResponse = decode_json(response).await;
    assert!(payload.chain_valid);
    assert!(payload.total_matches >= 16);
}
