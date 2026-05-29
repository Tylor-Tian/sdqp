use axum::body::{Body, to_bytes};
use http::{Method, Request, StatusCode, header};
use sdqp_core::{RequestContext, TenantId, UserId};
use sdqp_system_security::{SessionBinding, SessionPolicy, issue_access_token};
use sdqp_worker::{WorkerProjectResponse, build_router};
use tower::ServiceExt;

fn worker_token() -> String {
    let request = RequestContext::new(
        TenantId::new("tenant-alpha").expect("tenant"),
        UserId::new("user-analyst").expect("user"),
    );
    let claims = SessionPolicy { ttl_minutes: 15 }.issue(
        &request,
        SessionBinding {
            ip_address: "127.0.0.1".into(),
            device_fingerprint: "device-worker".into(),
        },
    );
    issue_access_token(&claims, "sdqp-phase1-dev-secret").expect("token")
}

#[tokio::test]
async fn uat_worker_business_route_requires_scope_and_returns_audited_response() {
    let app = build_router(sdqp_config::AppSettings::local_dev().worker);
    let response = app
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
    assert!(payload.audit_chain_valid);
}

#[tokio::test]
async fn uat_worker_rejects_cross_project_scope() {
    let app = build_router(sdqp_config::AppSettings::local_dev().worker);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/worker/project-queue")
                .header(header::AUTHORIZATION, format!("Bearer {}", worker_token()))
                .header("x-tenant-id", "tenant-alpha")
                .header("x-project-id", "project-missing")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn uat_worker_metrics_expose_prometheus_counters_and_request_headers() {
    let app = build_router(sdqp_config::AppSettings::local_dev().worker);

    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/healthz")
                .header("x-request-id", "worker-fixed")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(
        health
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some("worker-fixed")
    );
    assert!(health.headers().contains_key("x-sdqp-span-id"));

    let metrics = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/metrics")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(metrics.status(), StatusCode::OK);
    let bytes = to_bytes(metrics.into_body(), usize::MAX)
        .await
        .expect("body");
    let body = String::from_utf8(bytes.to_vec()).expect("utf8");
    assert!(body.contains("sdqp_http_requests_total{service=\"sdqp-worker\"} 1"));
    assert!(body.contains("sdqp_http_responses_2xx_total{service=\"sdqp-worker\"} 1"));
}
