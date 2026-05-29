use axum::body::{Body, to_bytes};
use http::{Method, Request, StatusCode, header};
use sdqp_api::build_router;
use sdqp_test_kit::sample_settings;
use tower::ServiceExt;

async fn text_body(response: http::Response<Body>) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf8")
}

#[tokio::test]
async fn uat_api_metrics_expose_prometheus_counters() {
    let app = build_router(sample_settings().api);

    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/healthz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(health.status(), StatusCode::OK);

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
    let body = text_body(metrics).await;
    assert!(body.contains("sdqp_http_requests_total{service=\"sdqp-api\"} 1"));
    assert!(body.contains("sdqp_http_responses_2xx_total{service=\"sdqp-api\"} 1"));
}

#[tokio::test]
async fn uat_api_responses_include_request_and_span_headers() {
    let app = build_router(sample_settings().api);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/healthz")
                .header("x-request-id", "req-fixed")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some("req-fixed")
    );
    assert!(response.headers().contains_key("x-sdqp-span-id"));
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}
