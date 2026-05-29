use axum::body::{Body, to_bytes};
use http::{Method, Request, StatusCode, header};
use sdqp_api::{
    ConfigChangeResponse, LoginResponse, LogoutResponse, TokenPairResponse, build_router,
};
use sdqp_test_kit::sample_settings;
use tower::ServiceExt;

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

#[tokio::test]
async fn uat_login_mfa_refresh_and_logout_flow_succeeds() {
    let app = build_router(sample_settings().api);

    let login = json_request(
        app.clone(),
        Method::POST,
        "/auth/login",
        serde_json::json!({
            "username": "sysadmin",
            "password": "password123",
            "device_fingerprint": "device-phase1"
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

    let refresh = json_request(
        app.clone(),
        Method::POST,
        "/auth/refresh",
        serde_json::json!({
            "refresh_token": mfa.refresh_token
        }),
        &[],
    )
    .await;
    assert_eq!(refresh.status(), StatusCode::OK);
    let refresh: TokenPairResponse = decode_json(refresh).await;

    let logout = json_request(
        app,
        Method::POST,
        "/auth/logout",
        serde_json::json!({
            "refresh_token": refresh.refresh_token
        }),
        &[],
    )
    .await;
    assert_eq!(logout.status(), StatusCode::OK);
    let logout: LogoutResponse = decode_json(logout).await;
    assert!(logout.revoked);
}

#[tokio::test]
async fn uat_cross_project_request_is_rejected() {
    let app = build_router(sample_settings().api);

    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            serde_json::json!({
                "username": "analyst",
                "password": "password123",
                "device_fingerprint": "device-phase1"
            }),
            &[("x-forwarded-for", "127.0.0.1")],
        )
        .await,
    )
    .await;
    let tokens: TokenPairResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/mfa/verify",
            serde_json::json!({
                "pending_session_id": login.pending_session_id,
                "code": "000000"
            }),
            &[],
        )
        .await,
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/project-context")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", tokens.access_token),
                )
                .header("x-tenant-id", "tenant-alpha")
                .header("x-project-id", "project-archive")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn uat_config_change_requires_system_admin_and_writes_audit_checkpoint() {
    let app = build_router(sample_settings().api);

    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            serde_json::json!({
                "username": "sysadmin",
                "password": "password123",
                "device_fingerprint": "device-phase1"
            }),
            &[("x-forwarded-for", "127.0.0.1")],
        )
        .await,
    )
    .await;
    let tokens: TokenPairResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/mfa/verify",
            serde_json::json!({
                "pending_session_id": login.pending_session_id,
                "code": "000000"
            }),
            &[],
        )
        .await,
    )
    .await;

    let response = json_request(
        app,
        Method::POST,
        "/v1/admin/config-change",
        serde_json::json!({
            "key": "kms.rotation.interval_days",
            "value": "90"
        }),
        &[
            ("authorization", &format!("Bearer {}", tokens.access_token)),
            ("x-tenant-id", "tenant-alpha"),
        ],
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let payload: ConfigChangeResponse = decode_json(response).await;
    assert!(payload.accepted);
    assert!(!payload.checkpoint_id.is_empty());
    assert!(payload.audit_events >= 3);
}
