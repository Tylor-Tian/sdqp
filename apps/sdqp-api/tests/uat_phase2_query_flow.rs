use std::time::Duration;

use axum::body::{Body, to_bytes};
use futures_util::StreamExt;
use http::{Method, Request, StatusCode, header};
use sdqp_api::{
    LoginResponse, QuerySubmitResponse, QueryTaskStatusResponse, SnapshotMetadataResponse,
    TokenPairResponse, build_router,
};
use sdqp_test_kit::sample_settings;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tower::ServiceExt;

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
                "device_fingerprint": "device-phase2"
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
    for _ in 0..40 {
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

        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    panic!("task {task_id} did not reach terminal state");
}

#[tokio::test]
async fn uat_permission_application_and_encrypted_snapshot_flow_succeeds() {
    let app = build_router(sample_settings().api);
    let tokens = analyst_tokens(app.clone()).await;
    let bearer = format!("Bearer {}", tokens.access_token);

    let application = json_request(
        app.clone(),
        Method::POST,
        "/v1/permissions/applications",
        Some(serde_json::json!({
            "data_source_id": "datasource-rest",
            "requested_fields": ["employee_id"]
        })),
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(application.status(), StatusCode::OK);
    let application: serde_json::Value = decode_json(application).await;
    assert_eq!(application["status"], "Pending");

    let submit = json_request(
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
    .await;
    assert_eq!(submit.status(), StatusCode::OK);
    let submit: QuerySubmitResponse = decode_json(submit).await;

    let status = wait_for_terminal_status(app.clone(), &bearer, &submit.task_id).await;
    assert_eq!(status.state, "completed");
    assert!(!status.cache_hit);
    let snapshot_id = status.snapshot_id.expect("snapshot id");

    let metadata = json_request(
        app,
        Method::GET,
        &format!("/v1/snapshots/{snapshot_id}/metadata"),
        None,
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(metadata.status(), StatusCode::OK);
    let metadata: SnapshotMetadataResponse = decode_json(metadata).await;
    assert!(metadata.encrypted);
    assert!(metadata.storage_key.contains("tenant-alpha/project-alpha"));
    assert_eq!(metadata.data_source_id, "datasource-rest");
    assert!(!metadata.dek_id.is_empty());
}

#[tokio::test]
async fn uat_query_rejects_unauthorized_fields() {
    let app = build_router(sample_settings().api);
    let tokens = analyst_tokens(app.clone()).await;
    let bearer = format!("Bearer {}", tokens.access_token);

    let response = json_request(
        app,
        Method::POST,
        "/v1/queries",
        Some(serde_json::json!({
            "data_source_id": "datasource-rest",
            "source_type": "rest",
            "fields": ["employee_email"]
        })),
        &scoped_headers(&bearer),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn uat_repeat_query_hits_encrypted_snapshot_cache() {
    let app = build_router(sample_settings().api);
    let tokens = analyst_tokens(app.clone()).await;
    let bearer = format!("Bearer {}", tokens.access_token);

    let first_submit: QuerySubmitResponse = decode_json(
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
    let first_status = wait_for_terminal_status(app.clone(), &bearer, &first_submit.task_id).await;
    let first_snapshot = first_status.snapshot_id.expect("snapshot");

    let second_submit: QuerySubmitResponse = decode_json(
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

    let second_status =
        wait_for_terminal_status(app.clone(), &bearer, &second_submit.task_id).await;
    assert_eq!(second_status.state, "completed");
    assert!(second_status.cache_hit);
    assert_eq!(
        second_status.snapshot_id.as_deref(),
        Some(first_snapshot.as_str())
    );
}

#[tokio::test]
async fn uat_long_running_query_can_be_cancelled() {
    let app = build_router(sample_settings().api);
    let tokens = analyst_tokens(app.clone()).await;
    let bearer = format!("Bearer {}", tokens.access_token);

    let submit: QuerySubmitResponse = decode_json(
        json_request(
            app.clone(),
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

    let cancel = json_request(
        app.clone(),
        Method::DELETE,
        &format!("/v1/tasks/{}/cancel", submit.task_id),
        None,
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(cancel.status(), StatusCode::OK);

    tokio::time::sleep(Duration::from_millis(220)).await;
    let status = wait_for_terminal_status(app, &bearer, &submit.task_id).await;
    assert_eq!(status.state, "cancelled");
}

#[tokio::test]
async fn uat_timeout_failures_open_circuit_breaker() {
    let app = build_router(sample_settings().api);
    let tokens = analyst_tokens(app.clone()).await;
    let bearer = format!("Bearer {}", tokens.access_token);

    for attempt in 0..2 {
        let submit: QuerySubmitResponse = decode_json(
            json_request(
                app.clone(),
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
        let status = wait_for_terminal_status(app.clone(), &bearer, &submit.task_id).await;
        assert_eq!(status.state, "failed");
        assert_eq!(
            status.error.as_deref(),
            Some("query timed out"),
            "attempt {attempt}"
        );
    }

    let third_submit: QuerySubmitResponse = decode_json(
        json_request(
            app.clone(),
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
    let third_status = wait_for_terminal_status(app, &bearer, &third_submit.task_id).await;
    assert_eq!(third_status.state, "failed");
    assert_eq!(third_status.error.as_deref(), Some("circuit breaker open"));
}

#[tokio::test]
async fn uat_websocket_stream_receives_query_progress_updates() {
    let app = build_router(sample_settings().api);
    let tokens = analyst_tokens(app.clone()).await;
    let bearer = format!("Bearer {}", tokens.access_token);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server_app = app.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, server_app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server");
    });

    let submit: QuerySubmitResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-hive",
                "source_type": "hive",
                "fields": ["employee_id"],
                "timeout_secs": 1
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;

    let mut request = format!("ws://{address}/v1/tasks/{}/ws", submit.task_id)
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

    let first_message = tokio::time::timeout(Duration::from_secs(1), socket.next())
        .await
        .expect("first message timeout")
        .expect("first message")
        .expect("ws frame");
    let first_text = first_message.into_text().expect("text");
    let first_status: QueryTaskStatusResponse =
        serde_json::from_str(&first_text).expect("status json");
    assert_eq!(first_status.state, "running");

    let second_message = tokio::time::timeout(Duration::from_secs(1), socket.next())
        .await
        .expect("second message timeout")
        .expect("second message")
        .expect("ws frame");
    let second_text = second_message.into_text().expect("text");
    let second_status: QueryTaskStatusResponse =
        serde_json::from_str(&second_text).expect("status json");
    assert_eq!(second_status.state, "completed");
    assert!(second_status.snapshot_id.is_some());

    let _ = socket.close(None).await;
    let _ = shutdown_tx.send(());
    server.await.expect("server join");
}

#[tokio::test]
async fn uat_websocket_stream_accepts_browser_style_query_auth() {
    let app = build_router(sample_settings().api);
    let tokens = analyst_tokens(app.clone()).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server_app = app.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, server_app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server");
    });

    let bearer = format!("Bearer {}", tokens.access_token);
    let submit: QuerySubmitResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-hive",
                "source_type": "hive",
                "fields": ["employee_id"],
                "timeout_secs": 1
            })),
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;

    let request = format!(
        "ws://{address}/v1/tasks/{}/ws?access_token={}&tenant_id=tenant-alpha&project_id=project-alpha",
        submit.task_id, tokens.access_token
    );
    let (mut socket, _) = connect_async(request).await.expect("websocket");

    let first_message = tokio::time::timeout(Duration::from_secs(1), socket.next())
        .await
        .expect("first message timeout")
        .expect("first message")
        .expect("ws frame");
    let first_status: QueryTaskStatusResponse =
        serde_json::from_str(&first_message.into_text().expect("text")).expect("status json");
    assert_eq!(first_status.task_id, submit.task_id);
    assert!(matches!(
        first_status.state.as_str(),
        "running" | "completed"
    ));

    let terminal_status = if first_status.state == "completed" {
        first_status
    } else {
        let second_message = tokio::time::timeout(Duration::from_secs(1), socket.next())
            .await
            .expect("second message timeout")
            .expect("second message")
            .expect("ws frame");
        serde_json::from_str(&second_message.into_text().expect("text")).expect("status json")
    };
    assert_eq!(terminal_status.state, "completed");
    assert!(terminal_status.snapshot_id.is_some());

    let _ = socket.close(None).await;
    let _ = shutdown_tx.send(());
    server.await.expect("server join");
}
