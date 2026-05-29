use axum::body::{Body, to_bytes};
use base64::Engine as _;
use http::{Method, Request, StatusCode, header};
use sdqp_api::{
    AnalysisTemplateDeleteResponse, AnalysisTemplateListResponse, AnalysisTemplateResponse,
    DrilldownRequest, LoginResponse, PivotAnalysisArrowMetadata, PivotAnalysisResponse,
    QuerySubmitResponse, QueryTaskStatusResponse, SnapshotPageArrowMetadata, SnapshotPageResponse,
    TokenPairResponse, build_router,
};
use sdqp_test_kit::sample_settings;
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

async fn decode_arrow_rows(
    response: http::Response<Body>,
) -> (
    http::HeaderMap,
    Vec<std::collections::HashMap<String, String>>,
) {
    use arrow::array::Array;

    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let reader = std::io::Cursor::new(bytes.to_vec());
    let mut stream = arrow::ipc::reader::StreamReader::try_new(reader, None).expect("stream");
    let batches = stream
        .by_ref()
        .collect::<Result<Vec<_>, _>>()
        .expect("batches");
    let mut rows = Vec::new();
    for batch in batches {
        let schema = batch.schema();
        for row_index in 0..batch.num_rows() {
            let mut row = std::collections::HashMap::new();
            for (column_index, field) in schema.fields().iter().enumerate() {
                let value = batch
                    .column(column_index)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .map(|array| {
                        if array.is_null(row_index) {
                            String::new()
                        } else {
                            array.value(row_index).to_string()
                        }
                    })
                    .or_else(|| {
                        batch
                            .column(column_index)
                            .as_any()
                            .downcast_ref::<arrow::array::Float64Array>()
                            .map(|array| array.value(row_index).to_string())
                    })
                    .or_else(|| {
                        batch
                            .column(column_index)
                            .as_any()
                            .downcast_ref::<arrow::array::UInt64Array>()
                            .map(|array| array.value(row_index).to_string())
                    })
                    .or_else(|| {
                        batch
                            .column(column_index)
                            .as_any()
                            .downcast_ref::<arrow::array::Int64Array>()
                            .map(|array| array.value(row_index).to_string())
                    })
                    .expect("supported arrow type");
                row.insert(field.name().to_string(), value);
            }
            rows.push(row);
        }
    }

    (headers, rows)
}

async fn analyst_token(app: axum::Router) -> String {
    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            Some(serde_json::json!({
                "username": "analyst",
                "password": "password123",
                "device_fingerprint": "device-phase4"
            })),
            &[("x-forwarded-for", "127.0.0.1")],
        )
        .await,
    )
    .await;

    let tokens: TokenPairResponse = decode_json(
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
    .await;

    format!("Bearer {}", tokens.access_token)
}

fn scoped_headers(token: &str) -> [(&str, &str); 3] {
    [
        ("authorization", token),
        ("x-tenant-id", "tenant-alpha"),
        ("x-project-id", "project-alpha"),
    ]
}

async fn wait_for_snapshot_id(app: axum::Router, token: &str) -> String {
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
            &scoped_headers(token),
        )
        .await,
    )
    .await;

    for _ in 0..20 {
        let status: QueryTaskStatusResponse = decode_json(
            json_request(
                app.clone(),
                Method::GET,
                &format!("/v1/tasks/{}/status", submit.task_id),
                None,
                &scoped_headers(token),
            )
            .await,
        )
        .await;

        if status.state == "completed" {
            return status.snapshot_id.expect("snapshot id");
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    panic!("query did not complete in time");
}

#[tokio::test]
async fn uat_snapshot_page_returns_masked_display_rows_and_watermark_metadata() {
    let app = build_router(sample_settings().api);
    let token = analyst_token(app.clone()).await;
    let snapshot_id = wait_for_snapshot_id(app.clone(), &token).await;

    let response = json_request(
        app,
        Method::GET,
        &format!("/v1/snapshots/{snapshot_id}/page?page_size=1"),
        None,
        &scoped_headers(&token),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let page: SnapshotPageResponse = decode_json(response).await;
    assert_eq!(page.snapshot_id, snapshot_id);
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.next_cursor, None);
    assert!(page.columns.contains(&"employee_id".to_string()));
    assert!(page.columns.contains(&"department".to_string()));
    assert!(
        page.field_policies
            .iter()
            .all(|policy| policy.render_mode == "canvas")
    );
    assert_eq!(
        page.watermark_text,
        "tenant-alpha / project-alpha / user-analyst"
    );
}

#[tokio::test]
async fn uat_pivot_analysis_and_drilldown_recheck_permissions() {
    let app = build_router(sample_settings().api);
    let token = analyst_token(app.clone()).await;
    let snapshot_id = wait_for_snapshot_id(app.clone(), &token).await;

    let pivot: PivotAnalysisResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/analysis/pivot",
            Some(serde_json::json!({
                "snapshot_id": snapshot_id,
                "dimension": "department",
                "metric": "count_distinct",
                "metric_field": "employee_id"
            })),
            &scoped_headers(&token),
        )
        .await,
    )
    .await;

    assert_eq!(pivot.metric, "count_distinct");
    assert_eq!(pivot.metric_field.as_deref(), Some("employee_id"));
    assert_eq!(pivot.buckets.len(), 1);
    assert!(
        pivot
            .buckets
            .iter()
            .any(|bucket| bucket.key == "fraud" && bucket.value == 1.0)
    );

    let drilldown = json_request(
        app.clone(),
        Method::POST,
        "/v1/analysis/pivot/drilldown",
        Some(
            serde_json::to_value(DrilldownRequest {
                snapshot_id: snapshot_id.clone(),
                dimension: "department".into(),
                value: "fraud".into(),
                fields: vec!["employee_id".into(), "department".into()],
                page_size: Some(10),
                cursor: None,
            })
            .expect("json"),
        ),
        &scoped_headers(&token),
    )
    .await;
    assert_eq!(drilldown.status(), StatusCode::OK);
    let drilldown: SnapshotPageResponse = decode_json(drilldown).await;
    assert_eq!(drilldown.rows.len(), 1);
    assert_eq!(
        drilldown.rows[0].get("department").map(String::as_str),
        Some("fraud")
    );

    let unauthorized = json_request(
        app,
        Method::POST,
        "/v1/analysis/pivot/drilldown",
        Some(
            serde_json::to_value(DrilldownRequest {
                snapshot_id,
                dimension: "department".into(),
                value: "fraud".into(),
                fields: vec!["employee_email".into()],
                page_size: Some(10),
                cursor: None,
            })
            .expect("json"),
        ),
        &scoped_headers(&token),
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn uat_snapshot_page_supports_arrow_ipc_output() {
    let app = build_router(sample_settings().api);
    let token = analyst_token(app.clone()).await;
    let snapshot_id = wait_for_snapshot_id(app.clone(), &token).await;

    let response = json_request(
        app,
        Method::GET,
        &format!("/v1/snapshots/{snapshot_id}/page?page_size=1&response_format=arrow_ipc"),
        None,
        &scoped_headers(&token),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let metadata = response
        .headers()
        .get("x-sdqp-response-meta")
        .and_then(|value| value.to_str().ok())
        .expect("metadata header");
    let metadata: SnapshotPageArrowMetadata = serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(metadata)
            .expect("decode metadata"),
    )
    .expect("metadata json");
    assert_eq!(metadata.snapshot_id, snapshot_id);

    let (headers, rows) = decode_arrow_rows(response).await;
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/vnd.apache.arrow.stream")
    );
    assert_eq!(rows.len(), 1);
    assert!(rows[0].contains_key("employee_id"));
}

#[tokio::test]
async fn uat_pivot_analysis_supports_arrow_ipc_output() {
    let app = build_router(sample_settings().api);
    let token = analyst_token(app.clone()).await;
    let snapshot_id = wait_for_snapshot_id(app.clone(), &token).await;

    let response = json_request(
        app,
        Method::POST,
        "/v1/analysis/pivot",
        Some(serde_json::json!({
            "snapshot_id": snapshot_id,
            "dimension": "department",
            "metric": "count_distinct",
            "metric_field": "employee_id",
            "response_format": "arrow_ipc"
        })),
        &scoped_headers(&token),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let metadata = response
        .headers()
        .get("x-sdqp-response-meta")
        .and_then(|value| value.to_str().ok())
        .expect("metadata header");
    let metadata: PivotAnalysisArrowMetadata = serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(metadata)
            .expect("decode metadata"),
    )
    .expect("metadata json");
    assert_eq!(metadata.metric, "count_distinct");

    let (headers, rows) = decode_arrow_rows(response).await;
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/vnd.apache.arrow.stream")
    );
    assert!(rows.iter().any(|row| {
        row.get("bucket_key").map(String::as_str) == Some("fraud")
            && row.get("metric_value").map(String::as_str) == Some("1")
    }));
}

#[tokio::test]
async fn uat_analysis_templates_support_private_publish_and_delete_flows() {
    let app = build_router(sample_settings().api);
    let token = analyst_token(app.clone()).await;
    let _snapshot_id = wait_for_snapshot_id(app.clone(), &token).await;

    let created = json_request(
        app.clone(),
        Method::POST,
        "/v1/analysis/templates",
        Some(serde_json::json!({
            "name": "Fraud triage",
            "description": "Default fraud workspace",
            "data_source_id": "datasource-rest",
            "config": {
                "page_size": 2,
                "detail_fields": ["employee_id", "department"],
                "pivot_dimension": "department",
                "pivot_metric": "record_count",
                "pivot_metric_field": null,
                "pivot_percentile": null
            }
        })),
        &scoped_headers(&token),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: AnalysisTemplateResponse = decode_json(created).await;
    assert_eq!(created.name, "Fraud triage");
    assert_eq!(
        created.visibility,
        sdqp_api::AnalysisTemplateVisibility::Private
    );
    assert!(created.editable);

    let listed: AnalysisTemplateListResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/analysis/templates",
            None,
            &scoped_headers(&token),
        )
        .await,
    )
    .await;
    assert_eq!(listed.templates.len(), 1);
    assert_eq!(listed.templates[0].template_id, created.template_id);

    let updated: AnalysisTemplateResponse = decode_json(
        json_request(
            app.clone(),
            Method::PUT,
            &format!("/v1/analysis/templates/{}", created.template_id),
            Some(serde_json::json!({
                "name": "Fraud triage v2",
                "description": "Escalation-first fraud workspace",
                "data_source_id": "datasource-rest",
                "config": {
                    "page_size": 5,
                    "detail_fields": ["employee_id", "department"],
                    "pivot_dimension": "department",
                    "pivot_metric": "count_distinct",
                    "pivot_metric_field": "employee_id",
                    "pivot_percentile": null
                }
            })),
            &scoped_headers(&token),
        )
        .await,
    )
    .await;
    assert_eq!(updated.name, "Fraud triage v2");
    assert_eq!(updated.config.page_size, Some(5));
    assert_eq!(
        updated.config.pivot_metric,
        sdqp_api::PivotMetricKind::CountDistinct
    );
    assert_eq!(
        updated.config.pivot_metric_field.as_deref(),
        Some("employee_id")
    );

    let published: AnalysisTemplateResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            &format!("/v1/analysis/templates/{}/publish", created.template_id),
            Some(serde_json::json!({})),
            &scoped_headers(&token),
        )
        .await,
    )
    .await;
    assert_eq!(
        published.visibility,
        sdqp_api::AnalysisTemplateVisibility::Published
    );
    assert!(published.published_at.is_some());

    let loaded: AnalysisTemplateResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/analysis/templates/{}", created.template_id),
            None,
            &scoped_headers(&token),
        )
        .await,
    )
    .await;
    assert_eq!(loaded.template_id, created.template_id);

    let unpublished: AnalysisTemplateResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            &format!("/v1/analysis/templates/{}/unpublish", created.template_id),
            Some(serde_json::json!({})),
            &scoped_headers(&token),
        )
        .await,
    )
    .await;
    assert_eq!(
        unpublished.visibility,
        sdqp_api::AnalysisTemplateVisibility::Private
    );
    assert_eq!(unpublished.published_at, None);

    let deleted: AnalysisTemplateDeleteResponse = decode_json(
        json_request(
            app.clone(),
            Method::DELETE,
            &format!("/v1/analysis/templates/{}", created.template_id),
            None,
            &scoped_headers(&token),
        )
        .await,
    )
    .await;
    assert!(deleted.deleted);
    assert_eq!(deleted.template_id, created.template_id);

    let empty_list: AnalysisTemplateListResponse = decode_json(
        json_request(
            app,
            Method::GET,
            "/v1/analysis/templates",
            None,
            &scoped_headers(&token),
        )
        .await,
    )
    .await;
    assert!(empty_list.templates.is_empty());
}
