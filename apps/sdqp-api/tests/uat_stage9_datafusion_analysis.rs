use std::time::Duration;

use axum::body::{Body, to_bytes};
use http::{Method, Request, StatusCode, header};
use sdqp_api::{
    AnalysisTemplateListResponse, AnalysisTemplateResponse, ApprovalTasksResponse,
    ClassificationCatalogResponse, ClassificationPoliciesResponse,
    ClassificationRuleVersionResponse, ClassificationRuleVersionsResponse,
    ConfirmClassificationRequest, LoginResponse, PermissionGrantsResponse, QuerySubmitResponse,
    QueryTaskStatusResponse, TokenPairResponse, build_persistent_router,
};
use sdqp_config::AppSettings;
use sqlx::{Executor, Row};
use sqlx_postgres::PgPoolOptions;
use tower::ServiceExt;

fn stage9_enabled() -> bool {
    std::env::var("SDQP_ENABLE_STAGE9_TESTS").ok().as_deref() == Some("1")
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
                "device_fingerprint": format!("stage9-{username}")
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

async fn wait_for_grant_field(
    app: axum::Router,
    token: &str,
    field_name: &str,
) -> PermissionGrantsResponse {
    for _ in 0..120 {
        let grants: PermissionGrantsResponse = decode_json(
            json_request(
                app.clone(),
                Method::GET,
                "/v1/permissions/grants",
                None,
                &scoped_headers(token),
            )
            .await,
        )
        .await;
        if grants.grants.iter().any(|grant| {
            grant.status == "active" && grant.fields.iter().any(|field| field == field_name)
        }) {
            return grants;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!("field grant {field_name} did not become active");
}

async fn wait_for_policy(
    app: axum::Router,
    token: &str,
    data_source_id: &str,
    field_name: &str,
) -> sdqp_api::ClassificationPolicyResponse {
    for _ in 0..120 {
        let response = json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/classification/policies/{data_source_id}"),
            None,
            &scoped_headers(token),
        )
        .await;
        if response.status() != StatusCode::OK {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        }

        let policies: ClassificationPoliciesResponse = decode_json(response).await;
        if let Some(policy) = policies
            .policies
            .into_iter()
            .find(|policy| policy.field_name == field_name && policy.detection_run_id.is_some())
        {
            return policy;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!("classification policy for field {field_name} did not appear in time");
}

#[tokio::test]
async fn uat_stage9_classification_detection_and_confirmation_flow() {
    if !stage9_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage9_api_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let settings = test_settings(&database_name);
    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent router");

    let analyst = user_tokens(app.clone(), "analyst").await;
    let manager = user_tokens(app.clone(), "manager").await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);
    let manager_bearer = format!("Bearer {}", manager.access_token);

    let seeded_versions: ClassificationRuleVersionsResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/classification/rule-versions/datasource-rest",
            None,
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    let seeded_active = seeded_versions
        .active_rule_version_id
        .as_deref()
        .expect("seeded active classification rule version");
    assert!(seeded_active.starts_with("crv-project-alpha-datasource-rest-v1"));

    let draft_version: ClassificationRuleVersionResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/classification/rule-versions/datasource-rest",
            Some(serde_json::json!({
                "description": "stage9 governed personal-contact rule",
                "rules": [
                    {
                        "rule_id": "governed-email",
                        "catalog_entry_id": "catalog-governed-personal-contact",
                        "field_matchers": ["email"],
                        "sample_patterns": ["Email"],
                        "level": "L4Sensitive",
                        "data_category": "PersonalContact",
                        "applicable_regulations": [
                            {
                                "code": "PIPL",
                                "jurisdiction": "CN",
                                "title": "Personal Information Protection Law",
                                "retention_basis": "manual confirmation bound to approved investigation purpose"
                            }
                        ],
                        "retention_policy": {
                            "policy_id": "retention-governed-contact",
                            "retain_for_days": 540,
                            "disposal_action": "Review",
                            "legal_hold_supported": true
                        },
                        "manual_confirmation_required": true,
                        "masking_strategy": "PartialEmail",
                        "watermark_strength": "High"
                    }
                ]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(draft_version.status, "draft");
    assert_eq!(draft_version.catalog_entries.len(), 1);

    let activated_version: ClassificationRuleVersionResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            &format!(
                "/v1/classification/rule-versions/datasource-rest/{}/activate",
                draft_version.rule_version_id
            ),
            Some(serde_json::json!({})),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(activated_version.status, "active");

    let active_catalog: ClassificationCatalogResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/classification/catalog/datasource-rest",
            None,
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(
        active_catalog.active_rule_version_id,
        activated_version.rule_version_id
    );
    assert_eq!(
        active_catalog.entries[0].retention_policy.policy_id,
        "retention-governed-contact"
    );

    let application: serde_json::Value = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/permissions/applications",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "requested_fields": ["employee_email"]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(application["status"], "Pending");
    let application_id = application["application_id"]
        .as_str()
        .expect("application id")
        .to_string();
    let instance_id = application["approval_instance_id"]
        .as_str()
        .expect("approval instance id")
        .to_string();

    let manager_tasks: ApprovalTasksResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/approvals/tasks",
            None,
            &scoped_headers(&manager_bearer),
        )
        .await,
    )
    .await;
    assert!(
        manager_tasks
            .tasks
            .iter()
            .any(|task| task.application_id == application_id)
    );

    let approval = json_request(
        app.clone(),
        Method::POST,
        "/v1/approvals/callback",
        Some(serde_json::json!({
            "instance_id": instance_id,
            "action": "approve"
        })),
        &scoped_headers(&manager_bearer),
    )
    .await;
    assert_eq!(approval.status(), StatusCode::OK);

    wait_for_grant_field(app.clone(), &analyst_bearer, "employee_email").await;

    let submit: QuerySubmitResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "source_type": "rest",
                "fields": ["employee_email"]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    let status =
        wait_for_task_state(app.clone(), &analyst_bearer, &submit.task_id, "completed").await;
    assert!(status.snapshot_id.is_some());

    let detected = wait_for_policy(
        app.clone(),
        &analyst_bearer,
        "datasource-rest",
        "employee_email",
    )
    .await;
    assert_eq!(detected.status, "pending_confirmation");
    assert_eq!(detected.source, "sample_detection");
    assert_eq!(detected.level, "l4_sensitive");
    assert_eq!(detected.masking_strategy, "partial_email");
    assert_eq!(detected.sample_value.as_deref(), Some("alice@example.com"));
    assert_eq!(
        detected.rule_version_id.as_deref(),
        Some(activated_version.rule_version_id.as_str())
    );
    assert_eq!(detected.data_category, "personal_contact");
    assert_eq!(
        detected.catalog_entry_id.as_deref(),
        Some("catalog-governed-personal-contact")
    );
    assert_eq!(detected.retention_policy.retain_for_days, 540);
    assert!(
        detected
            .applicable_regulations
            .iter()
            .any(|regulation| regulation.code == "PIPL")
    );
    let detection_run_id = detected.detection_run_id.clone().expect("detection run id");

    let confirm_response: ClassificationPoliciesResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/classification/policies/datasource-rest/confirm",
            Some(
                serde_json::to_value(ConfirmClassificationRequest {
                    fields: vec!["employee_email".into()],
                    rule_version_id: Some(activated_version.rule_version_id.clone()),
                    reviewer_note: Some("uat manual confirmation".into()),
                })
                .expect("confirm payload"),
            ),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    let confirmed = confirm_response
        .policies
        .into_iter()
        .find(|policy| policy.field_name == "employee_email")
        .expect("confirmed policy");
    assert_eq!(confirmed.status, "confirmed");
    assert_eq!(confirmed.source, "manual_confirmation");
    assert_eq!(
        confirmed.detection_run_id.as_deref(),
        Some(detection_run_id.as_str())
    );
    assert_eq!(
        confirmed.rule_version_id.as_deref(),
        Some(activated_version.rule_version_id.as_str())
    );
    assert_eq!(
        confirmed.retention_policy.policy_id,
        "retention-governed-contact"
    );

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&settings.database.postgres.dsn)
        .await
        .expect("postgres");
    let policy_row = sqlx::query(
        r#"
        SELECT
            status,
            source,
            confirmed_by_user_id,
            rule_version_id,
            data_category,
            catalog_entry_id,
            retention_policy_json->>'policy_id' AS retention_policy_id,
            retention_policy_json->>'retain_for_days' AS retain_for_days
        FROM classification_field_policies
        WHERE project_id = 'project-alpha'
          AND data_source_id = 'datasource-rest'
          AND field_name = 'employee_email'
        "#,
    )
    .fetch_one(&pool)
    .await
    .expect("classification policy row");
    assert_eq!(
        policy_row
            .try_get::<String, _>("status")
            .expect("policy status"),
        "confirmed"
    );
    assert_eq!(
        policy_row
            .try_get::<String, _>("source")
            .expect("policy source"),
        "manual_confirmation"
    );
    assert_eq!(
        policy_row
            .try_get::<String, _>("confirmed_by_user_id")
            .expect("confirmed by user"),
        "user-analyst"
    );
    assert_eq!(
        policy_row
            .try_get::<String, _>("rule_version_id")
            .expect("rule version"),
        activated_version.rule_version_id
    );
    assert_eq!(
        policy_row
            .try_get::<String, _>("data_category")
            .expect("data category"),
        "personal_contact"
    );
    assert_eq!(
        policy_row
            .try_get::<String, _>("catalog_entry_id")
            .expect("catalog entry"),
        "catalog-governed-personal-contact"
    );
    assert_eq!(
        policy_row
            .try_get::<String, _>("retention_policy_id")
            .expect("retention policy"),
        "retention-governed-contact"
    );
    assert_eq!(
        policy_row
            .try_get::<String, _>("retain_for_days")
            .expect("retain for days"),
        "540"
    );

    let run_row = sqlx::query(
        r#"
        SELECT status, confirmed_by_user_id
        FROM classification_detection_runs
        WHERE detection_run_id = $1
        "#,
    )
    .bind(&detection_run_id)
    .fetch_one(&pool)
    .await
    .expect("detection run row");
    assert_eq!(
        run_row.try_get::<String, _>("status").expect("run status"),
        "confirmed"
    );
    assert_eq!(
        run_row
            .try_get::<String, _>("confirmed_by_user_id")
            .expect("run confirmed by user"),
        "user-analyst"
    );

    drop_database(&database_name).await;
}

#[tokio::test]
async fn uat_stage9_analysis_templates_persist_and_publish_with_project_scope() {
    if !stage9_enabled() {
        return;
    }

    let database_name = format!("sdqp_stage9_templates_{}", ulid::Ulid::new());
    create_database(&database_name).await;

    let settings = test_settings(&database_name);
    let app = build_persistent_router(settings.clone())
        .await
        .expect("persistent router");

    let analyst = user_tokens(app.clone(), "analyst").await;
    let manager = user_tokens(app.clone(), "manager").await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);
    let manager_bearer = format!("Bearer {}", manager.access_token);

    let created: AnalysisTemplateResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/analysis/templates",
            Some(serde_json::json!({
                "name": "Fraud reuse",
                "description": "Private fraud workspace",
                "data_source_id": "datasource-rest",
                "config": {
                    "page_size": 3,
                    "detail_fields": ["employee_id", "department"],
                    "pivot_dimension": "department",
                    "pivot_metric": "count_distinct",
                    "pivot_metric_field": "employee_id",
                    "pivot_percentile": null
                }
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(
        created.visibility,
        sdqp_api::AnalysisTemplateVisibility::Private
    );

    let list_before_publish: AnalysisTemplateListResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/analysis/templates",
            None,
            &scoped_headers(&manager_bearer),
        )
        .await,
    )
    .await;
    assert!(list_before_publish.templates.is_empty());

    let restarted = build_persistent_router(settings.clone())
        .await
        .expect("restarted router");

    let analyst_list: AnalysisTemplateListResponse = decode_json(
        json_request(
            restarted.clone(),
            Method::GET,
            "/v1/analysis/templates",
            None,
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(analyst_list.templates.len(), 1);
    assert_eq!(analyst_list.templates[0].template_id, created.template_id);

    let published: AnalysisTemplateResponse = decode_json(
        json_request(
            restarted.clone(),
            Method::POST,
            &format!("/v1/analysis/templates/{}/publish", created.template_id),
            Some(serde_json::json!({})),
            &scoped_headers(&analyst_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(
        published.visibility,
        sdqp_api::AnalysisTemplateVisibility::Published
    );

    let manager_list: AnalysisTemplateListResponse = decode_json(
        json_request(
            restarted.clone(),
            Method::GET,
            "/v1/analysis/templates",
            None,
            &scoped_headers(&manager_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(manager_list.templates.len(), 1);
    assert_eq!(manager_list.templates[0].template_id, created.template_id);
    assert!(!manager_list.templates[0].editable);

    let manager_load = json_request(
        restarted.clone(),
        Method::GET,
        &format!("/v1/analysis/templates/{}", created.template_id),
        None,
        &scoped_headers(&manager_bearer),
    )
    .await;
    assert_eq!(manager_load.status(), StatusCode::OK);

    let manager_update = json_request(
        restarted.clone(),
        Method::PUT,
        &format!("/v1/analysis/templates/{}", created.template_id),
        Some(serde_json::json!({
            "name": "Manager override",
            "description": "should fail",
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
        &scoped_headers(&manager_bearer),
    )
    .await;
    assert_eq!(manager_update.status(), StatusCode::FORBIDDEN);

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&settings.database.postgres.dsn)
        .await
        .expect("postgres");
    let row = sqlx::query(
        r#"
        SELECT visibility, owner_user_id, data_source_id
        FROM analysis_templates
        WHERE template_id = $1
        "#,
    )
    .bind(&created.template_id)
    .fetch_one(&pool)
    .await
    .expect("analysis template row");
    assert_eq!(
        row.try_get::<String, _>("visibility").expect("visibility"),
        "published"
    );
    assert_eq!(
        row.try_get::<String, _>("owner_user_id").expect("owner"),
        "user-analyst"
    );
    assert_eq!(
        row.try_get::<String, _>("data_source_id")
            .expect("data source"),
        "datasource-rest"
    );

    drop_database(&database_name).await;
}
