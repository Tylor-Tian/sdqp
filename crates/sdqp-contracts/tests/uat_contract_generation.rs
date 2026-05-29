use sdqp_contracts::{
    build_openapi_document, build_proto_contract_index,
    proto::{PROTO_PACKAGES, auth, project, query, watermark},
};

#[test]
fn uat_openapi_document_covers_health_auth_and_query_paths() {
    let document = build_openapi_document();
    let paths = document
        .get("paths")
        .and_then(|value| value.as_object())
        .expect("paths");

    assert!(paths.contains_key("/healthz"));
    assert!(paths.contains_key("/auth/login"));
    assert!(paths.contains_key("/auth/sso/start"));
    assert!(paths.contains_key("/auth/device-posture"));
    assert!(paths.contains_key("/auth/scim/users"));
    assert!(paths.contains_key("/v1/queries"));
    assert!(paths.contains_key("/v1/analysis/templates"));
    assert!(paths.contains_key("/v1/analysis/templates/{template_id}"));
    assert!(paths.contains_key("/v1/audit/events/search"));
    assert!(paths.contains_key("/v1/projects"));
    assert!(paths.contains_key("/v1/projects/{project_id}/state"));
    assert!(paths.contains_key("/v1/admin/config-drift"));

    let snapshot_page = paths
        .get("/v1/snapshots/{snapshot_id}/page")
        .and_then(|value| value.get("get"))
        .expect("snapshot page get");
    let snapshot_parameters = snapshot_page
        .get("parameters")
        .and_then(|value| value.as_array())
        .expect("snapshot page parameters");
    assert!(snapshot_parameters.iter().any(|parameter| {
        parameter.get("name").and_then(|value| value.as_str()) == Some("response_format")
    }));

    let pivot_analysis = paths
        .get("/v1/analysis/pivot")
        .and_then(|value| value.get("post"))
        .expect("pivot analysis post");
    let pivot_body_properties = pivot_analysis
        .get("requestBody")
        .and_then(|value| value.get("content"))
        .and_then(|value| value.get("application/json"))
        .and_then(|value| value.get("schema"))
        .and_then(|value| value.get("$ref"))
        .and_then(|value| value.as_str());
    assert_eq!(
        pivot_body_properties,
        Some("#/components/schemas/PivotAnalysisRequest")
    );

    let template_create = paths
        .get("/v1/analysis/templates")
        .and_then(|value| value.get("post"))
        .expect("analysis template create");
    let template_body_ref = template_create
        .get("requestBody")
        .and_then(|value| value.get("content"))
        .and_then(|value| value.get("application/json"))
        .and_then(|value| value.get("schema"))
        .and_then(|value| value.get("$ref"))
        .and_then(|value| value.as_str());
    assert_eq!(
        template_body_ref,
        Some("#/components/schemas/AnalysisTemplateUpsertRequest")
    );
}

#[test]
fn uat_proto_index_matches_generated_packages() {
    let document = build_proto_contract_index();
    let contracts = document
        .get("contracts")
        .and_then(|value| value.as_array())
        .expect("contracts");

    assert_eq!(contracts.len(), PROTO_PACKAGES.len());
    assert_eq!(
        contracts[0].get("package").and_then(|value| value.as_str()),
        Some("sdqp.common.v1")
    );
}

#[test]
fn uat_generated_grpc_types_are_accessible() {
    let login = auth::LoginRequest {
        username: "analyst".into(),
        password: "password123".into(),
        device_fingerprint: "test-device".into(),
    };
    let sso = auth::SsoStartRequest {
        protocol: "oidc".into(),
        login_hint: "analyst".into(),
    };
    let task = query::QueryTaskRef {
        task_id: "task-123".into(),
    };
    let project = project::UpdateProjectStateRequest {
        tenant_id: "tenant-alpha".into(),
        project_id: "project-alpha".into(),
        next_state: "frozen".into(),
        reason: "uat".into(),
    };
    let watermark = watermark::DetectWatermarksRequest {
        document: Some(watermark::WatermarkDocument {
            document_id: "dlp-doc-1".into(),
            content: b"document".to_vec(),
            content_format: watermark::WatermarkContentFormat::Text.into(),
            media_type: "text/plain".into(),
            inspection_context: Some(watermark::DlpInspectionContext {
                caller_system: "dlp-gateway".into(),
                policy_id: "policy-sensitive-export".into(),
                source_uri: "dlp://document/1".into(),
                correlation_id: "corr-1".into(),
                scope: Some(watermark::WatermarkRequestScope {
                    tenant_id: "tenant-alpha".into(),
                    project_id: "project-alpha".into(),
                    user_id: "user-analyst".into(),
                }),
                attributes: Default::default(),
            }),
        }),
        include_payload: true,
    };

    assert_eq!(login.username, "analyst");
    assert_eq!(sso.protocol, "oidc");
    assert_eq!(task.task_id, "task-123");
    assert_eq!(project.next_state, "frozen");
    assert_eq!(
        watermark
            .document
            .as_ref()
            .expect("watermark document")
            .inspection_context
            .as_ref()
            .expect("dlp context")
            .caller_system,
        "dlp-gateway"
    );
}
