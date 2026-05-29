use std::time::Duration;

use axum::body::{Body, to_bytes};
use chrono::Utc;
use http::{Method, Request, StatusCode, header};
use sdqp_api::{
    EvidenceExportResponse, LoginResponse, QuerySubmitResponse, QueryTaskStatusResponse,
    TokenPairResponse, UebaAlertsResponse, UebaCalibrationRunResponse, UebaReplayRunResponse,
    UebaRulesResponse, UebaTuningProposalApplyResponse, UebaTuningProposalResponse, build_router,
};
use sdqp_config::SecuritySettings;
use sdqp_system_security::{
    MfaChallenge, MfaChallengePayload, MfaMethod, MfaProviderConfig, MfaProviderRegistry,
    TotpProviderConfig, WebAuthnProviderConfig, WebAuthnRequestOptions,
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

async fn analyst_tokens(app: axum::Router) -> TokenPairResponse {
    user_tokens(app, "analyst", "device-phase6").await
}

async fn sysadmin_tokens(app: axum::Router) -> TokenPairResponse {
    user_tokens(app, "sysadmin", "device-phase6-admin").await
}

async fn user_tokens(
    app: axum::Router,
    username: &str,
    device_fingerprint: &str,
) -> TokenPairResponse {
    let settings = sample_settings();
    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            Some(serde_json::json!({
                "username": username,
                "password": "password123",
                "device_fingerprint": device_fingerprint
            })),
            &[("x-forwarded-for", "127.0.0.1")],
        )
        .await,
    )
    .await;
    let proof = mfa_proof_for_login(&settings.security, username, &login);

    decode_json(json_request(app, Method::POST, "/auth/mfa/verify", Some(proof), &[]).await).await
}

fn mfa_proof_for_login(
    security: &SecuritySettings,
    username: &str,
    login: &LoginResponse,
) -> serde_json::Value {
    let registry = MfaProviderRegistry::new(MfaProviderConfig {
        bootstrap_seed: security.mfa_bootstrap_seed.clone(),
        challenge_ttl_secs: security.mfa_challenge_ttl_secs,
        totp: TotpProviderConfig {
            issuer: security.totp_issuer.clone(),
            period_secs: security.totp_period_secs,
            digits: security.totp_digits,
            allowed_drift_steps: security.totp_allowed_drift_steps,
        },
        webauthn: WebAuthnProviderConfig {
            rp_id: security.webauthn_rp_id.clone(),
            origin: security.webauthn_origin.clone(),
            timeout_ms: security.webauthn_timeout_ms,
            challenge_ttl_secs: security.mfa_challenge_ttl_secs,
            require_user_verification: security.webauthn_require_user_verification,
        },
    });
    let user_id = match username {
        "sysadmin" => "user-sysadmin",
        "analyst" => "user-analyst",
        other => panic!("unsupported phase6 test user: {other}"),
    };

    match login.method.as_str() {
        "totp" => {
            let code =
                registry.bootstrap_totp_code_at("tenant-alpha", user_id, username, Utc::now());
            serde_json::json!({
                "pending_session_id": login.pending_session_id,
                "code": code
            })
        }
        "webauthn" => {
            let response = login.challenge.as_ref().expect("webauthn challenge");
            let options = response
                .webauthn_request
                .as_ref()
                .expect("webauthn options");
            let challenge = MfaChallenge {
                challenge_id: response.challenge_id.clone(),
                method: MfaMethod::WebAuthn,
                issued_at: Utc::now(),
                expires_at: response.expires_at,
                reason: response.reason.clone(),
                challenge_payload: Some(MfaChallengePayload::WebAuthn(WebAuthnRequestOptions {
                    challenge: options.challenge.clone(),
                    rp_id: options.rp_id.clone(),
                    origin: options.origin.clone(),
                    credential_id: options.credential_id.clone(),
                    timeout_ms: options.timeout_ms,
                    user_verification: options.user_verification.clone(),
                })),
                dev_only_code: None,
            };
            let assertion = registry
                .bootstrap_webauthn_assertion("tenant-alpha", user_id, username, &challenge)
                .expect("webauthn assertion");
            serde_json::json!({
                "pending_session_id": login.pending_session_id,
                "webauthn_assertion": assertion
            })
        }
        other => panic!("unsupported phase6 mfa method: {other}"),
    }
}

fn scoped_headers(token: &str) -> [(&str, &str); 3] {
    [
        ("authorization", token),
        ("x-tenant-id", "tenant-alpha"),
        ("x-project-id", "project-alpha"),
    ]
}

async fn completed_snapshot(app: axum::Router, token: &str) -> String {
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
            &scoped_headers(token),
        )
        .await,
    )
    .await;

    for _ in 0..40 {
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
            return status.snapshot_id.expect("snapshot");
        }

        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    panic!("snapshot not ready")
}

#[tokio::test]
async fn uat_ueba_governance_replay_tuning_and_calibration_closure() {
    let app = build_router(sample_settings().api);
    let analyst = analyst_tokens(app.clone()).await;
    let analyst_bearer = format!("Bearer {}", analyst.access_token);
    let admin = sysadmin_tokens(app.clone()).await;
    let admin_bearer = format!("Bearer {}", admin.access_token);

    for _ in 0..5 {
        let response = json_request(
            app.clone(),
            Method::POST,
            "/v1/queries",
            Some(serde_json::json!({
                "data_source_id": "datasource-rest",
                "source_type": "rest",
                "fields": ["employee_id"]
            })),
            &scoped_headers(&analyst_bearer),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    let rules: UebaRulesResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/ueba/rules",
            None,
            &scoped_headers(&admin_bearer),
        )
        .await,
    )
    .await;
    let high_frequency = rules
        .rules
        .iter()
        .find(|rule| rule.rule_name == "HighFrequencyQuery" && rule.status == "active")
        .expect("active high frequency rule");

    let replay: UebaReplayRunResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/ueba/replays",
            Some(serde_json::json!({
                "rule_version_id": high_frequency.rule_version_id
            })),
            &scoped_headers(&admin_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(replay.state, "completed");
    assert!(replay.hit_count > 0);

    let replay_lookup: UebaReplayRunResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            &format!("/v1/ueba/replays/{}", replay.run_id),
            None,
            &scoped_headers(&admin_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(replay_lookup.run_id, replay.run_id);

    let proposal: UebaTuningProposalResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/ueba/tuning/proposals",
            Some(serde_json::json!({
                "replay_run_id": replay.run_id,
                "rule_name": "HighFrequencyQuery",
                "threshold_delta": 1,
                "target_hit_rate_per_1000": 10
            })),
            &scoped_headers(&admin_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(proposal.status, "proposed");
    assert_eq!(proposal.rule_name, "HighFrequencyQuery");

    let applied: UebaTuningProposalApplyResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            &format!("/v1/ueba/tuning/proposals/{}/apply", proposal.proposal_id),
            Some(serde_json::json!({ "activate": true })),
            &scoped_headers(&admin_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(applied.proposal.status, "applied");
    assert_eq!(applied.applied_rule.status, "active");
    assert!(applied.applied_rule.version > high_frequency.version);

    let calibration: UebaCalibrationRunResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/ueba/calibrations",
            Some(serde_json::json!({
                "model_version": "ueba-governance-uat"
            })),
            &scoped_headers(&admin_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(calibration.model_version, "ueba-governance-uat");
    assert!(!calibration.result.external_final_uat_required);

    let calibration_lookup: UebaCalibrationRunResponse = decode_json(
        json_request(
            app,
            Method::GET,
            &format!("/v1/ueba/calibrations/{}", calibration.calibration_id),
            None,
            &scoped_headers(&admin_bearer),
        )
        .await,
    )
    .await;
    assert_eq!(
        calibration_lookup.calibration_id,
        calibration.calibration_id
    );
}

#[tokio::test]
async fn uat_ueba_marks_session_for_step_up_after_query_burst() {
    let app = build_router(sample_settings().api);
    let tokens = analyst_tokens(app.clone()).await;
    let bearer = format!("Bearer {}", tokens.access_token);

    for _ in 0..5 {
        let response = json_request(
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
        assert_eq!(response.status(), StatusCode::OK);
    }

    let alerts: UebaAlertsResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/ueba/alerts",
            None,
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert!(alerts.step_up_sessions > 0);
    assert!(
        alerts
            .alerts
            .iter()
            .any(|alert| alert.rule == "HighFrequencyQuery")
    );

    let response = json_request(
        app,
        Method::GET,
        "/v1/project-context",
        None,
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn uat_ueba_suspends_permissions_after_denied_burst() {
    let app = build_router(sample_settings().api);
    let tokens = analyst_tokens(app.clone()).await;
    let bearer = format!("Bearer {}", tokens.access_token);

    for _ in 0..2 {
        let response = json_request(
            app.clone(),
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

    let alerts: UebaAlertsResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/ueba/alerts",
            None,
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert!(alerts.permissions_suspended > 0);
    assert!(
        alerts
            .alerts
            .iter()
            .any(|alert| alert.rule == "UnauthorizedQueryBurst")
    );

    let grant_response = json_request(
        app,
        Method::GET,
        "/v1/permissions/grants/active/datasource-rest",
        None,
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(grant_response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn uat_ueba_terminates_session_after_export_spike() {
    let app = build_router(sample_settings().api);
    let tokens = analyst_tokens(app.clone()).await;
    let bearer = format!("Bearer {}", tokens.access_token);
    let snapshot_id = completed_snapshot(app.clone(), &bearer).await;

    for _ in 0..3 {
        let response: EvidenceExportResponse = decode_json(
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
        assert!(response.verification_ready);
    }

    let alerts: UebaAlertsResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/ueba/alerts",
            None,
            &scoped_headers(&bearer),
        )
        .await,
    )
    .await;
    assert!(alerts.terminated_sessions > 0);
    assert!(
        alerts
            .alerts
            .iter()
            .any(|alert| alert.rule == "ExportSpike")
    );

    let response = json_request(
        app,
        Method::GET,
        "/v1/project-context",
        None,
        &scoped_headers(&bearer),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
