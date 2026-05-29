use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use chrono::Utc;
use http::{Method, Request, StatusCode, header};
use reqwest::{Url, redirect::Policy};
use sdqp_api::{
    CredentialRotationRunResponse, CredentialRotationStatesResponse, DevicePostureResponse,
    LoginResponse, MfaChallengeResponse, ScimProviderSyncResponse, SsoStartResponse,
    TokenPairResponse, build_router, build_router_with_settings,
};
use sdqp_config::AppSettings;
use sdqp_system_security::{
    MfaChallenge, MfaChallengePayload, MfaMethod, MfaProviderConfig, MfaProviderRegistry,
    ScimSyncSummary, WebAuthnAssertion, WebAuthnRequestOptions,
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

fn provider_settings(base_url: &str) -> AppSettings {
    let mut settings = sample_settings();
    settings.identity_provider.issuer_url = "https://login.example.internal/issuer".into();
    settings.identity_provider.oidc_provider = "oidc".into();
    settings.identity_provider.saml_provider = "saml".into();
    settings.identity_provider.scim_provider = "bearer".into();
    settings.identity_provider.oidc_authorize_url = format!("{base_url}/oidc/authorize");
    settings.identity_provider.oidc_token_url = format!("{base_url}/oidc/token");
    settings.identity_provider.oidc_userinfo_url = format!("{base_url}/oidc/userinfo");
    settings.identity_provider.saml_sso_url = format!("{base_url}/saml/sso");
    settings.identity_provider.saml_exchange_url = format!("{base_url}/saml/exchange");
    settings.identity_provider.saml_entity_id = "sdqp-api".into();
    settings.identity_provider.saml_audience = "sdqp-api".into();
    settings.identity_provider.scim_base_url = format!("{base_url}/scim");
    settings.identity_provider.scim_token = "stage4-scim-token".into();
    settings.security.integration_api_keys[0].secret = "integration-stage4-key".into();
    settings
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

fn totp_code(settings: &AppSettings, tenant_id: &str, user_id: &str, username: &str) -> String {
    mfa_registry(settings).bootstrap_totp_code_at(tenant_id, user_id, username, Utc::now())
}

fn challenge_from_response(method: &str, response: &MfaChallengeResponse) -> MfaChallenge {
    let method = match method {
        "webauthn" => MfaMethod::WebAuthn,
        "biometric" => MfaMethod::Biometric,
        _ => MfaMethod::Totp,
    };
    let challenge_payload = response.webauthn_request.as_ref().map(|request| {
        MfaChallengePayload::WebAuthn(WebAuthnRequestOptions {
            challenge: request.challenge.clone(),
            rp_id: request.rp_id.clone(),
            origin: request.origin.clone(),
            credential_id: request.credential_id.clone(),
            timeout_ms: request.timeout_ms,
            user_verification: request.user_verification.clone(),
        })
    });

    MfaChallenge {
        challenge_id: response.challenge_id.clone(),
        method,
        issued_at: Utc::now(),
        expires_at: response.expires_at,
        reason: response.reason.clone(),
        challenge_payload,
        dev_only_code: None,
    }
}

fn webauthn_assertion(
    settings: &AppSettings,
    tenant_id: &str,
    user_id: &str,
    username: &str,
    response: &MfaChallengeResponse,
) -> WebAuthnAssertion {
    let challenge = challenge_from_response("webauthn", response);
    mfa_registry(settings)
        .bootstrap_webauthn_assertion(tenant_id, user_id, username, &challenge)
        .expect("webauthn assertion")
}

async fn login_sysadmin(app: axum::Router, settings: &AppSettings) -> TokenPairResponse {
    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            Some(serde_json::json!({
                "username": "sysadmin",
                "password": "password123",
                "device_fingerprint": "device-stage4-admin"
            })),
            &[],
        )
        .await,
    )
    .await;
    let challenge = login.challenge.as_ref().expect("admin webauthn challenge");
    decode_json(
        json_request(
            app,
            Method::POST,
            "/auth/mfa/verify",
            Some(serde_json::json!({
                "pending_session_id": login.pending_session_id,
                "webauthn_assertion": webauthn_assertion(
                    settings,
                    "tenant-alpha",
                    "user-sysadmin",
                    "sysadmin",
                    challenge
                )
            })),
            &[],
        )
        .await,
    )
    .await
}

#[derive(Clone)]
struct IdentityProviderState {
    issuer: String,
    audience: String,
}

async fn spawn_identity_provider(issuer: &str, audience: &str) -> String {
    async fn oidc_authorize(Query(query): Query<HashMap<String, String>>) -> http::Response<Body> {
        let login_hint = query.get("login_hint").cloned().expect("oidc login hint");
        let redirect_uri = query
            .get("redirect_uri")
            .cloned()
            .expect("oidc redirect uri");
        let state = query.get("state").cloned().expect("oidc state");
        let mut location = Url::parse(&redirect_uri).expect("redirect url");
        location
            .query_pairs_mut()
            .append_pair("code", &format!("oidc-code:{login_hint}"))
            .append_pair("state", &state);

        http::Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, location.to_string())
            .body(Body::empty())
            .expect("oidc authorize response")
    }

    async fn oidc_token(Json(payload): Json<serde_json::Value>) -> Json<serde_json::Value> {
        let code = payload["code"].as_str().expect("oidc code");
        let login_hint = code.strip_prefix("oidc-code:").expect("oidc artifact");
        Json(serde_json::json!({
            "access_token": format!("oidc-access:{login_hint}")
        }))
    }

    async fn oidc_userinfo(headers: HeaderMap) -> Json<serde_json::Value> {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .expect("oidc bearer token");
        let login_hint = token
            .strip_prefix("oidc-access:")
            .expect("oidc access token");

        Json(serde_json::json!({
            "sub": format!("oidc-subject-{login_hint}"),
            "preferred_username": login_hint,
            "email": format!("{login_hint}@example.internal"),
            "display_name": "OIDC Analyst",
            "groups": ["scim:analysts", "scim:project-alpha"]
        }))
    }

    async fn saml_sso(Query(query): Query<HashMap<String, String>>) -> http::Response<Body> {
        let login_hint = query.get("login_hint").cloned().expect("saml login hint");
        let redirect_uri = query
            .get("redirect_uri")
            .cloned()
            .expect("saml redirect uri");
        let relay_state = query.get("relay_state").cloned().expect("saml relay state");
        let mut location = Url::parse(&redirect_uri).expect("redirect url");
        location
            .query_pairs_mut()
            .append_pair("code", &format!("saml-artifact:{login_hint}"))
            .append_pair("state", &relay_state);

        http::Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, location.to_string())
            .body(Body::empty())
            .expect("saml authorize response")
    }

    async fn saml_exchange(
        State(state): State<IdentityProviderState>,
        Json(payload): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let artifact = payload["artifact"].as_str().expect("saml artifact");
        let login_hint = artifact
            .strip_prefix("saml-artifact:")
            .expect("saml artifact");
        Json(serde_json::json!({
            "issuer": state.issuer,
            "audience": state.audience,
            "subject": format!("saml-subject-{login_hint}"),
            "username": login_hint,
            "email": format!("{login_hint}@example.internal"),
            "display_name": "SAML Admin",
            "groups": ["scim:admins", "scim:project-alpha"]
        }))
    }

    let app = Router::new()
        .route("/oidc/authorize", get(oidc_authorize))
        .route("/oidc/token", post(oidc_token))
        .route("/oidc/userinfo", get(oidc_userinfo))
        .route("/saml/sso", get(saml_sso))
        .route("/saml/exchange", post(saml_exchange))
        .with_state(IdentityProviderState {
            issuer: issuer.into(),
            audience: audience.into(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("idp bind");
    let addr = listener.local_addr().expect("idp addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("idp server");
    });
    format!("http://{addr}")
}

async fn provider_callback_code(authorization_url: &str) -> String {
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("redirectless client");
    let response = client
        .get(authorization_url)
        .send()
        .await
        .expect("provider authorize");
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("provider redirect");
    Url::parse(location)
        .expect("redirect location")
        .query_pairs()
        .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
        .expect("callback code")
}

#[derive(Clone)]
struct ScimProviderState {
    token: String,
    users: Arc<Mutex<Vec<serde_json::Value>>>,
    groups: Arc<Mutex<Vec<serde_json::Value>>>,
}

async fn scim_users(
    State(state): State<ScimProviderState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, usize>>,
) -> http::Response<Body> {
    scim_list_response(
        &state,
        headers,
        query,
        state.users.lock().expect("users").clone(),
    )
}

async fn scim_groups(
    State(state): State<ScimProviderState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, usize>>,
) -> http::Response<Body> {
    scim_list_response(
        &state,
        headers,
        query,
        state.groups.lock().expect("groups").clone(),
    )
}

fn scim_list_response(
    state: &ScimProviderState,
    headers: HeaderMap,
    query: HashMap<String, usize>,
    resources: Vec<serde_json::Value>,
) -> http::Response<Body> {
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value == format!("Bearer {}", state.token))
        .unwrap_or(false);
    if !authorized {
        return http::Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::empty())
            .expect("unauthorized scim response");
    }

    let start_index = query.get("startIndex").copied().unwrap_or(1).max(1);
    let count = query.get("count").copied().unwrap_or(100).max(1);
    let page = resources
        .iter()
        .skip(start_index.saturating_sub(1))
        .take(count)
        .cloned()
        .collect::<Vec<_>>();
    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": resources.len(),
        "startIndex": start_index,
        "itemsPerPage": page.len(),
        "Resources": page
    });

    http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("scim response")
}

async fn spawn_scim_provider() -> (String, ScimProviderState) {
    let state = ScimProviderState {
        token: "stage4-scim-token".into(),
        users: Arc::new(Mutex::new(vec![
            serde_json::json!({
                "id": "idp-u-1",
                "externalId": "scim-provider-user-1",
                "userName": "scim-provider-one",
                "displayName": "SCIM Provider One",
                "active": true,
                "emails": [{"value": "provider-one@example.internal", "primary": true}],
                "groups": [{"value": "scim:provider-analysts"}]
            }),
            serde_json::json!({
                "id": "idp-u-2",
                "externalId": "scim-provider-user-2",
                "userName": "scim-provider-two",
                "displayName": "SCIM Provider Two",
                "active": true,
                "emails": [{"value": "provider-two@example.internal"}],
                "groups": [{"value": "scim:provider-analysts"}]
            }),
        ])),
        groups: Arc::new(Mutex::new(vec![serde_json::json!({
            "id": "idp-g-1",
            "externalId": "scim:provider-analysts",
            "displayName": "Provider Analysts",
            "members": [
                {"value": "scim-provider-user-1"},
                {"value": "scim-provider-user-2"}
            ]
        })])),
    };
    let app = Router::new()
        .route("/scim/Users", get(scim_users))
        .route("/scim/Groups", get(scim_groups))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("scim bind");
    let addr = listener.local_addr().expect("scim addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("scim server");
    });
    (format!("http://{addr}/scim"), state)
}

#[tokio::test]
async fn uat_scim_provider_sync_paginates_and_closes_lifecycle() {
    let (scim_base_url, provider_state) = spawn_scim_provider().await;
    let mut settings = sample_settings();
    settings.identity_provider.scim_provider = "scim20".into();
    settings.identity_provider.scim_base_url = scim_base_url;
    settings.identity_provider.scim_token = "stage4-scim-token".into();
    settings.identity_provider.scim_page_size = 1;
    settings.identity_provider.scim_disable_missing_users = true;
    settings.identity_provider.scim_disable_missing_groups = true;
    settings.security.integration_api_keys[0].secret = "integration-stage4-key".into();
    let app = build_router_with_settings(settings.clone());
    let scim_token = format!("Bearer {}", settings.identity_provider.scim_token);

    let first_sync: ScimProviderSyncResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/scim/sync",
            Some(serde_json::json!({})),
            &[
                ("authorization", &scim_token),
                ("x-api-key", "integration-stage4-key"),
                ("x-forwarded-for", "127.0.0.1"),
            ],
        )
        .await,
    )
    .await;

    assert_eq!(first_sync.provider, "scim20");
    assert_eq!(first_sync.summary.users_changed, 2);
    assert_eq!(first_sync.summary.groups_changed, 1);
    assert_eq!(first_sync.summary.memberships_changed, 2);
    assert_eq!(first_sync.cursor.pages_fetched, 3);

    *provider_state.users.lock().expect("users") = vec![serde_json::json!({
        "id": "idp-u-1",
        "externalId": "scim-provider-user-1",
        "userName": "scim-provider-one",
        "displayName": "SCIM Provider One",
        "active": false,
        "emails": [{"value": "provider-one@example.internal", "primary": true}],
        "groups": []
    })];
    *provider_state.groups.lock().expect("groups") = vec![serde_json::json!({
        "id": "idp-g-1",
        "externalId": "scim:provider-analysts",
        "displayName": "Provider Analysts",
        "members": []
    })];

    let second_sync: ScimProviderSyncResponse = decode_json(
        json_request(
            app,
            Method::POST,
            "/auth/scim/sync",
            Some(serde_json::json!({})),
            &[
                ("authorization", &scim_token),
                ("x-api-key", "integration-stage4-key"),
                ("x-forwarded-for", "127.0.0.1"),
            ],
        )
        .await,
    )
    .await;

    assert_eq!(second_sync.summary.users_disabled, 2);
    assert_eq!(second_sync.summary.groups_changed, 1);
    assert_eq!(second_sync.summary.memberships_changed, 2);
    assert_eq!(second_sync.user_patches, 2);
}

#[tokio::test]
async fn uat_credential_rotation_automates_integration_api_key_chain() {
    let mut settings = sample_settings();
    settings.security.integration_api_keys[0].secret = "integration-rotation-old".into();
    settings.security.credential_rotation.interval_secs = 90 * 24 * 60 * 60;
    let app = build_router_with_settings(settings.clone());
    let admin_tokens = login_sysadmin(app.clone(), &settings).await;
    let admin_auth = format!("Bearer {}", admin_tokens.access_token);

    let states: CredentialRotationStatesResponse = decode_json(
        json_request(
            app.clone(),
            Method::GET,
            "/v1/admin/credential-rotations",
            None,
            &[
                ("authorization", &admin_auth),
                ("x-tenant-id", "tenant-alpha"),
            ],
        )
        .await,
    )
    .await;
    assert_eq!(states.states.len(), 1);
    assert_eq!(states.states[0].kind, "integration_api_key");
    assert_eq!(states.states[0].status, "due");

    let rotation: CredentialRotationRunResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/v1/admin/credential-rotations/run",
            Some(serde_json::json!({})),
            &[
                ("authorization", &admin_auth),
                ("x-tenant-id", "tenant-alpha"),
            ],
        )
        .await,
    )
    .await;
    assert_eq!(rotation.evaluated, 1);
    assert_eq!(rotation.rotated, 1);
    assert_eq!(rotation.failed, 0);
    assert!(!rotation.audit_checkpoint_id.is_empty());
    let rotated_secret = rotation.results[0]
        .new_secret
        .as_ref()
        .expect("rotated secret")
        .clone();
    assert_ne!(rotated_secret, "integration-rotation-old");
    assert!(rotation.results[0].new_version.is_some());

    let scim_token = format!("Bearer {}", settings.identity_provider.scim_token);
    let old_key_response = json_request(
        app.clone(),
        Method::POST,
        "/auth/scim/groups",
        Some(serde_json::json!({
            "operation": "upsert",
            "group": {
                "external_id": "scim:rotated",
                "tenant_id": "tenant-alpha",
                "display_name": "Rotated",
                "active": true,
                "members": []
            }
        })),
        &[
            ("authorization", &scim_token),
            ("x-api-key", "integration-rotation-old"),
            ("x-forwarded-for", "127.0.0.1"),
        ],
    )
    .await;
    assert_eq!(old_key_response.status(), StatusCode::UNAUTHORIZED);

    let new_key_response = json_request(
        app.clone(),
        Method::POST,
        "/auth/scim/groups",
        Some(serde_json::json!({
            "operation": "upsert",
            "group": {
                "external_id": "scim:rotated",
                "tenant_id": "tenant-alpha",
                "display_name": "Rotated",
                "active": true,
                "members": []
            }
        })),
        &[
            ("authorization", &scim_token),
            ("x-api-key", &rotated_secret),
            ("x-forwarded-for", "127.0.0.1"),
        ],
    )
    .await;
    assert_eq!(new_key_response.status(), StatusCode::OK);

    let no_due: CredentialRotationRunResponse = decode_json(
        json_request(
            app,
            Method::POST,
            "/v1/admin/credential-rotations/run",
            Some(serde_json::json!({})),
            &[
                ("authorization", &admin_auth),
                ("x-tenant-id", "tenant-alpha"),
            ],
        )
        .await,
    )
    .await;
    assert_eq!(no_due.evaluated, 0);
    assert_eq!(no_due.skipped, 1);
}

#[tokio::test]
async fn uat_oidc_scim_step_up_flow_succeeds() {
    let idp_base_url =
        spawn_identity_provider("https://login.example.internal/issuer", "sdqp-api").await;
    let settings = provider_settings(&idp_base_url);
    let app = build_router_with_settings(settings.clone());
    let scim_token = format!("Bearer {}", settings.identity_provider.scim_token);

    let group_sync: ScimSyncSummary = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/scim/groups",
            Some(serde_json::json!({
                "operation": "upsert",
                "group": {
                    "external_id": "scim:analysts",
                    "tenant_id": "tenant-alpha",
                    "display_name": "Analysts",
                    "active": true,
                    "members": ["scim-user-analyst"]
                }
            })),
            &[
                ("authorization", &scim_token),
                ("x-api-key", "integration-stage4-key"),
                ("x-forwarded-for", "127.0.0.1"),
            ],
        )
        .await,
    )
    .await;
    assert_eq!(group_sync.groups_changed, 1);

    let user_sync: ScimSyncSummary = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/scim/users",
            Some(serde_json::json!({
                "operation": "upsert",
                "user": {
                    "external_id": "scim-user-analyst",
                    "tenant_id": "tenant-alpha",
                    "user_name": "scim-analyst",
                    "display_name": "SCIM Analyst",
                    "email": "scim-analyst@example.internal",
                    "active": true,
                    "groups": ["scim:analysts"]
                }
            })),
            &[
                ("authorization", &scim_token),
                ("x-api-key", "integration-stage4-key"),
                ("x-forwarded-for", "127.0.0.1"),
            ],
        )
        .await,
    )
    .await;
    assert_eq!(user_sync.users_changed, 1);

    let sso_start: SsoStartResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/sso/start",
            Some(serde_json::json!({
                "protocol": "oidc",
                "login_hint": "scim-analyst"
            })),
            &[],
        )
        .await,
    )
    .await;
    assert!(sso_start.authorization_url.contains("/oidc/authorize"));
    assert!(sso_start.mock_code.is_empty());

    let callback_code = provider_callback_code(&sso_start.authorization_url).await;
    let sso_login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/sso/callback",
            Some(serde_json::json!({
                "protocol": "oidc",
                "code": callback_code,
                "device_fingerprint": "device-stage4-oidc"
            })),
            &[("x-forwarded-for", "127.0.0.1")],
        )
        .await,
    )
    .await;
    assert_eq!(sso_login.auth_source.as_deref(), Some("oidc"));
    assert_eq!(sso_login.method, "totp");

    let tokens: TokenPairResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/mfa/verify",
            Some(serde_json::json!({
                "pending_session_id": sso_login.pending_session_id,
                "code": totp_code(&settings, "tenant-alpha", "user-scim-analyst", "scim-analyst")
            })),
            &[],
        )
        .await,
    )
    .await;

    let posture: DevicePostureResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/device-posture",
            Some(serde_json::json!({
                "refresh_token": tokens.refresh_token,
                "profile": "legacy",
                "ip_drift": false,
                "impossible_travel": false,
                "exfiltration_hint": false,
                "query_burst": 5,
                "denied_burst": 0,
                "export_burst": 0
            })),
            &[],
        )
        .await,
    )
    .await;
    assert!(posture.step_up_required);
    assert!(posture.risk_score >= 30);
    assert!(posture.step_up_challenge.is_some());

    let bearer = format!("Bearer {}", tokens.access_token);
    let blocked = json_request(
        app.clone(),
        Method::GET,
        "/v1/project-context",
        None,
        &[
            ("authorization", &bearer),
            ("x-tenant-id", "tenant-alpha"),
            ("x-project-id", "project-alpha"),
        ],
    )
    .await;
    assert_eq!(blocked.status(), StatusCode::UNAUTHORIZED);
    let blocked_body = to_bytes(blocked.into_body(), usize::MAX)
        .await
        .expect("blocked body");
    let blocked_json: serde_json::Value =
        serde_json::from_slice(&blocked_body).expect("blocked json");
    assert_eq!(
        blocked_json["error"].as_str(),
        Some("step-up authentication required")
    );
    assert_eq!(blocked_json["step_up_required"].as_bool(), Some(true));
    assert_eq!(
        blocked_json["step_up_challenge"]["reason"].as_str(),
        Some("continuous risk assessment requires step-up")
    );

    let stepped_up: TokenPairResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/step-up/verify",
            Some(serde_json::json!({
                "refresh_token": tokens.refresh_token,
                "code": totp_code(&settings, "tenant-alpha", "user-scim-analyst", "scim-analyst")
            })),
            &[],
        )
        .await,
    )
    .await;

    let access = json_request(
        app,
        Method::GET,
        "/v1/project-context",
        None,
        &[
            (
                "authorization",
                &format!("Bearer {}", stepped_up.access_token),
            ),
            ("x-tenant-id", "tenant-alpha"),
            ("x-project-id", "project-alpha"),
        ],
    )
    .await;
    assert_eq!(access.status(), StatusCode::OK);
}

#[tokio::test]
async fn uat_saml_provider_flow_succeeds() {
    let idp_base_url =
        spawn_identity_provider("https://login.example.internal/issuer", "sdqp-api").await;
    let settings = provider_settings(&idp_base_url);
    let app = build_router_with_settings(settings.clone());

    let sso_start: SsoStartResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/sso/start",
            Some(serde_json::json!({
                "protocol": "saml",
                "login_hint": "security-admin"
            })),
            &[],
        )
        .await,
    )
    .await;
    assert!(sso_start.authorization_url.contains("/saml/sso"));
    assert!(sso_start.mock_code.is_empty());

    let callback_code = provider_callback_code(&sso_start.authorization_url).await;
    let sso_login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/sso/callback",
            Some(serde_json::json!({
                "protocol": "saml",
                "code": callback_code,
                "device_fingerprint": "device-stage4-saml"
            })),
            &[("x-forwarded-for", "127.0.0.1")],
        )
        .await,
    )
    .await;
    assert_eq!(sso_login.auth_source.as_deref(), Some("saml"));
    assert_eq!(sso_login.method, "webauthn");
    let challenge = sso_login.challenge.as_ref().expect("webauthn challenge");

    let tokens: TokenPairResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/mfa/verify",
            Some(serde_json::json!({
                "pending_session_id": sso_login.pending_session_id,
                "webauthn_assertion": webauthn_assertion(
                    &settings,
                    "tenant-alpha",
                    "user-security-admin",
                    "security-admin",
                    challenge
                )
            })),
            &[],
        )
        .await,
    )
    .await;

    let access = json_request(
        app,
        Method::GET,
        "/v1/project-context",
        None,
        &[
            ("authorization", &format!("Bearer {}", tokens.access_token)),
            ("x-tenant-id", "tenant-alpha"),
            ("x-project-id", "project-alpha"),
        ],
    )
    .await;
    assert_eq!(access.status(), StatusCode::OK);
}

#[tokio::test]
async fn uat_refresh_replay_and_session_binding_mismatch_are_rejected() {
    let app = build_router(sample_settings().api);

    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            Some(serde_json::json!({
                "username": "analyst",
                "password": "password123",
                "device_fingerprint": "device-stage4-local"
            })),
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
            Some(serde_json::json!({
                "pending_session_id": login.pending_session_id,
                "code": totp_code(&sample_settings(), "tenant-alpha", "user-analyst", "analyst")
            })),
            &[],
        )
        .await,
    )
    .await;

    let rotated: TokenPairResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/refresh",
            Some(serde_json::json!({
                "refresh_token": tokens.refresh_token
            })),
            &[],
        )
        .await,
    )
    .await;

    let replay = json_request(
        app.clone(),
        Method::POST,
        "/auth/refresh",
        Some(serde_json::json!({
            "refresh_token": tokens.refresh_token
        })),
        &[],
    )
    .await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

    let binding_mismatch = json_request(
        app,
        Method::GET,
        "/v1/project-context",
        None,
        &[
            ("authorization", &format!("Bearer {}", rotated.access_token)),
            ("x-tenant-id", "tenant-alpha"),
            ("x-project-id", "project-alpha"),
            ("x-device-fingerprint", "device-stage4-other"),
        ],
    )
    .await;
    assert_eq!(binding_mismatch.status(), StatusCode::UNAUTHORIZED);
}

async fn spawn_tee_attestation_server(secure: bool, measurement: &str) -> String {
    async fn attest(
        State(state): State<(bool, String)>,
        Json(payload): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "provider": "http-attestation",
            "workload": payload["workload"].as_str().unwrap_or("unknown"),
            "measurement": state.1,
            "secure": state.0
        }))
    }

    let app = Router::new()
        .route("/tee/attest", post(attest))
        .with_state((secure, measurement.to_string()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("tee bind");
    let addr = listener.local_addr().expect("tee addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("tee server");
    });
    format!("http://{addr}/tee/attest")
}

#[tokio::test]
async fn uat_integration_security_enforces_api_key_ip_mtls_and_rate_limit() {
    let mut settings = sample_settings();
    settings.security.integration_api_keys[0].secret = "integration-stage4-key".into();
    settings.security.integration_rate_limit.max_requests = 2;
    let app = build_router_with_settings(settings.clone());

    let scim_missing_key = json_request(
        app.clone(),
        Method::POST,
        "/auth/scim/groups",
        Some(serde_json::json!({
            "operation": "upsert",
            "group": {
                "external_id": "scim:test",
                "tenant_id": "tenant-alpha",
                "display_name": "Test",
                "active": true,
                "members": []
            }
        })),
        &[
            (
                "authorization",
                &format!("Bearer {}", settings.identity_provider.scim_token),
            ),
            ("x-forwarded-for", "127.0.0.1"),
        ],
    )
    .await;
    assert_eq!(scim_missing_key.status(), StatusCode::UNAUTHORIZED);

    let scim_bad_ip = json_request(
        app.clone(),
        Method::POST,
        "/auth/scim/groups",
        Some(serde_json::json!({
            "operation": "upsert",
            "group": {
                "external_id": "scim:test",
                "tenant_id": "tenant-alpha",
                "display_name": "Test",
                "active": true,
                "members": []
            }
        })),
        &[
            (
                "authorization",
                &format!("Bearer {}", settings.identity_provider.scim_token),
            ),
            ("x-api-key", "integration-stage4-key"),
            ("x-forwarded-for", "10.0.0.8"),
        ],
    )
    .await;
    assert_eq!(scim_bad_ip.status(), StatusCode::FORBIDDEN);

    let hr_missing_mtls = json_request(
        app.clone(),
        Method::POST,
        "/integrations/hr/events",
        Some(serde_json::json!({
            "source": "workday",
            "user_id": "user-analyst",
            "event_type": "employment.terminated"
        })),
        &[
            ("x-api-key", "integration-stage4-key"),
            ("x-sdqp-hr-token", &settings.integrations.hr.token),
            ("x-forwarded-for", "127.0.0.1"),
        ],
    )
    .await;
    assert_eq!(hr_missing_mtls.status(), StatusCode::FORBIDDEN);

    for _ in 0..2 {
        let response = json_request(
            app.clone(),
            Method::POST,
            "/integrations/hr/events",
            Some(serde_json::json!({
                "source": "workday",
                "user_id": "user-analyst",
                "event_type": "employment.terminated"
            })),
            &[
                ("x-api-key", "integration-stage4-key"),
                ("x-sdqp-hr-token", &settings.integrations.hr.token),
                ("x-client-cert-subject", "CN=sdqp-integration"),
                ("x-forwarded-for", "127.0.0.1"),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    let rate_limited = json_request(
        app,
        Method::POST,
        "/integrations/hr/events",
        Some(serde_json::json!({
            "source": "workday",
            "user_id": "user-analyst",
            "event_type": "employment.terminated"
        })),
        &[
            ("x-api-key", "integration-stage4-key"),
            ("x-sdqp-hr-token", &settings.integrations.hr.token),
            ("x-client-cert-subject", "CN=sdqp-integration"),
            ("x-forwarded-for", "127.0.0.1"),
        ],
    )
    .await;
    assert_eq!(rate_limited.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn uat_tee_attestation_blocks_project_routes_when_insecure() {
    let mut settings = sample_settings();
    settings.security.tee.provider = "http-attestation".into();
    settings.security.tee.expected_measurements = vec!["stage4-tee".into()];
    settings.security.tee.attestation_url = spawn_tee_attestation_server(false, "stage4-tee").await;
    let app = build_router_with_settings(settings.clone());

    let login: LoginResponse = decode_json(
        json_request(
            app.clone(),
            Method::POST,
            "/auth/login",
            Some(serde_json::json!({
                "username": "analyst",
                "password": "password123",
                "device_fingerprint": "device-stage4-tee"
            })),
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
            Some(serde_json::json!({
                "pending_session_id": login.pending_session_id,
                "code": totp_code(&settings, "tenant-alpha", "user-analyst", "analyst")
            })),
            &[],
        )
        .await,
    )
    .await;

    let blocked = json_request(
        app,
        Method::GET,
        "/v1/project-context",
        None,
        &[
            ("authorization", &format!("Bearer {}", tokens.access_token)),
            ("x-tenant-id", "tenant-alpha"),
            ("x-project-id", "project-alpha"),
        ],
    )
    .await;
    assert_eq!(blocked.status(), StatusCode::SERVICE_UNAVAILABLE);
}
