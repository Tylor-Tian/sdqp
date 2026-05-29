use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::session::TrustedAuthenticationSource;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SsoProtocol {
    Oidc,
    Saml,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsoInitiation {
    pub protocol: SsoProtocol,
    pub authorization_url: String,
    pub relay_state: String,
    pub mock_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsoCallbackClaims {
    pub subject: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub groups: Vec<String>,
    pub auth_source: TrustedAuthenticationSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcProviderConfig {
    pub provider: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamlProviderConfig {
    pub provider: String,
    pub issuer_url: String,
    pub entity_id: String,
    pub audience: String,
    pub sso_url: String,
    pub exchange_url: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SsoError {
    #[error("unknown sso provider: {0}")]
    UnknownProvider(String),
    #[error("provider configuration error: {0}")]
    ProviderConfiguration(String),
    #[error("provider protocol error: {0}")]
    ProviderProtocol(String),
    #[error("provider request failed: {0}")]
    ProviderRequest(String),
    #[error("invalid callback code")]
    InvalidCallbackCode,
}

#[derive(Debug, Clone)]
pub struct MockSsoAdapter {
    issuer_url: String,
    client_id: String,
}

impl MockSsoAdapter {
    pub fn new(issuer_url: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self {
            issuer_url: issuer_url.into(),
            client_id: client_id.into(),
        }
    }

    pub fn start_auth(
        &self,
        protocol: SsoProtocol,
        login_hint: &str,
        redirect_url: &str,
    ) -> SsoInitiation {
        let relay_state = relay_state_for(login_hint);
        let protocol_name = protocol_label(protocol);
        let mock_code = format!("mock:{protocol_name}:{login_hint}");
        let authorization_url = format!(
            "{}/authorize?client_id={}&redirect_uri={}&protocol={}&login_hint={}&state={}",
            self.issuer_url.trim_end_matches('/'),
            self.client_id,
            redirect_url,
            protocol_name,
            login_hint,
            relay_state
        );

        SsoInitiation {
            protocol,
            authorization_url,
            relay_state,
            mock_code,
        }
    }

    pub fn exchange_code(&self, protocol: SsoProtocol, code: &str) -> Option<SsoCallbackClaims> {
        let expected_prefix = format!("mock:{}:", protocol_label(protocol));
        let login_hint = code.strip_prefix(&expected_prefix)?;

        let (groups, auth_source) = match protocol {
            SsoProtocol::Oidc => (
                vec![
                    "scim:analysts".to_string(),
                    "scim:project-alpha".to_string(),
                ],
                TrustedAuthenticationSource::Oidc,
            ),
            SsoProtocol::Saml => (
                vec!["scim:admins".to_string(), "scim:project-alpha".to_string()],
                TrustedAuthenticationSource::Saml,
            ),
        };

        Some(SsoCallbackClaims {
            subject: format!("{protocol:?}-subject-{login_hint}").to_ascii_lowercase(),
            username: login_hint.to_string(),
            email: format!("{login_hint}@example.internal"),
            display_name: login_hint.replace('-', " ").to_ascii_uppercase(),
            groups,
            auth_source,
        })
    }
}

#[derive(Clone)]
pub struct SsoProviderRegistry {
    oidc: SsoProviderEntry,
    saml: SsoProviderEntry,
}

impl SsoProviderRegistry {
    pub fn from_configs(
        oidc_config: OidcProviderConfig,
        saml_config: SamlProviderConfig,
    ) -> Result<Self, SsoError> {
        let oidc = match oidc_config.provider.trim().to_ascii_lowercase().as_str() {
            "mock" => SsoProviderEntry::Mock(MockSsoAdapter::new(
                oidc_config.issuer_url,
                oidc_config.client_id,
            )),
            "oidc" => SsoProviderEntry::Oidc(OidcSsoAdapter::from_config(oidc_config)?),
            other => return Err(SsoError::UnknownProvider(other.into())),
        };

        let saml = match saml_config.provider.trim().to_ascii_lowercase().as_str() {
            "mock" => SsoProviderEntry::Mock(MockSsoAdapter::new(
                saml_config.issuer_url,
                saml_config.entity_id,
            )),
            "saml" => SsoProviderEntry::Saml(SamlSsoAdapter::from_config(saml_config)?),
            other => return Err(SsoError::UnknownProvider(other.into())),
        };

        Ok(Self { oidc, saml })
    }

    pub fn start_auth(
        &self,
        protocol: SsoProtocol,
        login_hint: &str,
        redirect_url: &str,
    ) -> Result<SsoInitiation, SsoError> {
        self.provider(protocol)
            .start_auth(protocol, login_hint, redirect_url)
    }

    pub async fn exchange_code(
        &self,
        protocol: SsoProtocol,
        code: &str,
        redirect_url: &str,
    ) -> Result<SsoCallbackClaims, SsoError> {
        self.provider(protocol)
            .exchange_code(protocol, code, redirect_url)
            .await
    }

    fn provider(&self, protocol: SsoProtocol) -> &SsoProviderEntry {
        match protocol {
            SsoProtocol::Oidc => &self.oidc,
            SsoProtocol::Saml => &self.saml,
        }
    }
}

#[derive(Clone)]
enum SsoProviderEntry {
    Mock(MockSsoAdapter),
    Oidc(OidcSsoAdapter),
    Saml(SamlSsoAdapter),
}

impl SsoProviderEntry {
    fn start_auth(
        &self,
        protocol: SsoProtocol,
        login_hint: &str,
        redirect_url: &str,
    ) -> Result<SsoInitiation, SsoError> {
        match self {
            Self::Mock(adapter) => Ok(adapter.start_auth(protocol, login_hint, redirect_url)),
            Self::Oidc(adapter) => adapter.start_auth(login_hint, redirect_url),
            Self::Saml(adapter) => adapter.start_auth(login_hint, redirect_url),
        }
    }

    async fn exchange_code(
        &self,
        protocol: SsoProtocol,
        code: &str,
        redirect_url: &str,
    ) -> Result<SsoCallbackClaims, SsoError> {
        match self {
            Self::Mock(adapter) => adapter
                .exchange_code(protocol, code)
                .ok_or(SsoError::InvalidCallbackCode),
            Self::Oidc(adapter) => adapter.exchange_code(code, redirect_url).await,
            Self::Saml(adapter) => adapter.exchange_code(code, redirect_url).await,
        }
    }
}

#[derive(Clone)]
struct OidcSsoAdapter {
    config: OidcProviderConfig,
    client: Client,
}

impl OidcSsoAdapter {
    fn from_config(config: OidcProviderConfig) -> Result<Self, SsoError> {
        validate_required("oidc.authorize_url", &config.authorize_url)?;
        validate_required("oidc.token_url", &config.token_url)?;
        validate_required("oidc.userinfo_url", &config.userinfo_url)?;
        validate_required("oidc.client_id", &config.client_id)?;
        validate_required("oidc.client_secret", &config.client_secret)?;

        Ok(Self {
            config,
            client: Client::new(),
        })
    }

    fn start_auth(&self, login_hint: &str, redirect_url: &str) -> Result<SsoInitiation, SsoError> {
        let relay_state = relay_state_for(login_hint);
        let mut authorization_url = Url::parse(&self.config.authorize_url).map_err(|error| {
            SsoError::ProviderConfiguration(format!("invalid oidc authorize url: {error}"))
        })?;
        authorization_url
            .query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", redirect_url)
            .append_pair("response_type", "code")
            .append_pair("scope", "openid profile email groups")
            .append_pair("login_hint", login_hint)
            .append_pair("state", &relay_state);

        Ok(SsoInitiation {
            protocol: SsoProtocol::Oidc,
            authorization_url: authorization_url.to_string(),
            relay_state,
            mock_code: String::new(),
        })
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_url: &str,
    ) -> Result<SsoCallbackClaims, SsoError> {
        if code.trim().is_empty() {
            return Err(SsoError::InvalidCallbackCode);
        }

        let token_response = self
            .client
            .post(&self.config.token_url)
            .json(&OidcTokenRequest {
                grant_type: "authorization_code".into(),
                code: code.to_string(),
                client_id: self.config.client_id.clone(),
                client_secret: self.config.client_secret.clone(),
                redirect_uri: redirect_url.to_string(),
            })
            .send()
            .await
            .map_err(|error| SsoError::ProviderRequest(error.to_string()))?;
        if !token_response.status().is_success() {
            return Err(SsoError::ProviderRequest(format!(
                "oidc token exchange failed with status {}",
                token_response.status()
            )));
        }
        let token: OidcTokenResponse = token_response
            .json()
            .await
            .map_err(|error| SsoError::ProviderProtocol(error.to_string()))?;
        if token.access_token.trim().is_empty() {
            return Err(SsoError::ProviderProtocol(
                "oidc token response missing access token".into(),
            ));
        }

        let userinfo_response = self
            .client
            .get(&self.config.userinfo_url)
            .bearer_auth(token.access_token)
            .send()
            .await
            .map_err(|error| SsoError::ProviderRequest(error.to_string()))?;
        if !userinfo_response.status().is_success() {
            return Err(SsoError::ProviderRequest(format!(
                "oidc userinfo failed with status {}",
                userinfo_response.status()
            )));
        }
        let userinfo: OidcUserInfoResponse = userinfo_response
            .json()
            .await
            .map_err(|error| SsoError::ProviderProtocol(error.to_string()))?;

        userinfo.into_claims()
    }
}

#[derive(Clone)]
struct SamlSsoAdapter {
    config: SamlProviderConfig,
    client: Client,
}

impl SamlSsoAdapter {
    fn from_config(config: SamlProviderConfig) -> Result<Self, SsoError> {
        validate_required("saml.sso_url", &config.sso_url)?;
        validate_required("saml.exchange_url", &config.exchange_url)?;
        validate_required("saml.entity_id", &config.entity_id)?;
        validate_required("saml.audience", &config.audience)?;
        validate_required("saml.issuer_url", &config.issuer_url)?;

        Ok(Self {
            config,
            client: Client::new(),
        })
    }

    fn start_auth(&self, login_hint: &str, redirect_url: &str) -> Result<SsoInitiation, SsoError> {
        let relay_state = relay_state_for(login_hint);
        let mut authorization_url = Url::parse(&self.config.sso_url).map_err(|error| {
            SsoError::ProviderConfiguration(format!("invalid saml sso url: {error}"))
        })?;
        authorization_url
            .query_pairs_mut()
            .append_pair("entity_id", &self.config.entity_id)
            .append_pair("audience", &self.config.audience)
            .append_pair("login_hint", login_hint)
            .append_pair("redirect_uri", redirect_url)
            .append_pair("relay_state", &relay_state);

        Ok(SsoInitiation {
            protocol: SsoProtocol::Saml,
            authorization_url: authorization_url.to_string(),
            relay_state,
            mock_code: String::new(),
        })
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_url: &str,
    ) -> Result<SsoCallbackClaims, SsoError> {
        if code.trim().is_empty() {
            return Err(SsoError::InvalidCallbackCode);
        }

        let response = self
            .client
            .post(&self.config.exchange_url)
            .json(&SamlArtifactExchangeRequest {
                artifact: code.to_string(),
                entity_id: self.config.entity_id.clone(),
                audience: self.config.audience.clone(),
                redirect_uri: redirect_url.to_string(),
            })
            .send()
            .await
            .map_err(|error| SsoError::ProviderRequest(error.to_string()))?;
        if !response.status().is_success() {
            return Err(SsoError::ProviderRequest(format!(
                "saml exchange failed with status {}",
                response.status()
            )));
        }

        let assertion: SamlExchangeResponse = response
            .json()
            .await
            .map_err(|error| SsoError::ProviderProtocol(error.to_string()))?;
        if assertion.issuer != self.config.issuer_url {
            return Err(SsoError::ProviderProtocol(format!(
                "unexpected saml issuer {}",
                assertion.issuer
            )));
        }
        if assertion.audience != self.config.audience {
            return Err(SsoError::ProviderProtocol(format!(
                "unexpected saml audience {}",
                assertion.audience
            )));
        }

        Ok(SsoCallbackClaims {
            subject: assertion.subject,
            username: assertion.username,
            email: assertion.email,
            display_name: assertion.display_name,
            groups: assertion.groups,
            auth_source: TrustedAuthenticationSource::Saml,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct OidcTokenRequest {
    grant_type: String,
    code: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OidcTokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct OidcUserInfoResponse {
    sub: String,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
}

impl OidcUserInfoResponse {
    fn into_claims(self) -> Result<SsoCallbackClaims, SsoError> {
        let username = self
            .preferred_username
            .or(self.username)
            .or_else(|| {
                self.email
                    .as_ref()
                    .and_then(|value| value.split('@').next().map(str::to_string))
            })
            .ok_or_else(|| SsoError::ProviderProtocol("oidc userinfo missing username".into()))?;
        let email = self
            .email
            .unwrap_or_else(|| format!("{username}@example.internal"));
        let display_name = self
            .display_name
            .or(self.name)
            .unwrap_or_else(|| username.clone());

        Ok(SsoCallbackClaims {
            subject: self.sub,
            username,
            email,
            display_name,
            groups: self.groups,
            auth_source: TrustedAuthenticationSource::Oidc,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SamlArtifactExchangeRequest {
    artifact: String,
    entity_id: String,
    audience: String,
    redirect_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SamlExchangeResponse {
    issuer: String,
    audience: String,
    subject: String,
    username: String,
    email: String,
    display_name: String,
    groups: Vec<String>,
}

fn validate_required(label: &str, value: &str) -> Result<(), SsoError> {
    if value.trim().is_empty() {
        Err(SsoError::ProviderConfiguration(format!(
            "{label} must not be empty"
        )))
    } else {
        Ok(())
    }
}

fn relay_state_for(login_hint: &str) -> String {
    format!("relay-{login_hint}")
}

fn protocol_label(protocol: SsoProtocol) -> &'static str {
    match protocol {
        SsoProtocol::Oidc => "oidc",
        SsoProtocol::Saml => "saml",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::{
        Json, Router,
        body::Body,
        extract::{Query, State},
        http::{HeaderMap, StatusCode, header},
        routing::{get, post},
    };
    use reqwest::{Url, redirect::Policy};

    use super::{
        MockSsoAdapter, OidcProviderConfig, OidcTokenRequest, OidcTokenResponse,
        SamlArtifactExchangeRequest, SamlExchangeResponse, SamlProviderConfig, SsoProtocol,
        SsoProviderRegistry,
    };
    use crate::auth::session::TrustedAuthenticationSource;

    #[test]
    fn mock_oidc_flow_returns_claims() {
        let adapter = MockSsoAdapter::new("https://mock-idp.local", "client");
        let initiation = adapter.start_auth(
            SsoProtocol::Oidc,
            "analyst",
            "http://127.0.0.1:4173/auth/callback",
        );

        assert!(initiation.authorization_url.contains("login_hint=analyst"));
        let claims = adapter
            .exchange_code(SsoProtocol::Oidc, &initiation.mock_code)
            .expect("claims");
        assert_eq!(claims.username, "analyst");
    }

    #[tokio::test]
    async fn registry_uses_http_oidc_and_saml_providers() {
        let issuer = "https://idp.example.internal/issuer";
        let audience = "sdqp-api";
        let base_url = spawn_identity_provider(issuer, audience).await;
        let redirect_url = "http://127.0.0.1:4173/auth/callback";
        let registry = SsoProviderRegistry::from_configs(
            OidcProviderConfig {
                provider: "oidc".into(),
                issuer_url: issuer.into(),
                client_id: "client".into(),
                client_secret: "secret".into(),
                authorize_url: format!("{base_url}/oidc/authorize"),
                token_url: format!("{base_url}/oidc/token"),
                userinfo_url: format!("{base_url}/oidc/userinfo"),
            },
            SamlProviderConfig {
                provider: "saml".into(),
                issuer_url: issuer.into(),
                entity_id: audience.into(),
                audience: audience.into(),
                sso_url: format!("{base_url}/saml/sso"),
                exchange_url: format!("{base_url}/saml/exchange"),
            },
        )
        .expect("registry");

        let oidc_start = registry
            .start_auth(SsoProtocol::Oidc, "scim-analyst", redirect_url)
            .expect("oidc start");
        assert!(oidc_start.mock_code.is_empty());
        let oidc_code = fetch_redirect_code(&oidc_start.authorization_url).await;
        let oidc_claims = registry
            .exchange_code(SsoProtocol::Oidc, &oidc_code, redirect_url)
            .await
            .expect("oidc claims");
        assert_eq!(oidc_claims.username, "scim-analyst");
        assert_eq!(oidc_claims.auth_source, TrustedAuthenticationSource::Oidc);

        let saml_start = registry
            .start_auth(SsoProtocol::Saml, "security-admin", redirect_url)
            .expect("saml start");
        assert!(saml_start.mock_code.is_empty());
        let saml_code = fetch_redirect_code(&saml_start.authorization_url).await;
        let saml_claims = registry
            .exchange_code(SsoProtocol::Saml, &saml_code, redirect_url)
            .await
            .expect("saml claims");
        assert_eq!(saml_claims.username, "security-admin");
        assert_eq!(saml_claims.auth_source, TrustedAuthenticationSource::Saml);
        assert!(
            saml_claims
                .groups
                .iter()
                .any(|group| group == "scim:admins")
        );
    }

    #[derive(Clone)]
    struct IdentityProviderState {
        issuer: String,
        audience: String,
    }

    async fn spawn_identity_provider(issuer: &str, audience: &str) -> String {
        async fn oidc_authorize(
            Query(query): Query<HashMap<String, String>>,
        ) -> http::Response<Body> {
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

        async fn oidc_token(Json(request): Json<OidcTokenRequest>) -> Json<OidcTokenResponse> {
            assert_eq!(request.grant_type, "authorization_code");
            let login_hint = request
                .code
                .strip_prefix("oidc-code:")
                .expect("oidc artifact");
            Json(OidcTokenResponse {
                access_token: format!("oidc-access:{login_hint}"),
            })
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
            Json(request): Json<SamlArtifactExchangeRequest>,
        ) -> Json<SamlExchangeResponse> {
            let login_hint = request
                .artifact
                .strip_prefix("saml-artifact:")
                .expect("saml artifact");
            Json(SamlExchangeResponse {
                issuer: state.issuer,
                audience: state.audience,
                subject: format!("saml-subject-{login_hint}"),
                username: login_hint.to_string(),
                email: format!("{login_hint}@example.internal"),
                display_name: "SAML Admin".into(),
                groups: vec!["scim:admins".into(), "scim:project-alpha".into()],
            })
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

    async fn fetch_redirect_code(authorization_url: &str) -> String {
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
            .expect("authorization code")
    }
}
