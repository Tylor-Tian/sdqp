pub mod auth;
pub mod config_audit;
pub mod exfiltration;
pub mod memory;
pub mod rbac;
pub mod supply_chain;
pub mod transport;

pub use auth::{
    AdaptiveResponse, AuthError, ContinuousAccessEvaluator, ContinuousAccessSignal, DevicePosture,
    DevicePostureReport, MfaChallenge, MfaChallengePayload, MfaError, MfaMethod, MfaProviderConfig,
    MfaProviderRegistry, MfaRegistration, MfaVerification, MockDevicePostureCollector,
    MockMfaService, MockScimDirectory, MockSsoAdapter, OidcProviderConfig, RiskAssessment,
    RiskDimension, RiskScore, SamlProviderConfig, ScimDirectoryRegistry, ScimDirectorySnapshot,
    ScimGroup, ScimGroupPatch, ScimIdentityState, ScimLifecyclePolicy, ScimMembershipChange,
    ScimMembershipChangeKind, ScimPageRequest, ScimProviderConfig, ScimResourcePage,
    ScimSyncConfig, ScimSyncCursor, ScimSyncError, ScimSyncPlan, ScimSyncSummary, ScimUser,
    ScimUserPatch, SessionBinding, SessionClaims, SessionPolicy, SsoCallbackClaims, SsoError,
    SsoInitiation, SsoProtocol, SsoProviderRegistry, StepUpChallenge, TotpProviderConfig,
    TrustedAuthenticationSource, WebAuthnAssertion, WebAuthnProviderConfig, WebAuthnRequestOptions,
    build_scim_sync_plan, issue_access_token, issue_refresh_token, parse_access_token,
    refresh_token_fingerprint, rotate_refresh_token,
};
pub use config_audit::{ConfigDrift, ConfigVersion, detect_config_drift};
pub use exfiltration::{
    DnsTunnelFinding, HttpCovertFinding, inspect_dns_tunnel, inspect_http_covert_channel,
};
pub use memory::{
    MockTeeProvider, SecretBytes, SecretString, TeeAttestation, TeeError, TeeProvider,
    TeeProviderConfig, TeeProviderRegistry,
};
pub use rbac::{Role, SecurityError, enforce_separation_of_duties};
pub use supply_chain::{CredentialRecord, ThirdPartyAssessment};
pub use transport::{
    ApiKeyRecord, AuthorizedIntegration, CredentialKind, CredentialRotationPolicy,
    CredentialRotationState, CredentialRotationStatus, GeneratedCredentialSecret,
    IntegrationRateLimiter, IntegrationRequestContext, IntegrationSecurityConfig,
    IntegrationSecurityError, IntegrationSecurityPolicy, MtlsPolicy, RateLimitPolicy,
    generate_integration_api_key_secret,
};
