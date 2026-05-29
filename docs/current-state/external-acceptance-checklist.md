# External Acceptance Checklist

Updated: 2026-05-04

Repository baseline:
- Repo-local implementation is complete for the current state.
- Module 6, Module 9, and Module 12 remain blocked only on external infrastructure acceptance.
- Existing repo-local UATs for Stage 4, Stage 8, and Stage 10 are boundary evidence only and must not be counted as final external acceptance.

## Module 12 external acceptance checklist

### Required external systems

- Real OIDC identity provider tenant.
- Real SAML identity provider tenant.
- Real SCIM 2.0 provider with `/Users` and `/Groups`.
- Real browser plus platform or roaming WebAuthn authenticator for the configured RP ID and origin.
- Real service TLS and mTLS termination path with a CA-managed client-certificate lifecycle.
- External secrets manager or provider API that receives or distributes rotated credentials outside the repo-local integration API key chain.

### Required environment variables / config items

- `SDQP_OIDC_PROVIDER`
- `SDQP_OIDC_ISSUER_URL`
- `SDQP_OIDC_CLIENT_ID`
- `SDQP_OIDC_CLIENT_SECRET`
- `SDQP_OIDC_REDIRECT_URL`
- `SDQP_OIDC_AUTHORIZE_URL`
- `SDQP_OIDC_TOKEN_URL`
- `SDQP_OIDC_USERINFO_URL`
- `SDQP_SAML_PROVIDER`
- `SDQP_SAML_SSO_URL`
- `SDQP_SAML_EXCHANGE_URL`
- `SDQP_SAML_ENTITY_ID`
- `SDQP_SAML_AUDIENCE`
- `SDQP_SCIM_PROVIDER`
- `SDQP_SCIM_BASE_URL`
- `SDQP_SCIM_TOKEN`
- `SDQP_SCIM_TENANT_ID`
- `SDQP_SCIM_PAGE_SIZE`
- `SDQP_SCIM_TIMEOUT_MS`
- `SDQP_SCIM_RETRY_ATTEMPTS`
- `SDQP_SCIM_RETRY_BACKOFF_MS`
- `SDQP_SCIM_DISABLE_MISSING_USERS`
- `SDQP_SCIM_DISABLE_MISSING_GROUPS`
- `SDQP_SCIM_DELETE_MISSING_USERS`
- `SDQP_SCIM_DELETE_MISSING_GROUPS`
- `SDQP_SECURITY_WEBAUTHN_RP_ID`
- `SDQP_SECURITY_WEBAUTHN_ORIGIN`
- `SDQP_SECURITY_WEBAUTHN_TIMEOUT_MS`
- `SDQP_SECURITY_WEBAUTHN_REQUIRE_UV`
- `SDQP_SECURITY_INTEGRATION_IP_ALLOWLIST`
- `SDQP_SECURITY_INTEGRATION_MTLS_SUBJECTS`
- `SDQP_SECURITY_INTEGRATION_API_KEY`
- `SDQP_SECURITY_INTEGRATION_RATE_LIMIT_MAX`
- `SDQP_SECURITY_INTEGRATION_RATE_LIMIT_WINDOW_SECS`
- `SDQP_SECURITY_CREDENTIAL_ROTATION_ENABLED`
- `SDQP_SECURITY_CREDENTIAL_ROTATION_INTERVAL_SECS`
- `SDQP_SECURITY_CREDENTIAL_ROTATION_RETRY_BACKOFF_SECS`
- `SDQP_SECURITY_CREDENTIAL_ROTATION_MAX_ATTEMPTS`
- `SDQP_SECURITY_CREDENTIAL_ROTATION_MANUAL_AFTER_ATTEMPTS`
- Config sections: `identity_provider`, `security.credential_rotation`, `security.integration_api_keys`, `security.integration_ip_allowlist`, `security.integration_mtls_subjects`.

### Required certificates / credentials / endpoints / tenants / test accounts

- OIDC issuer, authorization, token, and userinfo endpoints.
- OIDC client ID, client credential, registered redirect URI, scopes, and claims mapping.
- SAML SSO and artifact/assertion exchange endpoints.
- SAML entity ID, audience, IdP signing certificate, SP metadata, and accepted assertion attributes.
- SCIM bearer credential and tenant-bound SCIM data set.
- SCIM `/Users` and `/Groups` endpoints containing at least one analyst user, one security-admin user, and groups mapped to SDQP roles/projects.
- WebAuthn RP ID and origin matching the externally reachable SDQP URL.
- A real authenticator enrolled for a test user whose policy requires WebAuthn.
- mTLS CA trust chain, service TLS certificate, client certificate, client private key, allowed client certificate subject, and revocation or rotation path.
- External secrets-manager credential, endpoint, namespace/path, or provider API used to receive rotated integration credentials.

### Pre-run dependencies

- SDQP API is running with the external identity/security configuration loaded.
- PostgreSQL migrations are applied and persistent session, SCIM, integration credential, and credential rotation tables are available.
- The externally reachable SDQP origin matches the configured OIDC redirect URI and WebAuthn origin.
- Network, DNS, TLS trust, and firewall rules allow SDQP to call IdP, SCIM, and secrets-manager endpoints.
- Test accounts are pre-provisioned in the IdP and SCIM tenant with expected groups and MFA policy.
- Local temporary IdP/SCIM providers, bootstrap WebAuthn assertions, and `x-client-cert-subject` header simulation are not used as acceptance evidence.

### Minimal acceptance steps

1. Start SDQP with OIDC provider `oidc`, SAML provider `saml`, SCIM provider `scim20`, WebAuthn RP/origin, integration API key, mTLS subject allowlist, and credential-rotation settings pointed at real external systems.
2. Run SCIM provider pull sync through `POST /auth/scim/sync` and verify users, groups, lifecycle policy, membership changes, and cursor persistence.
3. Start and complete an OIDC SSO login through `POST /auth/sso/start`, the real IdP authorization page, `POST /auth/sso/callback`, and `POST /auth/mfa/verify`.
4. Start and complete a SAML SSO login through `POST /auth/sso/start`, the real IdP SSO flow, `POST /auth/sso/callback`, and WebAuthn verification with a real browser/authenticator ceremony.
5. Trigger medium-risk posture or policy conditions, verify step-up blocking on protected project routes, then clear it through `POST /auth/step-up/verify`.
6. Exercise integration security with real network path and mTLS termination: SCIM calls must require API key/IP policy; HR integration calls must require the allowed client certificate identity.
7. Run credential rotation through `GET /v1/admin/credential-rotations` and `POST /v1/admin/credential-rotations/run`, then prove the rotated credential is accepted where expected and the previous credential is no longer accepted.
8. Verify rotated credential distribution through the external secrets manager or provider API, not only repo-local persistence.

### Pass criteria

- OIDC and SAML flows complete against real IdP tenants and produce expected SDQP user/session state.
- SCIM pull sync uses real provider pages for `/Users` and `/Groups`, persists cursor/state, and applies lifecycle changes.
- WebAuthn challenge and assertion are completed by a real browser/authenticator ceremony for the configured RP ID and origin.
- mTLS acceptance uses real client certificate material and CA trust, not request-header simulation.
- Integration API key, IP allowlist, mTLS policy, rate limit, and scope checks are enforced.
- Credential rotation persists state, audits attempts, enforces the active credential, rejects stale credential material, and distributes the new material through an external secrets path.
- No acceptance evidence depends on mock IdP/SCIM, bootstrap WebAuthn assertions, local temporary providers, or `x-client-cert-subject` header-only behavior.

### Common failure causes

- IdP redirect URI, issuer, audience, entity ID, or callback URL mismatch.
- OIDC claims or SAML attributes do not map to expected SDQP user, tenant, role, or group fields.
- SCIM token lacks `/Users` or `/Groups` read permission, or provider pagination does not match configured page size.
- WebAuthn RP ID/origin does not match the browser URL, or the authenticator is not enrolled for the test user.
- Service TLS trust chain or client certificate subject does not match the configured allowlist.
- Credential rotation updates repo-local state but no external secrets manager or provider distribution is configured.
- Acceptance accidentally uses local mock providers, sample credentials, or header-simulated mTLS.

## Module 6 external acceptance checklist

### Required external systems

- Real TEE/enclave runtime capable of attesting the SDQP protected workload.
- Real attestation endpoint returning secure attestation results and workload measurements.
- Real KMS/HSM provider endpoint, such as Vault Transit, cloud KMS, HSM, or equivalent provider.
- KMS release policy binding successful attestation and expected measurement to data-key generation, unwrap, and rewrap.
- External Stage 8 runtime dependencies for snapshot creation, encrypted object storage, persistence, and audit evidence.

### Required environment variables / config items

- `SDQP_KMS_PROVIDER`
- `SDQP_KMS_ENDPOINT`
- `SDQP_KMS_MASTER_KEY_ID`
- `SDQP_KMS_KEY_RING`
- `SDQP_KMS_AUTH_TOKEN`
- `SDQP_KMS_REGION`
- `SDQP_KMS_KEY_VERSION`
- `SDQP_KMS_ROTATION_ENABLED`
- `SDQP_KMS_ROTATION_CYCLE_INTERVAL_SECS`
- `SDQP_KMS_ROTATION_BATCH_LIMIT`
- `SDQP_KMS_DEK_ROTATION_DAYS`
- `SDQP_KMS_KEK_ROTATION_DAYS`
- `SDQP_KMS_ALLOW_DEK_ROTATION`
- `SDQP_KMS_ALLOW_KEK_REWRAP`
- `SDQP_SECURITY_TEE_PROVIDER`
- `SDQP_SECURITY_TEE_ATTESTATION_URL`
- `SDQP_SECURITY_TEE_MEASUREMENTS`
- Shared runtime config: `SDQP_POSTGRES_DSN`, `SDQP_CLICKHOUSE_HTTP_URL`, `SDQP_S3_ENDPOINT`, `SDQP_S3_BUCKET_SNAPSHOTS`, `SDQP_KAFKA_BROKERS`.
- Config sections: `kms`, `kms.rotation`, `security.tee`, `object_store`, `database`, `kafka`.

### Required certificates / credentials / endpoints / tenants / test accounts

- TEE runtime identity and workload measurement policy.
- Attestation endpoint URL and expected measurements for the SDQP protected workload.
- Attestation service trust root, quote verification material, or provider-specific verification credentials.
- KMS/HSM endpoint, master key ID, key ring or namespace, key version, region, and auth credential.
- KMS/HSM policy proving DEK generation, unwrap, wrap, and rewrap are allowed only after successful attestation.
- Object-store credentials and buckets for encrypted snapshots.
- System-admin test account for `/v1/admin/key-rotations` and `/v1/admin/key-rotations/run`.
- Analyst or equivalent test account able to create a snapshot and read it after rotation.

### Pre-run dependencies

- SDQP API and any worker path needed for query/snapshot creation are running with external KMS and TEE configuration.
- PostgreSQL, ClickHouse, object store, and Kafka dependencies are reachable and initialized.
- A query path can create at least one encrypted snapshot under the external KMS provider.
- TEE attestation is enabled on protected project routes and returns a measurement in `SDQP_SECURITY_TEE_MEASUREMENTS`.
- KMS provider must be real and externally reachable; mock, provider-ready boundary text, and contract-style providers are not final acceptance evidence.
- Existing Stage 8 repo-local UAT is not rerun or counted as real TEE-backed key-release acceptance.

### Minimal acceptance steps

1. Start SDQP with a real KMS/HSM provider and real TEE attestation provider.
2. Verify protected project routes reject access when attestation is unavailable, insecure, or measurement-mismatched.
3. Verify the same protected routes succeed when the external attestation endpoint reports a secure expected measurement.
4. Create an encrypted snapshot through the normal query flow and confirm metadata records the external KMS provider, key ID/version, wrapped DEK, and persisted key-rotation state.
5. Age or select a due snapshot, then call `GET /v1/admin/key-rotations` to confirm the DEK/KEK due state.
6. Run `POST /v1/admin/key-rotations/run` against the due snapshot or batch.
7. Verify KMS/HSM logs or policy decisions show generate/unwrap/rewrap operations were released only after successful TEE attestation.
8. Read the snapshot after rotation and verify plaintext results are unchanged while DEK ID, ciphertext, key version, last rewrap time, persisted `key_rotation_state`, and key lifecycle audit events changed as expected.

### Pass criteria

- Attestation failure blocks protected access and prevents key-release dependent operations.
- Successful attestation with expected measurement enables protected access and KMS key release.
- DEK generation, unwrap, wrap, and rewrap use the real external KMS/HSM provider, not mock or contract-only behavior.
- Key rotation changes DEK/ciphertext and/or KEK wrapping as expected while preserving decrypted snapshot content.
- `key_rotation_state` and audit events record provider, KEK ID, DEK ID, key version, due state, operation, status, and cycle ID.
- External KMS/HSM audit logs independently corroborate the SDQP key lifecycle operations and attestation-bound release policy.
- `/v1/snapshots/{snapshot_id}/refresh` alone is not counted as Module 6 closure; final evidence must include external TEE-backed key release.

### Common failure causes

- TEE measurement does not match `SDQP_SECURITY_TEE_MEASUREMENTS`.
- Attestation endpoint is reachable but not bound to the actual protected SDQP workload.
- KMS policy allows key operations without attestation, so key release is not enclave-bound.
- KMS provider setting falls back to mock, Vault contract mode, or provider alias behavior rather than a real provider handshake.
- KMS auth credential lacks generate, unwrap, wrap, or rewrap permission.
- KMS key version, key ring, master key, namespace, or region does not match the configured key material.
- Object-store or database state is stale, so encrypted snapshot metadata does not reflect the external rotation run.

## Module 9 external acceptance checklist

### Required external systems

- Real RFC3161 TSA endpoint.
- Real judicial-chain or blockchain anchoring endpoint/network.
- Certificate issuer or signing material for evidence package authenticity, plus trust-chain policy.
- Optional mTLS client certificate/key if the TSA, anchoring provider, or certificate service requires it.
- External Stage 10 runtime dependencies for evidence package export, anchor refresh, download authorization, persistence, and audit evidence.

### Required environment variables / config items

- `SDQP_TSA_PROVIDER`
- `SDQP_TSA_BASE_URL`
- `SDQP_TSA_API_KEY`
- `SDQP_TSA_AUTHORITY`
- `SDQP_TSA_TIMEOUT_MS`
- `SDQP_TSA_REQUIRE_EXTERNAL`
- `SDQP_BLOCKCHAIN_PROVIDER`
- `SDQP_BLOCKCHAIN_BASE_URL`
- `SDQP_BLOCKCHAIN_API_KEY`
- `SDQP_BLOCKCHAIN_NETWORK`
- `SDQP_BLOCKCHAIN_TIMEOUT_MS`
- `SDQP_BLOCKCHAIN_REQUIRE_EXTERNAL`
- Shared runtime config: `SDQP_POSTGRES_DSN`, `SDQP_CLICKHOUSE_HTTP_URL`, `SDQP_S3_ENDPOINT`, `SDQP_S3_BUCKET_EVIDENCE`, `SDQP_KAFKA_BROKERS`.
- Config sections: `integrations.tsa`, `integrations.blockchain_anchor`, `object_store`, `database`, `kafka`.

### Required certificates / credentials / endpoints / tenants / test accounts

- RFC3161 TSA endpoint, authority name, authentication credential, signing certificate chain, and accepted timestamp policy.
- Judicial-chain/blockchain JSON-RPC or provider endpoint, network name, credential, chain ID or network identifier, and receipt verification method.
- Certificate issuer identity, signing material or service credential, certificate serial-number policy, trust anchors, and validation policy.
- Any required mTLS CA, client certificate, and private key.
- Analyst test account able to create a snapshot and submit evidence export.
- Auditor or analyst test account able to refresh anchor, authorize completed-only download, and download the evidence package.

### Pre-run dependencies

- SDQP API is running with `SDQP_TSA_REQUIRE_EXTERNAL` and `SDQP_BLOCKCHAIN_REQUIRE_EXTERNAL` enabled.
- The configured TSA and anchoring provider are real external providers; mock providers and local in-process servers are rejected.
- PostgreSQL, ClickHouse, object store evidence bucket, and Kafka dependencies are reachable and initialized.
- A completed snapshot exists for export, or the query path can create one.
- Network, DNS, TLS trust, provider credentials, and optional mTLS material are configured for TSA, anchor, and certificate/trust-chain services.
- Existing Stage 10 repo-local UAT is not rerun or counted as real TSA, judicial-chain/blockchain, or certificate acceptance.

### Minimal acceptance steps

1. Start SDQP with real TSA and blockchain/judicial-chain provider config, and require external providers.
2. Create or select a completed snapshot eligible for evidence export.
3. Submit an evidence export through `POST /v1/exports/evidence` using a jurisdiction template that requires timestamp, anchor, certificate, and manifest completeness.
4. Verify the package enters the expected pending or completed anchor state and records external provider names, timestamp authority, anchor network, transaction/receipt fields, certificate serial number, manifest digests, and `provider_runtime_mode` as external.
5. Confirm early download authorization through `POST /v1/exports/tasks/{task_id}/authorize-download` is rejected while the anchor is pending.
6. Run `POST /v1/exports/tasks/{task_id}/refresh-anchor` until the real provider returns a confirmed receipt, or capture the provider-defined pending behavior with a documented recheck interval.
7. Verify the completed export is marked verified, download-ready, and no longer refresh-recommended.
8. Authorize and download through `POST /v1/exports/tasks/{task_id}/authorize-download` and `GET /v1/exports/download/{download_token}`; verify one-time token consumption.
9. Cross-check persisted `evidence_packages`, `export_tasks`, and `download_authorizations` rows, plus TSA/chain/certificate provider-side receipts or logs.

### Pass criteria

- Mock TSA and mock anchor providers are rejected when external providers are required.
- RFC3161 timestamp is issued by the real TSA and validates against the configured authority/trust chain.
- Judicial-chain/blockchain anchor receipt is created, refreshed if pending, and verified against the real network/provider.
- Evidence package includes complete metadata manifest, hash chain, timestamp receipt, anchor receipt, certificate of authenticity, jurisdiction marker, and verification status.
- Download authorization is rejected before completion and allowed only after verified completion.
- Download token is one-time use and persisted as consumed.
- Provider-side receipts/logs corroborate TSA timestamping, chain anchoring, certificate/trust-chain validation, and refresh/download sequence.

### Common failure causes

- `SDQP_TSA_REQUIRE_EXTERNAL` or `SDQP_BLOCKCHAIN_REQUIRE_EXTERNAL` is unset, allowing local/mock providers.
- TSA response is not RFC3161-compatible or does not validate against the configured authority/trust chain.
- Anchor provider returns mismatched network, digest, transaction ID, proof, confirmation time, or status semantics.
- Certificate issuer/trust anchors are missing or do not bind to the evidence package manifest and hash-chain digest.
- Provider credentials lack timestamping, anchoring, receipt refresh, or verification permissions.
- Provider confirmation latency exceeds the test window and the refresh/recheck policy is not documented.
- Evidence bucket, database, or audit dependencies are not initialized, causing package or authorization persistence gaps.

Overall external acceptance summary table:

| Item | Current state |
| --- | --- |
| What the repository has completed | Repo-local implementation and evidence are complete. Modules 1, 2, 3, 4, 5, 7, 8, 10, 11, and 13 are done repo-locally. Module 6 persistent KEK/DEK rotation lifecycle runtime is implemented. Module 9 evidence export/certification provider hardening is implemented. Module 12 SCIM runtime and credential rotation automation are implemented. |
| Why Module 6 remains blocked | Final acceptance requires real TEE/enclave runtime, attestation endpoint, expected measurement policy, real KMS/HSM endpoint and credentials, and proof that key release is bound to successful attestation. Those systems are external to the repo and are not currently configured. |
| Why Module 9 remains blocked | Final acceptance requires real RFC3161 TSA, judicial-chain/blockchain provider, certificate/trust-chain material, optional mTLS material, and external Stage 10 runtime credentials/dependencies. The repo currently only has repo-local boundary evidence. |
| Why Module 12 remains blocked | Final acceptance requires real OIDC/SAML/SCIM IdP tenants, real WebAuthn browser/authenticator ceremony, real mTLS certificate lifecycle, and external secrets-manager/provider distribution for rotated credentials. Those systems are external to the repo and are not currently configured. |
| Acceptance order after external environments are ready | Run Module 12 first to validate identity, trusted access, WebAuthn, mTLS, SCIM, and credential distribution. Run Module 6 second to validate TEE-backed key release and KMS/HSM rotation. Run Module 9 third to validate evidence export against real TSA, judicial-chain/blockchain, certificate/trust-chain, and completed-only download gating. |
