# System Security Stage 4

## Summary

`Prod Stage 4` upgrades the local auth stack from password + demo MFA into a production-oriented security slice with:

- mock OIDC / SAML SSO start + callback flow
- SCIM user and group synchronization endpoints
- formal MFA challenge abstraction for TOTP / WebAuthn / biometric
- PostgreSQL-backed refresh rotation metadata and replay detection
- device posture reporting plus continuous risk scoring
- step-up verification endpoint for medium-risk sessions
- session binding checks on IP and device fingerprint

## REST Endpoints

- `POST /auth/sso/start`
  - Starts a mock OIDC or SAML authorization flow.
- `POST /auth/sso/callback`
  - Exchanges a mock callback code into a pending MFA session.
- `POST /auth/mfa/verify`
  - Completes login and issues access/refresh tokens.
- `POST /auth/device-posture`
  - Reports local mock device posture and runs continuous risk evaluation.
- `POST /auth/step-up/verify`
  - Clears a step-up-required session and re-issues rotated tokens.
- `POST /auth/refresh`
  - Rotates refresh tokens and rejects replayed tokens.
- `POST /auth/logout`
  - Revokes the active session bound to the provided refresh token.
- `POST /auth/scim/users`
  - Upserts, disables, or deletes SCIM-managed users.
- `POST /auth/scim/groups`
  - Upserts, disables, or deletes SCIM-managed groups.

## Verification

- `cargo test -p sdqp-system-security`
- `cargo test -p sdqp-contracts`
- `cargo test -p sdqp-api --test uat_stage4_system_security`

## Notes

- `build_router(sample_settings().api)` uses local-dev mock identity-provider defaults.
- `build_persistent_router(...)` persists Stage 4 session and SCIM metadata in PostgreSQL.
- Device posture profiles currently support `trusted`, `legacy`, and `compromised`.
