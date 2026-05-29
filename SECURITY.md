# Security Policy

## Project status

SDQP is a **reference / portfolio implementation**, not a production-hardened product.
It has **not** undergone an independent security audit. Three modules are intentionally
"provider-ready" rather than fully accepted, because final acceptance requires real
external infrastructure that is out of scope for this repository:

- **Module 6 (Encryption/KMS)** — requires a real TEE/HSM/KMS with attestation-bound key release.
- **Module 9 (Evidence)** — requires a real RFC 3161 TSA and judicial-chain/blockchain endpoint.
- **Module 12 (System security)** — requires a real IdP (OIDC/SAML/SCIM), WebAuthn ceremony, mTLS CA, and external secrets manager.

**Do not deploy this against real sensitive data** without completing those integrations
and a professional security review.

## Reporting a vulnerability

Please report security issues **privately** rather than opening a public issue.

- Email: **yitian2018123@gmail.com**
- Include: a description, affected component/path, reproduction steps, and impact.
- You can expect an acknowledgement within a reasonable timeframe. As this is a
  community/portfolio project maintained on a best-effort basis, there is no formal SLA.

Please do not include real personal data, credentials, or other sensitive material in
your report.

## Scope notes

- The repository ships only non-secret development placeholders (e.g. `dev-*` tokens,
  `mock` providers). Real secrets are expected in `configs/secrets.local.toml`, which is
  git-ignored and never committed.
- Dependency advisories are tracked with `cargo audit` and `cargo deny check`.
