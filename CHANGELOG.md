# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Open-source release scaffolding: root `README.md`, `LICENSE` (Apache-2.0), `NOTICE`,
  `SECURITY.md`, `CONTRIBUTING.md`, and this changelog.

### Changed
- Relicensed the project from a proprietary license to **Apache-2.0**.
- De-sensitized the design documents (removed the internal "confidential" classification
  and internal-strategy references; clarified that vendor/regulation names are pluggable,
  jurisdiction-neutral examples).

### Removed
- Internal AI-continuation / execution hand-off documents and their gate script from the
  published tree (kept out of version control).

## [0.1.0] — 2026-05

Initial baseline of the Sensitive Data Query & Protection (SDQP) system.

13 security/governance domains implemented as independent Rust crates, plus the
`sdqp-api` / `sdqp-worker` services and a React (`sdqp-frontend`) UI.

- **Design v1.0** — initial architecture, 12 modules.
- **Design v1.1** — unified async query interface; analysis layer on Rust + Apache
  DataFusion; added UEBA; added continuous auth, memory protection, covert-channel
  detection, supply-chain security, and SCIM.
- **Design v1.2** — external-infrastructure integration spec (Modules 6/9/12); CI/quality
  gates; cross-module integration test matrix and deployment topology; added the MCP
  Gateway module.

Repo-local module status at this baseline: 10 modules complete (non-mock), 3 modules
"provider-ready" pending real external infrastructure (KMS/TEE, TSA/judicial-chain,
IdP/WebAuthn/mTLS). See [`docs/current-state/design-gap-matrix.md`](docs/current-state/design-gap-matrix.md).

[Unreleased]: https://github.com/Tylor-Tian/sdqp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Tylor-Tian/sdqp/releases/tag/v0.1.0
