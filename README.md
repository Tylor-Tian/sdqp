# SDQP — Sensitive Data Query & Protection

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Language: Rust](https://img.shields.io/badge/Rust-1.93-orange.svg)](rust-toolchain.toml)
[![Frontend: React 19 + TS](https://img.shields.io/badge/Frontend-React_19_%2B_TypeScript-3178c6.svg)](apps/sdqp-frontend)

SDQP is a modular platform for **querying, analysing, and producing legal evidence
from sensitive data while keeping that data under tight, auditable control.** It is
built around the principle that convenience and security are not mutually exclusive:
analysts get an Excel-like pivot/drill-down experience, while every byte of access is
permission-gated, encrypted, watermarked, and recorded in a tamper-evident audit log.

The system is organised as **13 security/governance domains**, each implemented as an
independent Rust crate so it can be developed, tested, and reused on its own.

---

## ⚠️ Authorship & AI collaboration (please read)

The **architecture and system design were authored and directed by me
([Tylor Tian](mailto:yitian2018123@gmail.com))**. The **implementation was produced
primarily through AI pair-programming** (OpenAI Codex / Claude Code) under my direction
and review. I own the design decisions and can walk through every architectural
trade-off in the codebase.

This is stated openly and on purpose — the project is shared as a demonstration of
*system design + AI-assisted delivery*, not as hand-typed-from-scratch code. See
[`NOTICE`](NOTICE) for the formal attribution.

## ⚠️ Project maturity

This is a **reference / portfolio implementation**, not a production-hardened product.

- All in-repository functionality is implemented and passes the quality gates below.
- **Three modules are intentionally "provider-ready" rather than fully accepted**, because
  final acceptance requires real external infrastructure that is out of scope for this
  repo (see [Module status](#module-status)):
  - **Module 6 (Encryption/KMS)** — needs a real TEE/HSM/KMS with attestation-bound key release.
  - **Module 9 (Evidence)** — needs a real RFC 3161 TSA and judicial-chain/blockchain endpoint.
  - **Module 12 (System security)** — needs a real IdP (OIDC/SAML/SCIM), WebAuthn ceremony, mTLS CA, and external secrets manager.

Do **not** deploy this against real sensitive data without completing those integrations
and an independent security review.

---

## What problem it solves

Organisations that must expose sensitive data (PII, financial, medical, legal) to
investigators and analysts face a tension: too little access blocks legitimate work;
too much access leaks data and breaks compliance. SDQP resolves this with **defence in
depth**:

- **Least privilege** — field-level + row-level grants, requested on demand, auto-revoked on expiry / org change / project close.
- **Full-chain auditability** — who, when, why, on what, with what result — all hash-chained and tamper-evident.
- **Layered security** — encryption, watermarking, isolation, and audit stacked so a single breach is not enough to leak data.
- **Multi-jurisdiction compliance** — GDPR, eIDAS, PIPL, HIPAA, FRE, and more, via pluggable profiles.

## Architecture overview

```
            ┌──────────────────────────────────────────────┐
            │ Module 12: System Security (authn, RBAC,      │  (all modules depend)
            │ continuous auth, memory protection)           │
            └───────────────────────┬──────────────────────┘
            ┌───────────────────────┴──────────────────────┐
            │ Module 5: Tenant & Project Isolation          │  (all modules depend)
            └───────────────────────┬──────────────────────┘
   ┌──────────┬──────────┬──────────┼──────────┬──────────┬──────────┐
   ▼          ▼          ▼          ▼          ▼          ▼          ▼
 HR(3)   Classify(7)  Audit(11)  Encrypt(6) Watermark(10) ...
   │          │          ▲ │          │
   ▼          │          │ │(events from all modules)
Approval(4)   │       UEBA(13)
   │          ▼          │
   ▼   Permission Engine(2) ◄─(suspend)─┘
       │
       ▼
   Datasource Adapter(1)  ──►  Data View / Analysis(8, DataFusion)  ──►  Evidence(9)
```

| # | Crate | Responsibility |
|---|-------|----------------|
| 1 | `sdqp-datasource-adapter` | Unified async query abstraction over REST / RPC / Hive / RDBMS, with pushdown, snapshots, circuit breaking, scheduling |
| 2 | `sdqp-permission-engine` | Field/row-level grant lifecycle, merge (deny-wins), query-time enforcement, auto-revocation |
| 3 | `sdqp-hr-integration` | Org/identity sync + approver resolution (Workday, SAP SF, Feishu, LDAP) |
| 4 | `sdqp-approval-engine` | Configurable multi-step approval flows, IM notifications (Feishu/Slack/DingTalk/Telegram/Email), escalation |
| 5 | `sdqp-tenant-isolation` | Tenant/project context, scope guards, lifecycle, object-store namespacing |
| 6 | `sdqp-encryption` | Envelope encryption (RK→KEK→DEK), KMS adapters, key rotation, masked+watermarked decryption pipeline |
| 7 | `sdqp-data-classification` | L1–L5 classification, regulation/retention metadata, rule-version governance |
| 8 | `sdqp-data-view` | Server-side OLAP on **Apache DataFusion + Arrow**: pivot, drill-down, paginated detail (no raw dataset ever reaches the browser) |
| 9 | `sdqp-evidence` | Court-grade evidence packages: hash chains, trusted timestamps (TSA), optional blockchain anchoring, jurisdiction profiles |
| 10 | `sdqp-watermark` | Invisible watermark embedding (text/OOXML/PDF/JPEG-DCT) + detection API for DLP |
| 11 | `sdqp-audit` | Append-only, hash-chained, tamper-evident audit log with checkpoints, forwarding, retention, controlled-deletion tombstones |
| 12 | `sdqp-system-security` | SSO/SCIM/MFA, RBAC + separation-of-duties, continuous auth, memory protection, exfiltration detection |
| 13 | `sdqp-ueba` | User & entity behaviour analytics over the audit stream: anomaly rules, risk scoring, response orchestration |

Supporting crates: `sdqp-core`, `sdqp-contracts`, `sdqp-config`, `sdqp-test-kit`,
`sdqp-mcp-gateway`, `sdqp-sqlx`. Applications: `sdqp-api`, `sdqp-worker`, `sdqp-frontend`.

## Tech stack

- **Language / runtime:** Rust 1.93 (edition 2024), Tokio async
- **Analytics:** Apache DataFusion + Apache Arrow
- **Frontend:** TypeScript + React 19 (Vite)
- **Transport:** REST/HTTPS, gRPC (tonic), WebSocket
- **Storage:** PostgreSQL (metadata), ClickHouse (audit + UEBA), object storage (snapshots)
- **Crypto/keys:** AES-256-GCM envelope encryption; pluggable KMS (AWS/Azure/Aliyun/Vault)

## Module status

Repo-local acceptance (from [`docs/current-state/design-gap-matrix.md`](docs/current-state/design-gap-matrix.md)):
**10 done · 0 open · 3 blocked on external infrastructure only.**

| Module | Status | Note |
|--------|--------|------|
| 1, 2, 3, 4, 5, 7, 8, 10, 11, 13 | ✅ done (repo-local, non-mock) | Implemented with focused + UAT test evidence |
| 6 Encryption/KMS | ⛔ blocked (external) | Key-lifecycle runtime done; needs real TEE/KMS attestation |
| 9 Evidence | ⛔ blocked (external) | Package/cert hardening done; needs real TSA / judicial chain |
| 12 System security | ⛔ blocked (external) | SCIM/credential-rotation done; needs real IdP/WebAuthn/mTLS |

## Repository layout

```
crates/      13 domain crates + core/contracts/config/test-kit/mcp-gateway/sqlx
apps/        sdqp-api (HTTP/gRPC), sdqp-worker (background jobs), sdqp-frontend (React)
configs/     layered TOML config (base/dev/...); secrets via *.local.toml (gitignored)
db/          PostgreSQL migrations, ClickHouse init
proto/       gRPC contracts          openapi/   generated OpenAPI
deploy/ docker/ docker-compose*.yml  scripts/   PowerShell build/test/smoke scripts
docs/        design docs, ADRs, runbooks, current-state baseline
tests/       cross-cutting fixtures / integration / e2e / performance
```

## Getting started

### Prerequisites
- Rust 1.93 (pinned via [`rust-toolchain.toml`](rust-toolchain.toml))
- Node.js 20+ (for the frontend)
- Docker Desktop (for the infrastructure / Hive / prod-sim compose stacks)

### Configuration
```bash
cp .env.example .env
# secrets go in configs/secrets.local.toml (gitignored) — never commit real secrets
```

### Build & test (backend)
```bash
cargo build --workspace
cargo test  --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

### Run the API / worker
```bash
cargo run -p sdqp-api      # HTTP/gRPC API (default 127.0.0.1:8080)
cargo run -p sdqp-worker   # background worker  (default 127.0.0.1:8081)
```

### Frontend
```bash
cd apps/sdqp-frontend
npm install
npm run dev      # dev server on :4173
npm test         # vitest
npm run build
```

### Docker
```bash
docker compose -f docker-compose.infra.yml up -d   # Postgres / ClickHouse / object store / Kafka
docker compose up -d                               # app stack
# Windows helpers live in scripts/ (e.g. scripts/docker-up.ps1, scripts/test-all.ps1)
```

## Quality gates

The repository passes: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo audit`,
`cargo deny check`, `cargo test --workspace`, plus the frontend `npm test` and
`npm run build`. The aggregate gate is `scripts/test-all.ps1`.

## Documentation

- System design: [`SDQP_SYSTEM_DESIGN_v1.2.md`](SDQP_SYSTEM_DESIGN_v1.2.md) (and v1.1)
- Current baseline & gap matrix: [`docs/current-state/`](docs/current-state)
- ADRs / API / runbooks: [`docs/`](docs)

> Note: some design and planning documents are written in Chinese, reflecting the
> project's origin. The architecture and compliance coverage are jurisdiction-neutral
> and explicitly include GDPR / eIDAS profiles.

## Security

This project is a reference implementation and has **not** undergone an independent
security audit. Do not use it with real sensitive data without completing the external
integrations (Modules 6/9/12) and a professional review. Please report security issues
privately to the maintainer rather than via public issues.

## License

Licensed under the [Apache License 2.0](LICENSE). See [`NOTICE`](NOTICE) for attribution.
