# Local Verification Runbook

## Preconditions

- Rust toolchain from `rust-toolchain.toml`
- Node.js and npm for `apps/sdqp-frontend`
- Optional but recommended:
  - `cargo install cargo-audit`
  - `cargo install cargo-deny`

## Bootstrap

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
```

## Full Gate

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-all.ps1
```

The gate currently runs:

1. `cargo fmt --all --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo audit` when installed
4. `cargo deny check` when installed
5. `cargo test --workspace`
6. `npm test -- --run`
7. `npm run build`

## Phase 7 Assets

- Audit search fixtures: `D:\Project\SDQP\tests\fixtures\phase7`
- Phase 7 UAT and performance smoke: `D:\Project\SDQP\apps\sdqp-api\tests\uat_phase7_hardening.rs`
- Workspace deny policy: `D:\Project\SDQP\deny.toml`
