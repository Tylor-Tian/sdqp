# Contributing to SDQP

Thanks for your interest in SDQP. This is primarily a portfolio / reference project, but
issues and pull requests are welcome.

## Project context

The architecture was authored and directed by the maintainer; the implementation was
produced primarily through AI pair-programming (OpenAI Codex / Claude Code) under the
maintainer's direction and review. See [`NOTICE`](NOTICE). Contributions are reviewed
with that same standard: changes should be understandable and defensible, not just
"compiles and passes tests".

## Prerequisites

- Rust 1.93 (pinned via [`rust-toolchain.toml`](rust-toolchain.toml))
- Node.js 20+ (for the frontend)
- Docker Desktop (for the infrastructure / Hive / prod-sim compose stacks)

## Development workflow

1. Fork and create a feature branch off `main`.
2. Make your change, keeping it focused and matching the style of the surrounding code.
3. Run the quality gates locally (see below) — they must pass.
4. Open a pull request describing **what** changed and **why**, and how you verified it.

## Quality gates

Backend:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
cargo deny check
```

Frontend (`apps/sdqp-frontend`):

```bash
npm test -- --run
npm run build
```

On Windows, `scripts/test-all.ps1` runs the aggregate gate.

## Conventions

- Each module is an independent crate under `crates/`; keep module boundaries clean and
  avoid leaking SDQP-specific assumptions into reusable crates.
- Database changes go in `db/postgres/migrations/` and `db/clickhouse/init/`; generated
  artifacts go in `openapi/` and `generated/` — do not create parallel structures.
- Never commit real secrets. Use `configs/secrets.local.toml` (git-ignored); update
  `configs/secrets.example.toml` if you add a new secret key.

## License of contributions

By submitting a contribution, you agree that it is licensed under the
[Apache License 2.0](LICENSE), the same license as the project.
