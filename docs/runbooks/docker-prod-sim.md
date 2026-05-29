# Docker Prod-Sim Runbook

## Goal

Bring up a release-shaped local stack that uses the `prod-sim` profile and host ports reserved for Stage 13 smoke:

- Frontend: `http://127.0.0.1:34173`
- API: `http://127.0.0.1:38080`
- Worker: `http://127.0.0.1:38081`
- PostgreSQL: `127.0.0.1:35432`
- ClickHouse HTTP/native: `127.0.0.1:38123` / `127.0.0.1:39000`
- MinIO Console/API: `http://127.0.0.1:39001` / `http://127.0.0.1:39002`
- Redpanda external broker: `127.0.0.1:39092`
- MailHog SMTP/UI: `127.0.0.1:31025` / `http://127.0.0.1:38025`
- MockServer: `http://127.0.0.1:31080`

## Start

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/docker-prod-sim-up.ps1
```

## Smoke Only

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/docker-prod-sim-smoke.ps1
```

## Stage 13 Release Gate

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-release-smoke.ps1
```

## Stage 13 Backup/Restore Gate

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-backup-restore.ps1
```

## Stage 13 Perf Gate

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-perf-smoke.ps1
```

## Notes

- The compose file is `docker-compose.prod-sim.yml`.
- The compose project name is fixed to `sdqp-prod-sim`, and all prod-sim infra host ports are isolated from the default local-docker stack so Stage 13 smoke can run alongside the default stack without container, network, or host-port collisions.
- The app services run with `SDQP_ENVIRONMENT=prod-sim`, but local compose overrides point persistence/object-store/integration dependencies back to the local Docker stack so release smoke can run end to end.
- MinIO initialization creates `sdqp-prod-snapshots` and `sdqp-prod-evidence` for the prod-sim smoke path.
- Backup and restore operations are documented separately in `docs/runbooks/docker-prod-sim-backup-restore.md`.
- Stage 13 perf smoke is documented separately in `docs/runbooks/docker-prod-sim-perf.md`.
- Key recovery is documented in `docs/runbooks/kms-key-recovery.md`.
- Release tagging is documented in `docs/runbooks/release-tagging-policy.md`.
- Final acceptance is tracked in `docs/runbooks/stage13-final-acceptance-checklist.md`.
- The Grafana template for Stage 13 smoke corroboration lives in `deploy/grafana/stage13-prod-sim-dashboard.json`.
