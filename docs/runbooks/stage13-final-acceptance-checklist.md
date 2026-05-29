# Stage 13 Final Acceptance Checklist

Use this checklist before declaring `Prod Stage 13` complete.

## Mandatory Gates

- [ ] `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-all.ps1`
- [ ] `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-release-smoke.ps1`
- [ ] `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-backup-restore.ps1`
- [ ] `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-perf-smoke.ps1`

## Runtime Verification

- [ ] `docker compose -f docker-compose.prod-sim.yml ps` shows the expected Stage 13 services
- [ ] API `/metrics` exposes `sdqp_http_requests_total{service="sdqp-api"}`
- [ ] Worker `/metrics` exposes `sdqp_query_tasks_total{service="sdqp-worker",result="completed"}`
- [ ] API responses emit `x-request-id`
- [ ] API responses emit `x-sdqp-span-id`
- [ ] Worker responses emit `x-request-id`
- [ ] Worker responses emit `x-sdqp-span-id`

## Operational Assets

- [ ] `docs/runbooks/docker-prod-sim.md`
- [ ] `docs/runbooks/docker-prod-sim-backup-restore.md`
- [ ] `docs/runbooks/docker-prod-sim-perf.md`
- [ ] `docs/runbooks/kms-key-recovery.md`
- [ ] `docs/runbooks/release-tagging-policy.md`
- [ ] `deploy/grafana/stage13-prod-sim-dashboard.json`

## Sign-Off Record

- [ ] release tag selected under `docs/runbooks/release-tagging-policy.md`
- [ ] final release note links recorded
- [ ] acceptance date recorded
- [ ] release owner recorded

## Exit Rule

Do not mark `Prod Stage 13` completed until every checklist item above is explicitly satisfied.
