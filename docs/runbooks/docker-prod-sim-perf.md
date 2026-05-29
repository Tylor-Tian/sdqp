# Docker Prod-Sim Perf Smoke

## Goal

Run a repeatable Stage 13 performance smoke against the `prod-sim` release-shaped stack without requiring a dedicated benchmark environment.

The smoke keeps the scope intentionally small and maps each Stage 13 performance theme onto an existing production API path:

- Permission grant lookup: `GET /v1/permissions/grants/active/datasource-rest`
- Task status polling: `GET /v1/tasks/{task_id}/status`
- Snapshot pivot aggregation: `POST /v1/analysis/pivot`
- Audit ingress visibility: burst `GET /v1/project-context`, then verify `GET /v1/audit/events/search`
- UEBA window latency: denied-query burst, then verify `GET /v1/ueba/alerts`

The default smoke budgets live in `tests/fixtures/stage13/perf-smoke-budget.json`.

## Run On an Existing Stack

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/docker-prod-sim-perf.ps1
```

## Run the Full Stage 13 Perf Gate

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-perf-smoke.ps1
```

## Notes

- This is a smoke gate, not a full benchmark. It validates that the Stage 13 critical paths remain responsive on the local release-shaped compose stack.
- The script also checks API and worker `/metrics` surfaces so perf smoke leaves an observability trail for later dashboard work.
- UEBA latency is measured as wall-clock time from a denied-query burst to alert visibility because the current metrics surface exposes counters rather than latency histograms.
