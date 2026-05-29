# Docker Prod-Sim Backup And Restore

This runbook covers the Stage 13 prod-sim disaster-recovery slice for the local Docker stack.

## Scope

- `postgres-data`
- `clickhouse-data`
- `minio-data`

The scripts use volume-level tar archives after the stack is stopped, so the backup captures persisted application state, audit data, and snapshot objects together.

## Scripts

- `scripts/docker-prod-sim-backup.ps1`
- `scripts/docker-prod-sim-restore.ps1`
- `scripts/check-stage13-backup-restore.ps1`

## Manual Flow

1. Start or stop the prod-sim stack so the named volumes exist.
2. Stop the stack without `-v` before backup:

```powershell
docker compose -f docker-compose.prod-sim.yml down --remove-orphans
```

3. Create backup archives:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/docker-prod-sim-backup.ps1
```

4. Remove the old stack and volumes:

```powershell
docker compose -f docker-compose.prod-sim.yml down -v --remove-orphans
```

5. Restore the named volumes:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/docker-prod-sim-restore.ps1
```

6. Start the stack again:

```powershell
docker compose -f docker-compose.prod-sim.yml up -d
```

## Smoke Gate

Run the full disaster-recovery smoke:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-backup-restore.ps1
```

The smoke gate verifies:

- prod-sim can create a persisted snapshot before backup
- backup archives are produced for PostgreSQL, ClickHouse, and MinIO volumes
- the stack can be rebuilt from restored volumes
- the original snapshot page is still readable after restore
- persisted query audit events are still searchable after restore
