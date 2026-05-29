# Docker Deploy Assets

本目录用于存放 Docker 相关发布与编排资产。

## 当前状态

Prod Stage 1 已补齐以下交付物：

- 根目录 `.dockerignore`
- `apps/sdqp-api/Dockerfile`
- `apps/sdqp-worker/Dockerfile`
- `apps/sdqp-frontend/Dockerfile`
- `apps/sdqp-frontend/nginx.conf`
- `docker-compose.yml`
- `docker-compose.infra.yml`
- `docker-compose.prod-sim.yml`
- `scripts/docker-up.ps1`
- `scripts/docker-smoke.ps1`
- `scripts/docker-prod-sim-up.ps1`
- `scripts/docker-prod-sim-smoke.ps1`
- `scripts/docker-prod-sim-perf.ps1`
- `scripts/check-stage13-release-smoke.ps1`
- `scripts/docker-prod-sim-backup.ps1`
- `scripts/docker-prod-sim-restore.ps1`
- `scripts/check-stage13-backup-restore.ps1`
- `scripts/check-stage13-perf-smoke.ps1`

## 本地使用

启动完整整栈：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/docker-up.ps1
```

只做 smoke：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/docker-smoke.ps1
```

只启动依赖基础设施：

```powershell
docker compose -f docker-compose.infra.yml up -d
```

启动 prod-sim release smoke：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-release-smoke.ps1
```

执行 prod-sim backup/restore smoke：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-backup-restore.ps1
```

执行 prod-sim perf smoke：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-stage13-perf-smoke.ps1
```
