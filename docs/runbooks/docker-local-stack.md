# Docker 本地整栈运行

## 目标

通过 Docker 一键启动 SDQP 本地测试版，包括：

- PostgreSQL
- ClickHouse
- MinIO
- Redpanda
- MailHog
- MockServer
- API
- Worker
- Frontend

## 启动

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/docker-up.ps1
```

## 手工 smoke

如果只想验证容器健康和主链路登录/查询：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/docker-smoke.ps1
```

## 访问地址

- Frontend: `http://127.0.0.1:4173`
- API: `http://127.0.0.1:8080`
- Worker: `http://127.0.0.1:8081`
- MailHog: `http://127.0.0.1:18025`
- MockServer: `http://127.0.0.1:11080`
- MinIO Console: `http://127.0.0.1:19001`

## 当前限制

- 当前 Docker 版仍承载“本地验证版”业务实现，不等同于最终生产版。
- 若本机 Docker daemon 未启动，`docker-up.ps1` 和 `docker-smoke.ps1` 无法完成 Stage 1 gate。
