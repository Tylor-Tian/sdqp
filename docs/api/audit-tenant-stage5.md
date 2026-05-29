# Stage 5 Audit And Tenant Isolation API

本阶段新增并强化以下接口：

- `GET /v1/projects`
  - 返回当前租户下的项目目录与生命周期状态。
- `POST /v1/projects/{project_id}/state`
  - 驱动项目状态迁移。
  - 支持 `created/active/frozen/archived/deleted`。
  - `frozen` 会禁止新的权限申请与导出。
  - `archived/deleted` 会触发项目下快照清理，并撤销当前内存授权。
- `POST /v1/admin/config-change`
  - 除审计检查点外，新增写入 `config_versions`。
  - 每条版本记录包含 `value`、`payload_hash`、`checkpoint_id`、`approval_binding`。
- `GET /v1/admin/config-drift`
  - 对比当前运行配置与最新批准基线，返回漂移结果。
- `GET /v1/audit/events/search`
  - 继续保留 Stage 4/7 的查询语义，但底层审计链已切到 ClickHouse 持久化恢复。

持久化与外部校验：

- 审计事件与检查点写入 ClickHouse：`sdqp.audit_events`、`sdqp.audit_checkpoints`
- 最新审计副本导出到 `generated/audit/<database>-replica.json`
- 可通过 `cargo run -p sdqp-audit --bin sdqp-audit-verify -- <replica-path>` 独立校验哈希链与检查点

Stage 5 UAT 覆盖：

- `config_versions` 落库
- `/v1/projects` 列表与状态迁移
- `Frozen` 拒绝权限申请与证据导出
- `Archived` 清理项目快照并拒绝项目访问
- ClickHouse 审计写入
- 审计副本导出与独立校验
