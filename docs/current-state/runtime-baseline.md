# 运行态基线说明

更新时间：2026-03-29  
状态：Prod Stage 0 Baseline Frozen

## 应用入口

- API：`apps/sdqp-api/src/main.rs`
- Worker：`apps/sdqp-worker/src/main.rs`
- Frontend：`apps/sdqp-frontend`

## 当前默认开发配置

配置文件：`configs/dev/app.toml`

- API：`127.0.0.1:8080`
- Worker：`127.0.0.1:8081`
- Frontend：`4173`

## 当前已存在模块

- 安全与身份：`sdqp-system-security`
- 租户隔离：`sdqp-tenant-isolation`
- 审计：`sdqp-audit`
- 数据源适配：`sdqp-datasource-adapter`
- 权限引擎：`sdqp-permission-engine`
- 加密：`sdqp-encryption`
- HR 集成：`sdqp-hr-integration`
- 审批：`sdqp-approval-engine`
- 数据分类：`sdqp-data-classification`
- 数据查看：`sdqp-data-view`
- 水印：`sdqp-watermark`
- 证据：`sdqp-evidence`
- UEBA：`sdqp-ueba`

## 当前验证结论

- 单元测试、crate 级 UAT、API 阶段 UAT、前端测试与构建均可通过。
- 当前 gate 仍然是“本地验证版 gate”，不是“生产版 gate”。
- `cargo deny` 仍会报告 `winnow` 重复版本告警，但当前不阻断 Stage 0。

## 后续阶段的硬边界

- Prod Stage 1 必须先交付 Docker 可运行版，再允许推进配置和持久化阶段。
- Prod Stage 2 起生成产物必须进入 `openapi/` 和 `generated/`。
- Prod Stage 3 起正式迁移脚本只能进入 `db/postgres/migrations/` 和 `db/clickhouse/init/`。
