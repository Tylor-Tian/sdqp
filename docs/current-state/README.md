# 当前代码基线快照

更新时间：2026-03-29  
对应生产化阶段：Prod Stage 0

本目录用于冻结当前“本地可验证实现版”的代码基线，避免后续生产化改造过程中误判现状。

本目录保留对外有价值的基线与验收材料：

- `design-gap-matrix.md`：各模块设计落地状态（done / open / blocked）与证据
- `external-acceptance-checklist.md`：模块 6/9/12 接入真实外部基础设施的验收清单
- `runtime-baseline.md`：运行态基线说明

> 说明：早期用于 AI 协作续跑的内部上下文文件（`codex-continuation-protocol.md`、`codex-repo-map.md`、`codex-handoff.md`、`codex-handoff.json`）属于内部工程流水，已移出公开发布范围。

## 当前已存在的可运行资产

- Rust workspace 已建立，包含 `sdqp-api`、`sdqp-worker` 和多个领域 crate。
- 前端位于 `apps/sdqp-frontend`，可通过 `npm run dev` 本地运行。
- 根目录已有依赖基础设施编排：`docker-compose.yml`。
- 根目录已有统一 gate 脚本：`scripts/test-all.ps1`。
- 顶层测试目录 `tests/` 已包含 `fixtures/`、`integration/`、`performance/`、`e2e/`。

## 当前已通过的验证

以下命令在 2026-03-29 的 Prod Stage 0 校验中通过：

1. `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-all.ps1`
2. `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-baseline-freeze.ps1`

## 当前明确不是生产版的事实

- 当前没有任何应用容器 `Dockerfile`。
- 当前 `docker-compose.yml` 仅启动依赖基础设施，不启动 API、Worker、Frontend。
- 当前 `proto/` 仍是占位级契约。
- 当前核心数据链路仍以内存态和 mock/stub 为主。
- 当前尚无 `db/` 迁移和初始化脚本的真实内容，仅在 Prod Stage 0 创建了正式目录。

## 目录约定

Prod Stage 0 起，以下目录为后续生产化改造的固定落点：

- `db/postgres/migrations/`
- `db/clickhouse/init/`
- `deploy/docker/`
- `openapi/`
- `generated/`

后续 Codex 不得绕过这些目录另建平行结构，除非设计文档出现明确变更。
