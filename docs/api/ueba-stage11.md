# Stage 11 UEBA Streaming API

更新时间：2026-03-29

## 目标

Stage 11 将 UEBA 从“请求时基于内存或 ClickHouse 的临时计算”升级为“基于 Redpanda/Kafka 审计事件流的后台持续处理”。

## 输入与处理

- 审计事件继续通过 API 主链路写入 ClickHouse。
- 审计事件同时异步发布到 Kafka topic：`sdqp.audit.events.*`
- `apps/sdqp-api/src/stage11_ueba.rs` 后台循环消费审计 topic，并按租户触发 UEBA 评估。
- UEBA 评估会合并 ClickHouse 历史审计与本批流式事件，避免在 ClickHouse 落地和流消费之间出现窗口遗漏。

## 持久化结果

- 用户基线：`sdqp.ueba_user_baselines`
- 角色/实体基线：`sdqp.ueba_entity_baselines`
- 告警：`sdqp.ueba_alerts`
- 规则命中：`sdqp.ueba_rule_hits`
- Kafka 流偏移：PostgreSQL `stream_offsets`

## API

- `GET /v1/ueba/alerts`
  - 返回当前租户已持久化的 UEBA 告警
  - 聚合 step-up、权限撤销、会话终止计数
- `GET /v1/ueba/baselines`
  - 返回当前租户的用户基线与角色/项目等实体基线

## 响应联动

- `StepUpAuth`：会话 `step_up_required = true`
- `SuspendPermissions`：持久化撤销/挂起相关授权
- `TerminateSession`：持久化终止会话
- 所有新告警都会写入安全通知队列

## 验证

- gate：`scripts/check-stage11-ueba-streaming.ps1`
- 六类异常场景：
  - `HighFrequencyQuery`
  - `ExportSpike`
  - `UnauthorizedQueryBurst`
  - `AfterHoursAccess`
  - `HiddenChannelDns`
  - `HiddenChannelHttp`
