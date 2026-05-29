# Snapshot Lifecycle API（Stage 8）

本文档说明 Stage 8 新增的快照生命周期接口，以及它们与对象存储、授权生命周期的绑定关系。

## 目标

- 所有快照继续以加密 payload 形式写入对象存储
- 快照元数据在 PostgreSQL 中持久化，包含授权、保留期和删除状态
- 删除、恢复、刷新动作全部写审计并清理缓存命中关系

## 接口

### `POST /v1/snapshots/{snapshot_id}/delete`

- 语义：软删除快照
- 行为：
  - 将 `delete_state` 置为 `soft_deleted`
  - 记录 `deleted_at` 与删除原因
  - 清理 `snapshot_cache_entries` 与内存态缓存索引
  - 不删除对象存储中的密文对象，允许后续恢复

### `POST /v1/snapshots/{snapshot_id}/restore`

- 语义：恢复软删除快照
- 行为：
  - 将 `delete_state` 恢复为 `active`
  - 清空删除原因与 `deleted_at`
  - 保留对象存储中的原始密文对象

### `POST /v1/snapshots/{snapshot_id}/refresh`

- 语义：刷新快照密钥包装信息
- 行为：
  - 使用当前 KMS/Mock KMS 执行 DEK 包装重写（rewrap）
  - 更新 `encrypted_payload_json.key_version`
  - 记录 `last_rewrapped_at`
  - 返回基于 `RotationPolicy` 的轮换建议

### `DELETE /v1/snapshots/{snapshot_id}`

- 语义：不可恢复删除
- 行为：
  - 删除对象存储中的密文对象（若存在）
  - 将 `delete_state` 置为 `purged`
  - 记录 `purged_at`
  - 清空内存中的密文字段，并移除缓存命中关系
  - 后续恢复请求应返回 `409 Conflict`

## 生命周期字段

快照元数据新增并持久化以下字段：

- `owner_user_id`
- `grant_id`
- `grant_expires_at`
- `retention_until`
- `data_fingerprint`
- `object_bucket`
- `object_size_bytes`
- `delete_state`
- `delete_reason`
- `deleted_at`
- `purged_at`
- `last_rewrapped_at`

## 验证

Stage 8 gate 使用以下路径验证：

1. 启动 PostgreSQL / ClickHouse / MinIO / MinIO bucket init
2. 运行 `cargo test -p sdqp-encryption`
3. 运行 `cargo test -p sdqp-api --test uat_stage8_snapshot_encryption`
4. 校验：
   - 查询生成的快照对象真实落入 MinIO
   - 软删除后快照页面不可读
   - 恢复后重新可读
   - 刷新后 `last_rewrapped_at` 持久化
   - 硬删除后对象从 MinIO 移除且恢复被拒绝
