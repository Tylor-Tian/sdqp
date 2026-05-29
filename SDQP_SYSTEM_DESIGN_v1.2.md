# 敏感数据查询与保护系统（SDQP）— 系统架构设计文档

> **版本**: 1.2
> **日期**: 2026年5月
> **状态**: 公开（开源发布，Apache-2.0）
> **用途**: 系统架构设计文档，每个模块对应一个独立 Rust crate
> **变更记录**:
> - v1.0 — 初始版本，12 个模块
> - v1.1 — 统一异步查询接口；分析层改用 Rust + DataFusion；增加 UEBA 模块；补充持续认证、内存保护、隐蔽通道检测、供应链安全、SCIM 协议
> - v1.2 — 补充外部基础设施接入规范（解除 Module 6/9/12 阻塞）；新增 CI/代码质量门禁标准；新增跨模块集成测试矩阵与部署拓扑；新增 MCP Gateway 模块（模块 14）；更新开发阶段进度状态；产品定位更新

---

> **适用范围说明**: 本文中出现的具体厂商、平台与法规（如飞书、钉钉、Workday、Slack、PIPL、GDPR、eIDAS、国家授时中心等）均为可插拔适配器的示例实现；系统架构本身与具体司法辖区无关，多司法辖区合规通过可配置 profile 支持。

## 目录

- [系统总览](#系统总览)
- [模块 1: 数据源适配层 (sdqp-datasource-adapter)](#模块-1-数据源适配层)
- [模块 2: 权限引擎 (sdqp-permission-engine)](#模块-2-权限引擎)
- [模块 3: 人事系统集成 (sdqp-hr-integration)](#模块-3-人事系统集成)
- [模块 4: 审批流引擎 (sdqp-approval-engine)](#模块-4-审批流引擎)
- [模块 5: 多租户与项目隔离 (sdqp-tenant-isolation)](#模块-5-多租户与项目隔离)
- [模块 6: 加密与密钥管理 (sdqp-encryption)](#模块-6-加密与密钥管理)
- [模块 7: 数据分类分级 (sdqp-data-classification)](#模块-7-数据分类分级)
- [模块 8: 数据查看与分析层 (sdqp-data-view)](#模块-8-数据查看与分析层)
- [模块 9: 电子证据与存证 (sdqp-evidence)](#模块-9-电子证据与存证)
- [模块 10: 暗水印系统 (sdqp-watermark)](#模块-10-暗水印系统)
- [模块 11: 全链路审计日志 (sdqp-audit)](#模块-11-全链路审计日志)
- [模块 12: 系统自身安全 (sdqp-system-security)](#模块-12-系统自身安全)
- [模块 13: 用户与实体行为分析 (sdqp-ueba)](#模块-13-用户与实体行为分析)
- [模块 14: MCP Gateway (sdqp-mcp-gateway)](#模块-14-mcp-gateway)
- [外部基础设施接入规范](#外部基础设施接入规范)
- [代码质量门禁与 CI 规范](#代码质量门禁与-ci-规范)
- [跨模块集成测试矩阵](#跨模块集成测试矩阵)
- [部署拓扑](#部署拓扑)
- [模块依赖关系图](#模块依赖关系图)
- [开发阶段规划](#开发阶段规划)
- [可复用模块清单](#可复用模块清单)

---

## 系统总览

### 产品定位

> **从"帮你通过这次审计"→ 帮你建立持续的数据安全可观测性**

SDQP 不是一次性合规报告生成器，而是敏感数据访问的持续监控基础设施。它的差异化价值在于：AI 工具可以生成合规文档，但无法替代与客户系统深度集成、持续采集不可篡改证据链的基础设施层工作。

### 核心目标

在最大限度保证数据安全的前提下，方便敏感数据的查询、分析以及相关法律证据的出具。

### 设计原则

- **权限最小化**: 所有数据访问按字段级+条件级粒度控制，按需申请、按期回收
- **全链路可审计**: 谁在什么时候因为什么做了什么、结果怎样，全部有记录且防篡改
- **安全纵深**: 加密、水印、隔离、审计多层叠加，单点突破不足以造成数据泄露
- **模块独立性**: 每个模块是独立 Rust crate，接口清晰，可独立开发、测试、复用
- **AI 原生接入**: 通过 MCP Gateway 对 AI Agent 提供受控数据访问，SDQP 作为 AI 工作流的安全代理层

### 技术栈

- **主语言**: Rust（核心运行时，包括数据分析引擎）
- **分析引擎**: Apache DataFusion（Rust 原生查询引擎）+ Apache Arrow（列式内存格式）
- **前端**: TypeScript + React（数据查看与分析层 UI）
- **AI 接入**: MCP Server 协议（模块 14）
- **异步运行时**: Tokio（所有查询接口统一异步）
- **通信协议**: gRPC（内部模块间）、REST/HTTPS（外部接口）、WebSocket（查询状态推送）、MCP（AI Agent 接入）
- **存储**: PostgreSQL（元数据）、ClickHouse（审计日志 + UEBA 分析）、对象存储（快照）
- **密钥管理**: HSM / 云 KMS（AWS KMS、Azure Key Vault、阿里云 KMS、HashiCorp Vault）

---

## 模块 1: 数据源适配层

**crate 名称**: `sdqp-datasource-adapter`
**当前状态**: ✅ repo-local 完成

### 1.1 模块职责

提供统一的数据源抽象，屏蔽 RESTful 接口、RPC 接口、Hive 离线数据库等异构数据源的协议差异、延迟差异和查询能力差异。所有数据访问均通过本层，确保无论底层数据源是什么，上层的安全控制（权限过滤、加密、审计）都一致执行。

### 1.2 核心 Trait 定义

```rust
/// 所有数据源适配器实现此 trait
pub trait DataSourceAdapter: Send + Sync {
    /// 建立连接
    async fn connect(&self, config: &DataSourceConfig) -> Result<Connection>;

    /// 执行统一查询
    async fn execute_query(&self, query: &UnifiedQuery) -> Result<QueryResult>;

    /// 声明数据源能力（支持哪些过滤、投影、聚合）
    fn capabilities(&self) -> SourceCapabilities;

    /// 健康检查
    async fn health_check(&self) -> HealthStatus;

    /// 断开连接
    async fn disconnect(&self) -> Result<()>;
}
```

### 1.3 支持的数据源类型

| 数据源类型 | 协议 | 延迟特征 | 条件下推能力 |
|-----------|------|---------|------------|
| RESTful API | HTTPS / JSON | 毫秒到秒级 | 仅查询参数；复杂条件需后过滤 |
| RPC 服务 | gRPC / Thrift / Dubbo | 毫秒级 | 取决于服务定义；适配器将 UnifiedQuery 翻译为 RPC 请求 |
| Hive / 离线数据库 | JDBC / Thrift HiveServer2 | 秒到分钟级 | 完整 SQL 下推；支持分区裁剪和谓词下推 |
| RDBMS（预留） | JDBC / 原生驱动 | 毫秒级 | 完整 SQL 下推 |

### 1.4 查询抽象: UnifiedQuery

```rust
pub struct UnifiedQuery {
    /// 请求的字段列表，与权限授权对应
    pub fields: Vec<FieldSelector>,
    /// WHERE 等价的过滤条件，来自权限条件
    pub conditions: Vec<FilterCondition>,
    /// 分页：偏移量/游标
    pub pagination: Option<Pagination>,
    /// 最大执行时间（Hive 默认更长）
    pub timeout: Duration,
    /// 执行模式（v1.1: 统一为异步，具体策略由适配器决定）
    pub execution_mode: ExecutionMode,
}

pub enum ExecutionMode {
    /// 异步执行：提交查询返回 task_id，客户端通过轮询或 WebSocket 获取结果。
    /// 所有数据源统一使用此模式对外暴露，适配器内部根据数据源特性决定：
    ///   - 低延迟数据源（REST/RPC）：适配器内部同步执行，但对调用方仍表现为异步接口
    ///   - 高延迟数据源（Hive）：真异步提交，后台轮询完成状态
    Async,
    /// 快照模式：执行查询后加密结果存为不可变快照，返回 snapshot_id。
    /// 在 Async 基础上增加持久化步骤。
    Snapshot,
}
```

#### 统一异步查询接口（v1.1）

所有数据查询 API 统一为异步模式，工作流程如下：

1. 客户端提交查询 → 服务端立即返回 `task_id`
2. 服务端根据数据源类型选择执行策略（同步执行或真异步提交）
3. 客户端通过两种方式获取结果：
   - **轮询**: `GET /tasks/{task_id}/status` → Pending | Running | Completed | Failed
   - **WebSocket 推送**: 订阅 `ws://tasks/{task_id}` 接收状态变更和结果流
4. 查询完成后结果写入快照（如果是 Snapshot 模式）或缓存（如果是 Async 模式）
5. 长时间运行的查询支持取消：`DELETE /tasks/{task_id}`

### 1.5 条件下推策略

每个适配器声明 `SourceCapabilities` 结构体：

```rust
pub struct SourceCapabilities {
    pub supported_operators: Vec<Operator>,
    pub supported_logical_operators: Vec<LogicalOperator>,
    pub supports_field_projection: bool,
    pub supports_pagination: bool,
}
```

适配路由器（Adapter Router）将 UnifiedQuery 的条件拆分为：

- **pushdown_conditions**: 发送到数据源执行
- **postfilter_conditions**: 数据返回后在内存中过滤

### 1.6 快照与缓存策略

快照生命周期绑定到权限授权：TTL = min(权限授权过期时间, 项目结束日期, 配置的最大 TTL)。

缓存键为复合键：`data_source_id + hash(unified_query) + permission_grant_id`。

### 1.7 容错与韧性

- **连接池**: 每个数据源独立连接池
- **熔断器**: 连续 N 次失败后停止尝试，如有缓存快照则返回缓存
- **查询超时**: REST: 30s, RPC: 30s, Hive: 600s（均可配置）
- **重试策略**: 瞬时故障指数退避重试；认证/权限失败不重试

### 1.8 模块接口

| 接口 | 方向 | 说明 |
|------|------|------|
| `DataSourceAdapter` trait | 内部 | 各适配器实现；由 Adapter Router 调用 |
| `QueryService` API | 上游 → 本模块 | 接收权限引擎验证后的 UnifiedQuery |
| `SnapshotStore` API | 本模块 → 加密模块 | 读写加密快照 |
| `AuditEvent` 发射器 | 本模块 → 审计模块 | 发射查询执行事件 |

### 1.9 crate 文件结构

```
sdqp-datasource-adapter/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── traits.rs
│   ├── adapters/
│   │   ├── mod.rs
│   │   ├── rest.rs
│   │   ├── rpc.rs
│   │   └── hive.rs
│   ├── router.rs
│   ├── task.rs
│   ├── scheduler.rs
│   ├── snapshot.rs
│   └── error.rs
└── tests/
    ├── mock_adapter.rs
    └── integration/
```

---

## 模块 2: 权限引擎

**crate 名称**: `sdqp-permission-engine`
**当前状态**: ✅ repo-local 完成

### 2.1 模块职责

管理数据访问权限的完整生命周期：从申请、审批到撤销。通过字段级和条件级粒度支持最小权限原则，并根据组织变动或项目周期自动撤销权限。

### 2.2 权限授权模型

```rust
pub struct PermissionGrant {
    pub grant_id: Ulid,
    pub applicant: ActorRef,
    pub project_id: ProjectId,
    pub fields: Vec<FieldPermission>,
    pub conditions: Vec<FilterCondition>,
    pub data_source_id: DataSourceId,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub org_binding: OrgBinding,
    pub status: GrantStatus,
}

pub enum GrantStatus {
    Pending,
    Active,
    Expired,
    Revoked,
}
```

### 2.3 权限合并规则

- **字段**: 取并集（Union）
- **条件**: 取并集（OR）
- **时间窗口**: 取交集
- **冲突解决**: deny-wins

### 2.4 申请人资格配置

按部门、按个人、按角色三种模式，资格规则从人事系统同步，组织变动时自动更新。

### 2.5 申请范围

每个申请需指定：目标数据源及字段、行级条件、业务理由、申请时长。

### 2.6 权限生命周期与自动撤销

| 触发条件 | 动作 | 时效 |
|---------|------|------|
| 权限到期日到达 | 状态 → Expired；快照标记待删除 | 自动，每小时检查 |
| 项目关闭/归档 | 项目下所有授权 → Revoked | 项目状态变更时立即执行 |
| 用户调动部门 | org_binding 不匹配的授权 → Revoked | HR 同步事件触发（1 小时内） |
| 用户离职 | 所有授权 → Revoked；会话终止 | HR 同步事件触发（立即） |
| 管理员手动撤销 | 指定授权 → Revoked | 立即 |
| 审计模块检测到异常 | 授权挂起待审查 | 立即；需人工重新激活 |

**自动撤销取最短**: 权限有效期 = min(授权过期时间, 项目结束日期, 下次组织审查日期)

### 2.7 查询时强制执行

1. 验证用户在此数据源+项目组合上拥有 Active 授权
2. 将请求字段过滤为仅授权范围内的字段
3. 将授权条件作为强制 WHERE 子句注入 UnifiedQuery
4. 根据数据源类型设置查询超时和执行模式
5. 向审计模块发射权限检查事件

### 2.8 模块接口

| 接口 | 方向 | 说明 |
|------|------|------|
| `PermissionService` API | 上游（UI/API）→ 本模块 | 申请、查询、撤销权限 |
| `QueryGuard` API | 数据查看层 → 本模块 | 查询前验证并丰富查询条件 |
| `HRSyncListener` | 人事集成模块 → 本模块 | 接收组织变动事件，触发自动撤销 |
| `AuditEvent` 发射器 | 本模块 → 审计模块 | 发射所有权限生命周期事件 |

### 2.9 crate 文件结构

```
sdqp-permission-engine/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── model.rs
│   ├── merge.rs
│   ├── lifecycle.rs
│   ├── guard.rs
│   └── service.rs
└── tests/
```

---

## 模块 3: 人事系统集成

**crate 名称**: `sdqp-hr-integration`
**当前状态**: ✅ repo-local 完成

### 3.1 模块职责

与企业人事系统双向集成，作为组织架构、员工状态和汇报关系的权威数据源。当人事变动发生时，自动触发权限调整。

### 3.2 核心能力

- 组织架构同步、员工生命周期事件、审批人解析、批量同步、事件驱动同步

### 3.3 适配器模式

| 人事系统 | 集成方式 | 备注 |
|---------|---------|------|
| 飞书/Lark People | Open API + 事件订阅 | 国内公司首选；支持实时事件 |
| Workday | REST API + Webhooks | 跨国公司常用 |
| SAP SuccessFactors | OData API | 企业标准 |
| 自定义 LDAP/AD | LDAP 协议 | 遗留系统兜底 |
| 手动 CSV 导入 | 文件上传 | 无 API 系统的兜底方案 |

### 3.4 审批人升级逻辑

1. 检查审批人是否设置了委托人
2. 若无委托人，升级至审批人的直属上级
3. 若上级也不可用，沿汇报链继续向上
4. 若汇报链耗尽，路由至系统管理员并发出告警

超时阈值按审批流可配置（默认：24 小时）。

### 3.5 crate 文件结构

```
sdqp-hr-integration/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── traits.rs
│   ├── adapters/
│   │   ├── mod.rs
│   │   ├── feishu.rs
│   │   ├── workday.rs
│   │   └── ldap.rs
│   ├── sync.rs
│   └── resolver.rs
└── tests/
```

---

## 模块 4: 审批流引擎

**crate 名称**: `sdqp-approval-engine`
**当前状态**: ✅ repo-local 完成

### 4.1 模块职责

管理数据访问审批请求的完整生命周期。支持可配置的多级审批流，具备会签、自动升级和多渠道 IM 通知功能。

### 4.2 审批流配置

每个步骤指定：step_type（串行/并行会签/或签）、approvers、timeout、auto_actions（升级/自动拒绝/催办）。

**并发申请的合并规则**: 共同审批人合并；支持部分审批（审批人可独立审批各自关联的请求）。

### 4.3 IM 通知集成

| IM 平台 | 集成方式 | 支持的操作 |
|--------|---------|-----------|
| 飞书/Lark | Bot API + 交互式卡片 | 在卡片内直接审批/拒绝 |
| Telegram | Bot API + Inline Keyboards | 通过内联按钮审批/拒绝 |
| 钉钉 | Robot API + Action Cards | 在卡片内审批/拒绝 |
| Slack | Bot API + Block Kit | 通过交互式消息审批/拒绝 |
| 邮件 | SMTP + 操作链接 | 兜底方案 |

### 4.4 升级与委托

超时升级 → 委托 → 紧急旁路（管理员强制审批，触发增强审计，必须填写理由）。

### 4.5 crate 文件结构

```
sdqp-approval-engine/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── flow.rs
│   ├── executor.rs
│   ├── merge.rs
│   ├── notification/
│   │   ├── mod.rs
│   │   ├── feishu.rs
│   │   ├── telegram.rs
│   │   ├── dingtalk.rs
│   │   └── slack.rs
│   └── escalation.rs
└── tests/
```

---

## 模块 5: 多租户与项目隔离

**crate 名称**: `sdqp-tenant-isolation`
**当前状态**: ✅ repo-local 完成

### 5.1 模块职责

在项目与租户之间强制实施严格隔离，在逻辑访问控制、加密密钥分离和可选物理存储分离三个层面实施。

### 5.2 隔离架构

| 层面 | 隔离方式 | 粒度 |
|------|---------|------|
| 认证 | 每租户独立身份提供者；SSO 集成 | 租户级 |
| 授权 | RBAC + ABAC；所有查询限定 project_id | 项目级 |
| 加密密钥 | 每个项目独立 DEK；KEK 在租户级 | 项目级 |
| 数据存储 | 逻辑隔离：独立 schema/前缀；物理隔离：可选 | 可配置 |
| 快照 | snapshot_id 包含 project_id；跨项目访问返回 404 | 项目级 |
| 审计日志 | 日志标记 tenant_id + project_id | 项目级 |

### 5.3 项目生命周期

Created → Active → Frozen → Archived → Deleted

### 5.4 crate 文件结构

```
sdqp-tenant-isolation/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── context.rs
│   ├── guard.rs
│   └── lifecycle.rs
└── tests/
```

---

## 模块 6: 加密与密钥管理

**crate 名称**: `sdqp-encryption`
**当前状态**: ⛔ external blocked — 需要真实 TEE/enclave、KMS/HSM key-release 策略和外部 UAT
**接入规范**: 见[外部基础设施接入规范 — Module 6](#module-6-接入规范)

### 6.1 模块职责

处理系统中所有密码学操作，包括静态数据加密、传输中数据保护和安全的密钥生命周期管理。

### 6.2 三层密钥体系

```
Root Key (RK)
  └── 存储于 HSM / 云 KMS，永不离开 HSM
  └── 用途：加密/解密 KEK
      │
      Key Encryption Key (KEK)
        └── 每租户一个，由 RK 加密保护
        └── 用途：封装/解封 DEK
            │
            Data Encryption Key (DEK)
              └── 每项目一个，由租户 KEK 加密保护
              └── 用途：实际数据加密（AES-256-GCM）
```

### 6.3 加密流程（数据写入）

1. 数据源适配层返回明文查询结果
2. 加密模块生成或获取项目 DEK
3. 使用 AES-256-GCM 加密数据，每条记录独立 nonce
4. 加密数据 + 加密后的 DEK + nonce 一起存储在快照中
5. 明文从内存中安全清零

### 6.4 解密流程（受控访问）

1. 权限引擎验证用户对此数据拥有有效授权
2. 加密后的 DEK 发送至 KEK 持有方（KMS）解封
3. 解密在服务端可信执行环境（TEE）或隔离进程中完成
4. 解密数据经过处理（字段级脱敏、水印注入）后才进行传输
5. 通过 mTLS 传输至客户端；明文不在服务端缓存超过请求生命周期

**关键约束**: 前端永远不会收到未经水印注入和字段级脱敏处理的原始解密数据。这一点在架构上由"解密管道必须经过水印模块"来强制保证。

### 6.5 密钥轮换与备份

- **DEK 轮换**: 按项目级周期（默认：90 天）或按需
- **KEK 轮换**: 按租户级周期（默认：365 天）；触发重新封装所有项目 DEK
- **RK 轮换**: 由 HSM/KMS 供应商策略管理
- **密钥备份**: 加密密钥材料备份到地理隔离的 KMS 实例
- **密钥恢复**: 需要多方授权（M-of-N 密钥保管人）

### 6.6 crate 文件结构

```
sdqp-encryption/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── envelope.rs
│   ├── kms/
│   │   ├── mod.rs
│   │   ├── aws.rs
│   │   ├── azure.rs
│   │   ├── aliyun.rs
│   │   └── vault.rs
│   ├── pipeline.rs
│   └── rotation.rs
└── tests/
```

---

## 模块 7: 数据分类分级

**crate 名称**: `sdqp-data-classification`
**当前状态**: ✅ repo-local 完成

### 7.1 模块职责

提供元数据驱动的数据分类分级框架，决定每个字段如何保护：适用哪种审批流、使用什么脱敏规则、水印编码强度多大。

### 7.2 分级体系

| 级别 | 标签 | 示例 | 默认保护措施 |
|------|------|------|------------|
| L1 | 公开 | 公司名称、产品类别 | 仅标准访问日志 |
| L2 | 内部 | 员工姓名、部门 | 需登录；基础审计日志 |
| L3 | 机密 | 手机号、邮箱地址 | 需审批；展示时部分脱敏 |
| L4 | 高度机密 | 身份证号、银行账号、医疗记录 | 多级审批；默认全量脱敏；强水印；禁止批量导出 |
| L5 | 受限 | 进行中的调查对象、密封法律文件 | 仅指定授权人审批；字段级静态加密；禁止截图/导出；最高水印密度 |

### 7.3 分级元数据

每个字段标记：classification_level（L1-L5）、data_category（PII/Financial/Medical/Legal/Business/Technical）、applicable_regulations（GDPR/CCPA/PIPL/HIPAA/SOX）、masking_rule、retention_policy。

自动检测结果始终需要人工确认后才能生效。

### 7.4 crate 文件结构

```
sdqp-data-classification/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── model.rs
│   ├── rules.rs
│   └── detector.rs
└── tests/
```

---

## 模块 8: 数据查看与分析层

**crate 名称**: `sdqp-data-view`
**当前状态**: ✅ repo-local 完成

### 8.1 模块职责

提供用户界面用于查看查询结果和执行分析操作。在可用性（类 Excel 数据透视表拖拉拽）与安全性（所有聚合在服务端完成）之间取得平衡。分析引擎全部使用 Rust 实现，基于 Apache DataFusion + Apache Arrow 构建，可独立复用。

### 8.2 为什么用 Rust + DataFusion

- **性能**: 向量化多线程流式执行引擎，查询性能接近 ClickHouse/DuckDB
- **可扩展性**: 支持自定义 TableProvider（对接 SDQP 加密快照）、自定义 UDF、自定义优化器规则
- **复用性**: 分析引擎独立于 SDQP，可直接嵌入其他大数据分析场景
- **内存效率**: Arrow 列式格式在分析工作负载下内存利用率优于行式存储

### 8.3 架构原则：服务端计算

- **明细查看**: 分页展示，字段级脱敏已应用。每次翻页都是独立的后端调用并重新验证权限
- **聚合/透视**: 透视配置发送到后端执行，仅返回聚合输出，前端永远不会收到底层明细行
- **图表/可视化**: 基于服务端计算的聚合结果构建，而非原始数据

### 8.4 DataFusion 集成架构

```rust
pub struct EncryptedSnapshotProvider {
    snapshot_id: SnapshotId,
    decryption_pipeline: DecryptionPipeline,
    masking_rules: Vec<FieldMaskingRule>,
    watermark_injector: WatermarkInjector,
}

pub struct PivotQueryBuilder {
    pub row_fields: Vec<String>,
    pub column_fields: Vec<String>,
    pub value_aggregations: Vec<(String, AggFunction)>,
    pub filters: Vec<FilterCondition>,
}

pub enum AggFunction {
    Sum, Count, Avg, Min, Max, CountDistinct,
    Median, Percentile(f64),
}
```

执行流程：前端提交透视配置 → PivotQueryBuilder 生成 DataFusion LogicalPlan → DataFusion 优化 → EncryptedSnapshotProvider 提供解密后的 Arrow RecordBatch 流 → 执行聚合 → 序列化返回前端。

### 8.5 前端安全控制

- **Canvas 渲染敏感字段**: 防止浏览器 DOM 检查和复制粘贴
- **隐形水印覆盖层**: 所有展示数据上叠加不可见水印
- **截屏检测**: 可选的浏览器端 Visibility API 检测
- **会话超时**: 可配置的空闲超时，需重新认证
- **内容安全策略**: 严格的 CSP 头防止 XSS 数据外泄

### 8.6 crate 文件结构

```
sdqp-data-view/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── engine.rs
│   ├── providers/
│   │   ├── mod.rs
│   │   ├── snapshot.rs
│   │   └── streaming.rs
│   ├── pivot.rs
│   ├── functions/
│   │   ├── mod.rs
│   │   ├── masking.rs
│   │   └── watermark.rs
│   ├── pagination.rs
│   ├── export.rs
│   └── api.rs
└── tests/

sdqp-frontend/
├── package.json
├── src/
│   ├── components/
│   │   ├── PivotTable/
│   │   ├── DetailView/
│   │   ├── QueryProgress/
│   │   └── WatermarkOverlay/
│   ├── services/
│   └── security/
```

---

## 模块 9: 电子证据与存证

**crate 名称**: `sdqp-evidence`
**当前状态**: ⛔ external blocked — 需要真实 RFC3161 TSA、司法链/区块链、证书链/信任链
**接入规范**: 见[外部基础设施接入规范 — Module 9](#module-9-接入规范)

### 9.1 模块职责

确保导出的数据满足多个司法管辖区法院和监管机构要求的证据标准。提供防篡改封装、可信时间戳、哈希链完整性和可插拔的存证后端。

### 9.2 多司法管辖区合规

| 司法管辖区 | 关键标准 | 核心要求 |
|-----------|---------|---------|
| 中国大陆 | 最高法电子数据规定（2019）；电子签名法 | 可信时间戳；哈希完整性；全链路保管链审计日志 |
| 欧盟 | eIDAS 法规；GDPR | 合格电子签名（QES）；合格时间戳 |
| 美国 | 联邦证据规则（FRE 901/902） | 电子记录认证；保管链；元数据保留 |
| 英国 | 民事证据法 1995 | 真实性证书；审计追踪 |
| 新加坡 | 电子交易法；证据法 | 安全电子签名；系统可靠性证明 |
| 日本 | 电子签名与认证业务法 | 合格电子签名；时间戳机构认证 |

### 9.3 证据包结构

- **data_payload**: 导出数据（加密，使用接收方专属 DEK）
- **metadata_manifest**: 字段描述、查询参数、权限授权详情、数据源信息
- **hash_chain**: 各组件的 SHA-256 哈希，依次链式串联；最终哈希签名
- **trusted_timestamp**: 由认可的时间戳机构（TSA）签发
- **audit_extract**: 覆盖数据生命周期的相关审计日志条目
- **certificate_of_authenticity**: 数字签名的真实性与溯源证明文件
- **jurisdiction_marker**: 标识本证据包按哪个司法管辖区标准生成

### 9.4 可信时间戳供应商

- **中国**: 国家授时中心（NTSC）；第三方平台（联合信任、保全网）
- **欧盟**: eIDAS 合格信任服务提供者（DigiCert、Sectigo）
- **美国**: RFC 3161 兼容 TSA 服务
- **兜底**: 内部 NTP 同步时间戳 + HSM 签名证明

### 9.5 区块链存证（可插拔）

hash_chain 的最终摘要锚定到区块链上，作为不可篡改的存在性证明。锚定是异步非阻塞的；证据包在没有区块链回执的情况下也是有效的。

### 9.6 crate 文件结构

```
sdqp-evidence/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── package.rs
│   ├── hash_chain.rs
│   ├── tsa/
│   │   ├── mod.rs
│   │   ├── ntsc.rs
│   │   └── rfc3161.rs
│   ├── blockchain/
│   │   ├── mod.rs
│   │   ├── fabric.rs
│   │   └── ethereum.rs
│   └── compliance/
│       ├── mod.rs
│       ├── china.rs
│       ├── eu.rs
│       └── us.rs
└── tests/
```

---

## 模块 10: 暗水印系统

**crate 名称**: `sdqp-watermark`
**当前状态**: ✅ repo-local 完成

### 10.1 模块职责

在系统渲染或导出的所有数据中嵌入不可见的、可追踪的标识符。由水印嵌入 SDK 和水印检测 API 两个独立组件构成。

### 10.2 水印嵌入 SDK

- **前端水印**: SVG/Canvas 水印层；编码 user_id + session_id + timestamp
- **导出水印（文档）**: 隐写术编码；可抵抗格式转换和打印
- **导出水印（图像）**: DCT 域水印；可抵抗 JPEG 再压缩和适度裁剪
- **水印密度**: 按数据分类级别可配置（L3: 标准, L4: 密集, L5: 最大）

**水印载荷**: system_id + user_id + project_id + timestamp + sequence_number

### 10.3 水印检测 API

- `detect(file_or_image) → Option<WatermarkPayload>`
- `verify(file_or_image, expected_payload) → VerificationResult`
- `batch_scan(files) → Vec<ScanResult>`

### 10.4 DLP 集成接口

支持内联检查（DLP 网关对出站流量调用检测 API）、权限感知过滤、策略引擎（根据水印内容应用阻断/告警/记录）。

### 10.5 crate 文件结构

```
sdqp-watermark/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── embed/
│   │   ├── mod.rs
│   │   ├── svg_overlay.rs
│   │   ├── steganographic.rs
│   │   └── dct.rs
│   ├── detect/
│   │   ├── mod.rs
│   │   ├── extractor.rs
│   │   └── verifier.rs
│   ├── payload.rs
│   └── api.rs
└── tests/
```

---

## 模块 11: 全链路审计日志

**crate 名称**: `sdqp-audit`
**当前状态**: ✅ repo-local 完成

### 11.1 模块职责

捕获系统中每个操作的完整、防篡改记录。回答：谁（Who）在什么时候（When）因为什么（Why）对什么数据（What）做了什么动作（Action），结果怎样（Result）？

### 11.2 审计事件结构

```rust
pub struct AuditEvent {
    pub event_id: Ulid,
    pub timestamp: DateTime<Utc>,
    pub actor: ActorInfo,        // user_id + session_id + IP + 设备指纹
    pub action: ActionType,      // QUERY, VIEW, EXPORT, PERMISSION_APPLY, LOGIN...
    pub target: TargetRef,
    pub context: EventContext,
    pub result: ActionResult,    // SUCCESS | FAILURE | DENIED
    pub data_fingerprint: Option<String>,
    pub prev_hash: String,       // 哈希链
}
```

### 11.3 防篡改机制

- 每条事件包含前一条事件的哈希，形成哈希链
- 每 N 条事件（默认 1000）链式哈希由 HSM 签名，可选锚定到区块链
- 日志存储对应用层是只写的；管理员删除需要多方授权
- 审计事件同时转发到独立的 SIEM/日志聚合系统

### 11.4 保留与合规

| 保留类别 | 默认周期 | 适用法规 |
|---------|---------|---------|
| 常规访问日志 | 3 年 | SOX、内部制度 |
| 权限生命周期事件 | 5 年 | GDPR、个保法、SOX |
| 证据相关动作 | 10 年或按案件周期 | 法院规则、监管冻结 |
| 系统管理动作 | 5 年 | ISO 27001、SOC2 |

### 11.5 crate 文件结构

```
sdqp-audit/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── event.rs
│   ├── chain.rs
│   ├── store.rs
│   ├── forwarder.rs
│   └── retention.rs
└── tests/
```

---

## 模块 12: 系统自身安全

**crate 名称**: `sdqp-system-security`
**当前状态**: ⛔ external blocked — 需要真实 OIDC/SAML/SCIM IdP、WebAuthn、mTLS 证书生命周期、外部 secrets manager
**接入规范**: 见[外部基础设施接入规范 — Module 12](#module-12-接入规范)

### 12.1 模块职责

保护系统本身免受入侵、内部威胁和配置错误。SDQP 在设计上是高价值攻击目标，本模块是最后一道防线。

### 12.2 认证与访问控制

- **SSO 集成**: SAML 2.0 / OIDC 对接企业身份提供者
- **SCIM 协议支持**: 通过 SCIM 2.0 自动同步用户和组
- **强制 MFA**: TOTP、FIDO2/WebAuthn 或生物识别
- **会话管理**: 短生命周期 JWT（15 分钟）+ 刷新令牌轮换；会话绑定 IP + 设备指纹
- **API 认证**: 服务间 mTLS；外部集成使用 API 密钥 + IP 白名单

#### 持续认证机制

- **行为基线**: 为每个用户建立正常行为基线
- **实时风险评分**: 每次操作触发风险评分
- **自适应响应**: 低风险（0-30）放行 / 中风险（30-70）要求二次确认 / 高风险（70-100）立即终止会话

### 12.3 RBAC

| 角色 | 范围 | 能力 |
|------|------|------|
| 系统管理员 | 全局 | 系统配置、用户管理，但无直接数据访问权限 |
| 项目管理员 | 项目级 | 项目配置、审批流设置、成员管理 |
| 数据负责人 | 数据源级 | 分类管理、审批权限、数据源配置 |
| 调查员/分析师 | 项目级 | 申请权限、查询数据、经审批后导出 |
| 审计员 | 全局或项目级 | 只读访问审计日志；无数据访问权限 |
| 审批人 | 审批流级 | 审批/拒绝权限申请；无直接数据查询权限 |

**关键约束**: 没有任何单一角色同时拥有系统配置权限和数据访问权限。

### 12.4 配置变更管理

所有配置变更在内部审计追踪中版本化；关键变更（KMS 配置、管理员角色分配）需要多方审批；配置漂移检测定期执行。

### 12.5 漏洞管理

- 每次构建自动执行 `cargo audit`；持续监控 CVE
- 限流、输入验证、SQL 注入防护（仅参数化查询）
- 系统后端运行在专用网段；数据库和 KMS 访问受网络策略限制

### 12.6 内存保护与机密计算

- **TEE/安全飞地部署**: Intel SGX / AMD SEV / ARM TrustZone，内存加密由硬件保证
- **内存清零策略**: `zeroize` crate 确保密钥和明文在 Drop 时立即清零
- **进程隔离**: 解密进程独立运行，使用独立内存空间和安全上下文
- **核心转储禁用**: 解密进程禁用 core dump

### 12.7 隐蔽通道与数据外泄防护

- DNS 隧道检测（高频、长子域名、非标准记录类型）
- HTTP 隐蔽通道检测（出站 URL 参数、Header、Body 中是否编码敏感数据）
- 剪贴板管控（Canvas 渲染阻止 DOM 级复制；企业终端集成 EDR）
- 打印管控（打印事件触发审计记录，自动注入水印）
- 出站流量基线（异常偏差触发告警）

### 12.8 第三方集成安全

- 每个第三方集成接入前需通过安全评估清单
- 最小权限原则（如 HR 系统只需只读 org 结构）
- 所有第三方 API 密钥/Token 默认 90 天自动轮换
- 熔断与降级策略（IM 通知失败回退邮件；KMS 不可用时暂停新的解密请求）

### 12.9 高可用与灾难恢复

- **无状态应用层**: 负载均衡器后水平扩展
- **数据库复制**: 审计日志同步复制；快照异步复制
- **跨地域备份**: RPO: 1 小时；RTO: 4 小时
- **密钥恢复流程**: 文档化并每季度演练；需 M-of-N 密钥保管人

### 12.10 crate 文件结构

```
sdqp-system-security/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── sso.rs
│   │   ├── scim.rs
│   │   ├── mfa.rs
│   │   ├── session.rs
│   │   └── continuous.rs
│   ├── rbac/
│   │   ├── mod.rs
│   │   ├── roles.rs
│   │   └── sod.rs
│   ├── memory/
│   │   ├── mod.rs
│   │   ├── tee.rs
│   │   └── zeroize.rs
│   ├── exfiltration/
│   │   ├── mod.rs
│   │   ├── dns_tunnel.rs
│   │   └── http_covert.rs
│   ├── supply_chain.rs
│   └── config_audit.rs
└── tests/
```

---

## 模块 13: 用户与实体行为分析

**crate 名称**: `sdqp-ueba`
**当前状态**: ✅ repo-local 完成（注：`uat_phase6_ueba.rs` 存在 `cargo fmt` 未通过，需修复后 CI 才绿）

### 13.1 模块职责

基于全链路审计日志（模块 11）进行用户和实体行为分析（UEBA），检测异常访问模式、潜在数据泄露行为和内部威胁。将审计模块的"记录"能力扩展为"检测+响应"能力。

### 13.2 为什么需要独立的 UEBA 模块

审计模块负责忠实记录，UEBA 模块负责智能分析。分离原因：职责单一（审计写入路径必须极简）、独立扩展（UEBA 计算量远大于日志写入）、可复用性（可接入其他系统审计日志）。

### 13.3 检测能力

**异常行为检测**:
- 查询频率异常（对比个人历史基线和同角色群体基线）
- 数据量异常（单次或累计查询数据量异常偏大）
- 时间异常（非工作时间、节假日执行敏感查询）
- 权限使用异常（权限申请通过后立即批量查询）
- 下钻异常（频繁从聚合下钻到明细，试图拼凑完整数据集）
- 导出异常（高频导出、导出后立即注销、导出到非常规设备）

**实体行为检测**:
- API 调用模式异常（服务账号调用模式偏离基线，可能是凭证泄露）
- 数据源访问模式异常（可能是适配器被劫持）
- 审批流异常（秒级通过可能是自动化刷审批；审批人大量批准自己部门请求）

### 13.4 风险评分模型

```rust
pub struct RiskScore {
    pub score: f64,  // 0-100
    pub dimensions: HashMap<RiskDimension, f64>,
    pub triggered_rules: Vec<RuleMatch>,
    pub recommended_action: ResponseAction,
}

pub enum RiskDimension {
    QueryFrequency, DataVolume, TemporalPattern,
    PermissionUsage, ExportBehavior, DevicePosture, NetworkContext,
}

pub enum ResponseAction {
    LogOnly, Alert, StepUpAuth, SuspendPermission, TerminateSession,
}
```

### 13.5 响应编排

- **→ 权限引擎 (模块 2)**: 挂起可疑用户的权限授权
- **→ 系统安全 (模块 12)**: 触发持续认证风险评分提升
- **→ 审批引擎 (模块 4)**: 通过 IM 通知安全管理员进行人工研判
- **→ 审计模块 (模块 11)**: 记录完整的检测事件和响应动作

### 13.6 技术实现

- **流式处理**: 从 Kafka/事件流中实时消费，使用滑动窗口计算行为指标
- **基线计算**: 使用 ClickHouse 对历史审计日志做离线聚合
- **规则引擎**: 声明式规则定义（YAML/TOML），无需修改代码即可新增检测规则
- **ML 模型（预留）**: 为后续引入机器学习异常检测预留接口，初期使用规则方法

### 13.7 crate 文件结构

```
sdqp-ueba/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── consumer.rs
│   ├── baseline.rs
│   ├── rules/
│   │   ├── mod.rs
│   │   ├── query.rs
│   │   ├── export.rs
│   │   ├── approval.rs
│   │   └── entity.rs
│   ├── scoring.rs
│   ├── response.rs
│   └── api.rs
└── tests/
    └── scenarios/
```

---

## 模块 14: MCP Gateway

**crate 名称**: `sdqp-mcp-gateway`
**当前状态**: 🆕 v1.2 新增模块，待开发

### 14.1 模块职责

将 SDQP 的受控数据访问能力以 MCP Server 协议暴露，使任何 MCP 兼容的 AI Agent（Claude、Cursor、企业内部 Agent 等）能够通过标准化接口访问敏感数据，同时保证所有访问都经过权限验证、审计记录和水印注入。

SDQP 作为 **AI Agent 的安全代理层**，而不只是人工查询的保护系统。

### 14.2 设计动机

- **MCP 已成为 AI Agent 标准接入协议**: 任何支持 MCP 的 AI 工具，只需配置 SDQP MCP 服务器地址，即可受控访问敏感数据
- **现有安全控制无需改动**: MCP Gateway 是对已有 13 个模块的接口封装，所有权限检查、审计、水印逻辑由底层模块保证，Gateway 层只负责协议转换
- **扩展使用场景**: 除人工查询外，自动化分析工作流、AI 辅助调查、智能报表生成等场景都可以通过 MCP 接入，且保持与人工访问相同的安全级别

### 14.3 暴露的 MCP 工具定义

```rust
/// MCP 工具：查询数据
/// 等价于：权限检查 → 数据源查询 → 水印注入 → 返回结果
tool: "sdqp_query"
inputs:
  - project_id: string (required)
  - data_source_id: string (required)
  - fields: array<string> (required)
  - conditions: array<FilterCondition> (optional)
  - pagination: { page: int, page_size: int } (optional)
  - reason: string (required, 业务理由，写入审计日志)

/// MCP 工具：申请数据访问权限
tool: "sdqp_request_permission"
inputs:
  - project_id: string (required)
  - data_source_id: string (required)
  - fields: array<string> (required)
  - conditions: array<FilterCondition> (optional)
  - valid_days: int (required, 申请时长)
  - reason: string (required)

/// MCP 工具：查询当前有效权限
tool: "sdqp_list_grants"
inputs:
  - project_id: string (optional, 不填则返回所有项目)

/// MCP 工具：查询审计日志（仅限审计员角色）
tool: "sdqp_query_audit"
inputs:
  - project_id: string (optional)
  - actor_id: string (optional)
  - action_types: array<string> (optional)
  - time_range: { from: datetime, to: datetime } (required)
  - limit: int (default: 100)
```

### 14.4 请求处理流程

```
AI Agent → MCP Request
    │
    ▼
sdqp-mcp-gateway
    │
    ├─→ 模块 12 (系统安全): 验证 MCP 客户端身份（API Key + mTLS）
    │                        确认请求来自已注册的 AI Agent
    │
    ├─→ 模块 2 (权限引擎): 验证 Agent 操作的用户拥有对应的 Active 权限授权
    │                       注入强制 WHERE 条件
    │
    ├─→ 模块 1 (数据源适配): 执行查询，返回结果
    │
    ├─→ 模块 6 (加密): 解密快照数据
    │
    ├─→ 模块 10 (水印): 注入水印（标注来源为 AI Agent + 用户 + 会话）
    │
    ├─→ 模块 11 (审计): 记录 MCP 查询事件，标注 agent_id + 业务理由
    │
    └─→ 返回处理后的结果给 AI Agent
```

### 14.5 AI Agent 注册与管理

MCP Gateway 维护一个已注册 AI Agent 的白名单，每个注册的 Agent 需要：

- **agent_id**: 全局唯一标识符
- **api_key**: 用于认证的 API 密钥（定期轮换）
- **allowed_users**: 此 Agent 可以代理操作的用户列表（或 `*` 表示允许任意已认证用户）
- **allowed_tools**: 允许调用的工具列表（最小权限原则）
- **rate_limits**: 每分钟/每小时最大调用次数

注册新 Agent 需要系统管理员审批，并记录在审计日志中。

### 14.6 水印标注策略

通过 MCP 访问的数据，水印载荷额外包含：

```
标准载荷: system_id + user_id + project_id + timestamp + sequence_number
MCP 额外字段: agent_id + tool_name + mcp_session_id
```

这确保如果 AI Agent 产生的输出中出现了未授权数据，可以追溯到具体的 Agent 会话。

### 14.7 与人工访问的差异

| 维度 | 人工访问（浏览器） | MCP Agent 访问 |
|------|----------------|--------------|
| 认证方式 | SSO + MFA | API Key + mTLS |
| 水印方式 | SVG 覆盖层 + 隐写术 | 隐写术 + 元数据标注 |
| 速率限制 | 用户操作频率自然限速 | 强制速率限制 |
| 审计标注 | actor = user | actor = agent + impersonated_user |
| Canvas 保护 | 有 | 不适用（无浏览器） |

### 14.8 crate 文件结构

```
sdqp-mcp-gateway/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── server.rs          # MCP Server 协议实现（SSE transport）
│   ├── tools/
│   │   ├── mod.rs
│   │   ├── query.rs       # sdqp_query 工具实现
│   │   ├── permission.rs  # sdqp_request_permission 工具实现
│   │   ├── grants.rs      # sdqp_list_grants 工具实现
│   │   └── audit.rs       # sdqp_query_audit 工具实现
│   ├── auth.rs            # MCP 客户端身份验证（API Key + mTLS）
│   ├── registry.rs        # AI Agent 注册与白名单管理
│   ├── rate_limit.rs      # 速率限制（令牌桶算法）
│   └── watermark.rs       # MCP 专用水印标注策略
└── tests/
    ├── mock_agent.rs       # 模拟 MCP 客户端用于测试
    └── integration/
```

---

## 外部基础设施接入规范

> **v1.2 新增章节** — 对应三个 external blocked 模块的解阻塞设计

本章定义三个阻塞模块与外部基础设施对接的接口规范、配置 schema 和 UAT 验收标准。

### Module 6 接入规范

#### 支持的 KMS 清单

| KMS 供应商 | 配置字段 | key-release 触发条件 |
|-----------|---------|-------------------|
| AWS KMS | `region`, `key_id`, `role_arn` | IAM 策略 + 可选 Condition Key |
| Azure Key Vault | `vault_url`, `key_name`, `tenant_id`, `client_id` | Azure AD 服务主体 + 访问策略 |
| 阿里云 KMS | `region`, `key_id`, `access_key_id`, `access_key_secret` | RAM 角色策略 |
| HashiCorp Vault | `vault_addr`, `mount_path`, `key_name`, `token` / AppRole | Vault 策略（HCL） |

配置示例（TOML）：

```toml
[kms]
provider = "aws"               # "aws" | "azure" | "aliyun" | "vault"
region = "ap-northeast-1"
key_id = "arn:aws:kms:ap-northeast-1:123456789:key/xxxx"
role_arn = "arn:aws:iam::123456789:role/sdqp-kms-role"

[kms.key_release_policy]
# 仅允许来自 SDQP 加密模块进程的解密请求
require_caller_tag = "sdqp-encryption"
# 可选：仅在 TEE attestation 验证通过后释放密钥
require_tee_attestation = true
```

#### TEE Attestation 流程

```
sdqp-encryption (TEE 内)
    │
    ├─ 1. 生成 TEE Quote（包含飞地度量值、代码哈希）
    │
    ▼
KMS / Attestation Service
    │
    ├─ 2. 验证 Quote 签名（Intel IAS / AMD SEV-SNP / Azure Attestation）
    ├─ 3. 验证飞地度量值与已知良好值匹配
    ├─ 4. 验证代码哈希对应已审批版本
    │
    ├─ [验证通过] → 释放 KEK，允许解封 DEK
    └─ [验证失败] → 拒绝请求，写入审计日志
```

支持的 TEE 平台：Intel SGX（通过 Intel IAS 或 DCAP）、AMD SEV-SNP（通过 AMD KDS）、ARM TrustZone（通过 OP-TEE）、Azure Confidential Computing（通过 Azure Attestation Service）。

#### Module 6 UAT 验收标准

- [ ] 在目标 KMS 上完成密钥创建和策略配置
- [ ] `cargo test --package sdqp-encryption --test kms_integration` 全部通过
- [ ] TEE attestation 流程端到端验证通过（含故意注入错误度量值的失败场景）
- [ ] DEK 轮换测试：轮换后旧快照仍可解密，新快照使用新 DEK
- [ ] 密钥恢复演练：M-of-N 保管人场景完成恢复
- [ ] 安全审计：确认解密进程 core dump 已禁用，内存 zeroize 可验证

---

### Module 9 接入规范

#### RFC3161 TSA 对接协议

```rust
/// TSA 适配器 trait（所有 TSA 实现此接口）
pub trait TsaAdapter: Send + Sync {
    /// 对数据摘要请求时间戳
    /// data_hash: SHA-256 或 SHA-512 摘要
    /// 返回 RFC3161 TimeStampToken（DER 编码）
    async fn request_timestamp(
        &self,
        data_hash: &[u8],
        hash_algorithm: HashAlgorithm,
    ) -> Result<TimeStampToken>;

    /// 验证已有的时间戳令牌
    async fn verify_timestamp(
        &self,
        token: &TimeStampToken,
        data_hash: &[u8],
    ) -> Result<VerificationResult>;

    /// 返回此 TSA 的信任链证书
    fn trust_chain(&self) -> Vec<Certificate>;
}
```

信任链根证书管理：

- 每个司法管辖区维护独立的信任锚（Trust Anchor）列表
- 根证书存储在 `config/tsa_trust_anchors/` 目录，按司法管辖区分文件
- 根证书更新需要通过配置变更审批流（模块 4），不允许运行时热更新
- 证书过期监控：根证书到期前 90 天发出告警

#### EvidenceChainAdapter trait（区块链/司法链抽象）

```rust
/// 不绑定具体链，支持任意区块链或司法链后端
pub trait EvidenceChainAdapter: Send + Sync {
    /// 将摘要锚定到链上，返回链上凭证
    async fn anchor(
        &self,
        digest: &[u8],
        metadata: &AnchorMetadata,
    ) -> Result<ChainReceipt>;

    /// 验证已有的链上凭证
    async fn verify(&self, receipt: &ChainReceipt, digest: &[u8]) -> Result<bool>;

    /// 返回此适配器的标识（链名称、节点地址）
    fn chain_info(&self) -> ChainInfo;
}

pub struct ChainReceipt {
    pub chain_id: String,           // 链标识
    pub transaction_id: String,     // 链上交易 ID
    pub block_number: u64,          // 区块号
    pub block_timestamp: DateTime<Utc>,
    pub anchor_timestamp: DateTime<Utc>,
}
```

支持的后端配置：

```toml
[evidence.blockchain]
enabled = true
provider = "fabric"    # "fabric" | "ethereum" | "bsn" | "none"
async_anchor = true    # 锚定为异步非阻塞；证据包不等待区块链确认

[evidence.blockchain.fabric]
peer_endpoint = "grpcs://peer0.org1.example.com:7051"
channel_name = "evidence-channel"
chaincode_name = "sdqp-anchor"
tls_cert_path = "config/fabric/tls/ca.crt"
```

#### Module 9 UAT 验收标准

- [ ] RFC3161 TSA 连通性测试（至少一个生产 TSA 端点）
- [ ] 时间戳令牌验证测试（含篡改数据后验证失败场景）
- [ ] 信任链证书加载和验证测试
- [ ] 证据包完整性端到端测试（构建 → 序列化 → 反序列化 → 验证）
- [ ] 区块链锚定测试（如启用）：锚定后验证通过，篡改摘要后验证失败
- [ ] 各司法管辖区模板测试（至少覆盖中国大陆和欧盟模板）
- [ ] `cargo test --package sdqp-evidence --test integration` 全部通过

---

### Module 12 接入规范

#### OIDC/SAML IdP 配置 Schema

```toml
[auth.sso]
provider = "oidc"    # "oidc" | "saml"

[auth.sso.oidc]
issuer = "https://accounts.google.com"
client_id = "your-client-id"
client_secret = "${SECRET:OIDC_CLIENT_SECRET}"   # 从 secrets manager 读取
redirect_uri = "https://sdqp.example.com/auth/callback"
scopes = ["openid", "email", "profile"]
# 映射 IdP claims 到 SDQP 用户属性
claim_mappings = { sub = "user_id", email = "email", groups = "roles" }

[auth.sso.saml]
idp_metadata_url = "https://your-idp.example.com/metadata"
sp_entity_id = "https://sdqp.example.com"
sp_acs_url = "https://sdqp.example.com/auth/saml/acs"
sp_private_key_path = "config/saml/sp_private_key.pem"
```

#### SCIM 2.0 配置

```toml
[auth.scim]
enabled = true
base_url = "https://sdqp.example.com/scim/v2"
bearer_token = "${SECRET:SCIM_BEARER_TOKEN}"
# SCIM attribute 到 SDQP 字段的映射
user_attribute_map = { userName = "email", displayName = "display_name" }
group_attribute_map = { displayName = "role_name" }
# 同步策略
sync_on_provision = true      # 用户在 IdP 创建时立即同步
sync_on_deprovision = true    # 用户在 IdP 禁用时立即禁用 SDQP 访问
```

#### WebAuthn RP 配置

```toml
[auth.webauthn]
rp_id = "sdqp.example.com"           # 必须与部署域名匹配
rp_name = "SDQP"
rp_origin = "https://sdqp.example.com"
# 认证器要求
authenticator_attachment = "cross-platform"   # "platform" | "cross-platform" | null
user_verification = "required"                # "required" | "preferred" | "discouraged"
resident_key = "preferred"
```

#### mTLS 证书生命周期管理

```toml
[auth.mtls]
ca_cert_path = "config/mtls/ca.crt"
server_cert_path = "config/mtls/server.crt"
server_key_path = "${SECRET:MTLS_SERVER_KEY}"

[auth.mtls.rotation]
cert_validity_days = 90
rotation_warning_days = 14        # 到期前 14 天发出告警
auto_renewal = true               # 自动续期（需要 CA 支持 ACME 或类似协议）
rotation_audit = true             # 证书轮换事件记录在审计日志
```

#### 外部 Secrets Manager 配置

```toml
[secrets]
provider = "vault"    # "vault" | "aws_secrets_manager" | "azure_key_vault" | "env"

[secrets.vault]
addr = "https://vault.example.com"
auth_method = "approle"
role_id = "${VAULT_ROLE_ID}"
secret_id = "${VAULT_SECRET_ID}"

# Secret path 命名规范
# 格式：sdqp/<environment>/<component>/<secret_name>
# 示例：
#   sdqp/prod/encryption/kms_credentials
#   sdqp/prod/auth/oidc_client_secret
#   sdqp/prod/mtls/server_key
#   sdqp/prod/database/postgres_password
```

#### Module 12 UAT 验收标准

- [ ] OIDC/SAML SSO 完整登录流程测试（至少对接一个生产 IdP）
- [ ] SCIM 用户同步测试：新建用户、更新用户、禁用用户
- [ ] WebAuthn 注册和认证流程测试
- [ ] mTLS 服务间认证测试（服务 A 使用 mTLS 调用服务 B）
- [ ] mTLS 证书轮换测试（轮换期间服务不中断）
- [ ] Secrets Manager 集成测试（读取、更新、审计）
- [ ] 持续认证风险评分测试（构造高风险行为场景，验证会话终止响应）
- [ ] 职责分离约束测试（系统管理员无法执行数据查询）
- [ ] `cargo test --package sdqp-system-security --test integration` 全部通过

---

## 代码质量门禁与 CI 规范

> **v1.2 新增章节** — 定义"模块完成"的标准以及 CI pipeline 设计

### 必过门禁（缺一不可）

以下检查必须全部通过，才能认为代码可合并或模块"完成"：

| 门禁 | 命令 | 当前状态 |
|------|------|---------|
| 代码格式 | `cargo fmt --all --check` | ❌ `uat_phase6_ueba.rs` 未通过，需立即修复 |
| 静态检查 | `cargo clippy --workspace --all-targets -- -D warnings` | ❌ 多处 lint 警告需清理 |
| 单元测试 | `cargo test --workspace --lib` | ✅ 255 个测试通过 |
| 前端测试 | `npm test -- --run` | ✅ 80 个测试通过 |
| 前端构建 | `npm run build` | ✅ 通过 |
| 安全审计 | `cargo audit` | 需在 CI 中配置 |

### 已知需清理的 Clippy 问题

以下是 `cargo clippy` 当前报告的机械性问题，全部可在不影响逻辑的前提下修复：

| 文件 | 问题类型 | 修复方式 |
|------|---------|---------|
| `sdqp-watermark/src/lib.rs` (line 877) | DCT 循环中 `is_multiple_of` / 其他 lint | 按 clippy 建议重写 |
| `sdqp-audit/src/forwarder.rs` (line 59) | `default/filter/ref clone` | 按 clippy 建议简化 |
| `sdqp-hr-integration/src/lib.rs` (line 490) | `redundant/collapsible` | 合并冗余分支 |
| `sdqp-datasource-adapter/src/scheduler.rs` | `let_and_return` | 直接返回表达式 |
| `sdqp-*` 多处 | `derivable_impls`, `useless_conversion` | 使用 derive 宏；移除无效转换 |
| `sdqp-api` | `dead_code` warning | 移除或加 `#[allow(dead_code)]` 并注释原因 |

### 修复 uat_phase6_ueba.rs 的优先级说明

`cargo fmt` 失败是当前最紧迫的问题。该文件存在格式问题导致整个 workspace 的 fmt 检查不通过，所有后续 CI 都在红灯下运行。建议：

```bash
# 直接让 rustfmt 自动修复
cargo fmt --package sdqp-ueba

# 验证
cargo fmt --all --check
```

### CI Pipeline 设计

```
Stage 1: Lint
├── cargo fmt --all --check
└── cargo clippy --workspace --all-targets -- -D warnings

Stage 2: Test
├── cargo test --workspace --lib
├── cargo test --workspace --doc
├── npm test -- --run
└── npm run build

Stage 3: Security
├── cargo audit
└── cargo deny check (license + advisories)

Stage 4: Integration Test (Mock)
├── cargo test --workspace --test integration -- --features mock-kms,mock-tsa,mock-idp
└── (三个阻塞模块使用 mock 后端，确保 CI 不依赖外部基础设施)

Stage 5: External UAT（仅在 staging 环境 + 手动触发）
├── sdqp-encryption: KMS 真实连接 + TEE attestation
├── sdqp-evidence: TSA 真实时间戳申请 + 区块链锚定
└── sdqp-system-security: IdP 真实登录 + mTLS 证书链
```

### 三个阻塞模块的 Mock 策略

在真实外部基础设施不可用时，CI 使用以下 mock：

```rust
// Mock KMS（用于 sdqp-encryption 的 CI）
#[cfg(feature = "mock-kms")]
pub struct MockKmsAdapter {
    // 在内存中模拟 key-release，不做真实 HSM 调用
    // 仅用于测试；生产环境编译时此 feature 不启用
}

// Mock TSA（用于 sdqp-evidence 的 CI）
#[cfg(feature = "mock-tsa")]
pub struct MockTsaAdapter {
    // 生成合法结构的 RFC3161 令牌，但不经过真实 TSA
}

// Mock IdP（用于 sdqp-system-security 的 CI）
#[cfg(feature = "mock-idp")]
pub struct MockOidcProvider {
    // 内嵌轻量级 OIDC 服务器，生成合法 JWT
}
```

**关键约束**: `mock-*` feature 在 `Cargo.toml` 中标注 `[dev-dependencies]`，生产构建不包含。

---

## 跨模块集成测试矩阵

> **v1.2 新增章节** — 单元测试已通过，本章定义模块间端到端的集成测试设计

### 核心请求路径测试

这是最重要的集成测试，覆盖一条完整的查询请求从入口到输出：

```
测试路径：
用户发起查询
    → 模块 12 (认证): 验证 JWT 令牌有效
    → 模块 2 (权限引擎): 验证字段权限 + 注入强制 WHERE 条件
    → 模块 1 (数据源适配): 执行查询，返回原始结果集
    → 模块 6 (加密): 解密快照（使用 mock-kms）
    → 模块 7 (数据分级): 应用字段级脱敏规则
    → 模块 10 (水印): 注入暗水印
    → 模块 11 (审计): 记录完整审计事件
    → 模块 8 (数据查看): DataFusion 执行聚合，返回前端
```

验证点：
- 权限条件确实被注入到查询 WHERE 子句
- 未授权字段确实被过滤掉（请求3个字段，只有1个授权，返回1个）
- 水印载荷包含正确的 user_id + project_id
- 审计日志包含完整的事件链（认证事件 → 权限检查事件 → 查询执行事件 → 水印注入事件）
- L4 及以上字段触发了正确的脱敏规则

### 权限生命周期测试

```
测试路径：
申请权限 → 模块 4 审批（模拟审批通过）→ 模块 2 生效
    → 执行查询（应成功）
    → 模拟用户调动（HR 同步事件）
    → 模块 3 发出 OrgChanged 事件 → 模块 2 自动撤销权限
    → 再次执行查询（应返回 403 Forbidden）
    → 验证审计日志中包含撤销事件和被拒绝的查询事件
```

### UEBA 响应编排测试

```
测试路径：
构造异常行为（短时间内高频查询，超过基线阈值）
    → 模块 13 (UEBA) 触发告警
    → 风险评分超过 70
    → 模块 13 → 模块 2 (挂起权限)
    → 模块 13 → 模块 4 (发送 IM 告警)
    → 模块 13 → 模块 11 (记录检测事件)
    → 用户尝试查询 → 应返回 403（权限已挂起）
    → 管理员手动恢复权限 → 查询应恢复正常
```

### MCP Gateway 测试

```
测试路径（需要模块 14 开发完成后执行）：
使用 mock MCP 客户端发送 sdqp_query 请求
    → 验证身份验证（API Key + mTLS）
    → 验证权限检查走向模块 2
    → 验证返回结果包含水印（MCP 额外字段：agent_id）
    → 验证审计日志标注了 agent_id
    → 发送未注册 agent 的请求 → 应返回 401
    → 超出速率限制的请求 → 应返回 429
```

### 集成测试矩阵

| 测试场景 | 覆盖模块 | mock 依赖 | 优先级 |
|---------|---------|----------|-------|
| 核心请求路径 | 1, 2, 6, 7, 8, 10, 11, 12 | mock-kms | P0 |
| 权限生命周期 | 2, 3, 4, 11 | mock-idp | P0 |
| 快照加密/解密 | 1, 5, 6 | mock-kms | P0 |
| 证据包生成 | 8, 9, 11 | mock-tsa | P1 |
| UEBA 响应编排 | 2, 4, 11, 13 | — | P1 |
| 租户隔离（跨项目访问应被阻断） | 2, 5, 11 | — | P1 |
| MCP Gateway 端到端 | 1, 2, 10, 11, 12, 14 | mock-kms | P2 |

---

## 部署拓扑

> **v1.2 新增章节**

### 单节点开发/测试部署

```
┌─────────────────────────────────────────────┐
│               单节点部署                      │
│                                             │
│  ┌──────────┐    ┌──────────┐              │
│  │  Rust    │    │ Frontend │              │
│  │  服务    │    │  (React) │              │
│  │ (10 模块 │    │          │              │
│  │ 合并为   │    │ localhost│              │
│  │ 单 binary│    │  :3000   │              │
│  │  :8080)  │    └──────────┘              │
│  └────┬─────┘                              │
│       │                                    │
│  ┌────▼─────────────────────────┐          │
│  │  PostgreSQL (元数据)         │          │
│  │  ClickHouse (审计日志)       │          │
│  │  MinIO / 本地对象存储 (快照)  │          │
│  └──────────────────────────────┘          │
│                                            │
│  外部依赖（mock 替代）:                      │
│  ├── mock-kms (内存 KMS)                   │
│  ├── mock-tsa (本地 RFC3161 服务器)         │
│  └── mock-idp (内嵌 OIDC 服务器)           │
└─────────────────────────────────────────────┘
```

### 生产部署拓扑

```
                      ┌──────────────────────┐
                      │    负载均衡器 / API   │
                      │    Gateway (Nginx /  │
                      │    Envoy)            │
                      └─────────┬────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
              ▼                 ▼                 ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  SDQP API    │  │  SDQP API    │  │  MCP Gateway │
    │  实例 1      │  │  实例 2      │  │  实例        │
    │  (无状态)    │  │  (无状态)    │  │  (无状态)    │
    └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
           │                 │                 │
           └─────────────────┼─────────────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
           ▼                 ▼                 ▼
  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
  │  PostgreSQL  │  │  ClickHouse  │  │  对象存储    │
  │  (元数据,    │  │  (审计日志,  │  │  (加密快照)  │
  │  主从复制)   │  │  UEBA 分析)  │  │  (地域复制)  │
  └──────────────┘  └──────────────┘  └──────────────┘

  外部基础设施（独立部署，不在 SDQP 管控范围内）:
  ├── KMS/HSM（AWS KMS / Azure Key Vault / HashiCorp Vault）
  ├── IdP（Azure AD / Okta / 飞书）+ SCIM 端点
  ├── TSA（国家授时中心 / DigiCert）
  ├── 区块链节点（可选）
  └── SIEM（接收审计日志转发）
```

### 模块部署形态

在生产部署中，10 个已完成模块根据职责分组为两个进程：

| 进程 | 包含模块 | 说明 |
|------|---------|------|
| `sdqp-api` | 1, 2, 3, 4, 5, 7, 8, 12, 14 | 处理 HTTP/gRPC 请求的主进程；无状态，可水平扩展 |
| `sdqp-secure` | 6, 10 | 解密管道和水印注入；优先部署在 TEE 中；与 `sdqp-api` 通过 IPC 通信 |
| `sdqp-analytics` | 11, 13 | 审计日志写入和 UEBA 分析；消费 Kafka 事件流；可独立扩展 |
| `sdqp-evidence-svc` | 9 | 证据包生成服务；调用外部 TSA 和区块链；低频高可靠性要求 |

三个阻塞模块（6, 9, 12）的接口边界在部署层面通过**进程隔离 + IPC + mTLS**来保证：即使外部基础设施不可用，其他模块仍然可以通过 mock 后端继续运行。

---

## 模块依赖关系图

```
                    ┌─────────────────────────────────────────────────┐
                    │          模块 12: 系统自身安全                    │
                    │   （认证、RBAC、持续认证、内存保护 — 所有模块依赖）  │
                    └────────────────────┬────────────────────────────┘
                                         │
                    ┌────────────────────┴────────────────────────────┐
                    │          模块 5: 多租户与项目隔离                  │
                    │   （TenantContext/ProjectContext — 所有模块依赖）  │
                    └────────────────────┬────────────────────────────┘
                                         │
        ┌──────────┬─────────────────────┼──────────────────┬──────────┐
        │          │                     │                  │          │
        ▼          ▼                     ▼                  ▼          ▼
   ┌─────────┐ ┌─────────┐        ┌──────────┐       ┌─────────┐ ┌─────────┐
   │ 模块 3  │ │ 模块 7  │        │ 模块 11  │       │ 模块 6  │ │ 模块 10 │
   │ HR 集成 │ │数据分级  │        │ 审计日志  │       │加密密钥  │ │ 暗水印  │
   └────┬────┘ └────┬────┘        └────┬─────┘       └────┬────┘ └────┬────┘
        │           │                  │ ▲               │          │
        ▼           │                  │ │(所有模块发射)    │          │
   ┌─────────┐      │                  ▼ │               │          │
   │ 模块 4  │      │            ┌──────────┐            │          │
   │ 审批流  │      │            │ 模块 13  │            │          │
   └────┬────┘      │            │  UEBA    │←(联动)──┐  │          │
        │           │            └────┬─────┘         │  │          │
        │           │                 │          ┌────┴────┐         │
        ▼           ▼            (挂起权限)       │模块 12  │         │
   ┌──────────────────────┐           │          │持续认证  │         │
   │     模块 2: 权限引擎   │←──────────┘          └─────────┘         │
   └──────────┬───────────┘                                           │
              │                                                       │
   ┌──────────┴───────────┐                                           │
   │                      │                                           │
   ▼                      ▼                                           │
模块 1                  模块 14                                        │
数据源适配              MCP Gateway                                    │
   │                      │(同样经过权限引擎)                           │
   └──────────────────────┘                                           │
              │                                                       │
              ▼                                              ▼         │
   ┌──────────────────────┐                        ┌─────────────────┐ │
   │  模块 1 数据源适配层   │                        │  解密管道强制    │ │
   │  （统一异步查询接口）   │                        │  经过水印注入    │←┘
   └──────────┬───────────┘                        └────────┬────────┘
              │                                             │
              ▼                                             │
   ┌──────────────────────┐                                 │
   │  模块 8: 数据查看分析  │←──────────────────────────────────┘
   │  (Rust + DataFusion)  │
   └──────────┬───────────┘
              │
              ▼
   ┌──────────────────────┐
   │  模块 9: 电子证据存证  │
   └──────────────────────┘
```

### 模块间通信汇总

| 来源模块 | 目标模块 | 接口用途 |
|---------|---------|---------|
| 数据查看层 (8) | 权限引擎 (2) | 查询时权限验证与字段过滤 |
| 权限引擎 (2) | 数据源适配层 (1) | 传递验证后的 UnifiedQuery 执行查询 |
| 权限引擎 (2) | HR 集成 (3) | 组织变动事件触发自动撤销 |
| 权限引擎 (2) | 审批流引擎 (4) | 新申请触发审批工作流 |
| 审批流引擎 (4) | HR 集成 (3) | 审批人解析与升级 |
| 数据源适配层 (1) | 加密模块 (6) | 加密快照读写 |
| 加密模块 (6) | 水印模块 (10) | 解密管道强制经过水印注入 |
| 数据查看层 (8) | 数据分级 (7) | 确定每个字段的脱敏规则 |
| 数据查看层 (8) | 证据模块 (9) | 认证导出封装 |
| 证据模块 (9) | 审计模块 (11) | 提取审计追踪作为证据包的一部分 |
| UEBA (13) | 审计模块 (11) | 消费审计事件流进行行为分析 |
| UEBA (13) | 权限引擎 (2) | 异常检测后挂起可疑权限 |
| UEBA (13) | 系统安全 (12) | 触发持续认证风险评分提升 |
| UEBA (13) | 审批引擎 (4) | 通过 IM 通知安全管理员 |
| MCP Gateway (14) | 系统安全 (12) | 验证 MCP 客户端身份 |
| MCP Gateway (14) | 权限引擎 (2) | Agent 请求的权限验证 |
| MCP Gateway (14) | 数据源适配层 (1) | 代理数据查询 |
| MCP Gateway (14) | 水印模块 (10) | 注入 MCP 专用水印 |
| MCP Gateway (14) | 审计模块 (11) | 记录 Agent 访问事件 |
| 系统安全 (12) | HR 集成 (3) | SCIM 用户同步 + 持续认证的组织上下文 |
| 所有模块 | 审计模块 (11) | 发射所有重要动作的审计事件 |
| 所有模块 | 租户隔离 (5) | 项目范围的上下文注入 |
| 所有模块 | 系统安全 (12) | 认证、授权、API 安全 |

---

## 开发阶段规划

> v1.2 更新：新增当前进度状态列

| 阶段 | 包含模块 | 里程碑 | 当前状态 |
|------|---------|--------|---------|
| **Phase 1: 安全地基** | 12（系统安全）+ 5（租户隔离）+ 11（审计） | 安全外壳就绪：认证、隔离、审计日志可运行 | ✅ 完成（12 external blocked，本地代码完成） |
| **Phase 2: 核心数据通路** | 1（数据源适配）+ 2（权限引擎）+ 6（加密） | 端到端加密数据查询，统一异步接口，权限强制执行 | ✅ 完成（6 external blocked，本地代码完成） |
| **Phase 3: 工作流** | 3（HR 集成）+ 4（审批引擎）+ 7（数据分级） | 完整的 申请→审批→访问 生命周期 | ✅ 完成 |
| **Phase 4: 用户体验** | 8（数据查看与分析） | Rust + DataFusion 分析引擎，数据透视表、下钻、分页明细查看 | ✅ 完成 |
| **Phase 5: 合规增强** | 9（证据）+ 10（水印） | 认证导出与基于水印的泄露追踪 | ✅ 完成（9 external blocked，本地代码完成） |
| **Phase 6: 智能安全** | 13（UEBA）+ 12 增强（持续认证、隐蔽通道检测） | 行为分析驱动的主动安全防护 | ✅ 完成（`uat_phase6_ueba.rs` fmt 待修复） |
| **Phase 7: 外部对接** | 6, 9, 12（外部基础设施接入） | 三个阻塞模块完成 UAT；CI 全绿；git 工作树建立 | 🚧 进行中（阻塞于外部基础设施） |
| **Phase 8: 生态扩展** | 14（MCP Gateway）+ 开源发布准备 | AI Agent 通过 SDQP 受控访问敏感数据；核心 crate 上 crates.io | 📋 待启动 |

### Phase 7 解阻塞行动项

按优先级排序：

1. **立即**: 修复 `uat_phase6_ueba.rs` 的 `cargo fmt` 问题
2. **立即**: 批量清理所有 `cargo clippy` 警告（机械工作，约 2-4 小时）
3. **立即**: 初始化 git 工作树（`git init D:\Project\SDQP`）
4. **本周**: 完成 Module 12 外部接入（IdP + secrets manager 配置）——这是三个阻塞模块中外部依赖最容易获取的
5. **本周**: 完成 Module 6 外部接入（选定一个 KMS 供应商完成接入）
6. **下周**: 完成 Module 9 外部接入（TSA 接入；区块链可先用 mock）
7. **完成后**: 运行 Stage 4 外部 UAT，将所有模块状态从 `external blocked` 改为 `✅`

---

## 可复用模块清单

以下模块在设计上可独立复用于其他项目，可作为通用组件库独立发布：

| crate | 复用场景 |
|-------|---------|
| `sdqp-audit` | 任何需要防篡改日志的系统 |
| `sdqp-encryption` | 任何静态数据加密需求 |
| `sdqp-watermark` | 独立 DLP 组件 |
| `sdqp-approval-engine` | 任何工作流审批系统 |
| `sdqp-hr-integration` | 任何需要组织架构感知的企业系统 |
| `sdqp-data-classification` | 任何数据治理工具 |
| `sdqp-data-view` | 任何需要服务端 OLAP 分析的系统（BI 工具、数据质量平台、合规报告引擎） |
| `sdqp-ueba` | 任何需要用户行为分析的安全系统 |
| `sdqp-mcp-gateway` | 任何需要向 AI Agent 提供受控数据访问的系统 |

**发布策略**: 这些模块从第一天起就作为独立 Rust crate 发布，API 清晰，不泄露系统特定假设。每个后续项目使用和改进这些模块，使共享组件库不断强壮。

**GitHub 发布检查清单**（Phase 8 执行前需完成）:
- [ ] 每个可复用 crate 的 `README.md` 独立撰写（不依赖 SDQP 上下文）
- [ ] 公开 API 文档（`cargo doc`）覆盖率 > 80%
- [ ] 所有公开 API 参数的 `#[must_use]` 和错误类型清晰标注
- [ ] `CHANGELOG.md` 从第一个版本开始维护
- [ ] crates.io 发布前：`license = "Apache-2.0"` 确认
- [ ] CI 通过标志（Green badge）展示在 README 中
