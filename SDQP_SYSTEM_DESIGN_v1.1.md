# 敏感数据查询与保护系统（SDQP）— 系统架构设计文档

> **版本**: 1.1  
> **日期**: 2026年3月  
> **状态**: 公开（开源发布，Apache-2.0）  
> **用途**: 系统架构设计文档，每个模块对应一个独立 Rust crate  
> **变更记录**: v1.1 — 统一异步查询接口；分析层改用 Rust + DataFusion；增加 UEBA 模块；补充持续认证、内存保护、隐蔽通道检测、供应链安全、SCIM 协议

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
- [模块依赖关系图](#模块依赖关系图)
- [开发阶段规划](#开发阶段规划)
- [可复用模块清单](#可复用模块清单)

---

## 系统总览

### 核心目标

在最大限度保证数据安全的前提下，方便敏感数据的查询、分析以及相关法律证据的出具。

### 设计原则

- **权限最小化**: 所有数据访问按字段级+条件级粒度控制，按需申请、按期回收
- **全链路可审计**: 谁在什么时候因为什么做了什么、结果怎样，全部有记录且防篡改
- **安全纵深**: 加密、水印、隔离、审计多层叠加，单点突破不足以造成数据泄露
- **模块独立性**: 每个模块是独立 Rust crate，接口清晰，可独立开发、测试、复用

### 技术栈

- **主语言**: Rust（核心运行时，包括数据分析引擎）
- **分析引擎**: Apache DataFusion（Rust 原生查询引擎）+ Apache Arrow（列式内存格式）
- **前端**: TypeScript + React（数据查看与分析层 UI）
- **异步运行时**: Tokio（所有查询接口统一异步）
- **通信协议**: gRPC（内部模块间）、REST/HTTPS（外部接口）、WebSocket（查询状态推送）
- **存储**: PostgreSQL（元数据）、ClickHouse（审计日志 + UEBA 分析）、对象存储（快照）
- **密钥管理**: HSM / 云 KMS（AWS、Azure、阿里云、HashiCorp Vault）

---

## 模块 1: 数据源适配层

**crate 名称**: `sdqp-datasource-adapter`

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
    /// 统一异步接口的好处：前端交互体验一致，后端可透明切换执行策略
    Async,
    /// 快照模式：执行查询后加密结果存为不可变快照，返回 snapshot_id。
    /// 在 Async 基础上增加持久化步骤。
    Snapshot,
}
```

#### 统一异步查询接口（v1.1 新增）

所有数据查询 API 统一为异步模式，工作流程如下：

1. 客户端提交查询 → 服务端立即返回 `task_id`
2. 服务端根据数据源类型选择执行策略（同步执行或真异步提交）
3. 客户端通过两种方式获取结果：
   - **轮询**: `GET /tasks/{task_id}/status` → Pending | Running | Completed | Failed
   - **WebSocket 推送**: 订阅 `ws://tasks/{task_id}` 接收状态变更和结果流
4. 查询完成后结果写入快照（如果是 Snapshot 模式）或缓存（如果是 Async 模式）
5. 长时间运行的查询支持取消：`DELETE /tasks/{task_id}`

这种设计确保：大数据量查询不会阻塞 HTTP 连接；前端可以展示统一的查询进度条；后端可以对长时间运行的查询做资源管控和优先级调度。

### 1.5 条件下推策略

每个适配器声明 `SourceCapabilities` 结构体：

```rust
pub struct SourceCapabilities {
    /// 支持下推的比较运算符（=, >, <, IN, LIKE 等）
    pub supported_operators: Vec<Operator>,
    /// 支持的逻辑运算符（AND, OR, NOT）
    pub supported_logical_operators: Vec<LogicalOperator>,
    /// 是否支持字段投影（只返回指定字段）
    pub supports_field_projection: bool,
    /// 是否支持原生分页
    pub supports_pagination: bool,
}
```

适配路由器（Adapter Router）将 UnifiedQuery 的条件拆分为两组：

- **pushdown_conditions**: 发送到数据源执行
- **postfilter_conditions**: 数据返回后在内存中过滤

拆分过程对调用方透明，但会记录在审计日志中。

### 1.6 快照与缓存策略

#### 快照生命周期

快照是向数据查看层提供数据的主要机制，其生命周期绑定到权限授权：

- **创建**: 首次审批通过后执行查询时触发，或按配置定时刷新
- **存储**: 使用项目级数据加密密钥（DEK）加密后存储；详见模块 6
- **过期**: TTL = min(权限授权过期时间, 项目结束日期, 配置的最大 TTL)
- **刷新**: 在权限仍有效的情况下可手动刷新
- **删除**: 权限撤销或项目关闭时硬删除；删除操作记录在审计日志中

#### 缓存键设计

缓存键为复合键：`data_source_id + hash(unified_query) + permission_grant_id`。这确保两个用户查询相同字段但权限条件不同时，获得独立的快照，维护隔离性。

### 1.7 容错与韧性

- **连接池**: 每个数据源独立连接池，池大小可配置
- **熔断器**: 连续 N 次失败后停止尝试，如有缓存快照则返回缓存
- **查询超时**: 按数据源类型硬超时（REST: 30s, RPC: 30s, Hive: 600s，均可配置）
- **重试策略**: 瞬时故障指数退避重试；认证/权限失败不重试

### 1.8 模块接口

| 接口 | 方向 | 说明 |
|------|------|------|
| `DataSourceAdapter` trait | 内部 | 各适配器实现；由 Adapter Router 调用 |
| `QueryService` API | 上游 → 本模块 | 接收权限引擎验证后的 UnifiedQuery |
| `SnapshotStore` API | 本模块 → 加密模块 | 读写加密快照 |
| `AuditEvent` 发射器 | 本模块 → 审计模块 | 发射查询执行事件，包含下推/后过滤拆分信息 |

### 1.9 crate 文件结构

```
sdqp-datasource-adapter/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── traits.rs          # DataSourceAdapter trait, UnifiedQuery, SourceCapabilities
│   ├── adapters/
│   │   ├── mod.rs
│   │   ├── rest.rs        # RESTful 适配器
│   │   ├── rpc.rs         # gRPC/Thrift 适配器
│   │   └── hive.rs        # Hive 适配器（含异步执行）
│   ├── router.rs          # 适配器选择与条件下推逻辑
│   ├── task.rs            # 统一异步任务管理（task_id 生成、状态跟踪、WebSocket 推送）
│   ├── scheduler.rs       # 查询优先级调度与资源管控
│   ├── snapshot.rs        # 快照创建、缓存、生命周期管理
│   └── error.rs           # 统一错误类型
└── tests/
    ├── mock_adapter.rs    # 模拟适配器用于单元测试
    └── integration/
```

---

## 模块 2: 权限引擎

**crate 名称**: `sdqp-permission-engine`

### 2.1 模块职责

管理数据访问权限的完整生命周期：从申请、审批到撤销。通过字段级和条件级粒度支持最小权限原则，并根据组织变动或项目周期自动撤销权限。

### 2.2 权限授权模型

```rust
pub struct PermissionGrant {
    pub grant_id: Ulid,
    /// 申请人（用户或部门引用）
    pub applicant: ActorRef,
    /// 绑定的项目
    pub project_id: ProjectId,
    /// 可访问的字段列表
    pub fields: Vec<FieldPermission>,
    /// 行级过滤条件（查询时作为强制 WHERE 子句注入）
    pub conditions: Vec<FilterCondition>,
    /// 关联的数据源
    pub data_source_id: DataSourceId,
    /// 时间窗口
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    /// 授权时的组织关系绑定
    pub org_binding: OrgBinding,
    /// 状态
    pub status: GrantStatus,
}

pub enum GrantStatus {
    Pending,   // 等待审批
    Active,    // 审批通过，生效中
    Expired,   // 到期自动失效
    Revoked,   // 被主动撤销
}
```

### 2.3 权限合并规则

当同一用户在同一项目的同一数据源上持有多个有效授权时：

- **字段**: 取并集（Union）
- **条件**: 取并集（OR）— 用户可以看到满足任一已批准条件的行
- **时间窗口**: 取交集 — 仅在重叠期间有效
- **冲突解决**: 若某授权明确拒绝某字段，拒绝优先（deny-wins）

### 2.4 申请人资格配置

谁可以申请数据访问，按项目级配置：

- **按部门**: 指定部门的所有成员可申请
- **按个人**: 指名用户可申请
- **按角色**: 拥有特定角色（如调查员、分析师）的用户可申请

资格规则从人事系统同步（见模块 3），组织变动时自动更新。

### 2.5 申请范围

每个申请需指定：

- 目标数据源及请求访问的具体字段
- 行级条件（过滤器），说明需要什么范围的数据
- 业务理由（自由文本 + 预定义类别）
- 申请时长（不得超过项目结束日期）

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

用户发起查询时，权限引擎执行以下校验，通过后才将 UnifiedQuery 传递给数据源适配层：

1. 验证用户在此数据源+项目组合上拥有 Active 授权
2. 将请求字段过滤为仅授权范围内的字段（请求未授权字段直接拒绝）
3. 将授权条件作为强制 WHERE 子句注入 UnifiedQuery
4. 根据数据源类型设置查询超时和执行模式
5. 向审计模块发射权限检查事件（通过或拒绝，含详细信息）

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
│   ├── model.rs           # PermissionGrant, FieldPermission, FilterCondition
│   ├── merge.rs           # 权限合并与冲突解决
│   ├── lifecycle.rs       # 自动撤销调度器与事件处理
│   ├── guard.rs           # 查询时强制执行（QueryGuard）
│   └── service.rs         # 权限授权的 CRUD 操作
└── tests/
```

---

## 模块 3: 人事系统集成

**crate 名称**: `sdqp-hr-integration`

### 3.1 模块职责

与企业人事系统双向集成，作为组织架构、员工状态和汇报关系的权威数据源。当人事变动发生时，自动触发权限调整。

### 3.2 核心能力

- **组织架构同步**: 部门层级、团队成员、汇报线
- **员工生命周期事件**: 入职、调动、晋升、离职
- **审批人解析**: 给定用户，解析其直属上级及管理链
- **批量同步**: 全量组织架构刷新，可配置周期（默认：每日）
- **事件驱动同步**: 关键变更（调动、离职）的实时 Webhook/事件监听

### 3.3 适配器模式

与数据源适配层类似，人事集成使用适配器模式支持不同人事系统：

| 人事系统 | 集成方式 | 备注 |
|---------|---------|------|
| 飞书/Lark People | Open API + 事件订阅 | 国内公司首选；支持实时事件 |
| Workday | REST API + Webhooks | 跨国公司常用 |
| SAP SuccessFactors | OData API | 企业标准 |
| 自定义 LDAP/AD | LDAP 协议 | 遗留系统兜底 |
| 手动 CSV 导入 | 文件上传 | 无 API 系统的兜底方案 |

### 3.4 审批人升级逻辑

当审批人不可用（请假、离职或超过配置的超时时间未响应）时：

1. 检查审批人是否设置了委托人（飞书/Lark 常见功能）
2. 若无委托人，通过 HR 数据升级至审批人的直属上级
3. 若上级也不可用，沿汇报链继续向上
4. 若汇报链耗尽，路由至系统管理员并发出告警

超时阈值按审批流可配置（默认：24 小时）。

### 3.5 crate 文件结构

```
sdqp-hr-integration/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── traits.rs          # HRAdapter trait
│   ├── adapters/
│   │   ├── mod.rs
│   │   ├── feishu.rs      # 飞书/Lark 实现
│   │   ├── workday.rs     # Workday 实现
│   │   └── ldap.rs        # LDAP 实现
│   ├── sync.rs            # 批量与事件驱动同步编排
│   └── resolver.rs        # 审批人解析与升级逻辑
└── tests/
```

---

## 模块 4: 审批流引擎

**crate 名称**: `sdqp-approval-engine`

### 4.1 模块职责

管理数据访问审批请求的完整生命周期。支持可配置的多级审批流，具备会签、自动升级和多渠道 IM 通知功能。

### 4.2 审批流配置

#### 流程定义

每个项目可定义自定义审批流。一个流程由有序步骤组成，每个步骤指定：

- **step_type**: 串行（依次审批）| 并行会签（所有人都通过才算通过）| 或签（一人通过即可）
- **approvers**: 静态用户列表，或动态解析（如申请人直属上级、数据负责人）
- **timeout**: 单步超时时间
- **auto_actions**: 超时后的动作（升级 | 自动拒绝 | 催办提醒）

#### 并发申请的合并规则

当多个申请指向相同数据源且审批链有重叠时：

- **共同审批人合并**: 若 A 需要 审批人1→审批人2，B 需要 审批人1→审批人3，则合并为 审批人1→（审批人2 AND 审批人3 会签）
- 每个审批人看到所有绑定申请的完整上下文
- 支持部分审批：审批人2 可以通过 A 的字段，同时审批人3 仍在处理 B 的字段

### 4.3 IM 通知集成

| IM 平台 | 集成方式 | 支持的操作 |
|--------|---------|-----------|
| 飞书/Lark | Bot API + 交互式卡片 | 在卡片内直接审批/拒绝；查看详情 |
| Telegram | Bot API + Inline Keyboards | 通过内联按钮审批/拒绝；文件附件 |
| 钉钉 | Robot API + Action Cards | 在卡片内审批/拒绝 |
| Slack | Bot API + Block Kit | 通过交互式消息审批/拒绝 |
| 邮件 | SMTP + 操作链接 | 兜底方案；链接跳转到 Web 审批页面 |

通知系统使用可插拔的 `NotificationChannel` trait，添加新 IM 平台无需修改审批流核心引擎。每个用户可配置首选通知渠道。

### 4.4 升级与委托

- **超时升级**: 步骤超时后，系统查询人事集成模块获取审批人的直属 leader 并重新路由
- **委托**: 审批人可预设委托人，缺席期间由委托人接收审批请求
- **紧急旁路**: 系统管理员可强制审批，但会触发增强审计日志记录且必须填写理由

### 4.5 crate 文件结构

```
sdqp-approval-engine/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── flow.rs            # 审批流定义、步骤类型、流程 DSL
│   ├── executor.rs        # 流程执行引擎（状态机）
│   ├── merge.rs           # 并发申请合并逻辑
│   ├── notification/
│   │   ├── mod.rs         # NotificationChannel trait
│   │   ├── feishu.rs
│   │   ├── telegram.rs
│   │   ├── dingtalk.rs
│   │   └── slack.rs
│   └── escalation.rs     # 超时检测与升级路由
└── tests/
```

---

## 模块 5: 多租户与项目隔离

**crate 名称**: `sdqp-tenant-isolation`

### 5.1 模块职责

在项目与租户之间强制实施严格隔离。鉴于所处理数据的敏感性，隔离在多个层面实施：逻辑访问控制、加密密钥分离，以及可选的物理存储分离。

### 5.2 隔离架构

| 层面 | 隔离方式 | 粒度 |
|------|---------|------|
| 认证 | 每租户独立身份提供者；SSO 集成 | 租户级 |
| 授权 | RBAC + ABAC；所有查询限定 project_id | 项目级 |
| 加密密钥 | 每个项目独立 DEK；KEK 在租户级 | 项目级 |
| 数据存储 | 逻辑隔离：独立 schema/前缀；物理隔离：可选每租户独立数据库 | 可配置 |
| 快照 | snapshot_id 包含 project_id；跨项目访问返回 404 | 项目级 |
| 审计日志 | 日志标记 tenant_id + project_id；查询按范围过滤 | 项目级 |

### 5.3 项目生命周期

- **创建（Created）**: 管理员创建项目，绑定数据源、配置审批流、设置成员列表
- **活跃（Active）**: 成员可申请权限；查询和分析功能开放
- **冻结（Frozen）**: 不再接受新权限申请；已有访问只读；禁止数据导出
- **归档（Archived）**: 所有权限撤销；快照删除；审计日志按保留策略保留
- **删除（Deleted）**: 全量清除包括审计日志（仅在监管保留期满后）

### 5.4 crate 文件结构

```
sdqp-tenant-isolation/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── context.rs         # TenantContext, ProjectContext（注入到每个请求）
│   ├── guard.rs           # 中间件：对所有查询强制项目范围限定
│   └── lifecycle.rs       # 项目状态机与状态转换逻辑
└── tests/
```

---

## 模块 6: 加密与密钥管理

**crate 名称**: `sdqp-encryption`

### 6.1 模块职责

处理系统中所有密码学操作，包括静态数据加密、传输中数据保护和安全的密钥生命周期管理。实施信封加密方案，集成硬件安全模块（HSM）保护根密钥。

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

这种设计确保单个 DEK 泄露只暴露一个项目的数据，且轮换 KEK 无需重新加密所有数据。

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

- **DEK 轮换**: 按项目级周期（默认：90 天）或按需；旧 DEK 保留用于解密现有快照
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
│   ├── envelope.rs        # 信封加密/解密逻辑
│   ├── kms/
│   │   ├── mod.rs         # KMS 适配器 trait
│   │   ├── aws.rs         # AWS KMS 实现
│   │   ├── azure.rs       # Azure Key Vault 实现
│   │   ├── aliyun.rs      # 阿里云 KMS 实现
│   │   └── vault.rs       # HashiCorp Vault 实现
│   ├── pipeline.rs        # 解密管道（强制经过水印+脱敏步骤）
│   └── rotation.rs        # 密钥轮换调度器与重新封装逻辑
└── tests/
```

---

## 模块 7: 数据分类分级

**crate 名称**: `sdqp-data-classification`

### 7.1 模块职责

并非所有敏感数据同等敏感。本模块提供元数据驱动的数据分类分级框架，决定每个字段如何保护：适用哪种审批流、使用什么脱敏规则、水印编码强度多大。

### 7.2 分级体系

| 级别 | 标签 | 示例 | 默认保护措施 |
|------|------|------|------------|
| L1 | 公开 | 公司名称、产品类别 | 仅标准访问日志 |
| L2 | 内部 | 员工姓名、部门 | 需登录；基础审计日志 |
| L3 | 机密 | 手机号、邮箱地址 | 需审批；展示时部分脱敏（如 138****1234） |
| L4 | 高度机密 | 身份证号、银行账号、医疗记录 | 多级审批；默认全量脱敏；强水印；禁止批量导出 |
| L5 | 受限 | 进行中的调查对象、密封法律文件 | 仅指定授权人审批；字段级静态加密；禁止截图/导出；最高水印密度 |

### 7.3 分级元数据

每个已注册数据源中的字段标记以下元数据：

- **classification_level**: L1–L5
- **data_category**: PII（个人身份信息）、Financial（财务）、Medical（医疗）、Legal（法律）、Business（商业）、Technical（技术）
- **applicable_regulations**: GDPR、CCPA、PIPL（个保法）、HIPAA、SOX 等
- **masking_rule**: None（无脱敏）、Partial（部分脱敏）、Full（全量脱敏）、Hash（哈希）、Tokenize（令牌化）
- **retention_policy**: 此数据可被缓存/快照保留的时长

分级元数据可由数据负责人手动设置，也可通过模式匹配自动检测（如身份证号正则、银行卡号模式）。自动检测结果始终需要人工确认后才能生效。

### 7.4 crate 文件结构

```
sdqp-data-classification/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── model.rs           # ClassificationLevel, DataCategory, FieldClassification
│   ├── rules.rs           # 规则引擎：分级到保护策略的映射
│   └── detector.rs        # 常见敏感数据类型的自动检测模式
└── tests/
```

---

## 模块 8: 数据查看与分析层

**crate 名称**: `sdqp-data-view`（后端 Rust 分析引擎）+ 前端 TypeScript/React 项目

### 8.1 模块职责

提供用户界面用于查看查询结果和执行分析操作。在可用性（类 Excel 数据透视表拖拉拽分析）与安全性（所有聚合在服务端完成，前端只拿到处理后的结果）之间取得平衡。

**v1.1 变更**: 分析引擎全部使用 Rust 实现，基于 Apache DataFusion + Apache Arrow 构建。此模块设计为可独立复用的通用大数据分析引擎，不与 SDQP 业务逻辑强耦合。

### 8.2 为什么用 Rust + DataFusion

- **性能**: DataFusion 提供向量化多线程流式执行引擎，原生支持 Parquet、CSV、JSON 格式，查询性能接近 ClickHouse/DuckDB
- **可扩展性**: 支持自定义 TableProvider（对接 SDQP 加密快照作为数据源）、自定义标量/聚合/窗口函数、自定义优化器规则
- **复用性**: 分析引擎独立于 SDQP 使用，可直接嵌入其他大数据分析场景（BI 工具、数据质量平台、合规报告引擎）
- **内存效率**: Arrow 列式格式在分析工作负载下的内存利用率远优于行式存储，适合大数据集聚合

### 8.3 架构原则：服务端计算

为防止完整数据集暴露于浏览器内存，所有数据操作遵循严格模式：

- **明细查看**: 分页展示，字段级脱敏已应用。用户每次只能看到一页数据，永远看不到完整数据集。每次翻页都是一次独立的后端调用并重新验证权限。
- **聚合/透视**: 拖拉拽的透视配置发送到后端作为聚合查询。后端通过 DataFusion 执行计算（SUM、COUNT、AVG 等）后仅返回聚合输出。前端渲染结果但永远不会收到底层明细行，除非用户下钻（下钻触发独立的、经过权限检查的明细查询）。
- **图表/可视化**: 基于服务端计算的聚合结果构建，而非原始数据。

### 8.4 DataFusion 集成架构

```rust
/// 自定义 TableProvider：从加密快照中读取数据
/// 在 DataFusion 的执行计划中作为数据源注册
pub struct EncryptedSnapshotProvider {
    snapshot_id: SnapshotId,
    /// 解密后的 Arrow RecordBatch 流
    /// 解密在 TEE 中完成，数据以 Arrow 列式格式在内存中存在
    decryption_pipeline: DecryptionPipeline,
    /// 字段级脱敏规则（来自数据分类模块）
    masking_rules: Vec<FieldMaskingRule>,
    /// 水印注入器（解密后、返回前注入）
    watermark_injector: WatermarkInjector,
}

/// PivotQueryBuilder：将前端拖拉拽配置翻译为 DataFusion SQL
pub struct PivotQueryBuilder {
    /// 行维度字段
    pub row_fields: Vec<String>,
    /// 列维度字段
    pub column_fields: Vec<String>,
    /// 值字段及聚合函数
    pub value_aggregations: Vec<(String, AggFunction)>,
    /// 过滤条件
    pub filters: Vec<FilterCondition>,
}

pub enum AggFunction {
    Sum, Count, Avg, Min, Max, CountDistinct, 
    Median, Percentile(f64),
}
```

执行流程：

1. 前端提交透视配置 → PivotQueryBuilder 生成 DataFusion LogicalPlan
2. DataFusion 优化器应用谓词下推、投影裁剪等优化
3. EncryptedSnapshotProvider 提供解密后的 Arrow RecordBatch 流
4. DataFusion 执行聚合计算，结果以 Arrow 格式返回
5. 服务端将结果序列化为 JSON/Arrow IPC 发送到前端

### 8.5 数据透视与分析功能

前端提供类 Excel 数据透视表体验：

- 拖拽字段到"行"、"列"、"值"、"筛选"区域
- 支持的聚合函数：SUM、COUNT、AVG、MIN、MAX、COUNT DISTINCT、MEDIAN、PERCENTILE
- 从聚合单元格下钻到底层明细（经过权限检查）
- 保存分析配置为模板以便复用
- 分析配置限定在用户+项目范围内，不共享除非明确发布

### 8.6 前端安全控制

- **Canvas 渲染敏感字段**: 防止浏览器 DOM 检查和复制粘贴
- **隐形水印覆盖层**: 所有展示数据上叠加不可见水印（见模块 10）
- **截屏检测**: 可选的浏览器端 Visibility API 检测（建议性，非强制）
- **会话超时**: 可配置的空闲超时，需重新认证
- **内容安全策略**: 严格的 CSP 头防止 XSS 数据外泄

### 8.7 crate 文件结构

```
sdqp-data-view/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── engine.rs          # DataFusion SessionContext 初始化与管理
│   ├── providers/
│   │   ├── mod.rs
│   │   ├── snapshot.rs    # EncryptedSnapshotProvider（自定义 TableProvider）
│   │   └── streaming.rs   # 流式数据源 Provider（预留实时数据接入）
│   ├── pivot.rs           # PivotQueryBuilder：透视配置 → DataFusion LogicalPlan
│   ├── functions/
│   │   ├── mod.rs
│   │   ├── masking.rs     # 自定义 UDF：字段级脱敏函数
│   │   └── watermark.rs   # 自定义 UDF：水印注入函数
│   ├── pagination.rs      # 基于游标的分页（含权限重新验证）
│   ├── export.rs          # 导出编排（委托给证据模块执行认证导出）
│   └── api.rs             # gRPC/REST API 层（查询提交、结果获取）
└── tests/

# 前端项目（独立仓库）
sdqp-frontend/
├── package.json
├── src/
│   ├── components/
│   │   ├── PivotTable/    # 数据透视表组件
│   │   ├── DetailView/    # 明细分页查看
│   │   ├── QueryProgress/ # 异步查询进度展示（WebSocket）
│   │   └── WatermarkOverlay/  # 水印覆盖层
│   ├── services/          # API 调用
│   └── security/          # CSP、会话管理、Canvas 渲染
```

---

## 模块 9: 电子证据与存证

**crate 名称**: `sdqp-evidence`

### 9.1 模块职责

确保导出的数据满足多个司法管辖区法院和监管机构要求的证据标准。提供防篡改封装、可信时间戳、哈希链完整性和可插拔的存证后端（包括区块链）。

### 9.2 多司法管辖区合规

| 司法管辖区 | 关键标准 | 核心要求 |
|-----------|---------|---------|
| 中国大陆 | 最高法电子数据规定（2019）；电子签名法 | 可信时间戳；哈希完整性；全链路保管链审计日志；有争议时可公证 |
| 欧盟 | eIDAS 法规；GDPR | 合格电子签名（QES）；合格时间戳；导出中 GDPR 合规数据处理 |
| 美国 | 联邦证据规则（FRE 901/902）；ESI 指南 | 电子记录认证；保管链；元数据保留 |
| 英国 | 民事证据法 1995；Practice Direction 31B | 真实性证书；审计追踪；原始格式保留 |
| 新加坡 | 电子交易法；证据法 | 安全电子签名；系统可靠性证明 |
| 日本 | 电子签名与认证业务法 | 合格电子签名；时间戳机构认证 |

### 9.3 证据包结构

每次认证导出生成一个证据包（Evidence Package），包含：

- **data_payload**: 导出数据（加密，使用接收方专属 DEK）
- **metadata_manifest**: 字段描述、查询参数、权限授权详情、数据源信息
- **hash_chain**: 各组件的 SHA-256 哈希，依次链式串联；最终哈希签名
- **trusted_timestamp**: 由认可的时间戳机构（TSA）签发
- **audit_extract**: 覆盖数据生命周期的相关审计日志条目（查询、查看、导出事件）
- **certificate_of_authenticity**: 数字签名的真实性与溯源证明文件
- **jurisdiction_marker**: 标识本证据包按哪个司法管辖区标准生成

### 9.4 可信时间戳供应商

系统支持可插拔的 TSA 后端：

- **中国**: 国家授时中心（NTSC）；第三方平台（如联合信任、保全网）
- **欧盟**: eIDAS 合格信任服务提供者（如 DigiCert、Sectigo）
- **美国**: RFC 3161 兼容 TSA 服务
- **兜底**: 内部 NTP 同步时间戳 + HSM 签名证明（证据效力较低）

### 9.5 区块链存证（可插拔）

区块链作为可选增强存证层，不是必需组件：

- hash_chain 的最终摘要锚定到区块链上，作为不可篡改的存在性证明
- 支持的链：可配置；候选包括 Hyperledger Fabric（私有链）、Ethereum（公链）、BSN（中国）、以及各司法管辖区的司法链
- 锚定是异步非阻塞的；证据包在没有区块链回执的情况下也是有效的
- 区块链回执（交易 ID、区块号、时间戳）在确认后追加到证据包中

这种可插拔设计使组织可以根据自身所在司法管辖区和风险承受能力选择合适的存证级别，无需架构变更。

### 9.6 crate 文件结构

```
sdqp-evidence/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── package.rs         # 证据包构建器与序列化
│   ├── hash_chain.rs      # 哈希链构建与验证
│   ├── tsa/
│   │   ├── mod.rs         # TSA 适配器 trait
│   │   ├── ntsc.rs        # 国家授时中心
│   │   └── rfc3161.rs     # 通用 RFC 3161 实现
│   ├── blockchain/
│   │   ├── mod.rs         # 区块链锚定 trait
│   │   ├── fabric.rs      # Hyperledger Fabric
│   │   └── ethereum.rs    # Ethereum
│   └── compliance/
│       ├── mod.rs
│       ├── china.rs       # 中国大陆证据包模板
│       ├── eu.rs          # 欧盟 eIDAS 模板
│       └── us.rs          # 美国 FRE 模板
└── tests/
```

---

## 模块 10: 暗水印系统

**crate 名称**: `sdqp-watermark`

### 10.1 模块职责

在系统渲染或导出的所有数据中嵌入不可见的、可追踪的标识符。由两个独立组件构成：集成在应用中的水印嵌入 SDK，以及设计用于与外部 DLP 系统集成的水印检测 API。

### 10.2 水印嵌入 SDK

集成在数据查看层和导出管道中：

- **前端水印**: 所有展示数据上叠加不可见 SVG/Canvas 水印层；编码 user_id + session_id + timestamp
- **导出水印（文档）**: 导出的 XLSX、CSV、PDF 文件中进行隐写术编码；可抵抗格式转换和打印
- **导出水印（图像）**: DCT 域水印用于截屏和图像导出；可抵抗 JPEG 再压缩和适度裁剪
- **水印密度**: 按数据分类级别可配置（L3: 标准, L4: 密集, L5: 最大）

**水印载荷（Payload）**: system_id（标识系统实例）+ user_id + project_id + timestamp + sequence_number。这使得可以将泄露文件追溯到具体用户、会话和访问时间。

### 10.3 水印检测 API

作为独立 REST/gRPC 服务暴露，供外部系统集成：

- `detect(file_or_image) → Option<WatermarkPayload>`: 提取水印（如存在）
- `verify(file_or_image, expected_payload) → VerificationResult`: 检查特定水印是否存在
- `batch_scan(files) → Vec<ScanResult>`: 批量扫描，用于 DLP 集成

此 API 设计为被以下系统调用：公司现有 DLP 网关（出站流量检查）、邮件安全网关（附件扫描）、以及下文描述的未来独立 DLP 模块。

### 10.4 DLP 集成接口

当前系统提供检测 API；完整 DLP 网关作为独立产品，可通过以下方式集成：

- **内联检查**: DLP 网关对出站流量中的文件调用检测 API
- **权限感知过滤**: DLP 查询本系统权限数据库，判断流量发起者是否拥有活跃的敏感数据访问权限；仅检查来自授权用户的带水印流量（减少误报和处理负载）
- **策略引擎**: DLP 可根据水印内容（阻断、告警、记录）和关联项目的数据分类级别应用不同动作

这种分离确保水印系统保持轻量和聚焦，而未来的 DLP 模块可将其作为检测后端，无需修改核心系统。

### 10.5 crate 文件结构

```
sdqp-watermark/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── embed/
│   │   ├── mod.rs
│   │   ├── svg_overlay.rs     # SVG/Canvas 前端覆盖层
│   │   ├── steganographic.rs  # 文档隐写术
│   │   └── dct.rs             # DCT 域图像水印
│   ├── detect/
│   │   ├── mod.rs
│   │   ├── extractor.rs       # 水印提取算法
│   │   └── verifier.rs        # 水印验证
│   ├── payload.rs             # WatermarkPayload 编解码
│   └── api.rs                 # 检测 API 服务（REST + gRPC）
└── tests/
```

---

## 模块 11: 全链路审计日志

**crate 名称**: `sdqp-audit`

### 11.1 模块职责

捕获系统中每个操作的完整、防篡改记录。每条审计条目回答：谁（Who）在什么时候（When）因为什么（Why）对什么数据（What）做了什么动作（Action），结果怎样（Result）？审计日志本身是证据链的一部分，必须达到与其保护的数据相同的完整性标准。

### 11.2 审计事件结构

```rust
pub struct AuditEvent {
    /// 全局唯一、按时间排序（ULIDv2）
    pub event_id: Ulid,
    /// 高精度、NTP 同步
    pub timestamp: DateTime<Utc>,
    /// 操作者信息
    pub actor: ActorInfo, // user_id + session_id + IP + 设备指纹
    /// 动作类型枚举
    pub action: ActionType, // QUERY, VIEW, EXPORT, PERMISSION_APPLY, PERMISSION_APPROVE, CONFIG_CHANGE, LOGIN...
    /// 被操作的资源
    pub target: TargetRef, // project_id, data_source_id, snapshot_id, grant_id 等
    /// 上下文：业务理由、审批引用、或触发此动作的系统事件
    pub context: EventContext,
    /// 结果
    pub result: ActionResult, // SUCCESS | FAILURE | DENIED + 错误详情
    /// 相关数据的指纹（查询：结果集哈希；导出：导出文件哈希）
    pub data_fingerprint: Option<String>,
    /// 前一条事件的哈希（哈希链）
    pub prev_hash: String,
}
```

### 11.3 防篡改机制

审计日志是只追加的（append-only），并通过以下方式防止篡改：

- 每条事件包含前一条事件的哈希，形成哈希链（类区块链结构）
- **定期检查点**: 每 N 条事件（可配置，默认：1000），链式哈希由 HSM 签名，并可选锚定到证据模块的区块链后端
- 日志存储对应用层是只写的；管理员删除需要多方授权，且会留下墓碑记录
- **外部日志转发**: 审计事件同时转发到独立的 SIEM/日志聚合系统作为第二副本

### 11.4 保留与合规

| 保留类别 | 默认周期 | 适用法规 |
|---------|---------|---------|
| 常规访问日志 | 3 年 | SOX、内部制度 |
| 权限生命周期事件 | 5 年 | GDPR（涉及欧盟数据时）、个保法、SOX |
| 证据相关动作 | 10 年或按案件周期 | 法院规则、监管冻结 |
| 系统管理动作 | 5 年 | ISO 27001、SOC2 |

### 11.5 crate 文件结构

```
sdqp-audit/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── event.rs           # AuditEvent 结构体、动作类型、结果类型
│   ├── chain.rs           # 哈希链构建与验证
│   ├── store.rs           # 只追加存储后端（支持 PostgreSQL、ClickHouse、S3）
│   ├── forwarder.rs       # SIEM/外部日志转发（syslog、webhook、Kafka）
│   └── retention.rs       # 保留策略执行与归档
└── tests/
```

---

## 模块 12: 系统自身安全

**crate 名称**: `sdqp-system-security`

### 12.1 模块职责

本系统在设计上就是一个高价值攻击目标：它从多个数据源聚合敏感数据并提供访问工具。本模块聚焦于保护系统本身免受入侵、内部威胁和配置错误。

### 12.2 认证与访问控制

- **SSO 集成**: SAML 2.0 / OIDC 对接企业身份提供者（Azure AD、Okta、飞书/Lark、Google Workspace 等）
- **SCIM 协议支持（v1.1 新增）**: 通过 SCIM 2.0 协议自动同步用户和组的创建、更新、禁用，消除在身份提供者和本系统之间双重维护用户的需要
- **强制 MFA**: TOTP、硬件密钥（FIDO2/WebAuthn）或生物识别作为第二因子
- **会话管理**: 短生命周期 JWT 令牌（15 分钟）+ 刷新令牌轮换；会话绑定 IP + 设备指纹
- **API 认证**: 服务间 mTLS；外部集成使用 API 密钥 + IP 白名单

#### 持续认证机制（v1.1 新增）

传统认证只在登录时验证一次，会话期间不再检查。这为会话劫持、MFA 疲劳攻击留下了窗口。本系统实施持续认证：

- **行为基线**: 为每个用户建立正常行为基线（查询频率、数据量、访问时段、操作模式）
- **实时风险评分**: 每次操作触发风险评分计算（综合设备状态、位置变化、行为偏差）
- **自适应响应**: 
  - 低风险（评分 0-30）：正常放行
  - 中风险（评分 30-70）：要求二次确认（如重新输入密码或 MFA）
  - 高风险（评分 70-100）：立即终止会话，冻结权限，通知安全管理员
- **设备状态持续验证**: 通过轻量级客户端探针定期检查设备合规状态（OS 版本、安全补丁、是否越狱/root）

### 12.3 基于角色的访问控制（RBAC）

| 角色 | 范围 | 能力 |
|------|------|------|
| 系统管理员 | 全局 | 系统配置、用户管理，但无直接数据访问权限 |
| 项目管理员 | 项目级 | 项目配置、审批流设置、成员管理 |
| 数据负责人 | 数据源级 | 分类管理、审批权限、数据源配置 |
| 调查员/分析师 | 项目级 | 申请权限、查询数据、经审批后导出 |
| 审计员 | 全局或项目级 | 只读访问审计日志；无数据访问权限 |
| 审批人 | 审批流级 | 审批/拒绝权限申请；无直接数据查询权限 |

**关键约束**: 没有任何单一角色同时拥有系统配置权限和数据访问权限。系统管理员可以配置系统但不能查询敏感数据；分析师可以查询数据但不能修改系统配置。此职责分离在 API 网关层强制执行。

### 12.4 配置变更管理

- 所有配置变更（审批流、数据源连接、分类规则、用户角色）在内部审计追踪中版本化
- 关键变更（KMS 配置、管理员角色分配、审计保留策略）需要多方审批
- 配置漂移检测：定期比较运行中的配置与已批准的基线

### 12.5 漏洞管理

- **依赖扫描**: 每次构建自动执行 `cargo audit`；持续监控所有依赖的 CVE
- **API 安全**: 限流、输入验证、SQL 注入防护（仅参数化查询）
- **网络隔离**: 系统后端运行在专用网段；数据库和 KMS 访问受网络策略限制
- **渗透测试**: 每季度计划执行；发现的问题跟踪至解决

### 12.6 内存保护与机密计算（v1.1 新增）

系统在解密过程中 DEK 和明文数据不可避免地在内存中短暂存在，这是一个已知攻击面。防护措施：

- **TEE/安全飞地部署**: 解密管道优先部署在可信执行环境中（Intel SGX / AMD SEV / ARM TrustZone），内存加密由硬件保证，即使攻击者获得 root 权限也无法读取飞地内存
- **内存清零策略**: Rust 使用 `zeroize` crate 确保密钥和明文在 Drop 时立即清零，不依赖垃圾回收
- **进程隔离**: 解密进程与其他应用进程独立运行，使用独立的内存空间和安全上下文
- **核心转储禁用**: 解密进程禁用 core dump，防止内存快照泄露
- **DEK 缓存策略**: DEK 在内存中的保留时间不超过单次请求生命周期；不做跨请求的 DEK 内存缓存

### 12.7 隐蔽通道与数据外泄防护（v1.1 新增）

当前的暗水印系统（模块 10）聚焦于文件和流量层面的检测。但攻击者可能使用隐蔽通道外泄数据：

- **DNS 隧道检测**: 监控异常 DNS 查询模式（高频、长子域名、非标准记录类型），集成 DNS 日志到审计系统
- **HTTP 隐蔽通道检测**: 分析出站 HTTP 请求的 URL 参数、Header、Body 中是否编码了敏感数据特征
- **剪贴板管控**: 前端 Canvas 渲染已阻止 DOM 级复制；对于企业管控终端，建议集成 EDR 的剪贴板监控能力
- **打印管控**: 浏览器打印事件触发审计记录，打印输出自动注入水印
- **出站流量基线**: 建立每个用户/服务的正常出站流量基线，异常偏差触发告警

### 12.8 第三方集成安全（v1.1 新增）

本系统依赖多个第三方组件（KMS、HR 系统、IM 平台、TSA 服务），每个集成点都是潜在攻击面：

- **集成安全评估**: 每个第三方集成在接入前需通过安全评估清单（API 认证方式、数据传输加密、SLA、安全事件通知机制）
- **最小权限原则**: 每个第三方集成仅获得执行其功能所需的最小 API 权限（如 HR 系统只需只读 org 结构，不需要修改能力）
- **凭证轮换**: 所有第三方 API 密钥/Token 定期自动轮换（默认 90 天），轮换事件记录在审计日志中
- **熔断与降级**: 第三方服务不可用时系统有明确的降级策略（如 IM 通知失败时回退到邮件，KMS 不可用时暂停新的解密请求但不影响已缓存会话）
- **供应链扫描**: 除 `cargo audit` 外，定期审查第三方服务商的安全态势（SOC2 报告、渗透测试结果、安全事件历史）

### 12.9 高可用与灾难恢复

- **无状态应用层**: 负载均衡器后水平扩展
- **数据库复制**: 审计日志同步复制；快照异步复制
- **跨地域备份**: 加密备份至地理隔离的区域（RPO: 1 小时；RTO: 4 小时）
- **密钥恢复流程**: 文档化并每季度演练；需 M-of-N 密钥保管人

### 12.10 crate 文件结构

```
sdqp-system-security/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── sso.rs         # SSO 适配器（SAML、OIDC）
│   │   ├── scim.rs        # SCIM 2.0 用户/组同步
│   │   ├── mfa.rs         # MFA 验证
│   │   ├── session.rs     # 会话管理
│   │   └── continuous.rs  # 持续认证引擎（风险评分、自适应响应）
│   ├── rbac/
│   │   ├── mod.rs
│   │   ├── roles.rs       # 角色定义
│   │   └── sod.rs         # 职责分离强制执行
│   ├── memory/
│   │   ├── mod.rs
│   │   ├── tee.rs         # TEE/安全飞地集成
│   │   └── zeroize.rs     # 内存安全清零策略
│   ├── exfiltration/
│   │   ├── mod.rs
│   │   ├── dns_tunnel.rs  # DNS 隧道检测
│   │   └── http_covert.rs # HTTP 隐蔽通道检测
│   ├── supply_chain.rs    # 第三方集成安全评估与凭证管理
│   └── config_audit.rs    # 配置版本化与变更追踪
└── tests/
```

---

## 模块 13: 用户与实体行为分析

**crate 名称**: `sdqp-ueba`

> **v1.1 新增模块**

### 13.1 模块职责

基于全链路审计日志（模块 11）进行用户和实体行为分析（UEBA），检测异常访问模式、潜在数据泄露行为和内部威胁。将审计模块的"记录"能力扩展为"检测+响应"能力。

### 13.2 为什么需要独立的 UEBA 模块

审计模块负责忠实记录，UEBA 模块负责智能分析。分离的原因：

- **职责单一**: 审计模块的写入路径必须极简、高可用，不能因为分析逻辑的复杂性影响日志写入的可靠性
- **独立扩展**: UEBA 的计算量可能远大于日志写入；需要独立的计算资源和扩展策略
- **可复用性**: UEBA 引擎可以接入其他系统的审计日志，不限于 SDQP

### 13.3 检测能力

#### 异常行为检测

- **查询频率异常**: 单用户查询频率突增（对比个人历史基线和同角色群体基线）
- **数据量异常**: 单次查询或累计查询的数据量异常偏大
- **时间异常**: 在非工作时间、节假日执行敏感查询
- **权限使用异常**: 权限申请通过后立即批量查询（可能是权限被盗用或滥用）
- **下钻异常**: 从聚合视图频繁下钻到明细数据，可能试图逐步拼凑完整数据集
- **导出异常**: 高频导出、导出后立即注销、导出到非常规设备

#### 实体行为检测

- **API 调用模式异常**: 服务账号的调用模式偏离基线（可能是凭证泄露）
- **数据源访问模式异常**: 某数据源的查询模式突变（可能是适配器被劫持）
- **审批流异常**: 审批时间异常快（秒级通过，可能是自动化刷审批）或审批人大量批准自己部门的请求

### 13.4 风险评分模型

```rust
pub struct RiskScore {
    /// 总分 0-100
    pub score: f64,
    /// 各维度分数
    pub dimensions: HashMap<RiskDimension, f64>,
    /// 触发的规则列表
    pub triggered_rules: Vec<RuleMatch>,
    /// 建议动作
    pub recommended_action: ResponseAction,
}

pub enum RiskDimension {
    QueryFrequency,
    DataVolume,
    TemporalPattern,
    PermissionUsage,
    ExportBehavior,
    DevicePosture,
    NetworkContext,
}

pub enum ResponseAction {
    /// 仅记录，不干预
    LogOnly,
    /// 发送告警给安全管理员
    Alert,
    /// 要求用户二次认证
    StepUpAuth,
    /// 暂停用户权限待审查
    SuspendPermission,
    /// 终止会话并锁定账户
    TerminateSession,
}
```

### 13.5 响应编排

UEBA 检测到异常后的响应不是简单的告警，而是与其他模块联动：

- **→ 权限引擎 (模块 2)**: 挂起可疑用户的权限授权
- **→ 系统安全 (模块 12)**: 触发持续认证的风险评分提升
- **→ 审批引擎 (模块 4)**: 通过 IM 通知安全管理员进行人工研判
- **→ 审计模块 (模块 11)**: 记录完整的检测事件和响应动作作为证据

### 13.6 技术实现

- **流式处理**: 从审计日志的 Kafka/事件流中实时消费，使用滑动窗口计算行为指标
- **基线计算**: 使用 ClickHouse 对历史审计日志做离线聚合，生成用户/角色/时段的行为基线
- **规则引擎**: 支持声明式规则定义（YAML/TOML 配置文件），无需修改代码即可新增检测规则
- **ML 模型（预留）**: 为后续引入机器学习异常检测预留接口，初期使用基于规则的方法

### 13.7 crate 文件结构

```
sdqp-ueba/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── consumer.rs        # 审计事件流消费者（Kafka / 事件总线）
│   ├── baseline.rs        # 行为基线计算与更新
│   ├── rules/
│   │   ├── mod.rs         # 规则引擎框架
│   │   ├── query.rs       # 查询行为异常规则
│   │   ├── export.rs      # 导出行为异常规则
│   │   ├── approval.rs    # 审批行为异常规则
│   │   └── entity.rs      # 实体（服务账号/API）行为规则
│   ├── scoring.rs         # 风险评分模型
│   ├── response.rs        # 响应编排（与其他模块联动）
│   └── api.rs             # 管理 API（规则管理、基线查看、告警列表）
└── tests/
    └── scenarios/         # 预定义的异常场景测试用例
```

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
        ┌──────────┬─────────────────────┼─────────────────────┬──────────┐
        │          │                     │                     │          │
        ▼          ▼                     ▼                     ▼          ▼
   ┌─────────┐ ┌─────────┐        ┌──────────┐         ┌─────────┐ ┌─────────┐
   │ 模块 3  │ │ 模块 7  │        │ 模块 11  │         │ 模块 6  │ │ 模块 10 │
   │ HR 集成 │ │数据分级  │        │ 审计日志  │         │加密密钥  │ │ 暗水印  │
   └────┬────┘ └────┬────┘        └────┬─────┘         └────┬────┘ └────┬────┘
        │           │                  │ ▲                   │          │
        ▼           │                  │ │(所有模块发射事件)    │          │
   ┌─────────┐      │                  │ │                   │          │
   │ 模块 4  │      │                  ▼ │                   │          │
   │ 审批流  │      │            ┌──────────┐                │          │
   └────┬────┘      │            │ 模块 13  │                │          │
        │           │            │  UEBA    │←(联动)──┐      │          │
        ▼           ▼            └────┬─────┘         │      │          │
   ┌──────────────────────┐           │          ┌────┴────┐ │          │
   │     模块 2: 权限引擎   │←─(挂起权限)─┘          │模块 12  │ │          │
   └──────────┬───────────┘                      │持续认证  │ │          │
              │                                  └─────────┘ │          │
              ▼                                              ▼          │
   ┌──────────────────────┐                        ┌─────────────────┐  │
   │  模块 1: 数据源适配层  │                        │  解密管道强制    │  │
   │  （统一异步查询接口）   │                        │  经过水印注入    │←─┘
   └──────────┬───────────┘                        └────────┬────────┘
              │                                             │
              ▼                                             │
   ┌──────────────────────┐                                 │
   │  模块 8: 数据查看分析  │←──────────────────────────────────┘
   │ (Rust + DataFusion)  │
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
| 系统安全 (12) | HR 集成 (3) | SCIM 用户同步 + 持续认证的组织上下文 |
| 所有模块 | 审计模块 (11) | 发射所有重要动作的审计事件 |
| 所有模块 | 租户隔离 (5) | 项目范围的上下文注入 |
| 所有模块 | 系统安全 (12) | 认证、授权、API 安全 |

---

## 开发阶段规划

| 阶段 | 包含模块 | 里程碑 |
|------|---------|--------|
| **Phase 1: 安全地基** | 12（系统安全）+ 5（租户隔离）+ 11（审计） | 安全外壳就绪：认证、隔离、审计日志可运行 |
| **Phase 2: 核心数据通路** | 1（数据源适配）+ 2（权限引擎）+ 6（加密） | 端到端加密数据查询，统一异步接口，权限强制执行 |
| **Phase 3: 工作流** | 3（HR 集成）+ 4（审批引擎）+ 7（数据分级） | 完整的 申请→审批→访问 生命周期 |
| **Phase 4: 用户体验** | 8（数据查看与分析） | Rust + DataFusion 分析引擎，数据透视表、下钻、分页明细查看 |
| **Phase 5: 合规增强** | 9（证据）+ 10（水印） | 认证导出与基于水印的泄露追踪 |
| **Phase 6: 智能安全** | 13（UEBA）+ 12 增强（持续认证、隐蔽通道检测） | 行为分析驱动的主动安全防护 |

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

**发布策略**: 这些模块从第一天起就作为独立 Rust crate 发布，API 清晰，不泄露系统特定假设。每个后续项目使用和改进这些模块，使共享组件库不断强壮。
