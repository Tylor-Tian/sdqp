# PostgreSQL Migrations

本目录用于存放 SDQP PostgreSQL 正式迁移脚本。

Prod Stage 0 仅冻结目录结构，不引入真实迁移。
Prod Stage 3 起：

- 所有 PostgreSQL schema 变更必须落在本目录
- 迁移必须可重复执行
- 迁移必须附带回滚或补偿说明
