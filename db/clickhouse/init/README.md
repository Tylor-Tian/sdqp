# ClickHouse Init

本目录用于存放 SDQP ClickHouse 初始化脚本和建表语句。

Prod Stage 0 仅冻结目录结构，不引入真实初始化逻辑。
Prod Stage 3 起：

- 审计与 UEBA 表结构必须落在本目录
- 初始化脚本必须兼容本地 Docker 启动
- 所有变更必须有对应验证脚本或 smoke
