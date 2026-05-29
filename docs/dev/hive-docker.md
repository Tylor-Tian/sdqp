# Docker-backed Hive Execution

This repo includes a minimal Apache Hive environment for the real Module 1 Hive provider path.

Entrypoints:
- `docker-compose.hive.yml`: standalone Hive metastore, HiveServer2, and one-shot fixture init.
- `docker-compose.yml`: includes the same Hive services for local Docker runs.
- `docker-compose.prod-sim.yml`: includes Hive services with non-conflicting host ports.
- `scripts/hive-up.ps1`: starts Hive and seeds fixtures.
- `scripts/hive-smoke.ps1`: runs a direct beeline query against the fixture table.
- `scripts/test-hive-docker.ps1`: starts Hive and runs the Docker-backed Hive UAT.

Ports:
- Hive metastore: `9083` in local Hive compose, `39083` in prod-sim.
- HiveServer2 JDBC/Thrift: `10000` in local Hive compose, `31000` in prod-sim.
- HiveServer2 web UI: `10002` in local Hive compose, `31002` in prod-sim.

Fixture:
- `docker/hive/init/001_sdqp_fixture.hql`
- Table: `sdqp_fixture_employees(employee_id STRING, department STRING)`

Provider distinction:
- Mock Hive remains `mock://hive` and is test-only.
- Real Docker-backed Hive uses `connection_uri = jdbc:hive2://...` plus `adapter_config.provider = "beeline"`.
- The API and worker Docker images include the Hive beeline client so local Docker can use `SDQP_HIVE_COMMAND=beeline`.
