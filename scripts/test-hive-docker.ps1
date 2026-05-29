$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$composeFile = Join-Path $repoRoot "docker-compose.hive.yml"

docker compose -f $composeFile up -d hive-server
docker compose -f $composeFile run --rm hive-init

$env:SDQP_ENABLE_HIVE_DOCKER_TESTS = "1"
$env:SDQP_HIVE_DOCKER_COMPOSE_FILE = $composeFile
$env:SDQP_HIVE_DOCKER_SERVICE = "hive-server"
$env:SDQP_HIVE_DOCKER_JDBC_URL = "jdbc:hive2://127.0.0.1:10000/default"

cargo test -p sdqp-api --test uat_hive_docker_execution -- --test-threads=1 --nocapture
