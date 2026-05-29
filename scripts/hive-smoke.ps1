$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$composeFile = Join-Path $repoRoot "docker-compose.hive.yml"

docker compose -f $composeFile up -d hive-server
docker compose -f $composeFile run --rm hive-init
docker compose -f $composeFile exec -T hive-server /opt/hive/bin/beeline `
    -u "jdbc:hive2://127.0.0.1:10000/default" `
    -n hive `
    --outputformat=csv2 `
    --showHeader=false `
    --silent=true `
    -e "SELECT employee_id, department FROM sdqp_fixture_employees ORDER BY employee_id"
