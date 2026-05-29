$ErrorActionPreference = "Stop"

function Invoke-ExternalCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Label,
    [Parameter(Mandatory = $true)]
    [string]$FilePath,
    [string[]]$ArgumentList = @()
  )

  Write-Host $Label
  & $FilePath @ArgumentList
  if ($LASTEXITCODE -ne 0) {
    throw "$Label failed with exit code $LASTEXITCODE"
  }
}

function Invoke-PsqlFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Database,
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  Get-Content -Raw $Path | docker compose exec -T postgres psql -U sdqp -d $Database -v ON_ERROR_STOP=1 -f -
  if ($LASTEXITCODE -ne 0) {
    throw "psql execution failed for $Path"
  }
}

function Wait-PostgresReady {
  $deadline = (Get-Date).AddSeconds(120)
  while ((Get-Date) -lt $deadline) {
    docker compose exec -T postgres pg_isready -U sdqp -d sdqp | Out-Null
    $containerReady = $LASTEXITCODE -eq 0
    $hostReady = $false
    try {
      $client = [System.Net.Sockets.TcpClient]::new()
      $async = $client.BeginConnect("127.0.0.1", 15432, $null, $null)
      $hostReady = $async.AsyncWaitHandle.WaitOne(2000) -and $client.Connected
      $client.Close()
    }
    catch {
      $hostReady = $false
    }

    if ($containerReady -and $hostReady) {
      return
    }
    Start-Sleep -Seconds 2
  }

  throw "PostgreSQL did not become ready in time."
}

function Wait-ClickHouseReady {
  $deadline = (Get-Date).AddSeconds(120)
  while ((Get-Date) -lt $deadline) {
    docker compose exec -T clickhouse clickhouse-client --query "SELECT 1" | Out-Null
    $containerReady = $LASTEXITCODE -eq 0
    $hostReady = $false
    try {
      $response = Invoke-WebRequest -Uri "http://127.0.0.1:18123/?query=SELECT%201" -UseBasicParsing
      $hostReady = $response.StatusCode -eq 200
    }
    catch {
      $hostReady = $false
    }

    if ($containerReady -and $hostReady) {
      return
    }
    Start-Sleep -Seconds 2
  }

  throw "ClickHouse did not become ready in time."
}

function Wait-MinioReady {
  $deadline = (Get-Date).AddSeconds(120)
  while ((Get-Date) -lt $deadline) {
    try {
      Invoke-WebRequest -Uri "http://127.0.0.1:19002/minio/health/live" -UseBasicParsing | Out-Null
      return
    }
    catch {
      Start-Sleep -Seconds 2
    }
  }

  throw "MinIO did not become ready in time."
}

Invoke-ExternalCommand `
  -Label "Resetting Stage 3 infrastructure volumes..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "-f", "docker-compose.yml", "down", "-v", "--remove-orphans")

Invoke-ExternalCommand `
  -Label "Starting Stage 3 infrastructure..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "-f", "docker-compose.yml", "up", "-d", "postgres", "clickhouse", "minio", "minio-init")

Wait-PostgresReady
Wait-ClickHouseReady
Wait-MinioReady

$migrationDb = "sdqp_stage3_gate"

Invoke-ExternalCommand `
  -Label "Resetting Stage 3 migration smoke database..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "exec", "-T", "postgres", "psql", "-U", "sdqp", "-d", "postgres", "-c", "DROP DATABASE IF EXISTS $migrationDb;")

Invoke-ExternalCommand `
  -Label "Creating Stage 3 migration smoke database..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "exec", "-T", "postgres", "psql", "-U", "sdqp", "-d", "postgres", "-c", "CREATE DATABASE $migrationDb;")

Invoke-PsqlFile -Database $migrationDb -Path "db/postgres/migrations/20260329143000_stage3_core_schema.up.sql"

$tableCheck = docker compose exec -T postgres psql -U sdqp -d $migrationDb -t -A -c "SELECT to_regclass('public.query_tasks');"
if ($LASTEXITCODE -ne 0 -or $tableCheck.Trim() -ne "query_tasks") {
  throw "Migration up smoke failed: query_tasks table not created."
}

Invoke-PsqlFile -Database $migrationDb -Path "db/postgres/migrations/20260329143000_stage3_core_schema.down.sql"

$tableCheck = docker compose exec -T postgres psql -U sdqp -d $migrationDb -t -A -c "SELECT to_regclass('public.query_tasks');"
if ($LASTEXITCODE -ne 0) {
  throw "Migration down smoke failed: unable to query query_tasks table."
}
if (-not [string]::IsNullOrWhiteSpace($tableCheck)) {
  throw "Migration down smoke failed: query_tasks table still exists."
}

Invoke-ExternalCommand `
  -Label "Dropping Stage 3 migration smoke database..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "exec", "-T", "postgres", "psql", "-U", "sdqp", "-d", "postgres", "-c", "DROP DATABASE IF EXISTS $migrationDb;")

foreach ($table in @("audit_events", "audit_checkpoints", "ueba_user_baselines", "ueba_entity_baselines", "ueba_alerts", "ueba_rule_hits")) {
  $tableCheck = docker compose exec -T clickhouse clickhouse-client --query "EXISTS TABLE sdqp.$table"
  if ($LASTEXITCODE -ne 0 -or $tableCheck.Trim() -ne "1") {
    throw "ClickHouse init smoke failed: missing table $table."
  }
}

Invoke-ExternalCommand `
  -Label "Checking MinIO buckets..." `
  -FilePath "docker" `
  -ArgumentList @(
    "run",
    "--rm",
    "--network",
    "sdqp_default",
    "--entrypoint",
    "/bin/sh",
    "minio/mc:RELEASE.2025-02-15T10-36-16Z",
    "-c",
    "/usr/bin/mc alias set sdqp http://minio:9000 minio minio123 >/dev/null && /usr/bin/mc ls sdqp/sdqp-snapshots >/dev/null && /usr/bin/mc ls sdqp/sdqp-evidence >/dev/null"
  )

$env:SDQP_ENABLE_STAGE3_TESTS = "1"
try {
  Invoke-ExternalCommand `
    -Label "Running API Stage 3 persistence UAT..." `
    -FilePath "cargo" `
    -ArgumentList @("test", "-p", "sdqp-api", "--test", "uat_stage3_persistence")

  Invoke-ExternalCommand `
    -Label "Running Worker Stage 3 persistence UAT..." `
    -FilePath "cargo" `
    -ArgumentList @("test", "-p", "sdqp-worker", "--test", "uat_stage3_worker_persistence")
}
finally {
  Remove-Item Env:SDQP_ENABLE_STAGE3_TESTS -ErrorAction SilentlyContinue
}

Write-Host "Stage 3 persistence checks completed."
