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

$migrationUp = "db/postgres/migrations/20260330010000_stage10_evidence_exports.up.sql"
$migrationDown = "db/postgres/migrations/20260330010000_stage10_evidence_exports.down.sql"

if (-not (Test-Path $migrationUp) -or -not (Test-Path $migrationDown)) {
  throw "Stage 10 migration files are missing."
}

Invoke-ExternalCommand `
  -Label "Resetting Stage 10 infrastructure volumes..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "-f", "docker-compose.yml", "down", "-v", "--remove-orphans")

Invoke-ExternalCommand `
  -Label "Starting Stage 10 infrastructure..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "-f", "docker-compose.yml", "up", "-d", "postgres", "clickhouse", "minio", "minio-init")

Wait-PostgresReady
Wait-ClickHouseReady
Wait-MinioReady

$env:SDQP_ENABLE_STAGE10_TESTS = "1"
try {
  Invoke-ExternalCommand `
    -Label "Running Stage 10 watermark crate tests..." `
    -FilePath "cargo" `
    -ArgumentList @("test", "-p", "sdqp-watermark")

  Invoke-ExternalCommand `
    -Label "Running Stage 10 evidence crate tests..." `
    -FilePath "cargo" `
    -ArgumentList @("test", "-p", "sdqp-evidence")

  Invoke-ExternalCommand `
    -Label "Running Stage 10 API watermark and evidence UAT..." `
    -FilePath "cargo" `
    -ArgumentList @("test", "-p", "sdqp-api", "--test", "uat_phase5_evidence_watermark")

  Invoke-ExternalCommand `
    -Label "Running Stage 10 persistent export orchestration UAT..." `
    -FilePath "cargo" `
    -ArgumentList @("test", "-p", "sdqp-api", "--test", "uat_stage10_evidence_export")
}
finally {
  Remove-Item Env:SDQP_ENABLE_STAGE10_TESTS -ErrorAction SilentlyContinue
}

Write-Host "Stage 10 evidence export and watermark checks completed."
