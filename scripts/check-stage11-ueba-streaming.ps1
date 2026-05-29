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

function Wait-TcpPort {
  param(
    [Parameter(Mandatory = $true)]
    [string]$EndpointHost,
    [Parameter(Mandatory = $true)]
    [int]$Port,
    [Parameter(Mandatory = $true)]
    [string]$Label
  )

  $deadline = (Get-Date).AddSeconds(120)
  while ((Get-Date) -lt $deadline) {
    try {
      $client = [System.Net.Sockets.TcpClient]::new()
      $async = $client.BeginConnect($EndpointHost, $Port, $null, $null)
      $connected = $async.AsyncWaitHandle.WaitOne(2000) -and $client.Connected
      $client.Close()
      if ($connected) {
        return
      }
    }
    catch {
    }
    Start-Sleep -Seconds 2
  }

  throw "$Label did not become ready in time."
}

function Wait-PostgresReady {
  $deadline = (Get-Date).AddSeconds(120)
  while ((Get-Date) -lt $deadline) {
    docker compose exec -T postgres pg_isready -U sdqp -d sdqp | Out-Null
    if ($LASTEXITCODE -eq 0) {
      Wait-TcpPort -EndpointHost "127.0.0.1" -Port 15432 -Label "PostgreSQL"
      return
    }
    Start-Sleep -Seconds 2
  }

  throw "PostgreSQL did not become ready in time."
}

function Wait-ClickHouseReady {
  $deadline = (Get-Date).AddSeconds(120)
  while ((Get-Date) -lt $deadline) {
    try {
      Invoke-WebRequest -Uri "http://127.0.0.1:18123/?query=SELECT%201" -UseBasicParsing | Out-Null
      return
    }
    catch {
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

function Wait-MockServerReady {
  Wait-TcpPort -EndpointHost "127.0.0.1" -Port 11080 -Label "MockServer"
}

function Wait-RedpandaReady {
  Wait-TcpPort -EndpointHost "127.0.0.1" -Port 19092 -Label "Redpanda"
}

$migrationUp = "db/postgres/migrations/20260330020000_stage11_ueba_stream_runtime.up.sql"
$migrationDown = "db/postgres/migrations/20260330020000_stage11_ueba_stream_runtime.down.sql"

if (-not (Test-Path $migrationUp) -or -not (Test-Path $migrationDown)) {
  throw "Stage 11 migration files are missing."
}

Invoke-ExternalCommand `
  -Label "Resetting Stage 11 infrastructure volumes..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "-f", "docker-compose.yml", "down", "-v", "--remove-orphans")

Invoke-ExternalCommand `
  -Label "Starting Stage 11 infrastructure..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "-f", "docker-compose.yml", "up", "-d", "postgres", "clickhouse", "minio", "minio-init", "redpanda", "mockserver")

Wait-PostgresReady
Wait-ClickHouseReady
Wait-MinioReady
Wait-RedpandaReady
Wait-MockServerReady

$env:SDQP_ENABLE_STAGE11_TESTS = "1"
try {
  Invoke-ExternalCommand `
    -Label "Running Stage 11 UEBA rule crate tests..." `
    -FilePath "cargo" `
    -ArgumentList @("test", "-p", "sdqp-ueba")

  Invoke-ExternalCommand `
    -Label "Running Stage 11 legacy UEBA UAT..." `
    -FilePath "cargo" `
    -ArgumentList @("test", "-p", "sdqp-api", "--test", "uat_phase6_ueba")

  Invoke-ExternalCommand `
    -Label "Running Stage 11 streaming UEBA persistence UAT..." `
    -FilePath "cargo" `
    -ArgumentList @("test", "-p", "sdqp-api", "--test", "uat_stage11_ueba_persistence", "--", "--test-threads=1")
}
finally {
  Remove-Item Env:SDQP_ENABLE_STAGE11_TESTS -ErrorAction SilentlyContinue
}

Write-Host "Stage 11 UEBA streaming checks completed."
