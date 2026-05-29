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

Invoke-ExternalCommand `
  -Label "Resetting Stage 8 infrastructure volumes..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "-f", "docker-compose.yml", "down", "-v", "--remove-orphans")

Invoke-ExternalCommand `
  -Label "Starting Stage 8 infrastructure..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "-f", "docker-compose.yml", "up", "-d", "postgres", "clickhouse", "minio", "minio-init")

Wait-PostgresReady
Wait-ClickHouseReady
Wait-MinioReady

Invoke-ExternalCommand `
  -Label "Checking MinIO snapshot bucket..." `
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
    "/usr/bin/mc alias set sdqp http://minio:9000 minio minio123 >/dev/null && /usr/bin/mc ls sdqp/sdqp-snapshots >/dev/null"
  )

$env:SDQP_ENABLE_STAGE8_TESTS = "1"
try {
  Invoke-ExternalCommand `
    -Label "Running Stage 8 encryption crate tests..." `
    -FilePath "cargo" `
    -ArgumentList @("test", "-p", "sdqp-encryption")

  Invoke-ExternalCommand `
    -Label "Running API Stage 8 snapshot encryption UAT..." `
    -FilePath "cargo" `
    -ArgumentList @("test", "-p", "sdqp-api", "--test", "uat_stage8_snapshot_encryption")
}
finally {
  Remove-Item Env:SDQP_ENABLE_STAGE8_TESTS -ErrorAction SilentlyContinue
}

Write-Host "Stage 8 snapshot encryption checks completed."
