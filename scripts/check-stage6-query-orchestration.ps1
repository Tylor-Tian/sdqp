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
    if ($LASTEXITCODE -eq 0) {
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
      Invoke-WebRequest -Method Post -Body "" -Uri "http://127.0.0.1:18123/?query=SELECT%201" -UseBasicParsing | Out-Null
      return
    }
    catch {
      Start-Sleep -Seconds 2
    }
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
  -Label "Starting Stage 6 infrastructure..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "-f", "docker-compose.yml", "up", "-d", "postgres", "clickhouse", "minio", "minio-init")

Wait-PostgresReady
Wait-ClickHouseReady
Wait-MinioReady

$env:SDQP_ENABLE_STAGE6_TESTS = "1"
try {
  Invoke-ExternalCommand `
    -Label "Running datasource adapter Stage 6 contract UAT..." `
    -FilePath "cargo" `
    -ArgumentList @("test", "-p", "sdqp-datasource-adapter", "--test", "uat_stage6_adapters")

  Invoke-ExternalCommand `
    -Label "Running API/Worker Stage 6 query orchestration UAT..." `
    -FilePath "cargo" `
    -ArgumentList @("test", "-p", "sdqp-api", "--test", "uat_stage6_query_orchestration")
}
finally {
  Remove-Item Env:SDQP_ENABLE_STAGE6_TESTS -ErrorAction SilentlyContinue
}

Write-Host "Stage 6 query orchestration checks completed."
