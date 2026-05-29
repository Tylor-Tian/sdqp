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
  -Label "Starting Stage 5 infrastructure..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "-f", "docker-compose.yml", "up", "-d", "postgres", "clickhouse", "minio", "minio-init")

Wait-PostgresReady
Wait-ClickHouseReady
Wait-MinioReady

$env:SDQP_ENABLE_STAGE3_TESTS = "1"
try {
  Invoke-ExternalCommand `
    -Label "Running API Stage 5 audit and tenant isolation UAT..." `
    -FilePath "cargo" `
    -ArgumentList @("test", "-p", "sdqp-api", "--test", "uat_stage5_audit_tenant_isolation")
}
finally {
  Remove-Item Env:SDQP_ENABLE_STAGE3_TESTS -ErrorAction SilentlyContinue
}

$replica = Get-ChildItem "generated/audit" -Filter "*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($null -eq $replica) {
  throw "No audit replica export found under generated/audit."
}

Invoke-ExternalCommand `
  -Label "Verifying latest audit replica..." `
  -FilePath "cargo" `
  -ArgumentList @("run", "-p", "sdqp-audit", "--bin", "sdqp-audit-verify", "--", $replica.FullName)

Write-Host "Stage 5 audit and tenant isolation checks completed."
