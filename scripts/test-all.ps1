$ErrorActionPreference = "Stop"

function Test-CargoSubcommand {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  return $null -ne (Get-Command ("cargo-" + $Name) -ErrorAction SilentlyContinue)
}

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

Invoke-ExternalCommand -Label "Checking Rust formatting..." -FilePath "cargo" -ArgumentList @("fmt", "--all", "--check")
Invoke-ExternalCommand -Label "Running clippy..." -FilePath "cargo" -ArgumentList @("clippy", "--workspace", "--all-targets", "--", "-D", "warnings")

if (Test-CargoSubcommand -Name "audit") {
  Invoke-ExternalCommand -Label "Running cargo audit..." -FilePath "cargo" -ArgumentList @("audit")
}
else {
  Write-Warning "cargo-audit is not installed; skipping cargo audit."
}

if (Test-CargoSubcommand -Name "deny") {
  Invoke-ExternalCommand -Label "Running cargo deny..." -FilePath "cargo" -ArgumentList @("deny", "check")
}
else {
  Write-Warning "cargo-deny is not installed; skipping cargo deny check."
}

Invoke-ExternalCommand -Label "Running Rust tests..." -FilePath "cargo" -ArgumentList @("test", "--workspace")

if (Test-Path "apps/sdqp-frontend/package.json") {
  Push-Location "apps/sdqp-frontend"
  try {
    Invoke-ExternalCommand -Label "Running frontend tests..." -FilePath "npm" -ArgumentList @("test", "--", "--run")
    Invoke-ExternalCommand -Label "Building frontend..." -FilePath "npm" -ArgumentList @("run", "build")
  }
  finally {
    Pop-Location
  }
}

Invoke-ExternalCommand `
  -Label "Running baseline freeze checks..." `
  -FilePath "powershell" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/check-baseline-freeze.ps1")

Invoke-ExternalCommand `
  -Label "Running contract artifact checks..." `
  -FilePath "powershell" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/check-contract-artifacts.ps1")

Invoke-ExternalCommand `
  -Label "Running Stage 3 persistence checks..." `
  -FilePath "powershell" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/check-stage3-persistence.ps1")

Invoke-ExternalCommand `
  -Label "Running Stage 5 audit and tenant isolation checks..." `
  -FilePath "powershell" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/check-stage5-audit-tenant.ps1")

Invoke-ExternalCommand `
  -Label "Running Stage 6 query orchestration checks..." `
  -FilePath "powershell" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/check-stage6-query-orchestration.ps1")

Invoke-ExternalCommand `
  -Label "Running Stage 7 governance checks..." `
  -FilePath "powershell" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/check-stage7-governance.ps1")

Invoke-ExternalCommand `
  -Label "Running Stage 8 snapshot encryption checks..." `
  -FilePath "powershell" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/check-stage8-snapshot-encryption.ps1")

Invoke-ExternalCommand `
  -Label "Running Stage 9 datafusion and classification checks..." `
  -FilePath "powershell" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/check-stage9-datafusion-analysis.ps1")

Invoke-ExternalCommand `
  -Label "Running Stage 10 evidence export and watermark checks..." `
  -FilePath "powershell" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/check-stage10-evidence-export.ps1")

Invoke-ExternalCommand `
  -Label "Running Stage 11 UEBA streaming checks..." `
  -FilePath "powershell" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/check-stage11-ueba-streaming.ps1")

Invoke-ExternalCommand `
  -Label "Running Stage 12 frontend production checks..." `
  -FilePath "powershell" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/check-stage12-frontend-production.ps1")

Invoke-ExternalCommand `
  -Label "Running Stage 13 release compose smoke..." `
  -FilePath "powershell" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/check-stage13-release-smoke.ps1")

Invoke-ExternalCommand `
  -Label "Running Stage 13 backup and restore checks..." `
  -FilePath "powershell" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/check-stage13-backup-restore.ps1")

Invoke-ExternalCommand `
  -Label "Running Stage 13 perf smoke..." `
  -FilePath "powershell" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/check-stage13-perf-smoke.ps1")

Write-Host "All gate checks completed."
