$ErrorActionPreference = "Stop"
$composeProjectName = "sdqp-prod-sim"

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

if (-not (Test-Path "docker-compose.prod-sim.yml")) {
  throw "docker-compose.prod-sim.yml is missing."
}

Invoke-ExternalCommand `
  -Label "Starting prod-sim release compose and smoke..." `
  -FilePath "powershell" `
  -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/docker-prod-sim-up.ps1")

Invoke-ExternalCommand `
  -Label "Inspecting prod-sim release compose status..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "-p", $composeProjectName, "-f", "docker-compose.prod-sim.yml", "ps")

Write-Host "Stage 13 release compose smoke completed."
