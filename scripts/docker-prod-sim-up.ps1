param(
  [switch]$SkipSmoke
)

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

Invoke-ExternalCommand `
  -Label "Stopping existing SDQP prod-sim docker stack..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "-p", $composeProjectName, "-f", "docker-compose.prod-sim.yml", "down", "--remove-orphans")

Invoke-ExternalCommand `
  -Label "Starting SDQP prod-sim docker stack..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "-p", $composeProjectName, "-f", "docker-compose.prod-sim.yml", "up", "--build", "-d")

if (-not $SkipSmoke) {
  Invoke-ExternalCommand `
    -Label "Running prod-sim docker smoke..." `
    -FilePath "powershell" `
    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/docker-prod-sim-smoke.ps1")
}
