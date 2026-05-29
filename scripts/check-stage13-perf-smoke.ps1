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

try {
  Invoke-ExternalCommand `
    -Label "Resetting prod-sim stack and volumes..." `
    -FilePath "docker" `
    -ArgumentList @("compose", "-p", $composeProjectName, "-f", "docker-compose.prod-sim.yml", "down", "-v", "--remove-orphans")

  Invoke-ExternalCommand `
    -Label "Starting prod-sim stack without smoke..." `
    -FilePath "powershell" `
    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/docker-prod-sim-up.ps1", "-SkipSmoke")

  Invoke-ExternalCommand `
    -Label "Running prod-sim perf smoke..." `
    -FilePath "powershell" `
    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/docker-prod-sim-perf.ps1")

  Invoke-ExternalCommand `
    -Label "Inspecting prod-sim status after perf smoke..." `
    -FilePath "docker" `
    -ArgumentList @("compose", "-p", $composeProjectName, "-f", "docker-compose.prod-sim.yml", "ps")

  Write-Host "Stage 13 perf smoke gate completed."
}
finally {
  & docker compose -p $composeProjectName -f docker-compose.prod-sim.yml down -v --remove-orphans | Out-Null
}
