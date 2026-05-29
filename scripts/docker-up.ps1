param(
  [switch]$SkipSmoke
)

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

Invoke-ExternalCommand `
  -Label "Stopping existing SDQP docker stack..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "-f", "docker-compose.yml", "down", "--remove-orphans")

Invoke-ExternalCommand `
  -Label "Starting SDQP docker stack..." `
  -FilePath "docker" `
  -ArgumentList @("compose", "-f", "docker-compose.yml", "up", "--build", "-d")

if (-not $SkipSmoke) {
  Invoke-ExternalCommand `
    -Label "Running docker smoke..." `
    -FilePath "powershell" `
    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/docker-smoke.ps1")
}
