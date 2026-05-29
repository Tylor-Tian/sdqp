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

Push-Location "apps/sdqp-frontend"
try {
  Invoke-ExternalCommand -Label "Running Stage 12 frontend tests..." -FilePath "npm" -ArgumentList @("test", "--", "--run")
  Invoke-ExternalCommand -Label "Building Stage 12 frontend..." -FilePath "npm" -ArgumentList @("run", "build")
  Invoke-ExternalCommand -Label "Running Stage 12 browser e2e..." -FilePath "npm" -ArgumentList @("run", "e2e")
}
finally {
  Pop-Location
}

Write-Host "Stage 12 frontend production checks completed."
