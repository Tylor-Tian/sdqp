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
  -Label "Verifying generated contract artifacts..." `
  -FilePath "cargo" `
  -ArgumentList @("run", "-p", "sdqp-contracts", "--bin", "sdqp-contracts-generate", "--", "--verify")
