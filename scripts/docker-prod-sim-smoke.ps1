param(
  [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = "Stop"

powershell `
  -NoProfile `
  -ExecutionPolicy Bypass `
  -File "scripts/docker-smoke.ps1" `
  -ApiBaseUrl "http://127.0.0.1:38080" `
  -WorkerBaseUrl "http://127.0.0.1:38081" `
  -FrontendBaseUrl "http://127.0.0.1:34173" `
  -TimeoutSeconds $TimeoutSeconds

if ($LASTEXITCODE -ne 0) {
  throw "Prod-sim docker smoke failed with exit code $LASTEXITCODE"
}
