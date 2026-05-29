$ErrorActionPreference = "Stop"

Write-Host "Fetching Rust dependencies..."
cargo fetch

if (Test-Path "apps/sdqp-frontend/package.json") {
  Push-Location "apps/sdqp-frontend"
  try {
    Write-Host "Installing frontend dependencies..."
    npm install
  }
  finally {
    Pop-Location
  }
}

Write-Host "Bootstrap completed."
