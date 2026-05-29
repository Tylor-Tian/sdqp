$ErrorActionPreference = "Stop"

$fixturesDir = "tests/fixtures/generated"
New-Item -ItemType Directory -Force -Path $fixturesDir | Out-Null

$payload = @{
  generated_at = (Get-Date).ToString("s")
  phase = "phase0"
  fixtures = @("sample-context", "sample-health")
} | ConvertTo-Json -Depth 3

Set-Content -LiteralPath (Join-Path $fixturesDir "phase0.json") -Value $payload -Encoding UTF8

Write-Host "Seeded fixtures into $fixturesDir"
