$ErrorActionPreference = "Stop"

$requiredDirectories = @(
  "db/postgres/migrations",
  "db/clickhouse/init",
  "deploy/docker",
  "docs/current-state",
  "generated",
  "openapi",
  "tests/fixtures/phase7"
)

$requiredFiles = @(
  "docs/current-state/README.md",
  "docs/current-state/runtime-baseline.md",
  "docs/README.md",
  "docs/runbooks/local-verification.md",
  "openapi/README.md",
  "generated/README.md",
  "db/postgres/migrations/README.md",
  "db/clickhouse/init/README.md",
  "deploy/docker/README.md",
  "tests/fixtures/phase7/audit-search-query.json",
  "tests/fixtures/phase7/audit-search-budget.json"
)

foreach ($directory in $requiredDirectories) {
  if (-not (Test-Path $directory -PathType Container)) {
    throw "Missing required baseline directory: $directory"
  }
}

foreach ($file in $requiredFiles) {
  if (-not (Test-Path $file -PathType Leaf)) {
    throw "Missing required baseline file: $file"
  }
}

Write-Host "Baseline freeze assets verified."
