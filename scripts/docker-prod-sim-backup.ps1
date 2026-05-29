param(
  [string]$BackupDir = "artifacts/stage13-backup-restore",
  [string]$ProjectName
)

$ErrorActionPreference = "Stop"

function Get-ComposeProjectName {
  if ($ProjectName) {
    return $ProjectName
  }

  if ($env:COMPOSE_PROJECT_NAME) {
    return $env:COMPOSE_PROJECT_NAME
  }

  return "sdqp-prod-sim"
}

function Resolve-AbsolutePath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  if ([System.IO.Path]::IsPathRooted($Path)) {
    return [System.IO.Path]::GetFullPath($Path)
  }

  return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
}

function Convert-ToDockerHostPath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  return ($Path -replace "\\", "/")
}

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

$project = Get-ComposeProjectName
$backupPath = Resolve-AbsolutePath -Path $BackupDir
$dockerBackupPath = Convert-ToDockerHostPath -Path $backupPath

New-Item -ItemType Directory -Force -Path $backupPath | Out-Null

$volumeSpecs = @(
  @{ logical_name = "postgres-data"; archive = "postgres-data.tar" },
  @{ logical_name = "clickhouse-data"; archive = "clickhouse-data.tar" },
  @{ logical_name = "minio-data"; archive = "minio-data.tar" }
)

$volumeMetadata = @()
foreach ($spec in $volumeSpecs) {
  $volumeName = "{0}_{1}" -f $project, $spec.logical_name
  & docker volume inspect $volumeName | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Required volume '$volumeName' was not found. Stop the prod-sim stack without '-v' before running backup."
  }

  $archivePath = Join-Path $backupPath $spec.archive
  if (Test-Path -LiteralPath $archivePath) {
    Remove-Item -LiteralPath $archivePath -Force
  }

  Invoke-ExternalCommand `
    -Label ("Backing up volume {0}..." -f $volumeName) `
    -FilePath "docker" `
    -ArgumentList @(
      "run", "--rm",
      "-v", ("{0}:/source:ro" -f $volumeName),
      "-v", ("{0}:/backup" -f $dockerBackupPath),
      "alpine:3.20",
      "sh", "-lc",
      ("cd /source && tar -cf /backup/{0} ." -f $spec.archive)
    )

  $volumeMetadata += [ordered]@{
    logical_name = $spec.logical_name
    docker_volume = $volumeName
    archive = $spec.archive
  }
}

$metadata = [ordered]@{
  created_at = (Get-Date).ToUniversalTime().ToString("o")
  compose_project = $project
  compose_file = "docker-compose.prod-sim.yml"
  volumes = $volumeMetadata
}

$metadata | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 -Path (Join-Path $backupPath "metadata.json")
Write-Host ("Prod-sim backup written to {0}" -f $backupPath)
