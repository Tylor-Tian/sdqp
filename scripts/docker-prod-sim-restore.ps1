param(
  [string]$BackupDir = "artifacts/stage13-backup-restore",
  [switch]$Force
)

$ErrorActionPreference = "Stop"

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

$backupPath = Resolve-AbsolutePath -Path $BackupDir
if (-not (Test-Path -LiteralPath $backupPath)) {
  throw "Backup directory not found: $backupPath"
}

$metadataPath = Join-Path $backupPath "metadata.json"
if (-not (Test-Path -LiteralPath $metadataPath)) {
  throw "Backup metadata is missing: $metadataPath"
}

$metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
$dockerBackupPath = Convert-ToDockerHostPath -Path $backupPath

foreach ($volume in $metadata.volumes) {
  $archivePath = Join-Path $backupPath $volume.archive
  if (-not (Test-Path -LiteralPath $archivePath)) {
    throw "Backup archive is missing: $archivePath"
  }

  & docker volume inspect $volume.docker_volume | Out-Null
  $volumeExists = $LASTEXITCODE -eq 0
  if ($volumeExists -and -not $Force) {
    throw "Volume '$($volume.docker_volume)' already exists. Remove it first or rerun with -Force."
  }

  if ($volumeExists -and $Force) {
    Invoke-ExternalCommand `
      -Label ("Removing existing volume {0}..." -f $volume.docker_volume) `
      -FilePath "docker" `
      -ArgumentList @("volume", "rm", "-f", $volume.docker_volume)
  }

  Invoke-ExternalCommand `
    -Label ("Creating volume {0}..." -f $volume.docker_volume) `
    -FilePath "docker" `
    -ArgumentList @(
      "volume", "create",
      "--label", ("com.docker.compose.project={0}" -f $metadata.compose_project),
      "--label", ("com.docker.compose.volume={0}" -f $volume.logical_name),
      $volume.docker_volume
    )

  Invoke-ExternalCommand `
    -Label ("Restoring volume {0}..." -f $volume.docker_volume) `
    -FilePath "docker" `
    -ArgumentList @(
      "run", "--rm",
      "-v", ("{0}:/target" -f $volume.docker_volume),
      "-v", ("{0}:/backup" -f $dockerBackupPath),
      "alpine:3.20",
      "sh", "-lc",
      ("cd /target && tar -xf /backup/{0}" -f $volume.archive)
    )
}

Write-Host ("Prod-sim backup restored from {0}" -f $backupPath)
