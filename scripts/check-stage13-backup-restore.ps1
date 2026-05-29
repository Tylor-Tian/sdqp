param(
  [int]$TimeoutSeconds = 120,
  [string]$BackupDir = "artifacts/stage13-backup-restore"
)

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

function Wait-HttpReady {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Label,
    [Parameter(Mandatory = $true)]
    [string]$Url
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    try {
      Invoke-WebRequest -Uri $Url -UseBasicParsing | Out-Null
      Write-Host "$Label is ready: $Url"
      return
    }
    catch {
      Start-Sleep -Seconds 2
    }
  }

  throw "$Label did not become ready in $TimeoutSeconds seconds: $Url"
}

function Invoke-JsonRequest {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Method,
    [Parameter(Mandatory = $true)]
    [string]$Uri,
    [hashtable]$Headers,
    $Body
  )

  $params = @{
    Method = $Method
    Uri = $Uri
  }

  if ($Headers) {
    $params.Headers = $Headers
  }

  if ($null -ne $Body) {
    $params.ContentType = "application/json"
    $params.Body = ($Body | ConvertTo-Json -Depth 10 -Compress)
  }

  return Invoke-RestMethod @params
}

function Wait-ProdSimReady {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ApiBaseUrl,
    [Parameter(Mandatory = $true)]
    [string]$WorkerBaseUrl,
    [Parameter(Mandatory = $true)]
    [string]$FrontendBaseUrl
  )

  Wait-HttpReady -Label "Frontend" -Url "$FrontendBaseUrl/"
  Wait-HttpReady -Label "API health" -Url "$ApiBaseUrl/healthz"
  Wait-HttpReady -Label "API ready" -Url "$ApiBaseUrl/readyz"
  Wait-HttpReady -Label "Worker health" -Url "$WorkerBaseUrl/healthz"
}

function New-SessionHeaders {
  param(
    [Parameter(Mandatory = $true)]
    [string]$AccessToken
  )

  return @{
    authorization = "Bearer $AccessToken"
    "x-tenant-id" = "tenant-alpha"
    "x-project-id" = "project-alpha"
  }
}

function New-TokenPair {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ApiBaseUrl,
    [Parameter(Mandatory = $true)]
    [string]$Username,
    [Parameter(Mandatory = $true)]
    [string]$DeviceFingerprint
  )

  $login = Invoke-JsonRequest `
    -Method "Post" `
    -Uri "$ApiBaseUrl/auth/login" `
    -Body @{
      username = $Username
      password = "password123"
      device_fingerprint = $DeviceFingerprint
    }

  return Invoke-JsonRequest `
    -Method "Post" `
    -Uri "$ApiBaseUrl/auth/mfa/verify" `
    -Body @{
      pending_session_id = $login.pending_session_id
      code = "000000"
    }
}

function Wait-CompletedQuery {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ApiBaseUrl,
    [Parameter(Mandatory = $true)]
    [hashtable]$Headers,
    [Parameter(Mandatory = $true)]
    [string]$TaskId
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    $status = Invoke-JsonRequest `
      -Method "Get" `
      -Uri "$ApiBaseUrl/v1/tasks/$TaskId/status" `
      -Headers $Headers

    if ($status.state -eq "completed" -and $status.snapshot_id) {
      return $status
    }

    if ($status.state -in @("failed", "cancelled")) {
      $detail = if ($status.error) { $status.error } else { $status.state }
      throw "Query task reached terminal state '$($status.state)': $detail"
    }

    Start-Sleep -Seconds 1
  }

  throw "Query task did not complete successfully within $TimeoutSeconds seconds."
}

function Wait-AuditSearchTotal {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ApiBaseUrl,
    [Parameter(Mandatory = $true)]
    [hashtable]$Headers,
    [Parameter(Mandatory = $true)]
    [int]$MinimumTotal
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    $result = Invoke-JsonRequest `
      -Method "Get" `
      -Uri "$ApiBaseUrl/v1/audit/events/search?action=query&actor_user_id=user-analyst&limit=100" `
      -Headers $Headers

    if ($result.total_matches -ge $MinimumTotal) {
      return $result
    }

    Start-Sleep -Seconds 1
  }

  throw "Audit search did not reach the expected total ($MinimumTotal) within $TimeoutSeconds seconds."
}

function Convert-ToCanonicalObject {
  param(
    [Parameter(Mandatory = $true)]
    $Value
  )

  if ($null -eq $Value) {
    return $null
  }

  if ($Value -is [string] -or $Value -is [ValueType]) {
    return $Value
  }

  if ($Value -is [System.Collections.IDictionary]) {
    $ordered = [ordered]@{}
    foreach ($key in ($Value.Keys | Sort-Object)) {
      $ordered[$key] = Convert-ToCanonicalObject -Value $Value[$key]
    }

    return [pscustomobject]$ordered
  }

  $propertyNames = @($Value.PSObject.Properties | Select-Object -ExpandProperty Name)
  if ($propertyNames.Count -gt 0) {
    $ordered = [ordered]@{}
    foreach ($name in ($propertyNames | Sort-Object)) {
      $ordered[$name] = Convert-ToCanonicalObject -Value $Value.$name
    }

    return [pscustomobject]$ordered
  }

  if ($Value -is [System.Collections.IEnumerable]) {
    return @($Value | ForEach-Object { Convert-ToCanonicalObject -Value $_ })
  }

  return $Value
}

function Convert-ToCanonicalJson {
  param(
    [Parameter(Mandatory = $true)]
    $Value
  )

  return (Convert-ToCanonicalObject -Value $Value | ConvertTo-Json -Compress -Depth 20)
}

$apiBaseUrl = "http://127.0.0.1:38080"
$workerBaseUrl = "http://127.0.0.1:38081"
$frontendBaseUrl = "http://127.0.0.1:34173"
$cleanupRequired = $true

try {
  Invoke-ExternalCommand `
    -Label "Resetting prod-sim stack and volumes..." `
    -FilePath "docker" `
    -ArgumentList @("compose", "-p", $composeProjectName, "-f", "docker-compose.prod-sim.yml", "down", "-v", "--remove-orphans")

  Invoke-ExternalCommand `
    -Label "Starting prod-sim stack without smoke..." `
    -FilePath "powershell" `
    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/docker-prod-sim-up.ps1", "-SkipSmoke")

  Wait-ProdSimReady -ApiBaseUrl $apiBaseUrl -WorkerBaseUrl $workerBaseUrl -FrontendBaseUrl $frontendBaseUrl

  $analyst = New-TokenPair -ApiBaseUrl $apiBaseUrl -Username "analyst" -DeviceFingerprint "stage13-backup-analyst"
  $analystHeaders = New-SessionHeaders -AccessToken $analyst.access_token
  $submission = Invoke-JsonRequest `
    -Method "Post" `
    -Uri "$apiBaseUrl/v1/queries" `
    -Headers $analystHeaders `
    -Body @{
      data_source_id = "datasource-rest"
      source_type = "rest"
      fields = @("employee_id", "department")
    }
  $status = Wait-CompletedQuery -ApiBaseUrl $apiBaseUrl -Headers $analystHeaders -TaskId $submission.task_id
  $snapshotId = $status.snapshot_id
  $snapshotPage = Invoke-JsonRequest `
    -Method "Get" `
    -Uri "$apiBaseUrl/v1/snapshots/$snapshotId/page?page_size=1" `
    -Headers $analystHeaders
  if (-not $snapshotPage.rows -or $snapshotPage.rows.Count -lt 1) {
    throw "Snapshot page returned no rows before backup."
  }
  $expectedFirstRow = Convert-ToCanonicalJson -Value $snapshotPage.rows[0]

  $admin = New-TokenPair -ApiBaseUrl $apiBaseUrl -Username "sysadmin" -DeviceFingerprint "stage13-backup-admin"
  $adminHeaders = New-SessionHeaders -AccessToken $admin.access_token
  $baselineAudit = Wait-AuditSearchTotal -ApiBaseUrl $apiBaseUrl -Headers $adminHeaders -MinimumTotal 1
  $baselineAuditTotal = [int]$baselineAudit.total_matches

  Invoke-ExternalCommand `
    -Label "Stopping prod-sim stack before backup..." `
    -FilePath "docker" `
    -ArgumentList @("compose", "-p", $composeProjectName, "-f", "docker-compose.prod-sim.yml", "down", "--remove-orphans")

  Invoke-ExternalCommand `
    -Label "Backing up prod-sim volumes..." `
    -FilePath "powershell" `
    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/docker-prod-sim-backup.ps1", "-BackupDir", $BackupDir)

  Invoke-ExternalCommand `
    -Label "Removing prod-sim volumes before restore..." `
    -FilePath "docker" `
    -ArgumentList @("compose", "-p", $composeProjectName, "-f", "docker-compose.prod-sim.yml", "down", "-v", "--remove-orphans")

  Invoke-ExternalCommand `
    -Label "Restoring prod-sim volumes..." `
    -FilePath "powershell" `
    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/docker-prod-sim-restore.ps1", "-BackupDir", $BackupDir)

  Invoke-ExternalCommand `
    -Label "Starting restored prod-sim stack..." `
    -FilePath "docker" `
    -ArgumentList @("compose", "-p", $composeProjectName, "-f", "docker-compose.prod-sim.yml", "up", "-d")

  Wait-ProdSimReady -ApiBaseUrl $apiBaseUrl -WorkerBaseUrl $workerBaseUrl -FrontendBaseUrl $frontendBaseUrl

  $restoredAnalyst = New-TokenPair -ApiBaseUrl $apiBaseUrl -Username "analyst" -DeviceFingerprint "stage13-restore-analyst"
  $restoredAnalystHeaders = New-SessionHeaders -AccessToken $restoredAnalyst.access_token
  $restoredPage = Invoke-JsonRequest `
    -Method "Get" `
    -Uri "$apiBaseUrl/v1/snapshots/$snapshotId/page?page_size=1" `
    -Headers $restoredAnalystHeaders
  if (-not $restoredPage.rows -or $restoredPage.rows.Count -lt 1) {
    throw "Snapshot page returned no rows after restore."
  }
  $restoredFirstRow = Convert-ToCanonicalJson -Value $restoredPage.rows[0]
  if ($restoredFirstRow -ne $expectedFirstRow) {
    throw "Restored snapshot row does not match the backed-up snapshot content."
  }

  $restoredAdmin = New-TokenPair -ApiBaseUrl $apiBaseUrl -Username "sysadmin" -DeviceFingerprint "stage13-restore-admin"
  $restoredAdminHeaders = New-SessionHeaders -AccessToken $restoredAdmin.access_token
  $restoredAudit = Wait-AuditSearchTotal -ApiBaseUrl $apiBaseUrl -Headers $restoredAdminHeaders -MinimumTotal $baselineAuditTotal
  if ([int]$restoredAudit.total_matches -lt $baselineAuditTotal) {
    throw "Restored audit total dropped below the backed-up baseline."
  }

  Write-Host "Stage 13 backup/restore smoke completed."
}
finally {
  if ($cleanupRequired) {
    & docker compose -p $composeProjectName -f docker-compose.prod-sim.yml down -v --remove-orphans | Out-Null
  }
}
