param(
  [string]$ApiBaseUrl = "http://127.0.0.1:8080",
  [string]$WorkerBaseUrl = "http://127.0.0.1:8081",
  [string]$FrontendBaseUrl = "http://127.0.0.1:4173",
  [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = "Stop"

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

Wait-HttpReady -Label "Frontend" -Url "$FrontendBaseUrl/"
Wait-HttpReady -Label "API health" -Url "$ApiBaseUrl/healthz"
Wait-HttpReady -Label "API ready" -Url "$ApiBaseUrl/readyz"
Wait-HttpReady -Label "Worker health" -Url "$WorkerBaseUrl/healthz"

$login = Invoke-RestMethod `
  -Method Post `
  -Uri "$ApiBaseUrl/auth/login" `
  -ContentType "application/json" `
  -Body '{"username":"analyst","password":"password123","device_fingerprint":"docker-smoke"}'

$verify = Invoke-RestMethod `
  -Method Post `
  -Uri "$ApiBaseUrl/auth/mfa/verify" `
  -ContentType "application/json" `
  -Body (@{
      pending_session_id = $login.pending_session_id
      code = "000000"
    } | ConvertTo-Json)

$headers = @{
  authorization = "Bearer $($verify.access_token)"
  "x-tenant-id" = "tenant-alpha"
  "x-project-id" = "project-alpha"
}

$submission = Invoke-RestMethod `
  -Method Post `
  -Uri "$ApiBaseUrl/v1/queries" `
  -Headers $headers `
  -ContentType "application/json" `
  -Body '{"data_source_id":"datasource-rest","source_type":"rest","fields":["employee_id","department"]}'

$taskId = $submission.task_id
$status = $null
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $deadline) {
  $status = Invoke-RestMethod -Method Get -Uri "$ApiBaseUrl/v1/tasks/$taskId/status" -Headers $headers
  if ($status.state -eq "completed" -and $status.snapshot_id) {
    break
  }

  if ($status.state -eq "failed" -or $status.state -eq "cancelled") {
    throw "Query task finished in terminal failure state: $($status.state)"
  }

  Start-Sleep -Seconds 1
}

if (-not $status -or $status.state -ne "completed" -or -not $status.snapshot_id) {
  throw "Query task did not complete successfully within $TimeoutSeconds seconds."
}

$page = Invoke-RestMethod `
  -Method Get `
  -Uri "$ApiBaseUrl/v1/snapshots/$($status.snapshot_id)/page?page_size=2" `
  -Headers $headers

if (-not $page.rows -or $page.rows.Count -lt 1) {
  throw "Snapshot page returned no rows."
}

Write-Host "Docker smoke completed successfully."
