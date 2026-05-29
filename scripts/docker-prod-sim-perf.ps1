param(
  [string]$ApiBaseUrl = "http://127.0.0.1:38080",
  [string]$WorkerBaseUrl = "http://127.0.0.1:38081",
  [string]$FrontendBaseUrl = "http://127.0.0.1:34173",
  [int]$TimeoutSeconds = 120,
  [string]$BudgetFile = ""
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Net.Http

if (-not $BudgetFile) {
  $BudgetFile = Join-Path $PSScriptRoot "..\tests\fixtures\stage13\perf-smoke-budget.json"
}

$BudgetFile = (Resolve-Path $BudgetFile).Path
$script:PerfHttpClient = New-Object System.Net.Http.HttpClient
$script:PerfHttpClient.Timeout = [TimeSpan]::FromSeconds([Math]::Max($TimeoutSeconds, 30))

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

function Wait-ProdSimReady {
  Wait-HttpReady -Label "Frontend" -Url "$FrontendBaseUrl/"
  Wait-HttpReady -Label "API health" -Url "$ApiBaseUrl/healthz"
  Wait-HttpReady -Label "API ready" -Url "$ApiBaseUrl/readyz"
  Wait-HttpReady -Label "Worker health" -Url "$WorkerBaseUrl/healthz"
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
      throw "Query task '$TaskId' reached terminal state '$($status.state)': $detail"
    }

    Start-Sleep -Milliseconds 500
  }

  throw "Query task '$TaskId' did not complete within $TimeoutSeconds seconds."
}

function Load-PerfBudget {
  return Get-Content -Path $BudgetFile -Raw -Encoding UTF8 | ConvertFrom-Json
}

function New-HttpMethod {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Method
  )

  switch ($Method.ToUpperInvariant()) {
    "GET" { return [System.Net.Http.HttpMethod]::Get }
    "POST" { return [System.Net.Http.HttpMethod]::Post }
    "DELETE" { return [System.Net.Http.HttpMethod]::Delete }
    default { throw "Unsupported HTTP method: $Method" }
  }
}

function New-HttpRequestMessage {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Method,
    [Parameter(Mandatory = $true)]
    [string]$Uri,
    [hashtable]$Headers,
    $Body
  )

  $request = New-Object System.Net.Http.HttpRequestMessage (New-HttpMethod -Method $Method), $Uri
  if ($Headers) {
    foreach ($name in $Headers.Keys) {
      [void]$request.Headers.TryAddWithoutValidation($name, [string]$Headers[$name])
    }
  }

  if ($null -ne $Body) {
    $json = $Body | ConvertTo-Json -Depth 10 -Compress
    $request.Content = New-Object System.Net.Http.StringContent($json, [System.Text.Encoding]::UTF8, "application/json")
  }

  return $request
}

function Invoke-ParallelRequestBurst {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Label,
    [Parameter(Mandatory = $true)]
    [string]$Method,
    [Parameter(Mandatory = $true)]
    [string]$Uri,
    [hashtable]$Headers,
    [Parameter(Mandatory = $true)]
    [int]$RequestCount,
    [Parameter(Mandatory = $true)]
    [int]$MaxDurationMs,
    $BodyFactory
  )

  $entries = @()
  $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
  for ($index = 0; $index -lt $RequestCount; $index++) {
    $body = $null
    if ($null -ne $BodyFactory) {
      if ($BodyFactory -is [scriptblock]) {
        $body = & $BodyFactory $index
      }
      else {
        $body = $BodyFactory
      }
    }

    $request = New-HttpRequestMessage -Method $Method -Uri $Uri -Headers $Headers -Body $body
    $entries += [pscustomobject]@{
      Request = $request
      Task = $script:PerfHttpClient.SendAsync($request)
    }
  }

  [System.Threading.Tasks.Task]::WhenAll([System.Threading.Tasks.Task[]]($entries | ForEach-Object {
        [System.Threading.Tasks.Task]$_.Task
      })).GetAwaiter().GetResult()
  $stopwatch.Stop()

  $responses = @()
  foreach ($entry in $entries) {
    $response = $entry.Task.GetAwaiter().GetResult()
    $statusCode = [int]$response.StatusCode
    $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    $response.Dispose()
    $entry.Request.Dispose()

    $responses += [pscustomobject]@{
      StatusCode = $statusCode
      Content = $content
    }
  }

  $failures = @($responses | Where-Object { $_.StatusCode -lt 200 -or $_.StatusCode -ge 300 })
  if ($failures.Count -gt 0) {
    $codes = ($failures | Select-Object -First 5 | ForEach-Object { $_.StatusCode }) -join ", "
    throw "$Label received non-2xx responses: $codes"
  }

  if ($stopwatch.ElapsedMilliseconds -gt $MaxDurationMs) {
    throw "$Label exceeded performance budget: $($stopwatch.ElapsedMilliseconds)ms > ${MaxDurationMs}ms"
  }

  Write-Host "$Label completed $RequestCount requests in $($stopwatch.ElapsedMilliseconds)ms"

  return [pscustomobject]@{
    ElapsedMs = $stopwatch.ElapsedMilliseconds
    Responses = $responses
  }
}

function Wait-AuditSearchTotal {
  param(
    [Parameter(Mandatory = $true)]
    [hashtable]$Headers,
    [Parameter(Mandatory = $true)]
    [int]$MinimumTotal,
    [Parameter(Mandatory = $true)]
    [int]$MaxSeconds
  )

  $deadline = (Get-Date).AddSeconds($MaxSeconds)
  $lastTotal = -1
  while ((Get-Date) -lt $deadline) {
    $result = Invoke-JsonRequest `
      -Method "Get" `
      -Uri "$ApiBaseUrl/v1/audit/events/search?action=view&actor_user_id=user-analyst&resource_id_contains=project-context&limit=200" `
      -Headers $Headers

    if ([int]$result.total_matches -ne $lastTotal) {
      $lastTotal = [int]$result.total_matches
      Write-Host "Audit search total now $lastTotal (target $MinimumTotal)"
    }

    if ($result.chain_valid -and [int]$result.total_matches -ge $MinimumTotal) {
      return $result
    }

    Start-Sleep -Seconds 1
  }

  throw "Audit search did not reach total $MinimumTotal within $MaxSeconds seconds. Last observed total: $lastTotal"
}

function Wait-UebaRule {
  param(
    [Parameter(Mandatory = $true)]
    [hashtable]$Headers,
    [Parameter(Mandatory = $true)]
    [string]$Rule,
    [Parameter(Mandatory = $true)]
    [int]$MaxSeconds
  )

  $deadline = (Get-Date).AddSeconds($MaxSeconds)
  while ((Get-Date) -lt $deadline) {
    $alerts = Invoke-JsonRequest `
      -Method "Get" `
      -Uri "$ApiBaseUrl/v1/ueba/alerts" `
      -Headers $Headers

    $matched = @($alerts.alerts | Where-Object { $_.rule -eq $Rule })
    if ($matched.Count -gt 0) {
      return $alerts
    }

    Start-Sleep -Seconds 1
  }

  throw "UEBA rule '$Rule' was not visible within $MaxSeconds seconds."
}

function Wait-AuthorizedEndpoint {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Label,
    [Parameter(Mandatory = $true)]
    [string]$Uri,
    [Parameter(Mandatory = $true)]
    [hashtable]$Headers
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    try {
      Invoke-JsonRequest `
        -Method "Get" `
        -Uri $Uri `
        -Headers $Headers | Out-Null
      Write-Host "$Label is authorized: $Uri"
      return
    }
    catch {
      Start-Sleep -Milliseconds 500
    }
  }

  throw "$Label did not become authorized in $TimeoutSeconds seconds: $Uri"
}

function Assert-MetricsSurface {
  $apiMetrics = (Invoke-WebRequest -Uri "$ApiBaseUrl/metrics" -UseBasicParsing).Content
  if (-not $apiMetrics.Contains('sdqp_http_requests_total{service="sdqp-api"}')) {
    throw "API metrics endpoint did not expose the expected Prometheus counter."
  }

  $workerMetrics = (Invoke-WebRequest -Uri "$WorkerBaseUrl/metrics" -UseBasicParsing).Content
  if (-not $workerMetrics.Contains('sdqp_http_requests_total{service="sdqp-worker"}')) {
    throw "Worker metrics endpoint did not expose the expected HTTP counter."
  }
  if (-not $workerMetrics.Contains('sdqp_query_tasks_total{service="sdqp-worker",result="completed"}')) {
    throw "Worker metrics endpoint did not expose completed query task counters."
  }

  Write-Host "Metrics surfaces exposed expected API and worker counters."
}

try {
  $budget = Load-PerfBudget
  Wait-ProdSimReady

  $analyst = New-TokenPair -Username "analyst" -DeviceFingerprint "stage13-perf-analyst"
  $analystHeaders = New-SessionHeaders -AccessToken $analyst.access_token
  $admin = New-TokenPair -Username "sysadmin" -DeviceFingerprint "stage13-perf-admin"
  $adminHeaders = New-SessionHeaders -AccessToken $admin.access_token

  $submission = Invoke-JsonRequest `
    -Method "Post" `
    -Uri "$ApiBaseUrl/v1/queries" `
    -Headers $analystHeaders `
    -Body @{
      data_source_id = "datasource-rest"
      source_type = "rest"
      fields = @("employee_id", "department")
    }
  $completed = Wait-CompletedQuery -Headers $analystHeaders -TaskId $submission.task_id
  $snapshotId = $completed.snapshot_id

  Invoke-ParallelRequestBurst `
    -Label "Permission grant lookup perf smoke" `
    -Method "Get" `
    -Uri "$ApiBaseUrl/v1/permissions/grants/active/datasource-rest" `
    -Headers $analystHeaders `
    -RequestCount ([int]$budget.permission_grant_requests) `
    -MaxDurationMs ([int]$budget.permission_grant_max_duration_ms) | Out-Null

  Invoke-ParallelRequestBurst `
    -Label "Task status perf smoke" `
    -Method "Get" `
    -Uri "$ApiBaseUrl/v1/tasks/$($submission.task_id)/status" `
    -Headers $analystHeaders `
    -RequestCount ([int]$budget.task_status_requests) `
    -MaxDurationMs ([int]$budget.task_status_max_duration_ms) | Out-Null

  $pivotBurst = Invoke-ParallelRequestBurst `
    -Label "Snapshot pivot perf smoke" `
    -Method "Post" `
    -Uri "$ApiBaseUrl/v1/analysis/pivot" `
    -Headers $analystHeaders `
    -RequestCount ([int]$budget.pivot_requests) `
    -MaxDurationMs ([int]$budget.pivot_max_duration_ms) `
    -BodyFactory @{
      snapshot_id = $snapshotId
      dimension = "department"
    }

  $pivotPayload = $pivotBurst.Responses[0].Content | ConvertFrom-Json
  if (-not $pivotPayload.buckets -or $pivotPayload.buckets.Count -lt 1) {
    throw "Snapshot pivot perf smoke returned no buckets."
  }

  $auditTokens = New-TokenPair -Username "analyst" -DeviceFingerprint "stage13-audit-analyst"
  $auditHeaders = New-SessionHeaders -AccessToken $auditTokens.access_token
  Wait-AuthorizedEndpoint `
    -Label "Audit burst session" `
    -Uri "$ApiBaseUrl/v1/project-context" `
    -Headers $auditHeaders

  $baselineAudit = Invoke-JsonRequest `
    -Method "Get" `
    -Uri "$ApiBaseUrl/v1/audit/events/search?action=view&actor_user_id=user-analyst&resource_id_contains=project-context&limit=200" `
    -Headers $adminHeaders
  $baselineAuditTotal = [int]$baselineAudit.total_matches

  Invoke-ParallelRequestBurst `
    -Label "Audit ingress perf smoke" `
    -Method "Get" `
    -Uri "$ApiBaseUrl/v1/project-context" `
    -Headers $auditHeaders `
    -RequestCount ([int]$budget.audit_event_requests) `
    -MaxDurationMs ([int]$budget.audit_burst_max_duration_ms) | Out-Null

  $expectedAuditTotal = $baselineAuditTotal + [int]$budget.audit_event_requests
  $auditResult = Wait-AuditSearchTotal `
    -Headers $adminHeaders `
    -MinimumTotal $expectedAuditTotal `
    -MaxSeconds ([int]$budget.audit_visibility_max_seconds)
  Write-Host "Audit search observed $($auditResult.total_matches) matching project-context events."

  Assert-MetricsSurface

  $uebaTokens = New-TokenPair -Username "analyst" -DeviceFingerprint "stage13-ueba-denied"
  $uebaHeaders = New-SessionHeaders -AccessToken $uebaTokens.access_token
  $uebaTimer = [System.Diagnostics.Stopwatch]::StartNew()
  for ($index = 0; $index -lt [int]$budget.ueba_denied_burst_requests; $index++) {
    try {
      Invoke-JsonRequest `
        -Method "Post" `
        -Uri "$ApiBaseUrl/v1/queries" `
        -Headers $uebaHeaders `
        -Body @{
          data_source_id = "datasource-rest"
          source_type = "rest"
          fields = @("employee_email")
        } | Out-Null
      throw "Expected forbidden query to fail during UEBA smoke."
    }
    catch {
      if (-not $_.Exception.Message.Contains("(403)")) {
        throw
      }
    }
  }

  $uebaAlerts = Wait-UebaRule `
    -Headers $uebaHeaders `
    -Rule "UnauthorizedQueryBurst" `
    -MaxSeconds ([int]$budget.ueba_visibility_max_seconds)
  $uebaTimer.Stop()

  if ([int]$uebaAlerts.permissions_revoked -lt 1) {
    throw "UEBA alert surfaced but permission revocation counter was not incremented."
  }

  Write-Host "UEBA denied-burst alert surfaced in $($uebaTimer.ElapsedMilliseconds)ms"
  Write-Host "Stage 13 perf smoke completed."
}
finally {
  if ($null -ne $script:PerfHttpClient) {
    $script:PerfHttpClient.Dispose()
  }
}
