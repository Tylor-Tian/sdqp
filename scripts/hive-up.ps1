param(
    [switch] $Recreate
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$composeFile = Join-Path $repoRoot "docker-compose.hive.yml"

$upArgs = @("compose", "-f", $composeFile, "up", "-d")
if ($Recreate) {
    $upArgs += "--force-recreate"
}
$upArgs += "hive-server"

docker @upArgs
docker compose -f $composeFile run --rm hive-init
docker compose -f $composeFile ps
