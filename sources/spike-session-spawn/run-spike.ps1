#Requires -RunAsAdministrator
# Runs the session-spawn spike end to end and cleans up after itself.
#
#   round 1: the service runs without SeTcbPrivilege (expected: WTSQueryUserToken fails, 1314)
#   round 2: SeTcbPrivilege granted to NT SERVICE\OpWardenSpike (the question)
#
# Afterwards the right is revoked, the service deleted, the working folder removed,
# and the log copied to run.log beside this script. Run it from an elevated
# PowerShell while signed in at the console; the marker child starts in the active
# console session.

$ErrorActionPreference = 'Stop'
$name = 'OpWardenSpike'
$account = "NT SERVICE\$name"
$dir = Join-Path $env:ProgramData $name
$exe = Join-Path $dir 'opwarden-spike-spawn.exe'
$log = Join-Path $dir 'spike.log'
$source = Join-Path $PSScriptRoot 'bin\opwarden-spike-spawn.exe'

if (-not (Test-Path $source)) { throw "Build the spike first: dotnet publish -c Release -o ../bin (from src). Missing $source." }

function Invoke-Round([string] $label) {
    Add-Content $log "=== $label"
    sc.exe start $name | Out-Null
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 500
        if ((Get-Service $name).Status -eq 'Stopped') { return }
    }
    Add-Content $log "=== ${label}: service did not stop within 20 s"
}

New-Item -ItemType Directory -Force $dir | Out-Null
Copy-Item $source $exe -Force
Remove-Item $log -ErrorAction SilentlyContinue

$created = $false
$granted = $false
try {
    sc.exe create $name binPath= "`"$exe`" service" obj= $account type= own start= demand | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with $LASTEXITCODE." }
    $created = $true

    # The service account writes the log; the marker child runs as the signed-in user.
    icacls $dir /grant "${account}:(OI)(CI)M" /grant "${env:USERDOMAIN}\${env:USERNAME}:(OI)(CI)M" | Out-Null

    Invoke-Round 'round 1: no SeTcbPrivilege'

    & $exe grant $account
    if ($LASTEXITCODE -ne 0) { throw "grant failed with $LASTEXITCODE." }
    $granted = $true

    Invoke-Round 'round 2: SeTcbPrivilege granted'
}
finally {
    if ($granted) { & $exe revoke $account }
    if ($created) { sc.exe delete $name | Out-Null }
    if (Test-Path $log) { Copy-Item $log (Join-Path $PSScriptRoot 'run.log') -Force }
    Start-Sleep -Seconds 1
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`n--- run.log ---"
Get-Content (Join-Path $PSScriptRoot 'run.log')
