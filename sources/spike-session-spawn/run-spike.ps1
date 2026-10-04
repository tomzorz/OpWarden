#Requires -RunAsAdministrator
# Runs the session-spawn and process-event spike end to end and cleans up after itself.
#
#   round 1: bare virtual account            (expected: token query 1314, ETW refused)
#   round 2: + SeTcbPrivilege                (question 1: does the session spawn work?)
#   round 3: + Performance Log Users          (ETW: session starts, provider still refused?)
#   round 4: + provider grant (EventAccessControl on Kernel-Process)
#                                            (question 2: do process events arrive?)
#
# Afterwards the right is revoked, the group membership removed, the provider's ETW
# security restored exactly as it was, the service deleted, the working folder removed,
# and the log copied to run.log beside this script. Run it from an elevated PowerShell
# while signed in at the console.

$ErrorActionPreference = 'Stop'
$name = 'OpWardenSpike'
$account = "NT SERVICE\$name"
$dir = Join-Path $env:ProgramData $name
$exe = Join-Path $dir 'opwarden-spike-spawn.exe'
$log = Join-Path $dir 'spike.log'
$source = Join-Path $PSScriptRoot 'bin\opwarden-spike-spawn.exe'
$etwSecurityKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Security'
$kernelProcess = '22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716'
$perfLogUsers = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-559')).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]

if (-not (Test-Path $source)) { throw "Build the spike first: dotnet publish -c Release -o ../bin (from src). Missing $source." }

function Invoke-Round([string] $label) {
    Add-Content $log "=== $label"
    sc.exe start $name | Out-Null
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Milliseconds 500
        if ((Get-Service $name).Status -eq 'Stopped') { return }
    }
    Add-Content $log "=== ${label}: service did not stop within 30 s"
}

New-Item -ItemType Directory -Force $dir | Out-Null
Copy-Item $source $exe -Force
Remove-Item $log -ErrorAction SilentlyContinue

# The provider's ETW security value, kept byte for byte so the restore is exact.
$etwOriginal = (Get-ItemProperty -Path $etwSecurityKey -Name $kernelProcess -ErrorAction SilentlyContinue).$kernelProcess

$created = $false
$granted = $false
$inGroup = $false
$etwGranted = $false
try {
    sc.exe create $name binPath= "`"$exe`" service" obj= $account type= own start= demand | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with $LASTEXITCODE." }
    $created = $true

    # The service account writes the log; the marker child runs as the signed-in user.
    icacls $dir /grant "${account}:(OI)(CI)M" /grant "${env:USERDOMAIN}\${env:USERNAME}:(OI)(CI)M" | Out-Null

    Invoke-Round 'round 1: bare virtual account'

    & $exe grant $account
    if ($LASTEXITCODE -ne 0) { throw "grant failed with $LASTEXITCODE." }
    $granted = $true
    Invoke-Round 'round 2: SeTcbPrivilege granted'

    Add-LocalGroupMember -Group $perfLogUsers -Member $account
    $inGroup = $true
    Invoke-Round 'round 3: plus Performance Log Users'

    $etwGranted = $true
    & $exe grant-etw $account
    if ($LASTEXITCODE -ne 0) { throw "grant-etw failed with $LASTEXITCODE." }
    Invoke-Round 'round 4: plus the Kernel-Process provider grant'
}
finally {
    if ($etwGranted) {
        if ($null -eq $etwOriginal) { Remove-ItemProperty -Path $etwSecurityKey -Name $kernelProcess -ErrorAction SilentlyContinue }
        else { Set-ItemProperty -Path $etwSecurityKey -Name $kernelProcess -Value ([byte[]]$etwOriginal) -Type Binary }
        Add-Content $log "=== restored the Kernel-Process ETW security value ($(if ($null -eq $etwOriginal) { 'removed: it did not exist before' } else { 'original bytes put back' }))"
    }
    if ($inGroup) { Remove-LocalGroupMember -Group $perfLogUsers -Member $account -ErrorAction SilentlyContinue }
    if ($granted) { & $exe revoke $account }
    if ($created) { sc.exe delete $name | Out-Null }
    if (Test-Path $log) { Copy-Item $log (Join-Path $PSScriptRoot 'run.log') -Force }
    Start-Sleep -Seconds 1
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`n--- run.log ---"
Get-Content (Join-Path $PSScriptRoot 'run.log')
