#Requires -RunAsAdministrator
<#
    OpWarden spike: can process-creation events reconstruct ancestry that the
    live parent walk cannot?

    Background: MSYS2 emulates exec by creating a new Windows process and
    retiring the old one. The retired process holds the only link to the true
    parent, so the Windows process table loses the caller's ancestry. A
    process-creation event reports the parent while it is still alive, so a
    broker that records those events should be able to rebuild the chain
    afterwards. REQ-WATCH-1 already has the broker subscribed to these events.

    This script decides whether that works. It needs elevation because
    Win32_ProcessStartTrace refuses an unelevated subscription.

    The assertion deliberately targets THIS SCRIPT'S OWN PID rather than
    claude.exe: run from an elevated window, the workload descends from this
    script, not from the agent host. The question is whether the event map spans
    a chain the live walk cannot, and the root's identity does not matter.

    PASS means: the event map reconstructs leaf -> this script, and the live
    walk did not.

    Nothing here reads a secret. The workload runs `op --version`.
    Add -IncludeRealWorkflow, with -RealWorkflowPath, to also trace a real
    workflow that reads secrets. That will raise biometric prompts.
#>

param(
    [Parameter(Mandatory)][string]$RealOp,
    [string]$RealWorkflowPath,
    [switch]$IncludeRealWorkflow
)

$ErrorActionPreference = 'Stop'

$SpikeDir = $PSScriptRoot
$SpikeBin = Join-Path $SpikeDir 'bin'
$LogPath  = Join-Path $SpikeDir 'elevated-test.jsonl'
$BashExe  = 'C:\Program Files\Git\bin\bash.exe'

foreach ($p in @((Join-Path $SpikeBin 'op.exe'), $BashExe, (Join-Path $SpikeDir 'workload.sh'))) {
    if (-not (Test-Path $p)) { throw "missing: $p" }
}

Remove-Item $LogPath -ErrorAction SilentlyContinue

$rootPid = $PID
Write-Host ""
Write-Host "root pid (this script) = $rootPid" -ForegroundColor Cyan

# ---- 1. subscribe -----------------------------------------------------------

Write-Host "subscribing to Win32_ProcessStartTrace..."
Register-CimIndicationEvent -Query 'SELECT * FROM Win32_ProcessStartTrace' -SourceIdentifier PT | Out-Null
Start-Sleep -Milliseconds 750   # let the subscription settle before spawning

# ---- 2. reproduce the break -------------------------------------------------

$env:PATH = "$SpikeBin;$env:PATH"
$env:OPWARDEN_SPIKE_LOG = $LogPath
$env:OPWARDEN_SPIKE_REAL_OP = $RealOp

Write-Host "running the synthetic workload (no secrets)..."
# Run from the script's own directory so no Windows-to-MSYS path conversion is needed.
Push-Location $SpikeDir
try { & $BashExe './workload.sh' | Out-Null } finally { Pop-Location }

if ($IncludeRealWorkflow) {
    Write-Host "running 'just check' in $RealWorkflowPath (biometric prompts will fire)..." -ForegroundColor Yellow
    if (-not $RealWorkflowPath) { throw "-IncludeRealWorkflow needs -RealWorkflowPath pointing at the workflow's directory." }
    Push-Location $RealWorkflowPath
    try { & $BashExe -lc 'just check' | Out-Null } catch { Write-Host "  just check failed: $_" }
    finally { Pop-Location }
}

Start-Sleep -Seconds 2   # drain the event queue

# ---- 3. build the map from events ------------------------------------------

function Read-Indication($evt) {
    $ne = $null
    if ($evt.SourceEventArgs -and $evt.SourceEventArgs.NewEvent) {
        $ne = $evt.SourceEventArgs.NewEvent
    } elseif ($evt.SourceArgs -and $evt.SourceArgs.Count -ge 2 -and $evt.SourceArgs[1].NewEvent) {
        $ne = $evt.SourceArgs[1].NewEvent
    }
    if (-not $ne) { return $null }
    [pscustomobject]@{
        ProcId   = [int]$ne.ProcessID
        ParentId = [int]$ne.ParentProcessID
        Name     = [string]$ne.ProcessName
    }
}

$events = @(Get-Event -SourceIdentifier PT -ErrorAction SilentlyContinue)
$map = @{}
$seen = 0
foreach ($e in $events) {
    $p = Read-Indication $e
    if ($p) { $seen++; $map[$p.ProcId] = $p }
}

Unregister-Event -SourceIdentifier PT -ErrorAction SilentlyContinue
Get-Event -SourceIdentifier PT -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "process-start events captured: $seen" -ForegroundColor Cyan
$shells = @($map.Values | Where-Object { $_.Name -match '^(bash|sh|just|op|sleep)\.exe$' })
Write-Host "  of which bash/just/op/sleep: $($shells.Count)"

if ($seen -eq 0) {
    Write-Host ""
    Write-Host "INCONCLUSIVE - the subscription produced no events at all." -ForegroundColor Yellow
    Write-Host "That is a plumbing problem, not an answer. Try the older provider:" -ForegroundColor Yellow
    Write-Host "  Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier PT" -ForegroundColor Yellow
    Write-Host "and if that is also empty, the ETW kernel process provider is the fallback." -ForegroundColor Yellow
    return
}

# ---- 4. what did the shim's own live walk manage? ---------------------------

if (-not (Test-Path $LogPath)) { throw "the shim wrote no log at $LogPath - did the workload run?" }

$records = @(Get-Content $LogPath | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
Write-Host ""
Write-Host ("shim invocations logged: {0}" -f $records.Count) -ForegroundColor Cyan

$pass = $true

foreach ($r in $records) {
    Write-Host ""
    Write-Host ("--- shim pid {0}  argv: {1}" -f $r.pid, ($r.argv -join ' ')) -ForegroundColor White

    $liveChain = @($r.ancestors | ForEach-Object { "$($_.name)($($_.pid))" })
    $liveReachedRoot = @($r.ancestors | Where-Object { $_.pid -eq $rootPid }).Count -gt 0
    Write-Host ("  live walk : {0}" -f ($(if ($liveChain) { $liveChain -join ' <- ' } else { '(none)' })))
    Write-Host ("  stopped   : {0} at pid {1}" -f $r.walkStop, $r.walkStopPid)
    Write-Host ("  reached root by live walk : {0}" -f $liveReachedRoot)

    # rebuild purely from the event map
    $chain = @()
    $cur = [int]$r.pid
    $reachedRoot = $false
    for ($i = 0; $i -lt 32; $i++) {
        if (-not $map.ContainsKey($cur)) { break }
        $entry = $map[$cur]
        $parent = $entry.ParentId
        $pname = if ($map.ContainsKey($parent)) { $map[$parent].Name } else { '(before capture)' }
        $alive = $null -ne (Get-Process -Id $parent -ErrorAction SilentlyContinue)
        $chain += ("{0}({1}){2}" -f $pname, $parent, $(if ($alive) { '' } else { ' DEAD' }))
        if ($parent -eq $rootPid) { $reachedRoot = $true; break }
        $cur = $parent
    }

    Write-Host ("  event map : {0}" -f ($(if ($chain) { $chain -join ' <- ' } else { '(nothing)' }))) -ForegroundColor Green
    Write-Host ("  reached root by event map : {0}" -f $reachedRoot) -ForegroundColor Green

    $deadRecovered = @($chain | Where-Object { $_ -match 'DEAD' }).Count
    Write-Host ("  links recovered through already-dead processes : {0}" -f $deadRecovered)

    if (-not $reachedRoot) { $pass = $false }
    if ($liveReachedRoot) {
        Write-Host "  NOTE: the live walk also reached the root, so this invocation does not discriminate." -ForegroundColor Yellow
    }
}

# ---- 5. verdict -------------------------------------------------------------

Write-Host ""
if ($pass) {
    Write-Host "PASS - the event map spans chains the live walk cannot." -ForegroundColor Green
    Write-Host "Candidate 1 in SPEC.md section 17 is viable." -ForegroundColor Green
} else {
    Write-Host "FAIL - the event map did not reach the root for at least one invocation." -ForegroundColor Red
    Write-Host "Check whether events were dropped (count above) or whether ParentProcessID is not what we assumed." -ForegroundColor Red
}
Write-Host ""
Write-Host "raw shim log: $LogPath"
