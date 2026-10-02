#Requires -RunAsAdministrator
<#
    OpWarden spike: do process-creation events survive load, and is ETW better
    than WMI at it?

    The event-map design (SPEC.md section 17, candidate 1) is only as good as
    event delivery. A dropped event does not delay a caller, it makes that
    caller permanently unresolvable, which means a prompt the user cannot get
    rid of. The earlier elevated test captured 8 events in a quiet window and
    proved nothing about load.

    Method: spawn a known number of short-lived processes parented to this
    script, capture them through both pipelines at once, and compare each
    pipeline's count against the ground truth this script already knows.

    WHAT THIS CHANGES ON YOUR MACHINE
      It enables the Microsoft-Windows-Kernel-Process/Analytic ETW channel,
      raises that channel's maximum log size, and clears the channel's log.
      All three are restored in a finally block. The channel is currently
      disabled, so its log should be empty already, but the clear is destructive
      to whatever is in there. Pass -SkipEtw to measure WMI only and touch
      nothing.
#>

param(
    [int]$Count = 300,
    [switch]$SkipEtw,
    [switch]$RestoreOnly,
    [int64]$RestoreMaxSize = 1052672
)

$ErrorActionPreference = 'Stop'
$Channel = 'Microsoft-Windows-Kernel-Process/Analytic'
$Transcript = Join-Path $PSScriptRoot 'reliability-run.log'

# Every wevtutil call goes through here. The previous version piped these to
# Out-Null, which swallowed a failing restore and left the channel modified.
function Invoke-Wevtutil {
    param([string[]]$Arguments, [switch]$Tolerate)
    $out = & wevtutil @Arguments 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        $msg = "wevtutil $($Arguments -join ' ') failed with exit code $code`n$($out -join "`n")"
        if ($Tolerate) { Write-Host "  WARN: $msg" -ForegroundColor Yellow; return $false }
        throw $msg
    }
    return $true
}

function Get-ChannelState {
    $raw = & wevtutil gl $Channel 2>&1
    if ($LASTEXITCODE -ne 0) { throw "wevtutil gl $Channel failed: $($raw -join ' ')" }
    $en = @($raw | Select-String '^\s*enabled:\s*(\S+)')
    $ms = @($raw | Select-String '^\s*maxSize:\s*(\d+)')
    if ($en.Count -ne 1 -or $ms.Count -ne 1) { throw "could not parse channel state (enabled matches=$($en.Count), maxSize matches=$($ms.Count))" }
    [pscustomobject]@{
        Enabled = ($en.Matches.Groups[1].Value -eq 'true')
        MaxSize = [int64]$ms.Matches.Groups[1].Value
    }
}

function Show-ChannelState($label) {
    $s = Get-ChannelState
    Write-Host ("{0}: enabled={1} maxSize={2:N0}" -f $label, $s.Enabled, $s.MaxSize) -ForegroundColor Cyan
    return $s
}

# ---- restore-only path ------------------------------------------------------

if ($RestoreOnly) {
    Show-ChannelState 'before' | Out-Null
    Invoke-Wevtutil @('sl', $Channel, '/e:false') -Tolerate | Out-Null
    Invoke-Wevtutil @('sl', $Channel, "/ms:$RestoreMaxSize") -Tolerate | Out-Null
    $after = Show-ChannelState 'after '
    if ($after.MaxSize -eq $RestoreMaxSize -and -not $after.Enabled) {
        Write-Host "restored." -ForegroundColor Green
    } else {
        Write-Host "NOT restored. Report the WARN lines above." -ForegroundColor Red
    }
    return
}

Start-Transcript -Path $Transcript -Force | Out-Null
Write-Host "transcript: $Transcript" -ForegroundColor Cyan

$original = $null
$wmiRegistered = $false

try {
    # ---- 1. arm ETW --------------------------------------------------------

    if (-not $SkipEtw) {
        $original = Show-ChannelState 'ETW channel before'

        Write-Host "arming ETW..." -ForegroundColor Cyan
        Invoke-Wevtutil @('sl', $Channel, '/e:false') | Out-Null
        Invoke-Wevtutil @('cl', $Channel) -Tolerate | Out-Null      # empty channel cannot be cleared on some builds
        Invoke-Wevtutil @('sl', $Channel, '/ms:33554432') | Out-Null # 32 MB, so ETW is not handicapped by a 1 MB buffer
        Invoke-Wevtutil @('sl', $Channel, '/e:true') | Out-Null

        $armed = Show-ChannelState 'ETW channel armed '
        if (-not $armed.Enabled) { throw "the channel did not enable, so the ETW half cannot run. Rerun with -SkipEtw to measure WMI only." }
    }

    # ---- 2. arm WMI --------------------------------------------------------

    Register-CimIndicationEvent -Query 'SELECT * FROM Win32_ProcessStartTrace' -SourceIdentifier REL | Out-Null
    $wmiRegistered = $true
    Start-Sleep -Milliseconds 750

    # ---- 3. generate a known load -----------------------------------------

    Write-Host ""
    Write-Host "spawning $Count short-lived processes (ground truth = $Count)..." -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "$env:SystemRoot\System32\cmd.exe"
    $psi.Arguments = '/c exit'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $spawned = New-Object System.Collections.Generic.List[System.Diagnostics.Process]
    for ($i = 0; $i -lt $Count; $i++) {
        $spawned.Add([System.Diagnostics.Process]::Start($psi))   # deliberately not awaited: this is the load
    }
    foreach ($p in $spawned) { $p.WaitForExit() }

    $sw.Stop()
    Write-Host ("all exited in {0:N0} ms ({1:N1} process starts/sec)" -f $sw.ElapsedMilliseconds, ($Count / ($sw.Elapsed.TotalSeconds))) -ForegroundColor Cyan

    Start-Sleep -Seconds 3   # let both pipelines drain

    # ---- 4. count WMI ------------------------------------------------------

    $wmiHits = 0
    $wmiTotal = 0
    foreach ($e in @(Get-Event -SourceIdentifier REL -ErrorAction SilentlyContinue)) {
        $ne = $null
        if ($e.SourceEventArgs -and $e.SourceEventArgs.NewEvent) { $ne = $e.SourceEventArgs.NewEvent }
        elseif ($e.SourceArgs -and $e.SourceArgs.Count -ge 2 -and $e.SourceArgs[1].NewEvent) { $ne = $e.SourceArgs[1].NewEvent }
        if (-not $ne) { continue }
        $wmiTotal++
        if (([int]$ne.ParentProcessID) -eq $PID -and ([string]$ne.ProcessName) -eq 'cmd.exe') { $wmiHits++ }
    }

    Unregister-Event -SourceIdentifier REL -ErrorAction SilentlyContinue
    Get-Event -SourceIdentifier REL -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
    $wmiRegistered = $false

    # ---- 5. count ETW ------------------------------------------------------

    $etwHits = 0
    $etwTotal = 0
    $sample = $null
    if (-not $SkipEtw) {
        & wevtutil sl $Channel /e:false 2>&1 | Out-Null   # stop logging before reading
        try {
            $evts = @(Get-WinEvent -LogName $Channel -Oldest -ErrorAction Stop)
        } catch {
            $evts = @()
            Write-Host "could not read the ETW channel: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        foreach ($e in $evts) {
            if ($e.Id -ne 1) { continue }
            $etwTotal++
            $x = [xml]$e.ToXml()
            $d = @{}
            foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            if ($d['ParentProcessID'] -eq "$PID" -and $d['ImageName'] -match 'cmd\.exe$') {
                $etwHits++
                if (-not $sample) { $sample = $d }
            }
        }
    }

    # ---- 6. verdict --------------------------------------------------------

    function Show-Pipeline($name, $hits, $total) {
        $dropped = $Count - $hits
        $rate = if ($Count -gt 0) { 100.0 * $dropped / $Count } else { 0 }
        $colour = if ($dropped -eq 0) { 'Green' } elseif ($rate -lt 1) { 'Yellow' } else { 'Red' }
        Write-Host ("{0,-6} captured {1,6} of {2} target starts   dropped {3,5} ({4,5:N1}%)   [{5} events seen in total]" -f `
            $name, $hits, $Count, $dropped, $rate, $total) -ForegroundColor $colour
    }

    Write-Host ""
    Write-Host "=== delivery under load ===" -ForegroundColor White
    Show-Pipeline 'WMI' $wmiHits $wmiTotal
    if (-not $SkipEtw) { Show-Pipeline 'ETW' $etwHits $etwTotal }

    if ($sample) {
        Write-Host ""
        Write-Host "sample ETW ProcessStart fields (these are what the broker's map would store):" -ForegroundColor DarkGray
        foreach ($k in $sample.Keys | Sort-Object) { Write-Host ("  {0,-22} {1}" -f $k, $sample[$k]) -ForegroundColor DarkGray }
    }

    Write-Host ""
    if ($wmiHits -eq $Count -and ($SkipEtw -or $etwHits -eq $Count)) {
        Write-Host "Both pipelines lossless at this rate. Try a higher -Count before trusting it." -ForegroundColor Green
    } elseif (-not $SkipEtw -and $etwHits -gt $wmiHits) {
        Write-Host "ETW beat WMI. Candidate 1 should be built on ETW." -ForegroundColor Yellow
    } elseif ($wmiHits -lt $Count) {
        Write-Host "WMI dropped events. Any caller behind a dropped event is permanently unresolvable." -ForegroundColor Red
    }
}
finally {
    if ($wmiRegistered) {
        Unregister-Event -SourceIdentifier REL -ErrorAction SilentlyContinue
        Get-Event -SourceIdentifier REL -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
    }
    if ($original) {
        Write-Host ""
        Write-Host "restoring ETW channel..." -ForegroundColor Cyan
        Invoke-Wevtutil @('sl', $Channel, '/e:false') -Tolerate | Out-Null
        Invoke-Wevtutil @('sl', $Channel, "/ms:$($original.MaxSize)") -Tolerate | Out-Null
        if ($original.Enabled) { Invoke-Wevtutil @('sl', $Channel, '/e:true') -Tolerate | Out-Null }

        # Verify rather than assume. The previous version assumed, and was wrong.
        $now = Show-ChannelState 'ETW channel after '
        if ($now.Enabled -ne $original.Enabled -or $now.MaxSize -ne $original.MaxSize) {
            Write-Host ("RESTORE FAILED. Expected enabled={0} maxSize={1:N0}. Fix with:" -f $original.Enabled, $original.MaxSize) -ForegroundColor Red
            Write-Host ("  .\test-event-reliability.ps1 -RestoreOnly -RestoreMaxSize {0}" -f $original.MaxSize) -ForegroundColor Red
        } else {
            Write-Host "restored." -ForegroundColor Green
        }
    }
    try { Stop-Transcript | Out-Null } catch { }
}
