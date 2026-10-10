<#
.SYNOPSIS
Installs OpWarden (spec section 14): the broker as a service under NT SERVICE\OpWarden, the
session agent at each logon, and the shim first on PATH.

.DESCRIPTION
Run from an elevated PowerShell, signed in as the interactive user whose op CLI OpWarden
guards, after .\install\publish.ps1 has built the executables unelevated.

Running it again upgrades in place: it stops the service and the session agent, replaces
the executables and broker.json, and starts both again. The rules, the alias pairs and the
audit log in the data directory stay.

What it changes, each of which uninstall.ps1 reverts:
  - the install directory: the executables, broker.json, and install-state.json, which
    records what the install changed so the rollback can undo exactly that
  - the data directory, created with the access list of REQ-TRUST-2
  - the OpWarden service, under NT SERVICE\OpWarden, automatic start
  - NT SERVICE\OpWarden in Performance Log Users
  - Microsoft-Windows-Kernel-Process: NT SERVICE\OpWarden may enable it; the provider's
    original security value is saved first
  - HKLM\...\Run\OpWarden, which starts the session agent at each logon
  - the system PATH, with the shim directory first

-WhatIf lists the steps without making them, and runs unelevated.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # The published executables; by default artifacts\publish beside this folder.
    [string] $Source,
    [string] $InstallDirectory = (Join-Path $env:ProgramFiles 'OpWarden'),
    [string] $DataDirectory = (Join-Path $env:ProgramData 'OpWarden'),
    # The op CLI the shim runs. By default the first op.exe on PATH that is not the shim.
    [string] $OpPath,
    # The interactive user (REQ-TRUST-12). By default whoever runs this script, so elevate
    # your own account rather than signing in as another administrator.
    [string] $UserSid = ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if (-not $WhatIfPreference -and -not (Test-Administrator)) {
    throw 'Run install.ps1 from an elevated PowerShell, or add -WhatIf to list what it would do.'
}

$started = [DateTimeOffset]::UtcNow
# Windows PowerShell leaves $PSScriptRoot empty while it binds parameter defaults.
if (-not $Source) { $Source = Join-Path $PSScriptRoot '..\artifacts\publish' }
$Source = [IO.Path]::GetFullPath($Source)
foreach ($exe in 'OpWarden.Broker.exe', 'OpWarden.SessionAgent.exe', 'shim\op.exe') {
    if (-not (Test-Path (Join-Path $Source $exe))) { throw "$exe is missing from $Source; run .\install\publish.ps1 first, unelevated." }
}

$user = New-Object Security.Principal.SecurityIdentifier($UserSid)
try { $userName = $user.Translate([Security.Principal.NTAccount]).Value } catch { $userName = $UserSid }

if (-not $OpPath) {
    $OpPath = Get-Command op -All -CommandType Application -ErrorAction SilentlyContinue |
        Where-Object { (Get-Item $_.Source).VersionInfo.ProductName -ne 'OpWarden' } |
        Select-Object -First 1 -ExpandProperty Source
    if (-not $OpPath) { throw 'No op CLI on PATH besides the shim; pass -OpPath with the op.exe the shim should run.' }
}
$OpPath = [IO.Path]::GetFullPath($OpPath)
if ((Get-Item $OpPath).VersionInfo.ProductName -eq 'OpWarden') { throw "$OpPath is the OpWarden shim, not the op CLI." }
$signature = Get-AuthenticodeSignature $OpPath
if ($signature.Status -ne 'Valid') { Write-Warning "$OpPath carries no valid Authenticode signature ($($signature.Status)); the shim will run it anyway." }

$broker = Join-Path $InstallDirectory 'OpWarden.Broker.exe'
$agent = Join-Path $InstallDirectory 'OpWarden.SessionAgent.exe'
$shimDirectory = Join-Path $InstallDirectory 'shim'
$config = Join-Path $InstallDirectory 'broker.json'
$statePath = Join-Path $InstallDirectory 'install-state.json'

Write-Host "Installing OpWarden for $userName ($UserSid)"
Write-Host "  op CLI           $OpPath ($($signature.SignerCertificate.Subject))"
Write-Host "  install          $InstallDirectory"
Write-Host "  data             $DataDirectory"

# 1. Stop what runs, so the executables can be replaced.
$service = Get-Service $ServiceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -ne 'Stopped' -and $PSCmdlet.ShouldProcess($ServiceName, 'Stop the running service')) {
    Stop-Service $ServiceName -Force
    (Get-Service $ServiceName).WaitForStatus('Stopped', '00:00:30')
}
if ($PSCmdlet.ShouldProcess($agent, 'Stop the running session agent')) { Stop-SessionAgent $agent }

# 2. The executables (spec section 14, step 2), and the record of what this install changes.
if ($PSCmdlet.ShouldProcess($InstallDirectory, 'Copy the broker, the session agent and the shim')) {
    New-Item -ItemType Directory -Force $shimDirectory | Out-Null
    Copy-Item (Join-Path $Source 'OpWarden.Broker.exe') $broker -Force
    Copy-Item (Join-Path $Source 'OpWarden.SessionAgent.exe') $agent -Force
    Copy-Item (Join-Path $Source 'shim\op.exe') (Join-Path $shimDirectory 'op.exe') -Force
}

# The first install records the system state it is about to change; an upgrade keeps that
# record, because by then the provider's security value already carries OpWarden's grant.
$state = Read-InstallState $statePath
if (-not $state) {
    $original = (Get-ItemProperty $EtwSecurityKey -Name $KernelProcessProvider -ErrorAction SilentlyContinue).$KernelProcessProvider
    $state = [pscustomobject]@{
        version                    = 1
        etwSecurityExisted         = ($null -ne $original)
        etwSecurityOriginal        = $(if ($null -ne $original) { [Convert]::ToBase64String([byte[]]$original) } else { $null })
        etwGranted                 = $false
        addedToPerformanceLogUsers = $false
        addedToPath                = $false
    }
}
if (-not $WhatIfPreference) { Save-InstallState $state $statePath }

# 3. broker.json (step 8), without a byte-order mark.
$brokerConfig = [ordered]@{ opPath = $OpPath; dataDirectory = $DataDirectory; userSid = $UserSid; sessionAgentPath = $agent }
if ($PSCmdlet.ShouldProcess($config, 'Write the broker configuration')) {
    [IO.File]::WriteAllText($config, ($brokerConfig | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
}

# 4. The service (step 3).
$binPath = '\"' + $broker + '\" --service --config \"' + $config + '\"'
if (-not $service) {
    if ($PSCmdlet.ShouldProcess($ServiceName, "Create the service under $ServiceAccount, automatic start")) {
        Invoke-Sc "create $ServiceName binPath= `"$binPath`" obj= `"$ServiceAccount`" type= own start= auto DisplayName= `"OpWarden broker`""
        Invoke-Sc "description $ServiceName `"Gates each 1Password CLI invocation behind per-caller, per-secret rules.`""
        Invoke-Sc "failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000"
    }
}
elseif ($PSCmdlet.ShouldProcess($ServiceName, 'Point the existing service at this install')) {
    Invoke-Sc "config $ServiceName binPath= `"$binPath`" obj= `"$ServiceAccount`" start= auto"
}

# The virtual account exists only while its service does, so everything granted to it
# comes after the service.
$serviceSid = if ($WhatIfPreference -and -not $service) { $null } else { Get-ServiceSid }

# 5. Performance Log Users (step 4).
$members = net localgroup $PerformanceLogUsers 2>$null
if (-not ($members -contains $ServiceAccount) -and $PSCmdlet.ShouldProcess($ServiceAccount, "Add to $PerformanceLogUsers")) {
    net localgroup $PerformanceLogUsers $ServiceAccount /add | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Adding $ServiceAccount to $PerformanceLogUsers failed with exit code $LASTEXITCODE." }
    $state.addedToPerformanceLogUsers = $true
    Save-InstallState $state $statePath
}

# 6. The provider grant (step 5). EventAccessControl appends an entry each time it runs,
# so the recorded state keeps an upgrade from granting twice.
if (-not $state.etwGranted -and $PSCmdlet.ShouldProcess('Microsoft-Windows-Kernel-Process', "Let $ServiceAccount enable the provider")) {
    $sidBytes = New-Object byte[] ($serviceSid.BinaryLength)
    $serviceSid.GetBinaryForm($sidBytes, 0)
    $provider = [Guid]$KernelProcessProvider
    $status = [OpWardenInstall.Native]::EventAccessControl([ref]$provider, 2, $sidBytes, 0x80, $true)
    if ($status -ne 0) { throw "EventAccessControl failed with error $status." }
    $state.etwGranted = $true
    Save-InstallState $state $statePath
}

# 7. The session agent at each logon (step 6).
if ($PSCmdlet.ShouldProcess("$RunKey\$ServiceName", 'Start the session agent at each logon')) {
    Set-ItemProperty -Path $RunKey -Name $ServiceName -Value "`"$agent`""
}

# 8. The data directory and its access list (step 7, REQ-TRUST-2): the service account
# writes, Administrators keep full control for recovery, the interactive user reads.
if ($PSCmdlet.ShouldProcess($DataDirectory, 'Create the data directory and set its access list')) {
    New-Item -ItemType Directory -Force $DataDirectory | Out-Null
    icacls $DataDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$($serviceSid.Value):(OI)(CI)M" "*${UserSid}:(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls on $DataDirectory failed with exit code $LASTEXITCODE." }
}

# 9. The shim first on PATH (step 9). The system PATH precedes every user's own entries,
# which is where per-user installs of the op CLI put themselves.
$entries = @(Get-SystemPathEntries)
if ($entries.Count -eq 0 -or $entries[0] -ne $shimDirectory) {
    if ($PSCmdlet.ShouldProcess('system PATH', "Put $shimDirectory first")) {
        Set-SystemPathEntries (@($shimDirectory) + @($entries | Where-Object { $_ -ne $shimDirectory }))
        $state.addedToPath = $true
        Save-InstallState $state $statePath
    }
}

# 10. Start, and check what the broker itself reports.
if ($PSCmdlet.ShouldProcess($ServiceName, 'Start the service')) {
    try {
        Start-Service $ServiceName
        (Get-Service $ServiceName).WaitForStatus('Running', '00:00:30')
    }
    catch {
        Write-Warning "The service did not start: $($_.Exception.Message)"
        $log = Join-Path $DataDirectory 'broker.log'
        if (Test-Path $log) { Write-Host "--- $log ---"; Get-Content $log -Tail 30 }
        throw
    }

    Start-Sleep -Seconds 2
    # @() throughout: Windows PowerShell gives a single object no Count.
    $eventsDown = @(Get-AuditEvents $DataDirectory 'process-events-unavailable' $started)
    if ($eventsDown.Count -gt 0) { Write-Warning "The broker receives no process events, so callers behind MSYS2 shells resolve as unknown: $($eventsDown[-1].detail)" }
    else { Write-Host 'Broker running, process events flowing.' }
    foreach ($failure in Get-AuditEvents $DataDirectory 'integrity-failure' $started) { Write-Warning $failure.detail }
}

# Explorer starts the session agent, so it runs unelevated, as it will after each logon.
if ($PSCmdlet.ShouldProcess($agent, 'Start the session agent in this session, unelevated')) {
    Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList "`"$agent`""
    $pinned = $false
    for ($i = 0; $i -lt 20 -and -not $pinned; $i++) {
        Start-Sleep -Milliseconds 500
        $pinned = @(Get-AuditEvents $DataDirectory 'agent-pinned' $started).Count -gt 0
    }
    if ($pinned) { Write-Host 'Session agent pinned.' }
    else { Write-Warning 'The broker has not pinned a session agent yet; see agent-refused entries in the audit log.' }
}

Write-Host ''
Write-Host 'Programs started before now keep their old PATH: restart terminals and agent apps.'
Write-Host 'Then, in a new terminal: op --version   (expect an OpWarden prompt)'
