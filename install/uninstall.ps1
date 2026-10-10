<#
.SYNOPSIS
Removes OpWarden (spec section 14, rollback): afterwards the op CLI runs directly, unchanged.

.DESCRIPTION
Run from an elevated PowerShell. Reverts what install.ps1 recorded in install-state.json:
the PATH entry, the service, the Performance Log Users membership, the Kernel-Process
provider grant (the saved security value goes back byte for byte), the logon entry and the
running session agent, then deletes the install directory.

The data directory, which holds the rules and the audit log, stays unless -RemoveData is
given; removing it deletes both for good.

-WhatIf lists the steps without making them, and runs unelevated.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $InstallDirectory = (Join-Path $env:ProgramFiles 'OpWarden'),
    [string] $DataDirectory = (Join-Path $env:ProgramData 'OpWarden'),
    [switch] $RemoveData
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if (-not $WhatIfPreference -and -not (Test-Administrator)) {
    throw 'Run uninstall.ps1 from an elevated PowerShell, or add -WhatIf to list what it would do.'
}

$agent = Join-Path $InstallDirectory 'OpWarden.SessionAgent.exe'
$shimDirectory = Join-Path $InstallDirectory 'shim'
$state = Read-InstallState (Join-Path $InstallDirectory 'install-state.json')
if (-not $state) { Write-Warning 'No install-state.json: the provider grant and the group membership cannot be reverted from the record; the rest is removed where found.' }

# 1. The shim off PATH, first, so nothing reaches a broker that is going away.
$entries = @(Get-SystemPathEntries)
if (($entries -contains $shimDirectory) -and $PSCmdlet.ShouldProcess('system PATH', "Remove $shimDirectory")) {
    Set-SystemPathEntries @($entries | Where-Object { $_ -ne $shimDirectory })
}

# 2. Stop the service. The virtual account stops resolving once the service is deleted,
# so the group membership goes before the deletion.
$service = Get-Service $ServiceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -ne 'Stopped' -and $PSCmdlet.ShouldProcess($ServiceName, 'Stop the service')) {
    Stop-Service $ServiceName -Force
    (Get-Service $ServiceName).WaitForStatus('Stopped', '00:00:30')
}

if ($state -and $state.addedToPerformanceLogUsers -and $service -and $PSCmdlet.ShouldProcess($ServiceAccount, "Remove from $PerformanceLogUsers")) {
    net localgroup $PerformanceLogUsers $ServiceAccount /delete | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "Removing $ServiceAccount from $PerformanceLogUsers failed with exit code $LASTEXITCODE." }
}

# 3. The provider's security value, exactly as it was before the first install.
if ($state -and $state.etwGranted -and $PSCmdlet.ShouldProcess('Microsoft-Windows-Kernel-Process', 'Restore the original security value')) {
    if ($state.etwSecurityExisted) {
        Set-ItemProperty -Path $EtwSecurityKey -Name $KernelProcessProvider -Value ([Convert]::FromBase64String($state.etwSecurityOriginal)) -Type Binary
    }
    else {
        Remove-ItemProperty -Path $EtwSecurityKey -Name $KernelProcessProvider -ErrorAction SilentlyContinue
    }
}

if ($service -and $PSCmdlet.ShouldProcess($ServiceName, 'Delete the service')) { Invoke-Sc "delete $ServiceName" }

# 4. The logon entry and the running session agent.
if ((Get-ItemProperty -Path $RunKey -Name $ServiceName -ErrorAction SilentlyContinue) -and $PSCmdlet.ShouldProcess("$RunKey\$ServiceName", 'Remove the logon entry')) {
    Remove-ItemProperty -Path $RunKey -Name $ServiceName
}
if ($PSCmdlet.ShouldProcess($agent, 'Stop the session agent')) { Stop-SessionAgent $agent }

# 5. The executables, broker.json and the install record.
if ((Test-Path $InstallDirectory) -and $PSCmdlet.ShouldProcess($InstallDirectory, 'Delete the install directory')) {
    Remove-Item $InstallDirectory -Recurse -Force
}

# 6. The data, only on request.
if (Test-Path $DataDirectory) {
    if ($RemoveData) {
        if ($PSCmdlet.ShouldProcess($DataDirectory, 'Delete the rules, alias pairs and audit log for good')) { Remove-Item $DataDirectory -Recurse -Force }
    }
    else {
        Write-Host "Kept $DataDirectory (rules, alias pairs, audit log); -RemoveData deletes it."
    }
}

Write-Host 'OpWarden removed. Restart terminals and agent apps so they drop the old PATH.'
