# Shared by install.ps1 and uninstall.ps1: the names, locations and Win32 calls both need,
# so an install and its rollback can never disagree about them. Dot-source it.

$ServiceName = 'OpWarden'
$ServiceAccount = "NT SERVICE\$ServiceName"
$KernelProcessProvider = '22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716'
$EtwSecurityKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Security'
$RunKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$EnvironmentKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'

# The group's name is localized; its SID is not.
$PerformanceLogUsers = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-559')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]

if (-not ('OpWardenInstall.Native' -as [type])) {
    Add-Type -Namespace OpWardenInstall -Name Native -MemberDefinition @'
[DllImport("advapi32.dll")]
public static extern uint EventAccessControl(ref Guid provider, uint operation, byte[] sid, uint rights, [MarshalAs(UnmanagedType.U1)] bool allow);

[DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern IntPtr SendMessageTimeout(IntPtr window, uint message, UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);
'@
}

function Test-Administrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ServiceSid {
    return (New-Object Security.Principal.NTAccount($ServiceAccount)).Translate([Security.Principal.SecurityIdentifier])
}

# sc.exe parses its command line with the C runtime, so the whole line is handed over as
# one string: PowerShell's own quoting of arguments that contain quotes differs between
# versions and mangles binPath.
function Invoke-Sc([string] $arguments) {
    $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\sc.exe') -ArgumentList $arguments -Wait -NoNewWindow -PassThru
    if ($process.ExitCode -ne 0) { throw "sc.exe $arguments failed with exit code $($process.ExitCode)." }
}

function Get-SystemPathEntries {
    # Unexpanded, so %SystemRoot%-style entries survive the rewrite.
    $raw = (Get-Item $EnvironmentKey).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
    return @($raw -split ';' | Where-Object { $_ })
}

function Set-SystemPathEntries([string[]] $entries) {
    Set-ItemProperty -Path $EnvironmentKey -Name Path -Value ($entries -join ';') -Type ExpandString
    # Tell running programs, Explorer above all, so what they start next sees the new PATH.
    $result = [UIntPtr]::Zero
    [void][OpWardenInstall.Native]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
}

function Stop-SessionAgent([string] $path) {
    Get-Process -Name 'OpWarden.SessionAgent' -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -eq $path } |
        Stop-Process -Force
}

function Read-InstallState([string] $path) {
    if (Test-Path $path) { return Get-Content $path -Raw | ConvertFrom-Json }
    return $null
}

function Save-InstallState($state, [string] $path) {
    [IO.File]::WriteAllText($path, ($state | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
}

# The audit log is one JSON object per line; returns the entries of one event type
# written after a point in time.
function Get-AuditEvents([string] $dataDirectory, [string] $event, [DateTimeOffset] $since) {
    $log = Join-Path $dataDirectory 'audit.jsonl'
    if (-not (Test-Path $log)) { return @() }
    $lines = Get-Content $log -Tail 200
    return @($lines | ForEach-Object { $_ | ConvertFrom-Json } |
        Where-Object { $_.event -eq $event -and [DateTimeOffset]$_.timestamp -ge $since })
}
