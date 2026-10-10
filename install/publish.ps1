<#
.SYNOPSIS
Builds the shim and the broker as NativeAOT executables and the session agent as a
self-contained WPF app (spec section 14, step 1).

.DESCRIPTION
Run unelevated: a build as an administrator leaves files in bin and obj that a later
unelevated build cannot overwrite. The result lands in artifacts\publish, laid out the way
install.ps1 expects:

  artifacts\publish\OpWarden.Broker.exe
  artifacts\publish\agent\OpWarden.SessionAgent.exe   (and the runtime beside it)
  artifacts\publish\shim\op.exe
#>
[CmdletBinding()]
param(
    # Where the executables go; by default artifacts\publish beside this folder.
    [string] $Output
)

$ErrorActionPreference = 'Stop'
$solution = Join-Path $PSScriptRoot '..\sources\OpWarden'
# Windows PowerShell leaves $PSScriptRoot empty while it binds parameter defaults.
if (-not $Output) { $Output = Join-Path $PSScriptRoot '..\artifacts\publish' }
$Output = [IO.Path]::GetFullPath($Output)

# The native link step runs the Visual Studio environment scripts, which call vswhere.exe
# by bare name; the Installer folder that holds it is not always on PATH.
$installer = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
if ((Test-Path (Join-Path $installer 'vswhere.exe')) -and -not (($env:Path -split ';') -contains $installer)) {
    $env:Path = "$installer;$env:Path"
}

if (Test-Path $Output) { Remove-Item $Output -Recurse -Force }

# The session agent is WPF, which NativeAOT cannot compile: it ships with its own runtime,
# ReadyToRun so it starts quickly at logon.
$projects = @(
    @{ Project = 'OpWarden.Broker'; Target = $Output; Extra = @() },
    @{ Project = 'OpWarden.SessionAgent'; Target = (Join-Path $Output 'agent'); Extra = @('--self-contained', '-p:PublishReadyToRun=true') },
    @{ Project = 'OpWarden.Shim'; Target = (Join-Path $Output 'shim'); Extra = @() }
)
foreach ($p in $projects) {
    Write-Host "Publishing $($p.Project) to $($p.Target)"
    dotnet publish (Join-Path $solution $p.Project) -c Release -o $p.Target --nologo -v quiet @($p.Extra)
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish $($p.Project) failed with exit code $LASTEXITCODE." }
}

foreach ($exe in 'OpWarden.Broker.exe', 'agent\OpWarden.SessionAgent.exe', 'shim\op.exe') {
    $path = Join-Path $Output $exe
    if (-not (Test-Path $path)) { throw "Publishing finished but $path is missing." }
}

Write-Host "Done. Install from an elevated PowerShell: .\install\install.ps1"
