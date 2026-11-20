# Runs the op-parent spike: starts the op CLI under a parent of our choosing, five times,
# and records what the desktop app's prompt named each time.
#
#   call 1, 2: severed   op <- opwarden-spike-file <- (exited)
#   call 3, 4: direct    op <- opwarden-spike-file <- this shell
#   call 5:    direct    op <- op <- this shell
#
# Each shape runs twice to show whether one approval carries over to the next call. Call 5
# is the control: the same harness under the shim's file name, op.exe.
#
# Run it unelevated in a terminal, signed in at the console, with the 1Password desktop app
# running. Approve every prompt: a cancelled prompt shows its name, but only an approved
# one can show whether the next call still needs its own. After each call the script asks
# what the prompt named; press Enter when no prompt appeared. Answers and timings land in
# results.jsonl beside this script, which is gitignored.

param(
    # The op CLI. Defaults to the one an installed OpWarden broker is configured with.
    [string] $OpPath,

    # What to ask the op CLI. It must need the account, so that a cold call prompts. The
    # harness discards what the op CLI prints.
    [string[]] $OpArguments = @('vault', 'list')
)

$ErrorActionPreference = 'Stop'
$bin = Join-Path $PSScriptRoot 'bin'
$harness = Join-Path $bin 'opwarden-spike-file.exe'
$results = Join-Path $PSScriptRoot 'results.jsonl'

if (-not (Test-Path $harness)) { throw "Build the spike first: dotnet publish -c Release -o ../bin (from src). Missing $harness." }

if (-not $OpPath) {
    $brokerConfig = Join-Path $env:ProgramFiles 'OpWarden\broker.json'
    if (-not (Test-Path $brokerConfig)) { throw "Pass -OpPath: no installed broker at $brokerConfig names the op CLI." }
    $OpPath = (Get-Content $brokerConfig -Raw | ConvertFrom-Json).opPath
}
if (-not (Test-Path $OpPath)) { throw "The op CLI is not at $OpPath." }

# The control is the same build under another file name, so the name is all that differs.
$controlDirectory = Join-Path $bin 'control'
$control = Join-Path $controlDirectory 'op.exe'
New-Item -ItemType Directory -Force $controlDirectory | Out-Null
Get-ChildItem $bin -File | Copy-Item -Destination $controlDirectory -Force
Move-Item (Join-Path $controlDirectory 'opwarden-spike-file.exe') $control -Force

function Invoke-Call([int] $number, [string] $shape, [string] $executable, [string] $mode) {
    Write-Host "`n=== call $number of 5: $shape"
    $lines = @(& $executable $mode $OpPath @OpArguments | ForEach-Object { Write-Host "    $_"; $_ })
    $named = Read-Host 'What did the 1Password prompt name? (Enter when no prompt appeared)'
    [ordered]@{ time = (Get-Date).ToString('o'); call = $number; shape = $shape; harness = $lines; named = $named } |
        ConvertTo-Json -Compress |
        Add-Content $results
}

Write-Host 'Approve every prompt. A call that ends with exit code 0 was approved or needed no approval.'

Invoke-Call 1 'severed' $harness 'severed'
Invoke-Call 2 'severed, again' $harness 'severed'
Invoke-Call 3 'direct' $harness 'direct'
Invoke-Call 4 'direct, again' $harness 'direct'
Invoke-Call 5 'direct, parent named op.exe' $control 'direct'

Write-Host "`nDone. Results are in $results"
