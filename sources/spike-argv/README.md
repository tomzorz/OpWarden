# Spike sandbox: argv-only passthrough logger

Answers the last open decision in [SPEC.md](../../docs/SPEC.md) section 17: what surface the broker's opt-in cache is allowed to cover. To decide that, we need to know which op CLI subcommands an OpenTofu run against the homelab actually issues.

This is **not** the shim. No broker, no rules, no gating. It runs the real op CLI with whatever arguments it was handed, forwards stdio and the exit code, and appends one JSON line per invocation.

## What it records

Per invocation: UTC timestamp, pid, working directory, redacted argv, exit code, wall-clock duration, and the process ancestor chain up to 12 hops (pid, image name, full path where readable, start time, and whether the parent started before the child). `walkStop` says why the chain ended, which is the difference between reaching the shell and giving up.

The console spike added two more fields: `console`, every process attached to the caller's console, and `consoleWalks`, the parent chain walked upward from each of those. Together they test whether console attribution identifies a caller that the parent walk alone cannot.

## What it deliberately does not record

- **stdout.** Captured `op read` output is a secret value sitting on disk. REQ-CACHE-1 forbids that for the product and the spike does not get an exemption.
- **stdin.**
- **environment variables.**

Assignment arguments get their value half replaced with `<redacted>` before writing, the same rule as REQ-AUD-5. Flags keep their values (`--format=json` is exactly the data the spike is after) unless the flag name contains session, token, password, secret, or credential. Secret references carry no `=` and survive intact, which the name-vs-UUID question needs.

## Build

```bash
dotnet publish -c Release -o ../bin
```

Run that from `src/`. It publishes NativeAOT to `bin/op.exe`. If the native link step dies with `'vswhere.exe' is not recognized`, put the VS installer directory on PATH first:

```bash
export PATH="$PATH:/c/Program Files (x86)/Microsoft Visual Studio/Installer"
```

Or set `<PublishAot>false</PublishAot>` in the csproj; a JIT build is fine for a spike, cold start will not distort a tofu run.

## Run

Prepend `bin/` to PATH **in one shell only**. Never put it on the machine PATH; nothing here should outlive the trace, and there is then nothing to roll back.

PowerShell:

```powershell
$env:PATH = "$PWD\bin;$env:PATH"
```

git-bash. Note the msys path form: a Windows-style `D:\...` entry in PATH is silently ignored here, which costs an hour if you miss it.

```bash
export PATH="$(pwd)/bin:$PATH"
```

Confirm the shim is the one that answers, not the real binary:

```bash
op --version
```

Then run the OpenTofu plan or apply from that same shell. Biometric prompts fire exactly as they normally do; the logger inherits the console handles rather than redirecting them, so the desktop app sees no difference.

## The elevated test

`test-process-events.ps1` decides candidate 1 in SPEC.md section 17: can a broker that records process-creation events reconstruct ancestry that the live parent walk cannot? It needs elevation, because `Win32_ProcessStartTrace` refuses an unelevated subscription.

Run it from an **elevated** PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .	est-process-events.ps1 -RealOp "<absolute path to the genuine op.exe>"
```

It subscribes to process-start events, runs `workload.sh` (nested `bash -c` layers ending in the logger, which reproduces the exact break with no secrets involved), then rebuilds the chain from the event map and compares it against the live walk the logger recorded.

The assertion targets the script's own pid rather than `claude.exe` on purpose. Run from an elevated window the workload descends from the script, not from the agent host, and the question is only whether the event map spans a chain the live walk cannot. PASS means it did.

Add `-IncludeRealWorkflow` with `-RealWorkflowPath` to also trace a real workflow that reads secrets. That will raise biometric prompts.

Result, 2026-08-18: **PASS.** The event map rebuilt the full chain to the root across six processes that had already exited. The live walk managed two hops.

## The reliability test

`test-event-reliability.ps1` answers the follow-on question: does event delivery survive load? A dropped event does not delay a caller, it makes that caller permanently unresolvable, so the drop rate decides how much weight the event-map design can carry.

It spawns a known number of short-lived processes parented to itself, captures them through WMI and ETW at once, and compares each pipeline's count against a ground truth it already knows. Also elevated:

```powershell
powershell -ExecutionPolicy Bypass -File .	est-event-reliability.ps1
```

`-Count N` sets the load, default 300, which measured at roughly 390 process starts per second. `-SkipEtw` measures WMI only and changes nothing on the machine.

**It changes system configuration.** It enables the `Microsoft-Windows-Kernel-Process/Analytic` ETW channel, raises that channel's maximum log size to 32 MB so ETW is not handicapped by the 1 MB default, and clears the channel's log. All three are restored in a `finally` block. The channel ships disabled, so its log should already be empty, but the clear is destructive to anything in it.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `OPWARDEN_SPIKE_REAL_OP` | none, required | The genuine op CLI, by absolute path. There is no default: the path differs per machine, and a wrong guess would silently trace nothing. |
| `OPWARDEN_SPIKE_LOG` | `op-argv.jsonl` beside the executable | Where the JSON lines go. |

The real op CLI is never resolved through PATH. This executable is itself named `op.exe`, so PATH resolution would recurse into itself forever. It also refuses to start if the configured real path resolves to its own image.

## Files

- `src/` — the logger. One `Program.cs`, no dependencies beyond the BCL.
- `bin/` — publish output. `bin/op.exe` is the thing you put on PATH.
- `workload.sh` — nested `bash -c` layers that reproduce the caller-resolution break with no secrets involved.
- `test-process-events.ps1`, `test-event-reliability.ps1` — the two elevated tests.

Running any of these produces `*.jsonl` traces and `*.log` transcripts beside them. Those are **not committed**, and `.gitignore` keeps it that way. They record the full process tree of the machine that ran them, along with any `op://` reference the traced workflow used, which is nobody else's business.

## Findings

The three spike write-ups, with the measurement tables and the raw logs they point at, are kept outside this repository for the same reason. The conclusions they produced are in [the specification](../../docs/SPEC.md): the cacheable surface in section 9, and caller resolution in section 5.
