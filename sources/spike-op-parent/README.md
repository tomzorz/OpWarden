# Spike: which process the desktop app's prompt names

When the op CLI needs an account, the 1Password desktop app shows a Windows Hello prompt that names one process. With OpWarden installed the op CLI's parent is the shim, yet the prompt names a process further up: under an MSYS2 shell it says `bash`. This spike finds out what the op CLI's ancestry has to look like before the prompt names a process of ours, and how far one approval then reaches. See [SPEC.md](../../docs/SPEC.md), sections 13 and 15.

**Question 1, the name.** Does the prompt name the op CLI's parent when that parent is not called `op.exe`? If it does not, does it name the parent once nothing above the parent is alive?

**Question 2, the reach of an approval.** The op CLI identifies its session to the desktop app by the process ID and start time of the process that invoked it, and every shape here gives each call a fresh parent. Does the second call of a shape prompt again?

## What it does

`src/Program.cs` makes one executable, `opwarden-spike-file.exe`, that starts the op CLI in one of two shapes:

- `direct`: the op CLI is a child of the harness, and the harness is a child of the calling shell.
- `severed`: the harness starts a relay, the relay starts an orphan and exits, and the orphan starts the op CLI once the relay is gone. Nothing above the op CLI's parent is alive.

The executable's file name, description, product and company are four different strings, so whatever the prompt prints says which of them the desktop app reads. The harness reads the op CLI's output and throws it away.

`run-spike.ps1` makes five calls and asks after each one what the prompt named: severed twice, direct twice, and direct once more from a copy of the harness named `op.exe`, which is the control. It appends the answers and the harness's timings to `results.jsonl`. That file records process IDs and what a prompt said on one machine, so it is gitignored.

## Run

From `src/`:

```bash
dotnet publish -c Release -o ../bin
```

Then from an unelevated PowerShell, signed in at the console, with the desktop app running:

```powershell
.\run-spike.ps1
```

Expect up to five Windows Hello prompts, and approve each one: a cancelled prompt answers question 1 and leaves question 2 open. The script takes the op CLI's path from an installed broker's `broker.json`; pass `-OpPath` where there is none. It asks the op CLI for `vault list`, which needs the account and so prompts when no approval covers the call. The calls start the op CLI by its full path, so they go around the shim and leave no audit entry.

## Reading the result

- Calls 3 and 4 name the harness: the prompt names the op CLI's parent, and the shim goes unnamed only because it is called `op.exe`. Call 5 should then name the shell or something above it. One intermediate process with another name is enough.
- Calls 3 and 4 name something above the harness, and calls 1 and 2 name the harness: the prompt names the highest ancestor it can reach, and the op CLI has to start under a parent whose own parent has exited.
- Calls 1 and 2 name anything else, or the op CLI fails there: **no-go** for both routes.
- The second call of a shape shows no prompt and returns in a second or two: the first approval covered it. It prompts again: under that shape every run of the op CLI needs its own approval. This reading holds only for calls that ended with exit code 0, which is how an approved call ends.

## Result

Measured 2026-11-20 in two runs of five calls. The first run cancelled every prompt and the second approved every prompt. The names were the same in both.

| Call | The op CLI's parent | Above the parent | The prompt named |
|---|---|---|---|
| 1, 2 | `opwarden-spike-file.exe` | nothing running | `opwarden-spike-file` |
| 3, 4 | `opwarden-spike-file.exe` | PowerShell in Windows Terminal | `sihost` |
| 5 | `op.exe` | PowerShell in Windows Terminal | `sihost` |

- **Question 1: go, by the second route.** The desktop app names the highest ancestor it can reach through running processes, by executable file name without the extension. Under Windows Terminal that is `sihost.exe`. What the op CLI's parent is called makes no difference. Once the parent has no running parent, the prompt names the parent.
- **Question 2: every call prompted again.** In the approved run all five calls needed their own approval, seconds apart, in every shape. That matches the session scope the spec records in section 16: an approval belongs to the process that invoked the op CLI, and each call here had a new one.
- **The name proves nothing.** A process running as the same user can start the op CLI under an executable with the same file name and no running parent. The name is a label for cooperative callers, not evidence that an invocation passed the shim.

Acted on 2026-11-20: the launcher (spec section 4, REQ-SHIM-11 to REQ-SHIM-15, and the prompt-name decision there) starts the op CLI in the severed shape.
