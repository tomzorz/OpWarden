# Spike: what the service account can do

Two questions about the broker's service account, `NT SERVICE\OpWarden`, answered by one elevated run against a throwaway service `OpWardenSpike`. See [SPEC.md](../../docs/SPEC.md).

**Question 1, the session agent (REQ-TRUST-3).** The broker starts the session agent in the interactive user's logon session. That needs `WTSQueryUserToken`, which needs `SeTcbPrivilege`, which a virtual account does not hold by default. Once `LsaAddAccountRights` grants it, can the service call `WTSQueryUserToken` and `CreateProcessAsUser` to start a process in the console session as the signed-in user? If yes, the installer grants the right and REQ-TRUST-3 stands. If no, the spec changes so the session agent autostarts at logon and the broker pins the first connection from the installed path.

**Question 2, process events (spec section 17).** Caller resolution needs `Microsoft-Windows-Kernel-Process` events. A member of Performance Log Users can start an ETW session but is refused when enabling that provider (measured 2026-10-04), so membership alone is not enough. Does a provider grant through `EventAccessControl` let the service account receive process-start events? If yes, the installer grants it and the rollback revokes it.

## What it does

`src/Program.cs` and `src/EtwProbe.cs` make one AOT executable with modes `service` (what the service control manager starts), `grant` / `revoke` (the LSA right), `grant-etw` (the provider grant) and `marker` (the child, which logs its user and session). Each service run logs its token, tries the session spawn, then starts an ETW session, enables Kernel-Process, starts a child process and counts the ProcessStart events that arrive.

`run-spike.ps1` runs four rounds: bare virtual account, plus `SeTcbPrivilege`, plus Performance Log Users, plus the provider grant. Whatever happens, it then removes the provider grant by putting the provider's ETW security registry value back byte for byte (or deleting it if it did not exist), removes the group membership, revokes the right, deletes the service and removes its working folder.

## Run

From `src/`:

```bash
dotnet publish -c Release -o ../bin
```

Then from an elevated PowerShell, signed in at the console:

```powershell
.\run-spike.ps1
```

It prints `run.log` at the end. That file names the machine and the user, so it is gitignored.

## Reading the result

- Round 2 shows `WTSQueryUserToken ok`, `CreateProcessAsUser ok` and a `marker:` line naming the signed-in user and the console session: question 1 is **go**. Still 1314: **no-go** for the privilege route.
- Round 3 shows `etw StartTrace: ok` and `EnableTraceEx2 ... FAILED 5`: membership alone is confirmed insufficient for the service account too.
- Round 4 shows `EnableTraceEx2 Kernel-Process: ok` and at least one ProcessStart event: question 2 is **go**. Still `FAILED 5`: the grant does not reach the provider, and the broker needs another route (LocalSystem, or a different event source).
