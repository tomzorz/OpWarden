# Spike: can the broker start the session agent?

Feeds REQ-TRUST-3 in [SPEC.md](../../docs/SPEC.md): the broker, a service under the virtual account `NT SERVICE\OpWarden`, starts the session agent in the interactive user's logon session. That needs `WTSQueryUserToken`, which needs `SeTcbPrivilege`, which a virtual account does not hold by default.

**Question:** once `LsaAddAccountRights` grants `SeTcbPrivilege` to a virtual service account, can that service call `WTSQueryUserToken` and `CreateProcessAsUser` to start a process in the console session as the signed-in user?

**If yes:** the installer grants the right, and REQ-TRUST-3 stands as written. **If no:** amend the spec so the session agent autostarts at logon and the broker pins the first connection that arrives from the installed path in the interactive session.

## What it does

`src/Program.cs` is one AOT executable with four modes: `service` (what the service control manager starts), `grant` and `revoke` (the LSA right), and `marker` (the child, which logs its user and session). The service logs its token's privileges, enables `SeTcbPrivilege` if held, calls `WTSQueryUserToken` for the active console session, and starts the marker with `CreateProcessAsUser`.

`run-spike.ps1` runs two rounds against a throwaway service `OpWardenSpike`: first without the right (expected failure, error 1314), then with it. It revokes the right, deletes the service and removes its working folder whatever happens.

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

- Round 2 shows `WTSQueryUserToken ok`, `CreateProcessAsUser ok`, and a `marker:` line naming the signed-in user and the console session: **go**.
- Round 2 still fails with 1314: the grant did not reach the service token, **no-go** for the privilege route.
- Round 1 unexpectedly succeeds: the premise was wrong, and the right is not needed at all.
