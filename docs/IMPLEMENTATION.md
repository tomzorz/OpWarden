# Implementation notes

Practical guidance for building what [SPEC.md](SPEC.md) describes. The spec is the single normative source: where this file and the spec disagree, the spec wins and this file is the bug.

## Layout

```
sources/OpWarden/
  OpWarden.slnx
  OpWarden.Core/            pipe protocol, request/verdict types, argv classification, rule model
  OpWarden.Shim/            NativeAOT, named op.exe, must stay tiny
  OpWarden.Broker/          the service (console-runnable for development)
  OpWarden.SessionAgent/    prompts, notifications, management window
  OpWarden.Tests/           unit tests for Core, end-to-end tests that drive the real executables
  OpWarden.Probe/           test executable that reports what it received: argv, stdin, a requested exit code
sources/spike-argv/         the spikes that settled sections 5 and 9, kept as reference
```

Serialization is source-generated `System.Text.Json` everywhere. Reflection-based JSON fails under trimming and AOT, and the pipe protocol and the audit-log line format (REQ-AUD-2) both live in Core.

## Build order

1. **Core and shim passthrough.** Pipe protocol, argv classification (section 6), secret-reference extraction from arguments, environment files and templates. Exit criterion: REQ-SHIM-3 to REQ-SHIM-10 demonstrably hold against the fake op CLI and a stub broker.
2. **Rule engine as a pure library.** Tuple building, specificity matching, deny-wins ties, alias pairs, per-reference evaluation for `run`, `prompt-always` vaults. The most test-dense part of the system, with no Win32 in it. REQ-RULE-2, 13 and 16 are where the subtle bugs live, so the tests there are table-driven and exhaustive.
3. **Broker as a console app, plus the session agent.** The prompt flow end to end: queueing, the four decisions, the cache-grant control, the 30-second timeout, abandoned-on-disconnect, the queue cap (sections 7 and 11). Running the broker in a console before any service plumbing keeps the end-to-end loop fast.
4. **Cache** (section 9).
5. **Trust hardening.** Service registration, ACLs, session-agent pinning, the elevation gate (section 8).
6. **Process map and bypass watcher** (sections 5 and 10).
7. **Install and rollback script** (section 14). Acceptance is section 14 steps 7 to 9.

Step 5 builds on the service-account spike's results, summarised under "What the service account needs".

## AOT everywhere

Section 3 and section 14 step 1 make all three executables NativeAOT. REQ-SHIM-8 (under 50 ms on a rule hit) is the only hard reason, and it binds the shim alone, but the broker and session agent are AOT too: the session agent's prompt, with the per-field pin/wildcard controls of REQ-RULE-7, is raw Win32, and the broker drives the service API and every Win32 call through `LibraryImport`. A JIT session agent with WPF would need a spec amendment first.

## Win32 map

- **Pipe client identity:** `GetNamedPipeClientProcessId` on each connection. It anchors caller resolution (the walk starts at the shim's PID) and session-agent pinning (REQ-TRUST-4). After the first message, `NamedPipeServerStream.RunAsClient` takes the client's token: the broker reads the agent hosts' executables as that user (REQ-CALL-24), and the management pipe asks it the elevation question.
- **Pipe security:** every broker pipe comes from `NamedPipeServerStreamAcl.Create` with the broker's account at full control, the configured user SID at read/write (which leaves out `CreateNewInstance`), and a deny for the `NETWORK` SID (REQ-TRUST-9). The first instance is created with `FirstPipeInstance`, and a listener exists at all times, so the name is never free for a squatter (REQ-TRUST-10).
- **Process facts:** `NtQuerySystemInformation`, class 5 (`SystemProcessInformation`) for parent PIDs, creation times and sessions, class 88 (`SystemProcessIdInformation`) for image paths. Neither opens the process, which the service account could not do for any user process (REQ-CALL-25). Class 88 is undocumented but stable since Vista; Process Explorer and psutil rely on it.
- **Process-creation events:** a real-time ETW session on `Microsoft-Windows-Kernel-Process`, consumed through `advapi32` P/Invoke (`StartTrace`, `EnableTraceEx2`, `OpenTrace`, `ProcessTrace`), with each event decoded by the layout its manifest gives for its version (REQ-CALL-21).
- **Authenticode** (REQ-CALL-14): `WinVerifyTrust` with revocation checks configured never to touch the network, plus `CryptQueryObject` to read the signer name. Cache verdicts keyed by path, size and modification time.
- **Elevation check** (REQ-TRUST-5): `WindowsPrincipal.IsInRole(Administrator)` on the management client's token. A UAC-filtered token holds Administrators deny-only, so only an elevated token passes. Only rule mutations need this; prompt decisions must not (REQ-TRUST-6), and a cache flush takes access away, so it needs none.
- **Cache memory** (REQ-CACHE-1/2, REQ-CACHE-14): values in `NativeMemory.Alloc` buffers, `VirtualLock`ed, encrypted in place with `CryptProtectMemory`, zeroed on delete. Managed arrays move under the GC and can be paged before a lock call ever sees them.
- **Integrity vault** (REQ-INT-2): `CryptProtectData` / `CryptUnprotectData` through P/Invoke, which avoids the `ProtectedData` package. Under the service account the vault decrypts only for `NT SERVICE\OpWarden`.
- **Service registration:** `sc.exe create OpWarden binPath= "\"<install>\OpWarden.Broker.exe\" --service --config \"<install>\broker.json\"" obj= "NT SERVICE\OpWarden" start= auto`. The broker drives the service API itself (`StartServiceCtrlDispatcherW`, an `[UnmanagedCallersOnly]` service main and handler), which keeps the hosting package and its dependency injection stack out of the AOT binary. The virtual account exists implicitly; grant it the data-directory ACLs from REQ-TRUST-2 at install time, and write the user's SID into `broker.json` (REQ-TRUST-12). Run without `--service`, the same binary is the console broker for development.

## What the service account needs

The service-account spike (`sources/spike-session-spawn/`) settled both questions under a real virtual account; spec sections 5 and 8 carry the decisions and section 14 the install steps.

- **No session spawn.** `WTSQueryUserToken` refuses a virtual service account even with `SeTcbPrivilege` held and enabled (access denied), because Windows reserves it for LocalSystem. So the session agent starts itself at logon (a Run entry the installer writes), and the broker pins the first connection from the installed executable in the console session (REQ-TRUST-3, REQ-TRUST-4).
- **Process events need two grants.** Membership in Performance Log Users lets the account start the trace session, and an `EventAccessControl` grant (`TRACELOG_GUID_ENABLE` on `Microsoft-Windows-Kernel-Process`) lets it enable the provider. The grant lives in `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Security`, value named after the provider GUID; the installer saves that value first and the rollback puts it back byte for byte, which is what the spike script does.

## Testing

No mocks. Passthrough (REQ-SHIM-3, 4, 9) is a property of the shim, not of the op CLI, so it is tested against a probe executable that echoes its arguments and standard input back and exits with a requested code: the probe imitates nothing, it measures what the shim delivered. Where the real op CLI is installed, an end-to-end test also runs `op --version` through the shim, which needs no sign-in. The rule engine gets plain unit tests. Caller resolution needs at least one end-to-end test that runs through a real intermediate shell and one that kills the intermediate parent mid-flight to prove the `unknown` path (REQ-CALL-18), because a broken chain was the worst bug in the first draft of section 5.

Verify on the real machine rather than trusting the install-time list: the executable names and signers of the agent hosts in REQ-CALL-16, and the op CLI's install directory.

## Traps

- The shim runs the op CLI by its configured absolute path, never through `PATH`. The shim is itself named `op.exe`, so `PATH` resolution recurses into itself forever.
- In git-bash a Windows-style `D:\...` entry in `PATH` is silently ignored; use the msys form `/d/...`.
- In git-bash, `2>nul` creates a file literally named `nul` that Windows tools cannot delete. Use `2> /dev/null`.
- The desktop app's biometric prompt still fires on a cold op CLI session after OpWarden returns `allow`. That is correct (section 15), not a bug.
