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

The session-agent spawn question below gets validated before step 5 builds on it.

## AOT everywhere, for now

Section 3 and section 14 step 1 make all three executables NativeAOT, and that stands. REQ-SHIM-8 (under 50 ms on a rule hit) is the only hard reason, and it binds the shim alone, so the broker and session agent could run JIT. The current lean is to keep them AOT and write the prompt and management window in raw Win32, because the UI is small. Settle it when the session agent is built: if raw Win32 cannot carry the per-field pin/wildcard controls of REQ-RULE-7 without pain, a JIT session agent with WPF needs a spec amendment first.

## Win32 map

- **Pipe client identity:** `GetNamedPipeClientProcessId` on each connection. It anchors caller resolution (the walk starts at the shim's PID) and session-agent pinning (REQ-TRUST-4). Secure the pipe with an explicit `PipeSecurity`: the interactive user's SID gets connect, nothing wider.
- **Live parent chain:** `CreateToolhelp32Snapshot` for parent PIDs, `GetProcessTimes` for the started-before check (REQ-CALL-6, REQ-CALL-11).
- **Process-creation events:** ETW `Microsoft-Windows-Kernel-Process`. The spikes drove it through `logman` and `wevtutil`; the broker needs a real consumer. `Microsoft.Diagnostics.Tracing.TraceEvent` is the comfortable route and is a dependency (sign-off needed); WMI `Win32_ProcessStartTrace` needs no package but its delivery was not measured.
- **Authenticode** (REQ-CALL-14): `WinVerifyTrust` with revocation checks configured never to touch the network, plus `CryptQueryObject` to read the signer name. Cache verdicts keyed by path, size and modification time.
- **Elevation check** (REQ-TRUST-5): `ImpersonateNamedPipeClient`, open the thread token, `GetTokenInformation(TokenElevation)`, revert. Only rule mutations need this; prompt decisions must not (REQ-TRUST-6).
- **Cache memory** (REQ-CACHE-1/2): values in `NativeMemory.Alloc` buffers, `VirtualLock`ed, zeroed on delete. Managed arrays move under the GC and can be paged before a lock call ever sees them.
- **Service registration:** `sc.exe create OpWarden binPath= ... obj= "NT SERVICE\OpWarden" start= auto`. The virtual account exists implicitly; grant it the data-directory ACLs from REQ-TRUST-2 at install time.

## Known hard spot: starting the session agent from the service

REQ-TRUST-3 has the broker start the session agent in the user's logon session. `CreateProcessAsUser` into the interactive session needs a user token from `WTSQueryUserToken`, which requires `SeTcbPrivilege`, and a virtual service account does not hold that by default.

Plan, in order:

1. Grant `SeTcbPrivilege` to `NT SERVICE\OpWarden` at install time through `LsaAddAccountRights`, and prove with a throwaway service that `WTSQueryUserToken` plus `CreateProcessAsUser` then works from the virtual account.
2. If the grant is ugly or does not work, amend the spec instead of hacking around it: the session agent autostarts at logon, and the broker pins the first connection that arrives from the installed path inside the interactive session.

The proof needs an elevated shell, so it is a hands-on step for the machine owner.

## Testing

No mocks. Passthrough (REQ-SHIM-3, 4, 9) is a property of the shim, not of the op CLI, so it is tested against a probe executable that echoes its arguments and standard input back and exits with a requested code: the probe imitates nothing, it measures what the shim delivered. Where the real op CLI is installed, an end-to-end test also runs `op --version` through the shim, which needs no sign-in. The rule engine gets plain unit tests. Caller resolution needs at least one end-to-end test that runs through a real intermediate shell and one that kills the intermediate parent mid-flight to prove the `unknown` path (REQ-CALL-18), because a broken chain was the worst bug in the first draft of section 5.

Verify on the real machine rather than trusting the install-time list: the executable names and signers of the agent hosts in REQ-CALL-16, and the op CLI's install directory.

## Traps

- The shim runs the op CLI by its configured absolute path, never through `PATH`. The shim is itself named `op.exe`, so `PATH` resolution recurses into itself forever.
- In git-bash a Windows-style `D:\...` entry in `PATH` is silently ignored; use the msys form `/d/...`.
- In git-bash, `2>nul` creates a file literally named `nul` that Windows tools cannot delete. Use `2> /dev/null`.
- The desktop app's biometric prompt still fires on a cold op CLI session after OpWarden returns `allow`. That is correct (section 15), not a bug.
