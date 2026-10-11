# Implementation notes

Practical guidance for building what [SPEC.md](SPEC.md) describes. The spec is the single normative source: where this file and the spec disagree, the spec wins and this file is the bug.

## Layout

```
sources/OpWarden/
  OpWarden.slnx
  OpWarden.Core/            pipe protocol, request/verdict types, argv classification, rule model
  OpWarden.Shim/            NativeAOT, named op.exe, must stay tiny
  OpWarden.Broker/          the service (console-runnable for development)
  OpWarden.SessionAgent/    WPF: prompts, toasts, tray icon, status, audit log and rules windows
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
7. **Install and rollback script** (section 14), in `install/`. Acceptance is section 14 steps 10 to 12.

Step 5 builds on the service-account spike's results, summarised under "What the service account needs".

## NativeAOT for the shim and broker, WPF for the session agent

REQ-SHIM-8 (under 50 ms on a rule hit) binds the shim, so the shim is NativeAOT, and the broker is too: it drives the service API and every Win32 call through `LibraryImport`. The session agent is WPF and ships self-contained (spec section 3, session-agent UI decision): WPF cannot compile with NativeAOT. Its pieces:

- **Components** (`Components.cs`, styled in `Themes/Components.xaml`): one purpose each, each with an implicit style keyed by its type, none positioning itself. Every value in a style is a token named for where it is used, and two tokens that share a value today stay two tokens. Brushes come from `Themes/Palette.Dark.xaml` or `Palette.Light.xaml`, swapped when Windows changes its app theme; every key names where a colour is used.
- **Layouts** (`Layouts.cs`): every gap between components belongs to the layout that holds them, so no component carries a margin. WPF's panels have no gap of their own, so `SpacedStackPanel` stacks its children with one gap between neighbours, takes none for a collapsed child, and gives one child the space left over. The gaps are tokens named for what they separate: window sections, a heading and its content, neighbouring buttons, list items.
- **Windows:** the prompt and the toasts are borderless, topmost and never take focus; the status, audit and rules windows derive from `StandardWindow`, which loads their shared look and a title bar that follows the theme (`DwmSetWindowAttribute`).
- **Toasts:** a read's toast sits on the top edge of its origin window at that window's width, or in its top-right corner when there is no room above, and follows the window (REQ-RULE-41 to REQ-RULE-45). An `AnimationClock` on the frame's remaining lifetime drives both the countdown bar and the close, so pausing it under the pointer holds both (REQ-RULE-47, REQ-RULE-48).
- **Tray:** `Shell_NotifyIcon` through P/Invoke on a hidden top-level `HwndSource`, which also hears session-lock events and theme changes; the icon is a shield rendered in the broker-state colour at the small-icon size.
- **Rules editing:** the rules window restarts itself elevated with `--manage`; the elevated copy shows only that window.
- **`--open status|audit|rules`** opens a window at start, for the tests and for review without clicking the tray.

## Win32 map

- **Pipe client identity:** `GetNamedPipeClientProcessId` on each connection. It anchors caller resolution (the walk starts at the shim's PID) and session-agent pinning (REQ-TRUST-4). After the first message, `NamedPipeServerStream.RunAsClient` takes the client's token: the broker reads the agent hosts' executables as that user (REQ-CALL-24), and the management pipe asks it the elevation question.
- **Pipe security:** every broker pipe comes from `NamedPipeServerStreamAcl.Create` with the broker's account at full control, the configured user SID at read/write (which leaves out `CreateNewInstance`), and a deny for the `NETWORK` SID (REQ-TRUST-9). The first instance is created with `FirstPipeInstance`, and a listener exists at all times, so the name is never free for a squatter (REQ-TRUST-10).
- **Process facts:** `NtQuerySystemInformation`, class 5 (`SystemProcessInformation`) for parent PIDs, creation times and sessions, class 88 (`SystemProcessIdInformation`) for image paths. Neither opens the process, which the service account could not do for any user process (REQ-CALL-25). Class 88 is undocumented but stable since Vista; Process Explorer and psutil rely on it.
- **Process events:** a real-time ETW session on `Microsoft-Windows-Kernel-Process`, consumed through `advapi32` P/Invoke (`StartTrace`, `EnableTraceEx2`, `OpenTrace`, `ProcessTrace`), with ProcessStart and ProcessStop each decoded by the layout its manifest gives for its version (REQ-CALL-21). Events reach the consumer in per-processor batches up to a second late, so an exit can arrive before its start, and a walk that needs a parent still in transit calls `ControlTrace(EVENT_TRACE_CONTROL_FLUSH)` and walks again (REQ-CALL-26). `Get-WinEvent -ListProvider Microsoft-Windows-Kernel-Process` prints each event's template, which is where the layouts come from.
- **Authenticode** (REQ-CALL-14): `WinVerifyTrust` with revocation checks configured never to touch the network, plus `CryptQueryObject` to read the signer name. Cache verdicts keyed by path, size and modification time.
- **Elevation check** (REQ-TRUST-5): `WindowsPrincipal.IsInRole(Administrator)` on the management client's token. A UAC-filtered token holds Administrators deny-only, so only an elevated token passes. Only rule mutations need this; prompt decisions must not (REQ-TRUST-6), and a cache flush takes access away, so it needs none.
- **Cache memory** (REQ-CACHE-1/2, REQ-CACHE-14): values in `NativeMemory.Alloc` buffers, `VirtualLock`ed, encrypted in place with `CryptProtectMemory`, zeroed on delete. Managed arrays move under the GC and can be paged before a lock call ever sees them.
- **Integrity vault** (REQ-INT-2): `CryptProtectData` / `CryptUnprotectData` through P/Invoke, which avoids the `ProtectedData` package. Under the service account the vault decrypts only for `NT SERVICE\OpWarden`.
- **Origin window** (REQ-RULE-41): `EnumWindows` front to back, `GetWindowThreadProcessId` against the ancestors the notification lists, and `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` with `GetProcessTimes` to prove each owner is the listed process and not a later one with its ID. A window qualifies when it is visible, not cloaked (`DWMWA_CLOAKED`, which marks another virtual desktop), neither a tool window nor owned, and not empty. A classic console window names the console's first process as its owner, not conhost, so a plain PowerShell window matches its shell; the hidden window a pseudo console gives its shell is an owned tool window, and drops out.
- **Toast placement** (REQ-RULE-42 to REQ-RULE-45): `DWMWA_EXTENDED_FRAME_BOUNDS` for the frame a window shows (`GetWindowRect` counts the invisible resize borders), `MonitorFromWindow`, `GetMonitorInfo` and `GetDpiForMonitor` for the work area and its scale, and `SetWindowPos` to move each toast. All of them work in physical pixels in a per-monitor-aware process; WPF's `Left` and `Top` are DIPs, and a DIP is a different number of pixels on monitors with different scales. The agent polls the origin windows every 30 ms while toasts sit on them.
- **Notification sound** (REQ-RULE-46): `PlaySound("Notification.Default", SND_ALIAS | SND_ASYNC | SND_NODEFAULT | SND_SYSTEM)`, the sound scheme's own notification sound at the system-sounds volume, silent under "No sounds".
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
- WPF's font cache builds real cultures, so the session agent turns `InvariantGlobalization` off; with it on, every text layout throws.
- WPF projects drop `System.IO` from the implicit usings, because `Path` collides with `System.Windows.Shapes.Path`; files that need it import it.
- A `SizeToContent` window raises `SizeChanged` before WPF resizes its window handle to the new content, so the window rectangle read in the handler is the old one. The status window places itself from a dispatcher callback at `Loaded` priority instead, after layout and the resize; the toasts place themselves from WPF's own layout sizes and do not depend on it.
- .NET's managed UI Automation client takes tens of seconds to search a desktop's top-level windows (45 s on a real desktop, where .NET Framework's takes 46 ms). The UI tests find the agent's windows with Win32 and hand only those to UI Automation, which answers in milliseconds.
