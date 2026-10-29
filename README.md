# OpWarden

https://github.com/user-attachments/assets/06dac76b-596a-49e2-9b89-d03857a55444

A local authorization broker for the 1Password CLI on Windows. Every `op` invocation goes through OpWarden first, which decides per secret and per caller whether it runs, and logs it either way.

## Why

When something runs `op`, the 1Password desktop app's biometric prompt names the calling process and nothing else. It doesn't say which vault, item or field is being read, or whether the call is a read or a delete. Once you've approved it, the CLI session stays warm, and every call after that gets no prompt at all.

That's fine while you're the only one typing `op`. It stops being fine once coding agents run it in your terminal on your behalf. OpWarden puts a prompt in front of each call that says who is asking, what they want and from where, lets you turn the answer into a rule, and keeps an audit log of everything.

## How it works

There are three executables:

- **The shim** is an `op.exe` that sits on `PATH` ahead of the real one. It parses the command line, asks the broker for a verdict over a named pipe, and then runs the real op CLI, prints cached output, or refuses. The real op CLI still talks to the desktop app itself, so 1Password's own checks are unchanged and the desktop app never sees OpWarden.
- **The broker** is a Windows service running as `NT SERVICE\OpWarden`. It owns the rules, the audit log and the cache, works out who the caller is, and decides. Since it runs under its own account, a process running as you can't edit its rules, rewrite its log or read its cache.
- **The session agent** runs in your logon session. It shows prompts, toast notifications, a tray icon, the audit log and the rules window, and holds no state.

### Who is calling

The broker follows ETW process events to walk up from the shim through its ancestors. If it passes an agent host with a valid signature (Claude Code's `claude.exe`, signed by Anthropic, PBC, for example) the caller is that agent. If it gets to your logon shell without passing one, the caller is you. Anything else is `unknown`: it gets a prompt on every call and can never inherit a rule. Rules can treat agents more strictly than your own terminal.

### Rules and prompts

A rule matches on five fields: caller, action (`read`, `write`, `delete`, `manage`, `run`, `meta`), vault, item and field. Each field is either pinned or a wildcard. If no rule matches, you get a prompt with four choices: `allow-once`, `disallow-once`, `always-allow` and `always-disallow`. The `always-` choices store a rule, so the prompts thin out as your rules cover the routine calls.

The same vault, item or field can be referenced by name or by UUID. The broker learns which names go with which UUIDs from the item JSON that passes through it, and matching takes this into account. A deny rule acts when a reference might match it, while an allow rule acts only when the match is certain. That means naming a vault by an ID the broker hasn't seen yet won't get you past a deny.

### Cache

For workloads that read the same secrets over and over, such as an OpenTofu plan, an allow decision for `op read` can carry a cache grant with a TTL. Cached values stay in broker memory, encrypted with `CryptProtectMemory`, and are all dropped when the workstation locks. A cache hit doesn't run the op CLI, but it is logged and shown as a toast just like a read a rule allowed.

### Audit log

Every invocation is logged, prompted or not, along with the caller's full ancestor chain. Each line is chained to the previous one with an HMAC, so editing or deleting lines shows up. A full-path call to the real `op.exe` skips the shim. OpWarden can't block that. The spec has the broker watch for it and flag it as a bypass, but that watcher isn't built yet.

## Status

Early, and not packaged. There are no releases, so you build from source. It runs as an installed service on one machine. Everything above works except the bypass watcher. [docs/SPEC.md](docs/SPEC.md) is the full specification. Its section 16 lists what OpWarden does not protect against (an elevated attacker, for one, and an agent that starts a process outside its own ancestry). Section 17 lists the open decisions.

## Requirements

- Windows 10 or 11
- The 1Password desktop app with CLI integration turned on, and the op CLI
- The .NET 10 SDK, to build
- An elevated PowerShell, for the install

## Install

Build unelevated, from the repository root:

```powershell
.\install\publish.ps1
```

This builds the shim and broker NativeAOT and the session agent self-contained, into `artifacts\publish`. If the NativeAOT link fails because it can't find `vswhere.exe`, add `C:\Program Files (x86)\Microsoft Visual Studio\Installer` to `PATH` and try again.

Then install from an elevated PowerShell, signed in as the user whose op CLI OpWarden should guard:

```powershell
.\install\install.ps1
```

The script installs the service, the grants it needs to read process events, the session agent's logon entry and the `PATH` entry, and records each change in `install-state.json`. Running it again upgrades in place. You can override `-InstallDirectory` (default `%ProgramFiles%\OpWarden`), `-DataDirectory` (default `%ProgramData%\OpWarden`), `-OpPath` and `-UserSid`. `-WhatIf` shows the plan without changing anything.

Sign out and back in, open a new terminal and run `op --version`. A prompt should appear.

To remove it:

```powershell
.\install\uninstall.ps1
```

This undoes exactly what `install-state.json` recorded, and the op CLI then runs directly again. Your rules and audit log stay unless you pass `-RemoveData`.

## Build and test

From `sources/OpWarden`:

```bash
dotnet build --warnaserror
```

```bash
dotnet test
```

The end-to-end tests run the built shim and a probe executable as real processes. The session-agent UI tests open real windows and move the pointer, so they only run with `OPWARDEN_UI_TESTS=1`. [AGENTS.md](AGENTS.md) has the details.

## Layout

- `docs/SPEC.md`: the specification, and the record of every design decision
- `docs/IMPLEMENTATION.md`: build order, Win32 notes, testing approach and known traps
- `sources/OpWarden/`: the solution (Core, Shim, Broker, SessionAgent, Probe, Tests)
- `sources/spike-*`: the spikes that settled caller resolution, the cache surface and the service account (kept for reference, not shipped)
- `install/`: publish, install and uninstall scripts
- `sources/DemoVideo`: the video at the top of this README, an HTML page that plays in any browser. `node render.mjs` renders it frame by frame at 1080p through headless Edge, and ffmpeg encodes a 1080p MP4 from those frames, which the README embeds as a GitHub attachment. It needs Node 22, Edge and ffmpeg, and nothing from npm.

## License

[MIT](LICENSE)
