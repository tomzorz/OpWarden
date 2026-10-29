# OpWarden: agent guide

A local authorization broker that gates every 1Password CLI invocation behind a per-secret, per-caller permission model. Windows only.

- [docs/SPEC.md](docs/SPEC.md) is the single normative source, written in controlled English (Lojbanlite). Read it before changing behaviour. Decisions are recorded inline, dated, in the section they affect; there is no separate decisions file.
- [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md) holds the build order, the Win32 map, the testing approach and the known traps. Where it disagrees with the spec, the spec wins.
- The solution lives in `sources/OpWarden/`. `sources/spike-argv/` is the spike that settled sections 5 and 9; it is reference, not product.
- `sources/DemoVideo` renders the 1080p MP4 at the top of the README; change the page and run `node render.mjs` again. The MP4 stays out of the repo: the README embeds it as a GitHub attachment, so a new render goes up by dragging it into the README in GitHub's web editor in place of the old attachment URL. Its prompt, toast and colours copy the session agent's XAML, so a UI change there means a change here.
- This repository is public. It carries no reference to any particular machine: no drive paths, host names, account names or vault and item names, in code, docs or commit messages. Spike traces (`*.jsonl`, `*.log`) record a machine's process tree and secret references and stay gitignored.
- Git: single-branch. Work on `main`, commit to `main`, push `main`.

## Build and test

From `sources/OpWarden/`:

```bash
dotnet build --warnaserror
```

```bash
dotnet test
```

```bash
dotnet format
```

Tests run on Microsoft.Testing.Platform (`global.json`); pass xunit filters after `--`, for example `dotnet test -- --filter-method "*Shim*"`. The end-to-end tests run the built shim and probe as real processes, so build before `dotnet test --no-build`.

The session-agent UI tests put real windows on the desktop, play the notification sound, and drive them through UI Automation, so they run only with `OPWARDEN_UI_TESTS=1`. The hover test also moves the pointer for a second; it skips itself where the pointer cannot move, as on a locked workstation, so run it when nobody is using the mouse. With `OPWARDEN_UI_SCREENSHOTS` naming a folder, the session agent saves a PNG of each window it shows, rendered offscreen, which works while the workstation is locked.

The session-agent UI tests run against the debug build unless `OPWARDEN_SESSION_AGENT` names another executable, such as the published one in `artifacts/publish/agent`.

## Install

`install/` carries spec section 14 as scripts. `publish.ps1` builds the shim and the broker NativeAOT and the session agent self-contained into `artifacts/publish`; run it unelevated, because an elevated build leaves files in `bin` and `obj` that later builds cannot overwrite. `install.ps1` runs elevated and installs the service, the session agent's logon entry, the grants and the PATH entry; running it again upgrades in place and keeps the data directory. `uninstall.ps1` is the rollback, and keeps the data directory unless given `-RemoveData`. Both accept `-WhatIf`, which runs unelevated. `install-state.json` in the install directory records what the install changed, so the rollback reverts exactly that.

The shim publishes NativeAOT (`dotnet publish OpWarden.Shim -c Release -o <dir>`). If the native link cannot find `vswhere.exe`, put `C:\Program Files (x86)\Microsoft Visual Studio\Installer` on PATH; if it still fails, `-t:IlcCompile` proves the code is AOT-clean. The REQ-SHIM-8 latency test runs only against a published shim: set `OPWARDEN_AOT_SHIM` to its `op.exe`.
