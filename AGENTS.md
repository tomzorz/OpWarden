# OpWarden: agent guide

A local authorization broker that gates every 1Password CLI invocation behind a per-secret, per-caller permission model. Windows only.

- [docs/SPEC.md](docs/SPEC.md) is the single normative source, written in controlled English (Lojbanlite). Read it before changing behaviour. Decisions are recorded inline, dated, in the section they affect; there is no separate decisions file.
- [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md) holds the build order, the Win32 map, the testing approach and the known traps. Where it disagrees with the spec, the spec wins.
- The solution lives in `sources/OpWarden/`. `sources/spike-argv/` is the spike that settled sections 5 and 9; it is reference, not product.
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

The session-agent UI tests put real windows on the desktop, so they run only with `OPWARDEN_UI_TESTS=1`; set `OPWARDEN_UI_SCREENSHOTS` to a folder to get a PNG of each prompt. They render through `PrintWindow`, which works while the workstation is locked.

The shim publishes NativeAOT (`dotnet publish OpWarden.Shim -c Release -o <dir>`). If the native link cannot find `vswhere.exe`, put `C:\Program Files (x86)\Microsoft Visual Studio\Installer` on PATH; if it still fails, `-t:IlcCompile` proves the code is AOT-clean. The REQ-SHIM-8 latency test runs only against a published shim: set `OPWARDEN_AOT_SHIM` to its `op.exe`.
