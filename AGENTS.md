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

The shim publishes NativeAOT (`dotnet publish OpWarden.Shim -c Release`). If the native link fails on a machine whose MSVC environment is broken, `-t:IlcCompile` still proves the code is AOT-clean.
