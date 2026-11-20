# Records

Where information produced while working in this area gets recorded. Read by the `record` skill when it has something to write; created by `record-setup`. Edit by hand when the answers change.

## Area

- Scope: this repository
- Version control: git, single-branch, public on GitHub
- Ownership: the agent's own, stated in `AGENTS.md`
- Spec language: Lojbanlite for anything normative (`docs/SPEC.md`)
- Spike sandbox: `sources/spike-<slug>/`, committed, with a README holding the question, how to run it, how to read the result, and the result. Traces (`*.jsonl`, `*.log`) stay gitignored.

## Destinations

| Kind | Where | Notes |
|---|---|---|
| Rule | `AGENTS.md` | Rules that apply beyond this repo go to the next `AGENTS.md` up. |
| Code fact | Comment at the site | A Win32 fact or a trap that spans files goes in `docs/IMPLEMENTATION.md`. |
| Design | `docs/SPEC.md` | How to build what the spec says goes in `docs/IMPLEMENTATION.md`. Where the two disagree, the spec wins. |
| Decision | Inline in the section of `docs/SPEC.md` it affects, dated | Never a standalone decisions file. |
| Finding | Inline in the section of `docs/SPEC.md` it informs, dated, naming its spike folder | With no section to inform, a dated paragraph in the closest one. The measured result also goes in the spike's README. |
| Procedure | `docs/SPEC.md` | Lojbanlite, numbered steps. Build, test and install commands live in `AGENTS.md`. |
| Diagram | `docs/diagrams/` | Created on first use, referenced from the section it explains. |
| Parked work | An item in Portolan on this project | Plus a TODO comment at the site when there is one. |
| Question | Ask; an `ASSUMPTION:` comment at the site when the user is away | |
| Machine fact | Not in this repo | The repo is public. Machine facts and raw spike traces go to the next area up. |
| Not recorded | Progress, summaries, anything git already says | |
