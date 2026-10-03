# OpWarden specification

**Status:** approved, 2026-10-02. Drafted 2026-08-15, revised the same day after the design interview, revised 2026-08-17 after the argv spike, and section 5 rewritten 2026-08-18 after the caller-resolution spikes and the design interview that followed them. Tamás signed off the design on 2026-10-02, which closed the design gate and opened implementation.

**Name decision (2026-08-15):** OpWarden is the final name.

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when they appear in capitals.

---

## 1. Glossary

### op CLI (noun)
The genuine 1Password command-line binary published by AgileBits, named `op.exe`, and signed with AgileBits' Authenticode certificate.
Do not use: op, the CLI, 1Password CLI.

### desktop app (noun)
The 1Password desktop application that opens the named pipe and shows the biometric prompt.
Do not use: 1Password, the app.

### shim (noun)
The OpWarden executable that takes the name `op.exe` on `PATH` ahead of the op CLI, and that runs the op CLI, or serves cached output, after the broker returns a verdict.
Do not use: wrapper, proxy, interceptor.

### broker (noun)
The privileged OpWarden process, installed as a Windows service under the service account, that owns the rule store, the audit log, the cache, the bypass watcher, caller resolution, and verdicts.
Do not use: service, daemon, server.

### session agent (noun)
The unprivileged OpWarden process in the interactive user's logon session that renders prompts, notifications, and the management window.
Do not use: UI, tray app, agent (alone).

### service account (noun)
The dedicated Windows account that runs the broker: the virtual account `NT SERVICE\OpWarden`.
Do not use: broker account.

### management window (noun)
The part of the session agent that lists, edits, and deletes rules, and that flushes the cache.
Do not use: settings, admin panel.

### caller (noun)
The process that ran the shim, together with that process's ancestor chain.
Do not use: parent, invoker.

### caller identity (noun)
The classification the broker assigns to a caller: exactly one of a named agent (for example `claude-code`), the interactive user, or `unknown`.
Do not use: who, principal.

### action (noun)
The category the broker assigns to an op CLI invocation: exactly one of `read`, `write`, `delete`, `manage`, `run`, or `meta`.
Do not use: operation, verb, command type.

### secret path (noun)
The vault, item, and key that an invocation targets, when the shim can parse them from the invocation arguments.
Do not use: target, resource.

### secret reference (noun)
An `op://<vault>/<item>/<field>` string in an argument, in an environment variable, in an environment file, or in a template file.
Do not use: op URI, ref.

### alias pair (noun)
A vault name, an item name, or a field label, together with the UUID that names the same vault, item, or field.
Do not use: mapping, alias (alone).

### request tuple (noun)
The five values the broker matches a rule against: caller identity, action, vault, item, and key.
Do not use: request, tuple.

### rule (noun)
A stored pattern over the request tuple, with a verdict, where each of the five fields is either a pinned literal value or a wildcard.
Do not use: policy, permission.

### possible match (noun)
The comparison result when a pinned rule field and a request-tuple field might name the same value but the broker cannot prove it, for example when the request-tuple field is unknown.
Do not use: partial match, maybe.

### verdict (noun)
Exactly one of `allow` or `deny`.
Do not use: result, decision.

### decision (noun)
The choice the interactive user makes at a prompt: exactly one of `always-allow`, `always-disallow`, `allow-once`, or `disallow-once`.
Do not use: response, answer.

### cache grant (noun)
The optional addition to an `always-allow` or `allow-once` decision that lets the broker cache the invocation's output for a chosen TTL.
Do not use: caching flag, cache permission.

### cache (noun)
The store of granted invocation output that lives only in broker process memory.
Do not use: secret store, value cache.

### process map (noun)
The store of process entries that the broker builds from process-creation events and seeds at start, and that the broker walks to resolve a caller. It lives only in broker process memory.
Do not use: process table, ancestry cache, process history.

### prompt (noun)
The dialog the session agent shows the interactive user, containing the request tuple, the four decision controls, and, for a `read` invocation, the cache-grant control.
Do not use: popup, dialog.

### bypass watcher (noun)
The broker component that subscribes to process-creation events and detects op CLI starts that no shim requested.
Do not use: monitor, sentinel.

### audit log (noun)
The append-only file in which the broker records every invocation, every rule change, every cache hit, and every detected bypass.
Do not use: log, journal.

---

## 2. Overview

OpWarden is a local authorization broker for the op CLI on one Windows machine. The op CLI's own biometric prompt names only the calling process, and reveals neither the vault, the item, the key, nor the operation. After the first unlock, the op CLI session stays warm, and every call inside that window is invisible. OpWarden fills both gaps.

OpWarden gates every op CLI invocation behind a per-secret, per-caller permission model, styled after Claude Code's tool-permission prompts. The first time a given request tuple appears, the broker prompts the interactive user through the session agent. The user grants or denies the request, and optionally stores a rule so the same tuple never prompts again. Over time the stored rules cover the routine cases, and the prompts fade toward zero.

OpWarden records every invocation in the audit log, whether or not that invocation prompted. The audit log gives full visibility into op CLI usage without a prompt on each call.

OpWarden distinguishes three caller identities: named agents, the interactive user, and `unknown`. The user can hold agents to stricter rules than an interactive terminal, and an unresolvable caller never inherits either party's rules.

**Posture decision (2026-08-15):** OpWarden enforces privilege separation against same-user tampering. The broker runs under the service account, so a process that runs as the interactive user cannot edit the rule store, cannot append to the audit log, and cannot read cached secret values from broker memory. A caller can still bypass the shim with a full-path invocation; the bypass watcher detects that case, and section 16 states the remaining limits.

For repeated reads, such as OpenTofu runs against the homelab, the user can grant an opt-in cache so the broker serves a stored value without a fresh op CLI invocation. Section 9 defines the cache.

## 3. Architecture

OpWarden has three executables, two data files, and two in-memory stores:

- The shim: a small executable named `op.exe`, placed on `PATH` ahead of the op CLI. The shim parses the invocation, asks the broker for a verdict over a local named pipe, and acts on the verdict. The shim never connects to the desktop app's named pipe.
- The broker: a Windows service under the service account. The broker maintains the process map, resolves the caller, matches rules, evaluates cache grants, serializes prompts through the session agent, runs the bypass watcher, and writes the audit log.
- The session agent: an unprivileged process that the broker starts in the interactive user's logon session. The session agent renders prompts, notifications, and the management window. The session agent holds no state.
- The rule store and the audit log: files under the install directory, writable only by the service account and by Administrators (REQ-TRUST-2).
- The cache: broker process memory only.
- The process map: broker process memory only. The broker builds it from process-creation events and uses it to resolve callers (section 5).

The shim runs once per op CLI invocation and stays cheap. The broker runs continuously and holds all state. A single broker serializes prompts, so two agents that call the op CLI at the same time produce two queued prompts rather than two colliding dialogs.

The shim keeps the op CLI's identity intact. The op CLI, not the shim, connects to the desktop app's named pipe, so the desktop app's mutual Authenticode verification still passes unchanged. The desktop app never sees OpWarden.

**Transport decision (2026-08-15):** shim, session agent, and broker communicate over local named pipes. The broker reads each pipe client's process identifier from the pipe, and that identifier anchors caller resolution and session-agent pinning. A loopback TCP port was rejected because port-to-process mapping is racy.

The chosen implementation language is C# compiled with NativeAOT, which produces a single self-contained executable with near-native cold-start latency. Cold-start latency matters because the shim wraps every op CLI invocation, and agents invoke the op CLI in bursts.

### Data-flow summary

```
caller (agent shell, your terminal, or unknown process)
   │  runs
   ▼
op  →  SHIM (op.exe on PATH)
        │  1. parse argv → action + secret path + secret references
        │  2. send request over named pipe
        ▼
       BROKER (Windows service, service account)
        │  resolve caller (parent walk + Authenticode signer)
        │  match RULE STORE (alias-pair aware)
        │    ├─ matching rule → verdict, no prompt
        │    ├─ valid cache entry → cached output, op CLI not run
        │    └─ no rule → SESSION AGENT shows PROMPT (30 s, queue ≤ 10)
        │                  4 decisions, plus cache grant on read
        ▼
    verdict + AUDIT LOG entry
        │
        ├─ allow  → SHIM runs op CLI, relays stdio, tees read output to broker
        ├─ cached → SHIM prints cached output, exits 0
        └─ deny   → SHIM exits non-zero, op CLI not run

  BYPASS WATCHER: op.exe starts without a shim parent
      → bypass audit entry + notification to the session agent
```

## 4. Requirements: shim

REQ-SHIM-1: The shim MUST take the file name `op.exe` on `PATH` at a position ahead of the op CLI.

REQ-SHIM-2: On each invocation, the shim MUST send the request tuple, and each parsed secret reference, to the broker, and MUST wait for the verdict before it acts.

REQ-SHIM-3: When the verdict is `allow` and the broker returns no cached output, the shim MUST run the op CLI with the original arguments unchanged.

REQ-SHIM-4: When the shim runs the op CLI, the shim MUST connect the op CLI's standard input, standard output, and standard error to the shim's own, and MUST return the op CLI's exit code as the shim's exit code.

REQ-SHIM-5: When the verdict is `deny`, the shim MUST NOT run the op CLI, and MUST exit with a non-zero exit code, and MUST write nothing from the op CLI to standard output.

REQ-SHIM-6: When the shim cannot reach the broker, the shim MUST deny the invocation, MUST exit non-zero, and MUST print one line to standard error that names OpWarden as the cause.

REQ-SHIM-7: The shim MUST NOT connect to the desktop app's named pipe.

REQ-SHIM-8: The shim SHOULD add less than 50 milliseconds of latency to an invocation that a stored rule resolves without a prompt, so that burst usage stays responsive. The reason for the target is the burst-usage case in section 3.

REQ-SHIM-9: When the verdict is `allow` and the action is `read`, the shim MUST relay the op CLI's standard output and, at the same time, capture a copy. After the op CLI exits, the shim MUST send the captured copy to the broker.

REQ-SHIM-10: When the broker returns cached output, the shim MUST write the cached output to standard output, MUST exit with code 0, and MUST NOT run the op CLI.

## 5. Requirements: caller resolution

**Design decision (2026-08-18):** the broker resolves the caller from a process map that the broker builds from process-creation events, and the broker falls back to a live parent walk where that map does not reach. A live parent walk alone cannot resolve a caller under MSYS2. Win32 offers no `exec`, so Cygwin creates a new Windows process and retires the old one, and the retired process holds the only link to the true parent. Three spikes measured the failure, then the mechanism, then the fix. Findings: recorded in the project spike notes, which are kept outside this repository because they carry machine-specific and vault-specific detail.

### 5.1 The process map

REQ-CALL-1: The broker MUST subscribe to process-creation events for every process on the machine.

REQ-CALL-2: For each process-creation event, the broker MUST store one entry, and that entry MUST hold the process identifier, the parent process identifier, the image path, and the creation time.

REQ-CALL-3: For each process-creation event, the broker MUST do no work other than storing the entry. The broker MUST NOT resolve a caller while the broker handles the event. The broker MUST NOT read a file while the broker handles the event. The broker MUST NOT write a file while the broker handles the event. The reason is that a slow consumer causes the event source to drop events, and one dropped event makes one caller unresolvable for as long as that caller runs.

REQ-CALL-4: The broker MUST hold the process map in broker process memory only. The broker MUST NOT write the process map to disk. The broker MUST NOT write the process map to the audit log. The reason is that the process map records every process that the machine starts, and OpWarden exists to reduce what the interactive user must trust.

REQ-CALL-5: At broker start, and before the broker returns its first verdict, the broker MUST seed the process map from a snapshot of every running process.

REQ-CALL-6: For each seeded entry, the broker MUST confirm that the parent process started before the child process started. When that check fails, the broker MUST store the entry with the parent recorded as unknown. The reason is that Windows reuses process identifiers, and a snapshot alone cannot separate a true parent from a reused identifier.

REQ-CALL-7: The broker MUST retain each entry that the ancestry of at least one running process reaches. The broker MAY delete each entry that the ancestry of no running process reaches.

REQ-CALL-8: The broker MUST bound the process map with a maximum entry count. When the broker reaches that bound, the broker MUST record the fact in the audit log, and the broker MUST NOT record the deleted entries. The reason is that REQ-CALL-7 assumes the reachable set stays small, and a backstop MUST exist when that assumption fails.

REQ-CALL-9: When the broker resolves the parent of a process that Windows created at time T, the broker MUST select the entry whose process identifier equals the parent process identifier and whose creation time is the latest creation time at or before T. The reason is that the process map retains entries for exited processes, and Windows reuses process identifiers.

### 5.2 Resolving one caller

REQ-CALL-10: The broker MUST resolve the caller by walking the ancestry upward from the shim process through the process map.

REQ-CALL-11: When the process map holds no entry for a process in the chain, the broker MUST continue the walk upward from that process through the live parent-process chain. For each hop that the broker takes through the live chain, the broker MUST confirm that the parent process started before the child process started, and the broker MUST stop the walk at the first hop that fails this check.

REQ-CALL-12: The broker MUST end the walk at the first process that has no parent entry, or at the logon session's root process. The broker MUST stop the walk after 64 hops. The 64 hops guard against a cycle, and the 64 hops are not a policy limit. The reason for a large guard is that MSYS2 creates about two Windows processes for each shell level, so one real workflow reaches more than 12 processes.

REQ-CALL-13: When the walk reaches at least one process that matches an agent-host entry, the broker MUST classify the caller identity as the agent that the matching process nearest to the shim process names.

REQ-CALL-14: Before the broker classifies the caller as an agent, the broker MUST verify the Authenticode signature of the agent-host executable against the entry's signer. The broker MAY reuse a stored verification result whose path, file size, and modification time all match. Signature verification MUST NOT wait on the network.

REQ-CALL-15: The broker MUST classify the caller identity as the interactive user only when all three of the following hold: the walk ended without a failed hop, the walk reached the interactive logon session's shell, and no process in the walk matched an agent-host entry.

REQ-CALL-16: An agent-host entry names an executable file name and an Authenticode signer. An entry MAY omit the signer for an unsigned executable, and then the entry matches on file name alone. The configured entries at install are: `claude.exe` (Claude Code), `codex.exe` (Codex CLI), `Cursor.exe` (Cursor), and `opencode.exe` (OpenCode). One file name MAY match two products, because Claude Code and the desktop app share the file name `claude.exe` and share one signer. REQ-CALL-13 resolves that case.

REQ-CALL-17: The broker MUST record the full resolved ancestor chain in the audit log entry for the invocation.

REQ-CALL-18: When the walk stops at a failed hop, or when the walk ends without reaching an agent-host entry and without reaching the interactive logon session's shell, the broker MUST classify the caller identity as `unknown`. The reason is that a broken chain proves nothing, and an unproven caller does not inherit trusted rules.

REQ-CALL-19: For an `unknown` caller, the broker MUST show a prompt for every invocation, and the prompt MUST offer only `allow-once` and `disallow-once`.

REQ-CALL-20: When the broker cannot subscribe to process-creation events, the broker MUST record the failure in the audit log, and the broker MUST notify the session agent. The reason is that the broker then resolves most callers as `unknown`, and the interactive user otherwise meets a stream of prompts that states no cause.

## 6. Requirements: command classification

REQ-CLAS-1: The broker MUST assign exactly one action to each invocation, from the set `read`, `write`, `delete`, `manage`, `run`, and `meta`.

REQ-CLAS-2: The broker MUST classify the following as `read`: `op read`, `op item get`, `op document get`, `op item list`, and `op user get`.

REQ-CLAS-3: The broker MUST classify the following as `write`: `op item create`, `op item edit`, `op document create`, and `op document edit`.

REQ-CLAS-4: The broker MUST classify the following as `delete`: `op item delete`, `op document delete`, and `op vault delete`.

REQ-CLAS-5: The broker MUST classify account, vault, group, and user administration subcommands as `manage`.

REQ-CLAS-6: The broker MUST classify `op run` and `op inject` as `run`.

REQ-CLAS-7: The broker MUST classify `op --version`, `op signin`, `op signout`, and `op whoami` as `meta`.

REQ-CLAS-8: When the shim cannot map an invocation to a known subcommand, the broker MUST treat the action as unknown, MUST match it against rules as an unknown action, and MUST NOT run the op CLI without a verdict.

REQ-CLAS-9: For each invocation, the shim MUST parse the vault, the item, and the key from the arguments when the arguments state them, and MUST mark each field it cannot parse as unknown.

REQ-CLAS-10: The shim MUST parse a secret reference in an argument into the vault, the item, and the key of the secret path.

REQ-CLAS-11: For a `run` invocation, the shim MUST parse each secret reference from each of the following sources:

- the arguments
- each environment variable that the shim inherits
- each named environment file
- the named template file

REQ-CLAS-12: When the shim cannot read a named environment file or a named template file, the shim MUST mark the invocation's secret references as unknown.

REQ-CLAS-13: When a named environment file and an environment variable that the shim inherits assign the same variable name, the shim MUST use the value from the environment file. When two named environment files assign the same variable name, the shim MUST use the value from the file named last. The reason is that the op CLI applies the same precedence.

REQ-CLAS-14: Before the shim parses a secret reference from an environment variable, from an environment file, or from a template file, the shim MUST replace each `$NAME` and each `${NAME}` in it with the value of the environment variable `NAME` that the shim inherits.

REQ-CLAS-15: When the shim inherits no environment variable for a name in a secret reference, the shim MUST mark the invocation's secret references as unknown. When that variable's value contains `/` or `?`, the shim MUST mark the invocation's secret references as unknown. The reason is that such a value moves the boundaries between vault, item, and key, and the op CLI does not document the order in which it expands and splits.

REQ-CLAS-16: When the shim cannot determine where a secret reference ends, the shim MUST mark the invocation's secret references as unknown. The reason is that a secret reference can contain spaces, so a reference outside `{{ }}` in a template file has no visible end when a word follows it.

REQ-CLAS-17: When an `op inject` invocation names no template file, the shim MUST mark the invocation's secret references as unknown. The reason is that the template then arrives on standard input, and the shim passes standard input to the op CLI unread.

**Reference-source decision (2026-10-02):** the shim parses secret references from the environment variables it inherits, not only from arguments and files. The op CLI's own help for `op run` states that the op CLI scans environment variables for secret references, with environment files taking precedence. The first draft of REQ-CLAS-11 missed that source, so REQ-RULE-13 would have evaluated an `op run` with no per-reference tuple for each secret held in the shell environment. Implementation of the shim found the gap.

## 7. Requirements: rules, prompt, and verdict

REQ-RULE-1: For each invocation, the broker MUST build the request tuple from the caller identity, the action, the vault, the item, and the key.

REQ-RULE-2: The broker MUST select the matching rule whose pinned fields are the most specific, where a pinned field is more specific than a wildcard. When two rules tie on specificity and conflict, the broker MUST apply the `deny` rule. The reason is that deny is the safe default under ambiguity.

REQ-RULE-3: When a matching rule exists, the broker MUST apply that rule's verdict and MUST NOT show a prompt.

REQ-RULE-4: When no matching rule exists, the broker MUST show a prompt, including when the action is `read`.

REQ-RULE-5: The prompt MUST display the caller identity, the action, the vault, the item, and the key of the request tuple, and MUST mark any unknown field as unknown.

REQ-RULE-6: The prompt MUST offer exactly four decision controls: `always-allow`, `always-disallow`, `allow-once`, and `disallow-once`. REQ-CALL-19 and REQ-RULE-18 restrict the offered controls for `unknown` callers and `prompt-always` vaults.

REQ-RULE-7: For each of the five request-tuple fields, the prompt MUST let the user pin the field or wildcard the field independently, so that an `always-allow` or `always-disallow` decision stores a rule at the scope the user chooses.

REQ-RULE-8: When the user decides `always-allow`, the broker MUST store a rule with verdict `allow` at the chosen scope, then MUST return `allow`.

REQ-RULE-9: When the user decides `always-disallow`, the broker MUST store a rule with verdict `deny` at the chosen scope, then MUST return `deny`.

REQ-RULE-10: When the user decides `allow-once`, the broker MUST return `allow` and MUST NOT store a rule.

REQ-RULE-11: When the user decides `disallow-once`, the broker MUST return `deny` and MUST NOT store a rule.

REQ-RULE-12: When two or more invocations need a prompt at the same time, the broker MUST show one prompt at a time, and MUST queue the others.

REQ-RULE-13: For a `run` invocation with parsed secret references, the broker MUST evaluate one request tuple per secret reference, and MUST return `deny` when at least one of those tuples resolves to `deny`. The reason is that a single boundary rule for `run` grants every secret the environment file mentions.

REQ-RULE-14: The prompt for a `run` invocation MUST list each parsed secret reference, or MUST state that the secret references are unknown.

REQ-RULE-15: The broker MUST extract each alias pair that appears in captured `read` output, and MUST store each extracted alias pair.

REQ-RULE-16: When the broker compares a rule field with a request-tuple field, the broker MUST treat both members of a stored alias pair as the same value. The reason is that the op CLI accepts names and UUIDs interchangeably, and a literal-only match makes deny rules evadable.

REQ-RULE-17: The rule store MAY mark a vault as `prompt-always`.

REQ-RULE-18: For an invocation whose vault is marked `prompt-always`, and that no `deny` rule matches, the broker MUST show a prompt, and the prompt MUST offer only `allow-once` and `disallow-once`. When a `deny` rule matches, the broker MUST return `deny` without a prompt. The reason is that the prompt could offer only an `allow-once` that the stored `deny` rule already refuses.

REQ-RULE-19: For an `op read` invocation from a named agent or from the interactive user, the prompt MUST offer the cache-grant control. The reason for `op read` alone is REQ-CACHE-10: the broker caches no other output, so a cache grant on another invocation could never take effect. When the user attaches a cache grant to `always-allow`, the broker MUST store the cache grant on the stored rule.

### 7.1 Matching fields

**Matching decision (2026-10-02):** the broker compares fields with three results: match, possible match, and no match. A `deny` rule acts on a possible match, and an `allow` rule does not. Before this decision, the spec did not say how a pinned field compares with an unknown field. Without a possible match, an agent could avoid each pinned `deny` rule by omitting `--vault`, or by naming a vault by UUID instead of by name.

REQ-RULE-20: When the broker compares a pinned rule field with an unknown request-tuple field, the result MUST be a possible match.

REQ-RULE-21: A `deny` rule MUST match a request tuple when no field of the rule is a no match. An `allow` rule MUST match a request tuple only when each field of the rule is a match. REQ-RULE-2 then selects among the matching rules.

REQ-RULE-22: The broker MUST compare vault names, item names, and keys without regard to letter case. The reason is that the op CLI resolves secret references without regard to letter case.

REQ-RULE-23: When the broker compares a UUID with a name, and the broker stores no alias pair for that UUID, the result MUST be a possible match. The reason is that alias pairs reach the broker only from captured `read` output, so an unseen UUID can name each vault or item.

REQ-RULE-24: When a rule pins a name, and the broker stores an alias pair for that name and the request-tuple UUID, the comparison MUST be a match. When a rule pins a UUID, and the broker stores an alias pair for that UUID and the request-tuple name, the comparison MUST be a match only when the broker stores no other UUID for that name, and MUST be a possible match otherwise. The reason is that two vaults can each hold an item with the same name.

REQ-RULE-25: The broker MUST compare the field part of two keys, the part after the last `/`, by REQ-RULE-22 to REQ-RULE-24. When the field parts match and the keys name different sections, or only one key names a section, the comparison MUST be a possible match. The reason is that a secret reference can name a field with its section or without it.

REQ-RULE-26: For REQ-RULE-18, the broker MUST treat a vault that is a possible match for a `prompt-always` vault as marked `prompt-always`.

REQ-RULE-27: For a `run` invocation whose secret references are unknown, the broker MUST NOT return `allow` from rules alone. The broker MUST show a prompt, unless REQ-RULE-13 returns `deny`.

REQ-RULE-28: When two matching `allow` rules tie on specificity, the broker MUST apply the rule with the shorter cache grant, and a rule without a cache grant is the shortest.

### 7.2 Rule notices

**Notice decision (2026-10-03):** OpWarden tells the user about each rule that pins a vault, an item, or a key by only one of its two forms, name or UUID, and offers the rule for the other form when the broker knows it. Tamás asked for this after REQ-RULE-23 left one visible effect: an `allow` rule that pins one form prompts for the other form until the broker sees the alias pair. A `deny` rule needs no such notice, because REQ-RULE-23 already denies an unseen UUID.

REQ-RULE-29: The management window MUST show a notice beside each `allow` rule that pins a vault, an item, or a key, when the broker stores no alias pair for the pinned value. The notice MUST state that a request naming the value by its other form shows a prompt. A key that names a built-in field, whose UUID equals its label, needs no notice.

REQ-RULE-30: When the broker stores exactly one other form for a pinned value, and no stored rule pins that other form in the same position, the management window MUST show a notice that offers to store a second rule. The second rule MUST equal the first rule in each field except that one field, which pins the other form.

REQ-RULE-31: When the broker stores more than one other form for a pinned value, the management window MUST show a notice that lists each other form, and the notice MUST NOT offer a second rule.

REQ-RULE-32: When the broker stores a rule from a prompt, and REQ-RULE-29, REQ-RULE-30, or REQ-RULE-31 gives that rule a notice, the session agent MUST show that notice.

REQ-RULE-33: When a prompt lists more than one request tuple, an `always-allow` or `always-disallow` decision MUST store one rule for each listed request tuple, at the scope the user chose.

REQ-RULE-34: The broker MUST reject an `always-allow` or `always-disallow` decision whose scope pins a field that is unknown in at least one listed request tuple. The broker MUST then keep the prompt open. The reason is that a pinned unknown field would store a wildcard, and the stored rule would be broader than the rule the user saw.

## 8. Requirements: broker trust and rule management

**Management decision (2026-08-15):** rules are managed through the management window, not by hand-editing the rule store.

REQ-TRUST-1: The broker MUST run as a Windows service under the service account.

REQ-TRUST-2: The rule store and the audit log MUST accept writes only from the service account and from Administrators. The interactive user MAY read both files. The reason for the Administrators exception is recovery when the broker is broken.

REQ-TRUST-3: At each logon of the interactive user, the broker MUST start the session agent from its installed path in that logon session, and MUST record the started process's identifier.

REQ-TRUST-4: The broker MUST accept a decision only from the pipe connection whose client process identifier equals the recorded session-agent identifier. The reason is that without pinning, every same-user process can forge decisions, which defeats the service split.

REQ-TRUST-5: The broker MUST accept a rule mutation from the management window only when the pipe client's token is an elevated Administrators token. The session agent MUST request elevation before it opens the management window.

REQ-TRUST-6: A prompt decision MUST NOT require elevation.

REQ-TRUST-7: The broker MUST record each rule change in the audit log, with the source stated as exactly one of `prompt` or `management`.

### 8.1 Integrity

**Integrity decision (2026-10-03):** the broker seals the state it decides with, on disk and in memory, so a change that did not come from the broker is detected. Tamás asked for this as a step beyond a human-readable file edit or a memory editor such as Cheat Engine. Under the service account the seal key is out of the interactive user's reach, and the seal adds to the file permissions of REQ-TRUST-2. In the console broker the key belongs to the user who started it, so the seal stops casual edits only. A decompiled broker defeats it in either mode.

REQ-INT-1: The broker MUST seal the rule store and the alias file. A seal is an HMAC-SHA256, under the integrity key, over the file's name, the file's generation number, and the file's content bytes. The broker MUST raise the generation number at each write.

REQ-INT-2: The broker MUST keep the integrity key, and the latest generation number of each sealed file, in one vault file. The broker MUST encrypt the vault file with DPAPI for the account the broker runs as.

REQ-INT-3: When a sealed file fails its seal, when it carries a generation number older than the vault records, or when it is missing although the vault records a generation for it, the broker MUST treat the file as tampered. For a tampered file, the broker MUST move the file aside under a new name, MUST record an `integrity-failure` entry in the audit log, and MUST notify the session agent. For a tampered rule store, the broker MUST then start with no rules. The reason is that a forged `allow` rule must never take effect, and with no rules each invocation shows a prompt.

REQ-INT-4: A sealed file one generation ahead of the vault MUST pass. The reason is that a broker that stops between writing the file and writing the vault leaves exactly that state.

REQ-INT-5: When the broker cannot decrypt the vault, the broker MUST move the vault aside, MUST create a new vault, and MUST report the failure as REQ-INT-3 states. Each file sealed under the old key then fails its seal, and REQ-INT-3 applies to it.

REQ-INT-6: The broker MUST seal the rule set it holds in memory, under a key that the broker generates at start and never writes anywhere. Before each use of the rule set, the broker MUST verify that seal. When the seal fails, the broker MUST report the failure as REQ-INT-3 states, and MUST reload the rule store from disk.

REQ-INT-7: The broker MUST seal each cache entry over its cache key, its expiry, and its value, under the in-memory key of REQ-INT-6, and MUST verify the seal before the broker serves the entry. When the seal fails, the broker MUST delete the entry, MUST report the failure as REQ-INT-3 states, and MUST run the op CLI instead of serving the entry.

REQ-INT-8: When the broker raises a notice while no session agent is connected, the broker MUST hold the notice, and MUST deliver it when a session agent connects. The reason is that the broker checks its files at start, before a session agent exists.

## 9. Requirements: cache

REQ-CACHE-1: The broker MUST hold the cache in process memory only, and MUST NOT write a cached value to disk.

REQ-CACHE-2: The broker SHOULD lock cache memory pages against paging (`VirtualLock`). The reason is that the operating system otherwise copies process memory to the page file.

REQ-CACHE-3: The broker MUST store invocation output in the cache only under a cache grant.

REQ-CACHE-4: A cache grant carries exactly one TTL from the set: 15 minutes, 1 hour, or 8 hours.

REQ-CACHE-5: Each cache key MUST include the caller identity, so a cached value never serves a different caller identity.

REQ-CACHE-6: When a cache entry's TTL elapses, the broker MUST delete that entry.

REQ-CACHE-7: When the interactive user locks the workstation, the session agent MUST notify the broker, and the broker MUST delete every cache entry.

REQ-CACHE-8: The management window MUST offer a control that deletes every cache entry.

REQ-CACHE-9: The broker MUST record each cache hit in the audit log with the reason `cache`.

REQ-CACHE-10: The broker MUST store output in the cache only when the invocation is `op read`. The broker MUST NOT cache the output of any other `read`-classified invocation.

REQ-CACHE-11: The broker MUST NOT cache the output of an `op read` invocation that names `--out-file`, and MUST NOT cache the output of an invocation that exits with a non-zero code. The reason is that `--out-file` sends the value to a file, which a cached answer on standard output cannot reproduce.

REQ-CACHE-12: The broker MUST serve a cache entry only when a rule returns `allow` for the invocation, or when the invocation needs a prompt that offers all four decisions. The reason is that a `deny` rule, an `unknown` caller, and a `prompt-always` vault each outrank a cached value.

REQ-CACHE-13: A cache key MUST hold the caller identity and the exact argument list of the invocation. The reason is that a flag such as `--no-newline` changes the output.

REQ-CACHE-14: The broker MUST encrypt each cached value in memory with `CryptProtectMemory`, and MUST decrypt only a copy when the broker serves the entry. The reason is that a scan of broker memory then finds no secret value.

REQ-CACHE-15: The broker MUST record each cache flush in the audit log as a `cache-flush` entry.

**Cacheable surface decision (2026-08-17):** the cacheable surface is the output of `op read` invocations only, stated as REQ-CACHE-10. The argv spike traced the OpenTofu homelab workflow and found that every op CLI invocation it issues is `op read` with a secret reference, and that no other `read` subcommand appears at all. The narrow surface therefore covers the whole motivating workflow, and a narrow surface is preferred when both candidates would work. Findings: recorded in the project spike notes, which are kept outside this repository because they carry machine-specific and vault-specific detail.

## 10. Requirements: bypass watcher

REQ-WATCH-1: The bypass watcher MUST read the process-creation events that REQ-CALL-1 already subscribes to, and the bypass watcher MUST select the events whose image path is the op CLI's executable path. The reason is that one subscription serves both the process map and the bypass watcher, and a second subscription would double the event cost that REQ-CALL-3 bounds.

REQ-WATCH-2: When the op CLI starts and the parent process is not a shim process, the broker MUST append a `bypass` entry to the audit log, with the ancestor chain that section 5 resolves. The reason for resolving the chain the same way is that a bypassing caller is exactly the caller whose ancestry the Windows process table is least likely to hold.

REQ-WATCH-3: When the broker appends a `bypass` entry, the broker MUST notify the session agent, and the session agent MUST show a notification.

The bypass watcher detects a bypass. The bypass watcher does not prevent a bypass.

## 11. Requirements: timeout and failure

**Presence decision (2026-08-15):** OpWarden v1 does not query presence. The 30-second timeout covers absence, and REQ-CACHE-7 flushes the cache on lock.

**Prompt-flow decision (2026-10-03):** the timer starts when a prompt reaches the head of the queue, not when the session agent draws it. Without a connected session agent, nobody can answer, and the timeout turns that state into a `deny` instead of a shim that waits forever.

REQ-FAIL-1: When a prompt reaches the head of the queue, the broker MUST start a 30-second timer, whether or not a session agent is connected.

REQ-FAIL-2: When 30 seconds elapse before the user makes a decision, the broker MUST close the prompt, MUST return `deny`, and MUST record the reason as `timeout` in the audit log.

REQ-FAIL-3: A `timeout` verdict MUST NOT store a rule.

REQ-FAIL-4: The audit log entry for every invocation MUST record the request tuple, the resolved caller chain, the verdict, and the reason for the verdict. The reason is exactly one of `rule`, `user`, `timeout`, `abandoned`, `cache`, or `queue-full`.

REQ-FAIL-5: When a shim's pipe connection closes before the broker returns the verdict, the broker MUST cancel that invocation's prompt, MUST remove that invocation from the queue, and MUST record the reason `abandoned`. The reason for this requirement is that agent harnesses kill timed-out commands, and the broker otherwise prompts for dead callers.

REQ-FAIL-6: The broker MUST queue at most 10 prompts, and the prompt on screen counts as one of the 10. When the queue is full, the broker MUST return `deny` for each additional invocation that needs a prompt, and MUST record the reason `queue-full`.

REQ-FAIL-7: Before a queued prompt reaches the screen, the broker MUST evaluate the rules for its invocation again. When a rule now decides the invocation, the broker MUST return that rule's verdict without the prompt, and MUST record the reason `rule`. The reason is that a decision on an earlier prompt can store the rule that answers a later one.

## 12. Requirements: audit log

REQ-AUD-1: The broker MUST append one audit-log entry for every invocation, whether or not the invocation showed a prompt.

REQ-AUD-2: Each audit-log entry MUST be one JSON object on one line.

REQ-AUD-3: Each audit-log entry MUST record the timestamp in UTC in ISO 8601 format.

REQ-AUD-4: The broker MUST NOT record any secret value in the audit log. The broker records the key name, never the key's value.

REQ-AUD-5: Each entry for an invocation MUST record the invocation arguments. For a `write` or `manage` invocation, the broker MUST replace the value part of each `field=value` assignment argument with `<redacted>`. The reason is that assignment arguments carry secret values, and REQ-AUD-4 otherwise breaks.

REQ-AUD-6: For each invocation, the broker MUST replace the value of the `--session` flag with `<redacted>`. The reason is that a session token is a credential, whatever the action.

REQ-AUD-7: When the broker cannot append the audit-log entry for an invocation, the broker MUST return `deny`. The reason is that REQ-AUD-1 binds every invocation, and an unrecorded invocation would break it.

## 13. Procedure: a biometric prompt that OpWarden did not cause

After OpWarden is installed, every cooperative invocation reaches the desktop app through the shim. A biometric prompt that no OpWarden activity explains therefore indicates a bypass.

Preconditions: the install procedure in section 14 completed, and the shim is first on `PATH`.

1. When the desktop app shows the biometric prompt, check the session agent for a matching prompt or a recent `allow` verdict.
2. If no matching OpWarden activity exists, select **Cancel** on the biometric prompt.
3. Read the newest `bypass` entries in the audit log to identify the caller.

Note: a caller that bypasses the shim while the op CLI session is warm triggers no biometric prompt. The bypass watcher (section 10) covers that case.

## 14. Install procedure

Preconditions: the op CLI is installed, the desktop-app integration works, and the interactive user has confirmed the design in this document.

1. Build the shim, the broker, and the session agent as NativeAOT executables.
2. Install all three executables to the install directory.
3. Register the broker as a Windows service under `NT SERVICE\OpWarden`, with automatic start.
4. Set the file permissions from REQ-TRUST-2 on the rule store and the audit log.
5. Record the op CLI's directory in the broker configuration as the real op CLI path.
6. Place the shim directory on `PATH` ahead of the op CLI directory.
7. Sign out, then sign in. The session agent starts (REQ-TRUST-3).
8. Open a new terminal. Run `op --version`. The prompt appears, classified as a `meta` action from the interactive user.
9. Decide `allow-once`. The op CLI version prints. This result confirms transparent passthrough.

Rollback:

1. Remove the shim directory from `PATH`.
2. Stop and unregister the broker service. The session agent exits with it.
3. The op CLI then runs directly, unchanged.

## 15. Non-goals

- OpWarden does not replace, resign, or modify the op CLI binary.
- OpWarden does not connect to, proxy, or inspect the desktop app's named pipe.
- OpWarden does not weaken, bypass, or replace the desktop app's biometric prompt. When the op CLI's session is cold, the op CLI still shows its own biometric prompt after OpWarden returns `allow`, except when the broker serves cached output and the op CLI does not run.
- OpWarden does not defend against a caller that holds an elevated token. Section 16 records this limit.

## 16. Known limitations

- PATH bypass: a caller that runs the op CLI by its full path bypasses the shim. The bypass watcher records the start and notifies the session agent; nothing blocks the invocation. The procedure in section 13 closes the cold-session case at the biometric prompt.
- Elevated attacker: a process with an elevated Administrators token can stop the broker, edit the rule store, and read broker memory. OpWarden's privilege separation targets non-elevated same-user processes, which is what agents are.
- Session-agent replacement: the pinning in REQ-TRUST-3 and REQ-TRUST-4 raises the bar against decision forgery. A same-user process that kills the session agent and races the broker's restart is detectable through the audit log, not preventable.
- Paging: REQ-CACHE-2 is a SHOULD. Without `VirtualLock`, the operating system can copy cached values to the page file, but REQ-CACHE-14 means only ciphertext reaches it.
- Integrity in the console broker: the console broker runs as the interactive user, so the integrity key of REQ-INT-2 and the in-memory key of REQ-INT-6 are within that user's reach. A process that decrypts the vault, or reads the in-memory key from broker memory, can forge a seal. Section 8.1 targets file edits and memory edits, and the service account is what puts the keys out of reach.
- Dropped process-creation events: a dropped event leaves one caller unresolvable for as long as that caller runs, and REQ-CALL-18 then classifies it as `unknown`. The failure is a prompt the interactive user cannot clear, and the failure is not a wrong verdict. The reliability spike measured no drop at 402 process starts per second, which is roughly two orders of magnitude above a normal machine. REQ-CALL-3 keeps the consumer cheap, because a slow consumer is the documented cause of drops.
- Ancestry that predates the broker: REQ-CALL-5 seeds the map from a snapshot, and a snapshot cannot recover a parent that exited before the snapshot. A process whose recorded parent already exited at broker start therefore resolves no further than itself. The gap closes as processes cycle, and the gap reopens at every broker restart.
- Built-in field list: REQ-RULE-29 exempts built-in fields from notices, and the implementation recognises `password` and `username` as built-in. A built-in field outside that list gets a notice that it does not need.
- Machine-wide process observation: the broker sees every process start on the machine for as long as the broker runs. REQ-CALL-4 keeps that record in memory and off both the disk and the audit log, so the exposure is bounded by broker memory, which section 16 already grants to an elevated attacker.

## 17. Open decisions

**Prompt input from scripts (opened 2026-10-03, deferred by Tamás).** A named agent runs as the interactive user, so it can drive the prompt window with injected input or posted window messages, and answer its own prompt. Windows Hello does not close the gap while the op CLI session is warm, and a scripted `always-allow` stores a permanent rule. Two candidate answers:

- The session agent accepts a decision only from hardware input. Open sub-question: remote-desktop tools such as Parsec can inject their input, which would make prompts unanswerable remotely.
- OpWarden requires that the op CLI session never stays warm, so each op CLI run passes Windows Hello, and the cache (section 9) absorbs repeated reads. A scripted decision then cannot complete an op CLI run without Hello; it can still approve cached output and store rules, so the cache grant and the `always-` decisions become the controls to guard.

The session agent routes every decision through one acceptance check, so either answer fits without rework.

Every other decision this document opened is resolved and recorded in the section it affects.

| Was open | Resolved | Landed in |
|---|---|---|
| Cacheable surface | 2026-08-17 | Section 9, REQ-CACHE-10 |
| Caller resolution under MSYS2 | 2026-08-18 | Section 5, rewritten |
| Process-map retention and depth | 2026-08-18 | Section 5, REQ-CALL-7, REQ-CALL-8, REQ-CALL-12 |
| Event delivery reliability | 2026-08-18 | Section 5, REQ-CALL-3; section 16 |

Two values are deliberately left to implementation rather than pinned here: the maximum entry count in REQ-CALL-8, and how often the broker runs the retention pass in REQ-CALL-7. Neither changes the design, and both want measurement on a real machine.
