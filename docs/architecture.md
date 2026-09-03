# Architecture

## Overview

StealthyPrivesc is a small Rust core plus independently selectable plugins, with pure-script fallbacks when a custom binary cannot execute under application control.

For the end-to-end visual flow, see the [Architecture Diagram](architecture-diagram.md).

## Data flow

1. CLI parses flags and applies the authorization boundary
2. Safe local commands (`guide`, `doctor`, `disclaimer`, `report`, `diff`) run without host enumeration
3. Core detects OS and enumerates identity with minimal process spawning
4. Plugin IDs are validated, then the registry is filtered by OS, `--plugins`, and `--skip`
5. If `linux.app_control` / `windows.app_control` is selected, run live control collection (slim under `--profile quiet`); otherwise skip it
6. Each isolated worker returns findings, notes, and any error; worker notes are
   merged into the main encrypted store with the plugin ID preserved
7. Findings are sealed at rest in an encrypted in-memory store
8. Output mode emits a human report and optionally JSON, Markdown, SARIF, a sealed blob, or remote instructions
9. Plugin timeouts set a cooperative cancel flag so walks stop (in-flight helper processes may still finish)

## Core modules

| Module | Responsibility |
| --- | --- |
| `core::os` | OS family / version hints via files and constants |
| `core::identity` | UID/user/groups without `id` where possible |
| `core::plugin` | Plugin trait, selection, cancellation, noise budgets, and finding-scoped probe checks |
| `core::store` | ChaCha20-Poly1305 sealed findings at rest + sealed export + zeroizing key |
| `core::evasion` | Low-and-slow delays and OPSEC operator notes |
| `core::controls` | Live policy/EDR inventory; gated during enum to `*.app_control` |
| `core::output` | memory / file / remote emission and protected report-key files |
| `core::engine` | Authorization-aware orchestration, selection, checkpoints, and triage |
| `core::plugin_worker` | Isolated plugin execution, timeout termination, and finding/note/error transport |
| `core::reporting` | Report assembly, finding assessments, attack paths, and operator next-step defaults |
| `exploit` | Reversible probes plus `--allow-techniques` scaffolding |

## Plugin contract

Each plugin implements:

- `id`, `name`, `description`, `platforms`
- `run(ctx) -> Vec<Finding>`

Plugins should prefer direct filesystem/registry reads. When a noisy helper is required, findings must set `noisy: true`.

Every finding has a stable semantic identity: `plugin` identifies the producer,
`object` identifies the observed target, and `condition` identifies the tested
state. Finalization derives `finding_id` from that tuple rather than from the
operator-facing title. Scaffold-only capabilities use `FindingKind::Scaffold`,
which is assessed as low-confidence scaffold evidence and is not ranked as a
direct probe.

An approval file is bound to the checkpoint `run_id`. Its probe actions are
validated against prior findings and only the exact approved `finding_id` can
enable its reversible probe. Explicit standalone `--auto-exploit` remains the
separate blanket opt-in for supported reversible probes.

Endpoint-control plugins (`linux.endpoint_controls`, `windows.endpoint_controls`)
enumerate host policy that can block custom binaries. They recommend approved
script fallbacks and, when `--allow-techniques endpoint-bypass` is opted in,
record alternate-path intent and wire What's next / `next_command` to
`--artifact` trust prediction (`live-controls`) and benign fixture validation
(`controls --execute`). Under today's `endpoint-bypass` contract they do not
disable, unhook, or kill AppLocker, WDAC, SmartScreen, AMSI, ETW providers,
AppArmor, antivirus, or EDR — that interference belongs under the gated
evasion IDs `amsi-bypass`, `etw-unhook`, and `av-edr-service` (plus
`--confirm-evasion`), not under `endpoint-bypass`. Windows kits ship the
`windows-evasion` PowerShell module (`status=ready`); it is not imported by the
dispatcher unless an operator opts in. After the three gates pass, Rust emits
`FindingKind::ExploitAttempt` with `condition=technique-opted-in` (plugin
`windows.evasion`). See `docs/techniques.md` and `docs/evasion.md`.

## Script fallbacks

Under AppLocker/WDAC/SmartScreen/AV/`noexec`/AppArmor or missing binary execution,
the staged dispatcher walks an ordered, manifest-approved host list:

- Linux (`run.sh`): `python,bash,sh,perl` → `enum.py` / `enum.sh` / `enum-posix.sh` / `enum.pl`
- Windows (`run.ps1`): `powershell,jscript,msbuild` → `enum.ps1` / `enum.js` / `EnumTasks.csproj`

When the primary is blocked (missing, not executable, exit 126/127, signal
death, or vanished after launch), the dispatcher walks the list and continues
to the next host if a tier is itself blocked. Script tiers are fixed
enumerate-only reduced coverage: only authorization and `--json` / `-Json` are
forwarded from the binary CLI (`--profile`, `--plugins`, and similar flags are
not applied). Weaker tiers declare honest reduced `capability_delta`. Stronger
AV interference is Planned under separate gated technique families (see
`docs/techniques.md`).
