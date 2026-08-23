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
6. Each plugin returns `Finding` values; core adds provenance, assessments, and coverage timing
7. Findings are sealed at rest in an encrypted in-memory store
8. Output mode emits a human report and optionally JSON, Markdown, SARIF, a sealed blob, or remote instructions
9. Plugin timeouts set a cooperative cancel flag so walks stop (in-flight helper processes may still finish)

## Core modules

| Module | Responsibility |
| --- | --- |
| `core::os` | OS family / version hints via files and constants |
| `core::identity` | UID/user/groups without `id` where possible |
| `core::plugin` | Plugin trait and selection |
| `core::store` | ChaCha20-Poly1305 sealed findings at rest + sealed export + zeroizing key |
| `core::evasion` | Low-and-slow delays and OPSEC operator notes |
| `core::controls` | Live policy/EDR inventory; gated during enum to `*.app_control` |
| `core::output` | memory / file / remote emission |
| `core::engine` | Orchestration |
| `exploit` | Reversible probes plus `--allow-techniques` scaffolding |

## Plugin contract

Each plugin implements:

- `id`, `name`, `description`, `platforms`
- `run(ctx) -> Vec<Finding>`

Plugins should prefer direct filesystem/registry reads. When a noisy helper is required, findings must set `noisy: true`.

Endpoint-control plugins (`linux.endpoint_controls`, `windows.endpoint_controls`)
enumerate host policy that can block custom binaries. They recommend approved
script fallbacks and, when `--allow-techniques endpoint-bypass` is opted in,
record alternate-path intent and wire What's next / `next_command` to
`--artifact` trust prediction (`live-controls`) and benign fixture validation
(`controls --execute`). They do not disable, unhook, or kill AppLocker, WDAC,
SmartScreen, AMSI, ETW providers, AppArmor, antivirus, or EDR. See
`docs/techniques.md` for the authoritative contract.

## Script fallbacks

Under AppLocker/WDAC/SmartScreen/`noexec`/AppArmor or missing binary execution:

- Linux: `scripts/linux/enum.sh`, `scripts/linux/enum.py` (include endpoint-control checks)
- Windows: `scripts/windows/enum.ps1`, `enum.js`, MSBuild `EnumTasks.csproj` host stub

These mirror the highest-value checks — including endpoint-control inventory —
without shipping a custom `.exe` and without attempting to turn controls off.
