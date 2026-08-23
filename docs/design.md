# StealthyPrivesc Design

## Overview

StealthyPrivesc is a cross-platform, authorized-assessment enumerator. The
current product is a Rust command-line tool with independently selectable Linux
and Windows plugins, script fallbacks, and an explicit authorization boundary.
The design favors useful read-only evidence, operator-controlled scope, and
reversible behavior over autonomous exploitation or covert collection.

The implementation source of truth is the Rust workspace under
`crates/stealthy/`. The capability matrix, [architecture overview](architecture.md),
[CLI reference](cli-reference.md), and [operator runbook](operator-runbook.md)
describe the behavior users can rely on today.

## Goals & Non-Goals

### Goals

- Provide consistent Linux and Windows enumeration from one CLI.
- Make the first run safe, visible, and useful without requiring an output file.
- Require explicit authorization acknowledgment before host-enumerating actions.
- Keep plugin selection, pacing, output, and evidence handling operator-controlled.
- Produce human, JSON, Markdown, and SARIF results with provenance and coverage.
- Offer script fallbacks when binary execution is unavailable or restricted.
- Keep the core small enough to review, test, and build reproducibly.

### Non-Goals

- Fully automated exploitation or an auto-pwn workflow without operator opt-in.
- Silent C2, autonomous multi-host operation, or background network collection.
- Obfuscation that makes behavior difficult to inspect or maintain.
- Enabling high-impact techniques (kernel exploit, persistence, Potato, MSI,
  credential dump, service replace, host-crash, endpoint bypass) without an
  explicit `--allow-techniques` choice.

## Key Decisions

1. **Rust core** — provides a compact, typed implementation with a practical
   cross-compilation path and no required runtime service.
2. **Enumerate first** — the default command collects observations and
   recommendations; it does not attempt a privilege escalation.
3. **Explicit authorization** — host-enumerating commands require
   `--authorized` or `STEALTHY_AUTHORIZED=1`. Local commands such as `doctor`,
   `guide`, `report`, `diff`, `ingest`, and delivery helpers remain available
   without that gate. Staged dispatchers still require a fresh acknowledgment;
   a manifest is not authorization evidence.
4. **Opt-in probes and high-impact families** — `--auto-exploit` enables
   supported reversible, low-noise checks. High-impact families require a
   separate `--allow-techniques` opt-in when ROE permits (scaffolded in the
   current revision).
5. **Plugin isolation** — each plugin reports `Finding` values through a common
   contract, allowing platform-specific selection and targeted reruns.
6. **Memory-first output** — findings stay in the encrypted in-memory store by
   default. File and remote modes require an explicit operator choice.
7. **Script fallbacks** — approved Bash, Python, PowerShell, JScript, and
   MSBuild-hosted fallbacks cover restricted binary environments with reduced
   coverage and a separate evidence contract.

## Current architecture

The runtime flow is:

1. Parse global options and the selected subcommand.
2. Apply the authorization gate only when the command needs host access.
3. Detect the OS and execution identity.
4. Validate requested plugin IDs and filter the registry by platform, include,
   and skip selections.
5. Run selected plugins with the configured delay budget and collect findings,
   assessments, notes, and coverage status.
6. Seal the run in memory and render it as human, JSON, Markdown, or SARIF
   output, or persist it through the explicitly selected file/remote mode.

| Module | Responsibility |
| --- | --- |
| `core::os` | OS family, architecture, and version hints |
| `core::identity` | Host, user, groups, and elevation context |
| `core::plugin` | Plugin trait, registry filtering, and execution context |
| `core::engine` | Authorization-aware orchestration, timing, coverage, and report assembly |
| `core::types` | Findings, assessments, reports, severities, and provenance fields |
| `core::store` | ChaCha20-Poly1305 sealed export and zeroizing report key |
| `core::output` | Human, JSON, Markdown, SARIF, memory, file, and remote rendering |
| `core::diff` | Offline comparison of plaintext JSON reports |
| `core::evasion` | Low-and-slow pacing and operator-facing notes |
| `exploit` | Reversible probes plus `--allow-techniques` scaffolding |
| `plugins::linux/windows` | Platform-specific enumeration checks, including endpoint-control inventory |

The command surface is deliberately small:

| Command | Authorization | Purpose |
| --- | --- | --- |
| `guide`, `doctor`, `disclaimer` | Not required | Local readiness, first-run, and legal guidance |
| `list-plugins` / `plugins` | Required | Show plugins compiled into the current build |
| `enum` / `scan` | Required | Run the selected enumeration checks |
| `controls` / `validate-controls` | Required | Run disposable control-validation cases |
| `live-controls` / `collect-controls` | Required | Collect live read-only control state |
| `report` | Not required | Decode a sealed report with an operator-held key |
| `diff` | Not required | Compare two plaintext JSON reports offline |
| `ingest` | Not required | Normalize script JSON to schema v2 |
| `artifacts` / `cleanup` | Not required | Inspect or remove tracked artifacts |
| `stage` / `verify` / `one-liners` | Not required | Prepare and verify delivery workflows |

## Security & Privacy Considerations

- The authorization flag is a guardrail and audit signal, not a substitute for
  written Rules of Engagement.
- Default execution is enumerate-only, memory-only, and does not silently send
  results over the network.
- Sealed file output uses an ephemeral ChaCha20-Poly1305 key that must be
  handled separately from the report. Plaintext JSON and Markdown remain
  sensitive evidence.
- Findings avoid dumping raw credential material by default, but operators
  still control the target context, output path, and evidence custody.
- Plugins label noisy checks and possible artifacts so operators can account
  for telemetry and cleanup.
- Script fallbacks are intentionally documented as lower-coverage alternatives.
  Endpoint alternate-path / approved-fixture validation stays behind
  `--allow-techniques endpoint-bypass` (never control disable/evasion; see
  `docs/techniques.md`).

## Risks

- Read-only checks such as `sudo -l`, registry access, or credential-path
  inspection can still generate telemetry or expose sensitive metadata.
- Heuristic findings and kernel-version hints are not proof of exploitability.
- A successful process can still contain plugin coverage errors; conclusions
  must account for `coverage`, selected plugins, identity, and filtering.
- Running as root or SYSTEM changes visibility and is not equivalent to a
  standard-user assessment.
- Cross-compiled artifacts can be valid files for the wrong target; release
  packaging must record the target triple and verify hashes on both sides.
- Operators can misuse transport, remote output, or reversible probes outside
  the intended scope; the ROE and runbook remain the controlling policy.

## Maintenance and delivery plan

The project is maintained as an implemented product, not a scaffold. Changes
that affect behavior should update the code, tests, CLI contract, capability
matrix, and operator documentation together.

Every behavior change should preserve or update these checks:

- `cargo fmt --all -- --check`
- `cargo clippy --locked -p stealthy --all-targets -- -D warnings`
- `cargo test --locked --workspace`
- Locked release builds on Linux and Windows
- Release CLI UX smoke tests, including authorization, JSON, SARIF, sealed
  output, diff, and failure semantics
- Markdown structure, local links, required headings, and pinned workflow
  actions
- Linux/Python and Windows PowerShell fallback syntax checks
- Security/supply-chain checks and the final CI readiness gate

When a design decision changes, update this document and the linked
[capability status](capabilities.md), [phase coverage](phases.md), and
[architecture diagram](architecture-diagram.md) in the same change. Keep
historical rationale in the commit or issue record rather than leaving stale
“proposed” command lists in the current design document.
