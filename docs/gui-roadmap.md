# GUI Frontend Roadmap

This roadmap breaks the optional GUI frontend into independently testable
implementation slices. Every item is **planned** until its acceptance gate has
passed in CI and on the supported desktop platforms. A roadmap entry is not a
claim that the capability exists in a tagged release.

The GUI is an operator-workstation console. It does not replace the CLI,
dispatchers, or script fallbacks on assessment targets. Target kits remain
minimal, headless, and usable without a graphical session.

## Product constraints

- Preserve the two-machine model: the GUI runs on the operator workstation;
  staged CLI and script kits run on authorized targets.
- Keep the CLI a complete, supported interface and recovery path.
- Put authorization, technique gates, evidence handling, and output validation
  in shared core code rather than duplicating policy in the GUI.
- Default to enumeration-only, memory-only operation. Do not silently enable
  probes, remote output, persistence, or plaintext evidence.
- Do not require the GUI to run elevated. Explain reduced visibility instead
  of prompting for elevation automatically.
- Keep findings, keys, host identity, URLs, and sensitive paths out of GUI
  settings, logs, crash reports, and support bundles by default.
- Use a predictable per-user application-data directory for GUI state. Require
  an explicit engagement workspace for reports, checkpoints, staged kits, and
  other operator artifacts; do not inherit `.cache-run` from an arbitrary
  launch directory.
- Maintain report-schema, authorization, exit-code, and CLI behavior
  compatibility throughout the work.

## Recommended frontend and package shape

The initial implementation should use a separate native Rust
`stealthy-gui` binary built with `egui`/`eframe`. It should consume a shared
Rust library rather than reproduce business logic or permanently shell out to
the CLI. A short-lived subprocess adapter is acceptable only as a prototype
and must pin and verify the bundled CLI version and report schemas.

The target-side `stealthy` artifact must not acquire GUI, renderer, webview, or
desktop-session dependencies. Tauri or another webview frontend should be
reconsidered only if a packaging spike proves that it reduces support burden
on every supported desktop platform.

## Slice summary

| Slice | Outcome | Depends on | Status |
| --- | --- | --- | --- |
| GUI-0 | Product contract, threat model, and packaging spike | None | Planned |
| GUI-1 | Shared library and centralized safety boundary | GUI-0 | Planned |
| GUI-2 | Typed diagnostics, events, cancellation, and paths | GUI-1 | Planned |
| GUI-3 | Read-only desktop MVP | GUI-2 | Planned |
| GUI-4 | Guided scan workflow | GUI-3 | Planned |
| GUI-5 | Coverage-first results and evidence workflow | GUI-4 | Planned |
| GUI-6 | Operator-side staging and target-kit workflow | GUI-3 | Planned |
| GUI-7 | One-package install, upgrade, repair, and uninstall | GUI-3, GUI-6 | Planned |
| GUI-8 | Troubleshooting center and redacted support bundle | GUI-2, GUI-7 | Planned |
| GUI-9 | Cross-platform hardening and release gate | GUI-4 through GUI-8 | Planned |

## GUI-0 — Product contract and technical spike

**Outcome:** Freeze the GUI boundary before adding a second execution path.

Roadmap items:

- Record the operator-workstation-only deployment decision and confirm that
  the GUI will never be included in a staged target kit.
- Define supported desktop platforms for the first release. Start with Windows
  x86-64 and Linux x86-64; retain the existing target-kit architecture matrix
  independently.
- Prototype `egui`/`eframe` startup, renderer selection, accessibility, file
  dialogs, clipboard behavior, and release packaging on both platforms.
- Measure packaged size, cold start, idle memory, renderer failures, and the
  additional dependency/SBOM surface.
- Add a GUI threat model covering local privilege boundaries, untrusted report
  files, loopback/network prohibition, clipboard leakage, secrets, update
  provenance, staged artifacts, and crash diagnostics.
- Define the GUI-to-core API and a compatibility policy for GUI, core, CLI,
  doctor schema, progress events, and report schema versions.
- Produce wireframes for System Check, New Scan, Running, Results, Staging,
  Artifacts, and Troubleshooting. Avoid a one-control-per-CLI-flag design.

Acceptance gate:

- A reviewed design decision records the product boundary, supported desktop
  matrix, toolkit choice, package contents, measured prototype results, threat
  model, and rollback criteria. The prototype performs no host enumeration.

## GUI-1 — Shared library and centralized safety boundary

**Outcome:** The CLI and GUI consume one policy-enforcing application core.

Roadmap items:

- Add a library target or workspace crate exposing typed requests and results
  for doctor, scan, stage, verify, report, diff, disposition, artifacts, and
  cleanup workflows.
- Replace `Engine::from_cli` as the application boundary with a typed
  `ScanRequest`; keep Clap conversion in the CLI binary.
- Move authorization enforcement into the shared application service. Require
  a validated authorization context for every host-enumerating API call.
- Enforce `--auto-exploit`, technique allowlists, evasion confirmation, output
  validation, report/key separation, and artifact policy in the shared core.
- Convert safe local command implementations currently owned by `main.rs` into
  typed library functions. Keep presentation in the CLI and GUI adapters.
- Keep the plugin registry and platform filtering in shared code so the two
  frontends cannot disagree about available coverage.

Acceptance gate:

- Existing CLI snapshots, schemas, aliases, exit codes, safety failures, and
  integration tests remain unchanged. New direct-library tests prove that host
  enumeration cannot bypass authorization and that advanced technique gates
  behave identically through CLI and library calls.

## GUI-2 — Typed diagnostics, progress, cancellation, and paths

**Outcome:** Frontends receive structured state without scraping terminal text.

Roadmap items:

- Return a typed `DoctorReport` from the core; render human and JSON doctor
  output in the CLI adapter.
- Replace direct progress printing with a typed event sink. Preserve the
  existing JSON-lines stderr contract as a CLI event adapter.
- Cover scan start, plugin start/finish/error/timeout, checkpoint, cancel,
  output completion, and cleanup events with versioned event types.
- Replace the process-global Ctrl-C assumption with a caller-provided
  cancellation token while retaining Ctrl-C behavior in the CLI.
- Provide stable error codes, operator-facing summaries, remediation text, and
  source chains suitable for both frontends.
- Define per-user config/cache/log directories and explicit engagement
  workspace paths. Prevent the GUI from depending on its current directory.
- Add bounded in-memory diagnostic logging with deterministic secret and path
  redaction.

Acceptance gate:

- CLI output compatibility tests pass; library tests cover event order,
  cancellation, timeouts, bounded queues, redaction, and unwritable-path
  failures. No GUI-facing code parses ordinary stdout or human error strings.

## GUI-3 — Read-only desktop MVP

**Outcome:** Users can launch the application and obtain useful local value
without authorization or host enumeration.

Roadmap items:

- Implement the application shell, navigation, keyboard operation, scalable
  text, light/dark themes, and accessible status labels.
- Make System Check the first-run screen and automatically render Ready, Ready
  with Warnings, or Blocked plus a repair action for each failed check.
- Add safe views for the bundled demo, opening JSON/sealed reports, HTML-style
  finding search and severity filters, diff, coverage comparison, explanations,
  playbooks, presets, and artifact inventory.
- Detect unsupported or malformed report schemas before rendering any content.
- Treat report text and paths as untrusted data; escape presentation content,
  bound file sizes, and never execute links or finding commands automatically.
- Store only non-sensitive UI preferences. Provide a visible Reset Settings
  action.

Acceptance gate:

- A fresh supported desktop can launch the GUI, complete System Check, open the
  inert demo and supported report fixtures, and reset state without an
  authorization acknowledgment, network access, or writes outside the
  documented application-data directory.

## GUI-4 — Guided scan workflow

**Outcome:** An authorized operator can run a safe local scan without learning
the CLI grammar.

Roadmap items:

- Build New Scan around Quick, Standard, and Deep presets. Show estimated
  runtime/noise, selected coverage, and memory-only output before launch.
- Require an explicit authorized-use acknowledgment and offer an optional ROE
  reference before enabling the scan action. Never persist the acknowledgment
  as blanket authorization for later sessions or hosts.
- Put plugin include/skip, delay, timeout, severity, checkpoint, and output
  controls in an Advanced section with validated defaults.
- Put reversible probes, technique allowlists, evasion confirmation, remote
  output, and plaintext evidence in a separately gated expert workflow with
  risk text and explicit confirmation.
- Show a preflight summary of identity, OS, plugin count, output destination,
  expected artifacts, and safety mode.
- Implement Running with current plugin, total progress, elapsed time,
  structured warnings, cancellation, and checkpoint/resume status.
- Do not request elevation automatically. Explain which coverage is unavailable
  under the current identity.

Acceptance gate:

- End-to-end fixture tests prove preset-to-request mappings, authorization and
  advanced-option gates, progress, cancel, checkpoint/resume, memory-only
  defaults, and parity with equivalent CLI runs. Closing the window during a
  run produces a deterministic cancel/recovery outcome.

## GUI-5 — Coverage-first results and evidence workflow

**Outcome:** Results are understandable without hiding incomplete coverage or
weak evidence.

Roadmap items:

- Lead with target identity, execution mode, plugin coverage, errors, skipped
  checks, and capability delta before the finding count.
- Add severity/search filters, attack-path views, finding details, assessment
  confidence, "What's next," and safe copy actions.
- Add baseline comparison and disposition workflows without modifying original
  evidence.
- Support deliberate export to sealed report, protected key file, JSON,
  Markdown, SARIF, and self-contained HTML where the existing core permits it.
- Require separate report and key destinations, clearly mark plaintext outputs,
  and never place keys in command lines, logs, recent-file history, or the
  clipboard automatically.
- Present ledger entries and cleanup eligibility; require confirmation before
  cleanup and identify non-removable evidence.

Acceptance gate:

- Golden fixtures cover empty findings, partial coverage, plugin errors,
  malformed input, schema compatibility, baseline mismatch warnings, sealed
  report round trips, file permissions/ACLs, dispositions, and cleanup. GUI and
  CLI exports are semantically equivalent.

## GUI-6 — Operator staging and target-kit workflow

**Outcome:** The GUI simplifies delivery without becoming a remote execution
or autonomous multi-host tool.

Roadmap items:

- Provide a staging wizard for target OS, architecture, hostname, optional
  username, approved output directory, bundle name, and native versus
  script-only mode.
- Show the exact target-kit contents, execution-path policy, capability delta,
  and expected artifacts before writing.
- Verify the selected binary, release manifest, target triple, and hashes before
  staging. Preserve existing host binding and authorization requirements.
- Display generated checksums and approved copy/run instructions. Do not add
  unattended transfer, credential storage, remote execution, or C2 behavior.
- Verify staged bundles after creation and offer an explicit Open Folder action.
- Ensure the GUI binary, settings, logs, and desktop dependencies can never be
  copied into a target kit.

Acceptance gate:

- GUI-created native and script-only kits are byte/contract compatible with
  equivalent CLI staging across the existing target matrix. Negative tests
  cover wrong architecture, unverified binaries, unsafe paths, invalid host
  binding, partial writes, and GUI-file leakage.

## GUI-7 — One-package installation and lifecycle

**Outcome:** A first-time operator installs, launches, repairs, updates, and
uninstalls the product through supported paths.

Roadmap items:

- Publish one signed operator package per supported desktop containing the GUI,
  matching CLI, approved fallbacks, manifest, checksums, selected docs, licenses,
  and SBOM. Continue publishing portable archives and minimal target kits.
- Create a Start Menu shortcut on Windows and an application-menu entry on
  Linux; keep command-line access available.
- Remove the mandatory preinstalled GitHub CLI from the normal installation
  path without weakening provenance. Implement or bundle a narrowly scoped
  verifier, or use a platform package-signing chain, and retain a documented
  advanced `gh attestation verify` workflow.
- Verify package signature, checksums, manifest identity, GUI/CLI version match,
  and schema compatibility before first launch and update activation.
- Provide repair, side-by-side-safe update, rollback, and uninstall workflows.
  Preserve operator evidence unless the user explicitly selects identified
  application data for removal.
- Make interrupted installation/update recovery deterministic and test stale
  binaries, quarantined files, read-only locations, PATH refresh, and duplicate
  installations.

Acceptance gate:

- On clean Windows x86-64 and Linux x86-64 desktop fixtures, one downloaded
  package installs and launches without Rust, Node.js, a webview development
  kit, or a preinstalled GitHub CLI. Upgrade, repair, rollback, and uninstall
  tests preserve evidence and verify provenance at every transition.

## GUI-8 — Troubleshooting center and support bundle

**Outcome:** Operators can diagnose most failures without collecting sensitive
assessment data or manually assembling logs.

Roadmap items:

- Add a Troubleshooting screen that checks GUI/core/CLI versions and hashes,
  report and progress schema compatibility, data/workspace permissions,
  renderer health, fallback availability, release-manifest identity, and the
  most recent operation state.
- Translate stable error codes into plain-language cause, repair, retry, and
  recovery actions.
- Add Copy Summary and Save Support Bundle actions with a preview of every
  included field.
- Include versions, executable hashes, OS/architecture, redacted doctor output,
  renderer information, exit/error codes, structured lifecycle events, selected
  preset/plugin IDs, and artifact/cleanup state.
- Exclude findings, report bodies, report keys, authorization values,
  usernames, hostnames, URLs, and sensitive paths by default. Require an
  explicit field-level opt-in to add potentially sensitive diagnostics.
- Bound bundle and log sizes, make redaction deterministic, and never upload a
  bundle automatically.

Acceptance gate:

- Automated redaction tests seed every prohibited data class and prove it is
  absent from default summaries, logs, crash output, and support bundles.
  Fixture failures for install, renderer, permissions, schema mismatch,
  quarantine, and interrupted runs produce an actionable recovery path.

## GUI-9 — Cross-platform hardening and release gate

**Outcome:** The GUI becomes a supported release surface rather than an
experimental convenience.

Roadmap items:

- Add unit tests for view models and request mappings, headless interaction
  tests where supported, package smoke tests, and native Windows/Linux UAT.
- Add CLI/GUI parity fixtures for doctor, presets, plugin selection, scan
  reports, cancellation, staging, exports, artifacts, cleanup, and errors.
- Verify keyboard-only use, focus order, contrast, scaling, screen-reader
  labels, long paths, long findings, localization-safe layout, and clipboard
  behavior.
- Exercise renderer fallback, no graphical session, remote-desktop sessions,
  restricted desktops, read-only profiles, corrupted settings, and low-resource
  conditions.
- Add GUI artifacts to SBOM, checksum, attestation, signing, reproducibility,
  malware-scanning, release-evidence, rollback, and support-policy workflows.
- Document compatibility windows and ensure an unsupported GUI never launches
  a mismatched CLI/core operation.
- Keep a documented CLI recovery path for every GUI workflow and include the
  equivalent command in diagnostic details where it can be shown without
  exposing secrets.

Acceptance gate:

- The production-readiness and tag gates fail closed on any unsupported
  platform, signature/provenance failure, GUI/CLI mismatch, schema regression,
  safety-gate discrepancy, accessibility blocker, package smoke failure, or
  redaction leak. The supported release and rollback paths pass on clean
  Windows and Linux fixtures.

## Completion definition

The GUI roadmap is complete only when all slices pass their acceptance gates,
the CLI remains fully functional, target kits contain no GUI dependencies, and
the support policy identifies the GUI as a supported surface. Partial delivery
must retain the **experimental** label and name exactly which slices are
implemented.
