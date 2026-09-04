# Phase Coverage

This document records the implemented Phase 1 and Phase 2 scope for the
enumeration engine. Both phases remain read-only by default; reversible probes
are available through `--auto-exploit`, and high-impact families through
`--allow-techniques`.

## Phase 1

- Effective Linux owner, group, supplementary-group, and POSIX ACL evaluation.
- Sudoers applicability checks for the current user and groups.
- User systemd units and current-user crontab coverage.
- Windows token elevation context in the identity report.
- Windows token-aware file write checks using `AccessCheck`, with `icacls`
  fallback when native evaluation is unavailable.
- Windows service account context and Winlogon persistence coverage.
- Machine-readable confidence, applicability, and evidence-quality assessments.

## Phase 2

- Machine-level Windows PATH inspection in addition to process and HKCU PATHs.
- ACL-aware service, scheduled-task, autorun, and PATH target evaluation.
- Structured assessment metadata aligned with each finding in JSON/sealed reports.
- Fixture-style parser tests for Linux ACL and sudo applicability behavior.
- Integration coverage for identity metadata and assessment alignment.
- Documentation and CI contract updates for the expanded coverage.

## Phase 3

- Stable run identifiers and Unix start timestamps for report provenance.
- Per-plugin execution duration and status telemetry in coverage records.
- Offline JSON baseline comparison with `stealthy diff BASELINE CURRENT`.
- Added, removed, and materially changed finding classification.
- Provenance in Markdown and SARIF output for downstream evidence handling.
- Backward-compatible deserialization for reports created before Phase 3.
- CI-published Rust LCOV coverage for regression tracking.

## Phase 4 (operator productization)

- Schema v2 findings with stable `finding_id`, MITRE techniques, exploitability,
  and ranked `attack_paths`.
- Named OPSEC profiles (`--profile quiet|balanced|thorough|ci`).
- Per-plugin timeouts, SIGINT-aware cancellation, and checkpoint/resume.
- Artifact ledger with `artifacts` / `cleanup` commands.
- Triage flow (`--triage`, `--triage-out`, `--approve-file`) for stepwise probes.
- Script JSON parity (`enum.py --json`) and `stealthy ingest`.
- Delivery kit: `stage`, `verify`, `one-liners`.

## Roadmap hardening (implemented)

- Stable semantic finding identities from `plugin` + `object` + `condition`
  and a distinct `scaffold` finding kind.
- Finding-scoped approve-file probes and preserved isolated-worker notes.
- Quiet and balanced profiles run plugins in-process by default; isolated
  workers remain opt-in via `--plugin-timeout-ms` and the thorough/ci profiles.
- Profile noise budgets and bounded/cancellable Linux SUID/SGID/capability
  traversal, with structured recommend-only GTFOBins annotations.
- Distro/package-aware kernel CVE hints with backport uncertainty.
- Native Windows service/task object-security evaluation, read-only DLL
  candidate ACL enumeration, and explicit per-script coverage deltas.
- Protected sealed-report key output on Unix and Windows.
- Full release kits, SPDX SBOMs, GitHub attestations, Linux aarch64 GNU,
  full tag gates, cargo-deny/Gitleaks, an 80% coverage floor, constrained build
  flavors, and a nightly safe fixture matrix.

## Phase 5 (planned operator GUI)

Phase 5 adds an optional operator-workstation GUI while preserving the CLI and
script kits as the complete, minimal target-side interface. It is divided into
implementation slices so shared safety and diagnostic contracts land before
host-enumerating UI:

- GUI-0: product contract, threat model, and packaging spike.
- GUI-1: shared library and centralized authorization/safety boundary.
- GUI-2: typed diagnostics, progress events, cancellation, errors, and paths.
- GUI-3: read-only desktop MVP for readiness, demo, and report workflows.
- GUI-4: preset-led authorized scan workflow with advanced options separated.
- GUI-5: coverage-first findings, evidence export, dispositions, and cleanup.
- GUI-6: operator-side native/script-only target-kit staging and verification.
- GUI-7: signed one-package install, upgrade, repair, rollback, and uninstall.
- GUI-8: troubleshooting center and redacted support bundles.
- GUI-9: cross-platform parity, accessibility, packaging, and release gates.

The detailed scope, dependencies, and acceptance gates are in the
[GUI Frontend Roadmap](gui-roadmap.md). None of Phase 5 is implemented merely
by appearing in this roadmap.
