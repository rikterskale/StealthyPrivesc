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
