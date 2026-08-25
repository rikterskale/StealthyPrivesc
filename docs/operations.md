# Operations and release runbook

This document defines the operational controls for distributing StealthyPrivesc
to authorized operators. A tagged release is the supported deployment unit;
the `main` branch is development-only.

## Release candidate gate

The release owner must attach the following to the candidate record:

- CI run URL and commit SHA.
- Target triples, toolchain versions, and platform smoke-test results.
- Artifact manifest, internal and top-level checksum manifests, SPDX SBOMs,
  and GitHub attestations.
- User-readiness, production-readiness, installer, fallback, and HTML-report
  validator results.
- Reproducible-build result and per-plugin coverage matrix.
- Completed [production-readiness criteria](production-readiness.md), with
  skipped checks naming an owner and follow-up date.

The candidate must be built from a clean checkout. Never package a local
`target/`, report, ledger, key, cache, or operator artifact.

The minimum local preflight is:

```text
cargo fmt --all -- --check
cargo test --locked --workspace
cargo clippy --locked -p stealthy --all-targets -- -D warnings
python3 scripts/ci/validate_production_readiness.py
python3 scripts/ci/validate_operations_contract.py
python3 scripts/ci/validate_plugin_matrix.py
```

## Rollout

1. Publish the tagged, attested release and its evidence record.
2. Install it in an isolated lab and run `doctor --json`.
3. Run one authorized, read-only scan against an approved fixture or lab
   host; inspect `coverage`, `coverage_mode`, and `capability_delta`.
4. Roll out to a small operator cohort before wider use.
5. Record the installed version, binary hash, target, operator, and ROE
   reference in the engagement record.

Do not treat a successful process exit as complete coverage. Partial plugin
coverage, fallback mode, permissions, and unsupported platform details must be
reviewed before conclusions are issued.

## Rollback and withdrawal

If a release is defective or its provenance is questioned:

- Stop new deployments and withdraw the release links/tag from operator use.
- Preserve the release evidence, checksums, SBOMs, attestations, and CI URL.
- Record affected versions, platforms, workflows, and engagement impact.
- Return operators to the last attested supported release after checking its
  report-schema compatibility and ROE.
- Remove the installed binary and delivery kit only after recording their
  hashes and installation locations.
- Publish a replacement patch or advisory through the security process.

For local artifacts, preserve the report required for investigation, then use
the recorded ledger workflow: `stealthy cleanup --latest --secure-delete`.
Cleanup is not a substitute for evidence preservation or incident response.

## Incident response

Treat the following as security incidents: an authorization-gate bypass,
unexpected mutation, incorrect target binding, leaked key/report, corrupted
release evidence, or a fallback that reports native coverage.

The incident owner must preserve a redacted reproduction, version and hash,
platform, command shape, relevant coverage, and timeline. Do not include
credentials, private keys, host data, or collected findings in public issues.
Report suspected vulnerabilities privately as described in `SECURITY.md`.

## Manual validation ownership

CI provides automated Linux and Windows build, smoke, fallback, fixture, and
packaging checks. The release owner still records these manual validations when
the target environment is materially different from CI:

- Native Windows behavior on the supported Windows image.
- PowerShell, JScript, and MSBuild fallback behavior under the organization's
  application-control policy.
- Linux distribution, kernel, locale, permissions, and systemd variants used
  by the engagement.
- Remote verification and staged delivery in an isolated mock or lab target.
- Upgrade, rollback, interrupted-install, and quarantined-binary recovery.

Each skipped validation must include the reason, affected scope, owner, and
planned completion date. No remote target or production endpoint is required
for this validation; fixtures and isolated lab systems are preferred.

## Evidence retention

Retain the release evidence record, checksums, SBOMs, attestations, CI results,
validator output, and operator recovery checklist for the support window. Keep
assessment reports and keys under the engagement's separate evidence policy;
they do not belong in the source repository or release archive.
