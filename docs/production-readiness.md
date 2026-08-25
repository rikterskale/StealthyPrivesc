# Production-readiness acceptance criteria

This checklist is the release gate for a tagged StealthyPrivesc artifact. A
release is not ready for an engagement until every required item is evidenced
in CI or in the release record.

## Build and platform acceptance

- [ ] `doctor --json` reports a stable readiness state, blocking flag, detailed checks, fallback tool inventory, and remediation recommendations.
- [ ] Human `doctor` output clearly distinguishes READY, READY WITH WARNINGS, and BLOCKED states.
- [ ] `cargo fmt --all -- --check` passes.
- [ ] Locked workspace tests and clippy pass with `-D warnings`.
- [ ] Linux x86_64 and aarch64 artifacts build and receive native smoke tests.
- [ ] Linux runtime smoke tests pass in Ubuntu 22.04, Ubuntu 24.04, and Debian 12.
- [ ] Windows x86_64 MSVC builds and receives native smoke tests.
- [ ] Windows PowerShell fallback syntax and JSON contract checks pass.
- [ ] Disposable Linux and Windows release-package contract tests pass.
- [ ] Every shipped fallback reports `coverage_mode`, `capability_delta`, and
      reduced-coverage notes accurately.

## Safety and authorization acceptance

- [ ] Host enumeration without authorization exits `2`.
- [ ] Direct Linux and Windows fallback entry points enforce authorization.
- [ ] Staged dispatchers enforce fresh authorization and target binding.
- [ ] Default execution remains enumerate-only.
- [ ] `--fail-on` exits `4` and does not get confused with launch/block status.
- [ ] Explicit local mutations, cleanup, and probe paths have negative tests.

## Evidence and artifact acceptance

- [ ] Memory-only runs leave no artifact ledger.
- [ ] Explicit output and staged artifacts are private, integrity-checked, and
      represented in the ledger.
- [ ] Corrupt ledgers, missing keys, permission failures, interrupted cleanup,
      and symlink paths produce safe errors without deleting unrelated data.
- [ ] Corrupt checkpoints are rejected before plugin execution.
- [ ] Legacy script fixtures normalize to schema 2 without losing coverage
      metadata.
- [ ] Release archives contain no reports, keys, local caches, or target data.
- [ ] Release manifests, checksums, SBOMs, and attestations agree.

## Release and operational acceptance

- [ ] Readiness failures preserve exit code `3`; authorization failures preserve exit code `2`.
- [ ] The release is built from a clean checkout with no tracked local state,
      nested repositories, or generated artifacts.
- [ ] Dependency advisories, licenses, bans, and source policies pass.
- [ ] Secret scanning passes for the complete commit history.
- [ ] The release record includes source commit, toolchain, target triples,
      artifact hashes, test results, and rollback instructions.
- [ ] `RELEASE-EVIDENCE.json` is generated from the final release artifacts.
- [ ] The support window and report-schema compatibility policy are recorded.

## Required release evidence

Attach the CI run URL, artifact manifest, checksum manifest, SBOMs, attestations,
platform smoke-test results, and the operator recovery checklist to the release
record. Any skipped check must include the reason, affected scope, and owner
for follow-up.
