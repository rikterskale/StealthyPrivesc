# Workspace hygiene policy

The production repository inventory is the clean Git checkout represented by
`git ls-files`. Local build output, runtime ledgers, reports, keys, coverage
files, caches, and unrelated nested repositories are not project inputs.

## Release rule

Release jobs require a clean working tree and reject nested `.git` directories.
This prevents local tools or unrelated projects from entering manifests,
archives, scans, or release evidence. The release job must be run from a fresh
checkout; do not work around a failure by force-adding or deleting local data.

## Local nested repositories

`SecretAgent006/` is treated as unrelated local work when present in a
developer workspace. It is not part of StealthyPrivesc, is not reviewed as
source, and must not be included in a commit or release archive. The hygiene
validator reports it so the operator can move it outside the workspace or use a
separate clean checkout for release work. This policy does not delete or modify
that directory.

## Generated state

The following remain local-only and must stay ignored or outside the checkout:

- `target/`, `.cache-run/`, `.stealthy-artifacts/`, coverage output, and Python
  caches;
- report files, report keys, ledger keys, checkpoints, and target data; and
- release archives and SBOMs until they are intentionally attached to a release.

Run `python3 scripts/ci/validate_worktree_hygiene.py` before creating a release
record. A failure is a release blocker until the workspace is clean.
