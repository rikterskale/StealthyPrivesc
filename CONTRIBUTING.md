# Contributing

Contributions are welcome for authorized, defensive, and lab-safe use cases.

## Before opening a pull request

- Read the README and `SECURITY.md`.
- Keep the default behavior enumeration-only.
- High-impact techniques (kernel exploit, persistence, Potato, MSI, credential
  dump, service replace, host-crash, endpoint-bypass) must stay behind
  `--allow-techniques` and document ROE expectations. `endpoint-bypass` is
  alternate-path + approved-fixture validation only — never AMSI/ETW/EDR/
  AppLocker/WDAC disable, unhook, or kill payloads (see `docs/techniques.md`).
- `amsi-bypass`, `etw-unhook`, and `av-edr-service` are separately gated
  scaffold/planned IDs only. Do not add execution modules or script equivalents
  without a new safety review, tests, restoration contract, and documentation
  change.
- Add or update tests for behavior changes.
- Run `cargo fmt --all`, `cargo test --workspace`, and
  `cargo clippy --workspace --all-targets -- -D warnings`.
- Update the relevant documentation and risk notes.
- Follow the tagged-release and compatibility commitments in
  `docs/support-policy.md`; `main` is development-only.

## Pull requests

Describe the problem, the design, the security implications, and how you
validated the change. Keep commits focused and do not include assessment data,
secrets, generated binaries, or ignored operator notes.
