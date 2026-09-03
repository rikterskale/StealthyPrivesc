# Contributing

Contributions are welcome for authorized assessment, red-team, and lab use
cases.

## Before opening a pull request

- Read the README and `SECURITY.md`.
- Keep the default behavior enumeration-only.
- High-impact techniques (kernel exploit, persistence, Potato, MSI, credential
  dump, service replace, host-crash, endpoint-bypass, amsi-bypass, etw-unhook,
  av-edr-service, and related families) must stay behind `--allow-techniques`
  and document ROE expectations. Evasion-family work belongs under the
  dedicated IDs and `--confirm-evasion`; see `docs/evasion.md` and
  `docs/techniques.md`.
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
