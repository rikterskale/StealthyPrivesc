# Contributing

Contributions are welcome for authorized, defensive, and lab-safe use cases.

## Before opening a pull request

- Read the README and `SECURITY.md`.
- Keep the default behavior enumeration-only.
- Do not add kernel exploits, credential exfiltration, persistence, or covert
  execution.
- Add or update tests for behavior changes.
- Run `cargo fmt --all`, `cargo test --workspace`, and
  `cargo clippy --workspace --all-targets -- -D warnings`.
- Update the relevant documentation and risk notes.

## Pull requests

Describe the problem, the design, the security implications, and how you
validated the change. Keep commits focused and do not include assessment data,
secrets, generated binaries, or ignored operator notes.
