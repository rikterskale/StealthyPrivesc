# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project overview

StealthyPrivesc is a modular, cross-platform privilege-escalation **enumeration** framework (Rust) for authorized red team engagements. Default posture is enumerate + recommend; exploitation is opt-in and reversible.

**Authorized use only.** All changes must preserve the safety model:

- Refuses to run without `--authorized` / `STEALTHY_AUTHORIZED=1`
- Default = enumeration + recommendations only
- High-impact techniques require explicit `--allow-techniques` opt-in
- `endpoint-bypass` means alternate-path + approved-fixture validation only
  (see `docs/techniques.md`). AMSI/ETW/EDR/AppLocker/WDAC disable, quarantine
  tamper, and related interference are Planned under separate
  `--allow-techniques` families — do not silently fold them into
  `endpoint-bypass`
- Results stay in memory unless file/remote output is explicitly requested

## Layout

```text
crates/stealthy/          Rust core (single workspace member)
  src/core/               OS detect, identity, plugin runner, encrypted store, evasion helpers
  src/plugins/linux/      Linux plugins (16)
  src/plugins/windows/    Windows plugins (12)
  src/exploit/            Reversible probes + technique scaffolding
scripts/linux/            Bash + Python fallbacks
scripts/windows/          PowerShell + JScript + MSBuild host stubs
docs/                     Operator/architecture docs
tests/                    Test assets
.github/                  CI workflows
```

## Build & verify

```bash
cargo build -p stealthy --release        # release profile: lto, opt-level "z", strip, panic=abort
cargo test                               # run tests
./target/release/stealthy doctor         # readiness checks (no auth required)
```

Always run `cargo fmt --check` and `cargo clippy` after code changes when toolchain is available.

## Conventions

- Rust edition 2021; workspace deps are centralized in the root `[workspace.dependencies]` — add new crates there.
- Keep the static-friendly release profile settings in `Cargo.toml` unchanged.
- Plugin IDs are namespaced like `linux.sudo`, `windows.services`; follow this pattern for new plugins.
- No comments unless necessary; where techniques create artifacts or EDR telemetry, include a warning comment (repo convention).
- Docs live in `docs/`; update relevant docs when adding commands, flags, or plugins.

## Exit codes

`0` ok · `2` missing authorization · `4` `--fail-on` triggered — do not break these contracts.
