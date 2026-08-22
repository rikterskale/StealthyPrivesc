# First-User Journey

## Goals

Get an authorized operator from clone → build → first quiet enumeration without accidental exploitation or disk artifacts.

## Entry points

1. `README.md` disclaimer and quick start
2. [`docs/operator-runbook.md`](operator-runbook.md) for full copy-paste deploy steps
3. `stealthy disclaimer`
4. Script fallbacks under `scripts/` when binaries cannot run

## Journey stages

1. **Authorize** — confirm written ROE; pass `--i-understand-authorized-use-only`
2. **Build** — `cargo build -p stealthy --release` (or use scripts)
3. **List** — `stealthy list-plugins`
4. **Enumerate** — `stealthy ... enum` (default, no auto-exploit)
5. **Review** — read findings and recommendations
6. **Optional probes** — only with `--auto-exploit` when ROE allows
7. **Optional export** — `--output file` if evidence handling requires it

## Non-interactive contract

```bash
cargo build -p stealthy --release
./target/release/stealthy guide
./target/release/stealthy disclaimer
./target/release/stealthy --authorized list-plugins
./target/release/stealthy --authorized -q enum
./target/release/stealthy --authorized --format json -q enum >/dev/null
```

Exit codes:

- `0` success
- `2` missing authorization acknowledgment
- `4` `--fail-on` severity threshold hit
- non-zero for unexpected failures

## CI contract

CI must:

- Validate Markdown docs and links
- Build and test the Rust crate on Linux
- Syntax-check shell/Python agent scripts when present
- Skip Windows-only compilation on Linux agents (cross-job optional)

## Safety boundary

The first-user path never enables `--auto-exploit`, never writes findings to disk, and never attempts kernel exploits.
