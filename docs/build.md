# Build and release instructions

This guide covers reproducible source builds, cross-compilation, local CI
parity, release artifact packaging, and fallback-script validation. Build on a
reviewed operator/build machine; deploy the resulting artifact only when its
target, hash, and use are approved by the engagement policy.

## Prerequisites

- Rust stable and Cargo installed through [rustup](https://rustup.rs/)
- Git and a reviewed checkout of the repository
- A user-writable build directory
- Platform linker tools for cross-compilation
- Python 3 for CLI smoke, documentation, and Linux fallback checks

For the full coverage job, install the exact CI tool and Rust component:

```bash
rustup component add llvm-tools-preview
cargo install --locked cargo-llvm-cov --version 0.6.16
```

Keep `Cargo.lock` unchanged for reviewed builds. Use `--locked` for every
release, test, and coverage command below so dependency resolution cannot drift
silently.

## Build and test matrix

This table includes developer/cross-build targets. Only artifacts listed in
the [Support Policy](support-policy.md) are release-supported.

| Artifact / target | Build environment | Command | Runtime validation |
| --- | --- | --- | --- |
| Linux x86_64 | Linux | `cargo build --locked --workspace --release` | Linux CI and local smoke checks |
| Linux aarch64 | Linux with GNU linker | `cargo build --locked --workspace --release --target aarch64-unknown-linux-gnu` | Matching Linux aarch64 host |
| Windows x64 GNU | Linux with MinGW | `cargo build --locked --workspace --release --target x86_64-pc-windows-gnu` | Windows CI or approved Windows host |
| Windows x64 MSVC | Windows with MSVC toolchain | `cargo build --locked --workspace --release --target x86_64-pc-windows-msvc` | Windows CI or approved Windows host |

CI also runs the native Linux runtime smoke test in disposable Ubuntu 22.04,
Ubuntu 24.04, and Debian 12 environments. These are runtime validation
environments, not separate release artifacts; the published Linux kits retain
the GNU-compatible userspace contract described in the support policy.

The release gate also performs two clean release builds with
`SOURCE_DATE_EPOCH=0` and compares their stripped binary hashes. Per-plugin
coverage is emitted as `plugin-coverage.json` alongside the LCOV artifact.

The tagged release workflow publishes these supported assets:

- `stealthy-linux-x86_64.tar.gz`
- `stealthy-linux-aarch64.tar.gz`
- `stealthy-windows-x86_64.zip`
- one `.spdx.json` SBOM per kit
- `SHA256SUMS` for kits and SBOMs

Each archive is a full delivery kit rather than a binary-only asset: the
binary, platform fallback scripts, selected operator documentation,
`RELEASE-MANIFEST.json`, and an internal `SHA256SUMS` are included. See the
[Support Policy](support-policy.md) for the release-supported matrix. Windows
GNU and Linux musl can be developer builds but are not published/support
claims in the current release workflow.

## Native Linux build

```bash
cd /path/to/StealthyPrivesc
cargo build --locked --workspace --release
BIN="$PWD/target/release/stealthy"
file "$BIN"
sha256sum "$BIN"
"$BIN" --version
"$BIN" doctor --json
```

The release profile is optimized for a small distribution artifact:

- `lto = true`
- `codegen-units = 1`
- `opt-level = "z"`
- `strip = true`
- `panic = "abort"`

## Linux aarch64 cross-build

Install the Rust target and a matching linker on the build machine:

```bash
rustup target add aarch64-unknown-linux-gnu
# Debian/Ubuntu example:
# sudo apt-get install -y gcc-aarch64-linux-gnu
cargo build --locked --workspace --release \
  --target aarch64-unknown-linux-gnu
file target/aarch64-unknown-linux-gnu/release/stealthy
sha256sum target/aarch64-unknown-linux-gnu/release/stealthy
```

If the linker is not available, use an approved `cargo-zigbuild` or equivalent
toolchain. Record the target triple, linker, Rust version, and source revision
with the artifact.

## Windows x64 cross-build from Linux

```bash
rustup target add x86_64-pc-windows-gnu
# Debian/Ubuntu example:
# sudo apt-get install -y mingw-w64
cargo build --locked --workspace --release \
  --target x86_64-pc-windows-gnu
file target/x86_64-pc-windows-gnu/release/stealthy.exe
sha256sum target/x86_64-pc-windows-gnu/release/stealthy.exe
```

The GNU artifact must be run and smoke-tested on Windows before release. An
artifact that cross-compiles successfully is not proof that Windows runtime
behavior, ACL handling, or fallback execution is correct.

## Native Windows build

From PowerShell on a reviewed Windows checkout:

```powershell
Set-Location C:\path\to\StealthyPrivesc
cargo build --locked --workspace --release
$Bin = (Resolve-Path .\target\release\stealthy.exe).Path
Get-FileHash $Bin -Algorithm SHA256
& $Bin --version
& $Bin doctor --json
```

For an explicit MSVC target:

```powershell
rustup target add x86_64-pc-windows-msvc
cargo build --locked --workspace --release --target x86_64-pc-windows-msvc
```

## Local CI parity checks

Run these checks from the repository root before packaging or pushing a
behavior change:

```bash
set -euo pipefail
cargo fmt --all -- --check
cargo clippy --locked -p stealthy --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace --release
```

Run the Linux CLI smoke contract against the release binary:

```bash
BIN=./target/release/stealthy
"$BIN" guide
"$BIN" disclaimer
"$BIN" --help
if "$BIN" enum; then
  echo 'expected authorization failure' >&2
  exit 1
fi
"$BIN" --authorized list-plugins
"$BIN" --authorized --no-color enum \
  --plugins linux.kernel_cve --min-severity info | head -n 40
"$BIN" --authorized --format json -q enum \
  --plugins linux.kernel_cve | python3 -c 'import json,sys; json.load(sys.stdin)'
```

The release UX contract also covers `doctor --json`, TSV plugin output,
unknown-plugin errors, JSON/Markdown/SARIF rendering, offline `diff`, sealed
file output, missing-output-path failures, remote-output validation, and
`--fail-on` exit code `4`. Keep those checks aligned with the executable
contract in `.github/workflows/ci.yml`.

## Coverage report

The CI coverage job uses `cargo-llvm-cov` version `0.6.16` and publishes LCOV:

```bash
rustup component add llvm-tools-preview
cargo install --locked cargo-llvm-cov --version 0.6.16
cargo llvm-cov --locked --workspace --all-targets \
  --lcov --output-path lcov.info --fail-under-lines 80
test -s lcov.info
```

CI and the tag gate enforce an 80% line-coverage floor. Treat a missing/empty
report or a result below the floor as failed validation.

## Build flavors

The normal `release` profile uses the default `full` feature. Two constrained
profiles are validated in CI:

```bash
cargo check --locked -p stealthy --profile enum-only \
  --no-default-features --features enum-only
cargo build --locked -p stealthy --profile opsec-string-strip \
  --no-default-features --features opsec-string-strip
```

`enum-only` rejects `--auto-exploit`, every `--allow-techniques` family, and
executable control fixtures. `opsec-string-strip` includes `enum-only` and
omits product brand, GTFOBins/LOLBAS URLs, the GitHub repository URL, and
third-party vendor catalog text from the binary. Authorization, plugin IDs,
and audit fields remain. After the flavor build:

```bash
python3 scripts/ci/validate_opsec_strings.py \
  --binary target/opsec-string-strip/stealthy
```

## Windows CI validation

The Windows job runs the following on `windows-latest`:

```powershell
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace --release
cargo test --locked --workspace `
  native_acl_check_reports_missing_paths_as_unknown -- --nocapture
```

Native Windows runtime tests cannot be fully replaced by a Linux cross-build.
Use the GitHub Actions Windows job or an equivalent approved Windows runner
before publishing Windows artifacts.

## Fallback-script validation

Linux fallback syntax:

```bash
find scripts/linux -type f -name '*.sh' -print0 | \
  xargs -0 -r -n1 bash -n
python3 -m py_compile scripts/linux/enum.py
python3 -m py_compile scripts/windows/enum.py
bash -n scripts/windows/enum-git.sh
```

Windows PowerShell parsing, from PowerShell:

```powershell
$scripts = @(Get-ChildItem -Path scripts\windows -Filter *.ps1 -Recurse)
foreach ($script in $scripts) {
  $tokens = $null
  $errors = $null
  [System.Management.Automation.Language.Parser]::ParseFile(
    $script.FullName, [ref]$tokens, [ref]$errors) | Out-Null
  if ($errors.Count -gt 0) { throw "Parse failed: $($script.FullName)" }
}
```

Fallbacks are enumeration-only alternatives with reduced coverage. Syntax
validation does not prove that a target's policy permits execution.

## Release packaging

`scripts/release/package.py` is the canonical kit builder used by the release
workflow. For example:

```bash
cargo build --locked -p stealthy --release --target x86_64-unknown-linux-gnu
python3 scripts/release/package.py \
  --platform linux --arch x86_64 \
  --target x86_64-unknown-linux-gnu \
  --binary target/x86_64-unknown-linux-gnu/release/stealthy \
  --output stealthy-linux-x86_64.tar.gz \
  --version local --commit "$(git rev-parse HEAD)"
```

Every `v*` tag must pass the full release gate before build/publish:

- locked metadata, formatting, Clippy with warnings denied, tests, and release build;
- `enum-only` and `opsec-string-strip` flavor checks;
- the 80% Rust line-coverage floor;
- Linux/release script parsing;
- full-history Gitleaks scanning; and
- `cargo deny check --all-features` for advisories, licenses, bans, and sources.

After the gate, the workflow builds and smoke-tests Linux x86-64, Linux aarch64
GNU under QEMU, and Windows x86-64 MSVC. It creates full kits, SPDX JSON SBOMs,
and a top-level checksum manifest, then uses GitHub artifact attestations for
the kits, SBOMs, and checksums before creating the release.

The scheduled nightly safe-lab workflow runs the Rust fixture suite on Linux
and Windows, validates the enumeration-only flavor, parses platform fallback
scripts, and confirms the authorization gate remains closed. It uses local,
non-privileged fixtures; it is not a destructive vulnerable-host exploit lab.

## Script fallbacks without Rust

When a custom binary cannot be approved or executed, validate and run only the
fallback appropriate to the target:

```bash
bash scripts/linux/enum.sh --authorized
python3 scripts/linux/enum.py --authorized
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows\enum.ps1 -Authorized
cscript //nologo scripts\windows\enum.js --authorized
```

Use [Delivery](runbook/delivery.md) to stage a bundle and copy it to a target,
then the [Operator Runbook](operator-runbook.md) for hash verification,
evidence custody, cleanup, and reduced-coverage reporting.
