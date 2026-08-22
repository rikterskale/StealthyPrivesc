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

## Supported build matrix

| Artifact / target | Build environment | Command | Runtime validation |
| --- | --- | --- | --- |
| Linux x86_64 | Linux | `cargo build --locked --workspace --release` | Linux CI and local smoke checks |
| Linux aarch64 | Linux with GNU linker | `cargo build --locked --workspace --release --target aarch64-unknown-linux-gnu` | Matching Linux aarch64 host |
| Windows x64 GNU | Linux with MinGW | `cargo build --locked --workspace --release --target x86_64-pc-windows-gnu` | Windows CI or approved Windows host |
| Windows x64 MSVC | Windows with MSVC toolchain | `cargo build --locked --workspace --release --target x86_64-pc-windows-msvc` | Windows CI or approved Windows host |

The repository's release installers expect these published asset names:

- `stealthy-linux-x86_64.tar.gz`, containing `stealthy` at the archive root
- `stealthy-windows-x86_64.zip`, containing `stealthy.exe` at the archive root
- `SHA256SUMS`, containing one checksum entry for each published asset

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
  --lcov --output-path lcov.info
test -s lcov.info
```

Treat a missing or empty `lcov.info` as a failed validation, even if the build
itself succeeded.

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

Build and verify the artifact before assembling a drop bundle:

```bash
set -euo pipefail
REV=$(git rev-parse HEAD)
RUST_VERSION=$(rustc --version)
cargo build --locked --workspace --release
sha256sum target/release/stealthy
file target/release/stealthy
printf '%s\n' "$REV" > build-commit.txt
printf '%s\n' "$RUST_VERSION" > build-toolchain.txt
```

Linux bundle:

```bash
set -euo pipefail
STAGE=release-staging/stealthy-linux-x86_64
rm -rf "$STAGE"
mkdir -p "$STAGE/scripts/linux" "$STAGE/docs"
cp target/release/stealthy "$STAGE/"
cp scripts/linux/enum.sh scripts/linux/enum.py "$STAGE/scripts/linux/"
cp README.md docs/installation.md docs/user-guide.md \
  docs/operator-runbook.md docs/techniques.md "$STAGE/docs/"
chmod 0755 "$STAGE/stealthy" "$STAGE/scripts/linux/"*
# Archive the stage contents so the installer finds ./stealthy at the root.
tar -C "$STAGE" -czf stealthy-linux-x86_64.tar.gz .
sha256sum stealthy-linux-x86_64.tar.gz > SHA256SUMS
```

Windows bundle from Linux after the GNU cross-build:

```bash
set -euo pipefail
STAGE=release-staging/stealthy-windows-x86_64
rm -rf "$STAGE"
mkdir -p "$STAGE/scripts/windows" "$STAGE/docs"
cp target/x86_64-pc-windows-gnu/release/stealthy.exe "$STAGE/"
cp scripts/windows/enum.ps1 scripts/windows/enum.js \
  scripts/windows/EnumTasks.csproj "$STAGE/scripts/windows/"
cp README.md docs/installation.md docs/user-guide.md \
  docs/operator-runbook.md docs/techniques.md "$STAGE/docs/"
# Archive the stage contents so the installer finds ./stealthy.exe at the root.
(cd "$STAGE" && zip -r ../../stealthy-windows-x86_64.zip .)
sha256sum stealthy-windows-x86_64.zip >> SHA256SUMS
```

Before publishing, confirm that each archive has the expected executable at
its root, the checksum file names the exact archive bytes, and the artifact
was runtime-tested on its target platform. Keep source revision, target
triple, Rust toolchain, build command, hashes, and validation results with the
release record.

## Script fallbacks without Rust

When a custom binary cannot be approved or executed, validate and run only the
fallback appropriate to the target:

```bash
bash scripts/linux/enum.sh
python3 scripts/linux/enum.py
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows\enum.ps1
cscript //nologo scripts\windows\enum.js
```

Use the [Operator Runbook](operator-runbook.md) for target deployment, hash
verification, evidence custody, cleanup, and reduced-coverage reporting.
