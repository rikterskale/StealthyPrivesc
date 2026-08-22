# Build and package an operator artifact

Use this page to create one reviewed artifact before deployment. For the full
matrix and release archive contract, see [Build and release instructions](../build.md)
and [runbook section 1](../operator-runbook.md#1-build-matrix-operator-workstation).

## Select the target

| Target | Build command |
| --- | --- |
| Linux x86_64 | `cargo build --locked --workspace --release` |
| Linux aarch64 | `cargo build --locked --workspace --release --target aarch64-unknown-linux-gnu` |
| Windows x64 GNU | `cargo build --locked --workspace --release --target x86_64-pc-windows-gnu` |
| Windows x64 MSVC | `cargo build --locked --workspace --release --target x86_64-pc-windows-msvc` |

Install the Rust target and matching linker first. A successful cross-build is
not runtime validation; Windows artifacts require a Windows test runner or
approved Windows host.

## Verify provenance

```bash
set -euo pipefail
git rev-parse HEAD
rustc --version
cargo --version
cargo fmt --all -- --check
cargo clippy --locked -p stealthy --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace --release
```

Record the target triple, exact command, source revision, toolchain, artifact
path, and SHA-256. Verify the hash again after transfer.

```bash
sha256sum target/release/stealthy
file target/release/stealthy
./target/release/stealthy --version
./target/release/stealthy doctor --json
```

## Package safely

Published installers expect:

- `stealthy-linux-x86_64.tar.gz` with `stealthy` at the archive root
- `stealthy-windows-x86_64.zip` with `stealthy.exe` at the archive root
- `SHA256SUMS` containing the exact archive checksums

Keep documentation and fallback scripts in a separate approved bundle when the
target needs them. Do not place reports, keys, or target data in the package.

## Before deployment

- Confirm the artifact matches the target OS and architecture.
- Confirm the target drop path is approved and executable, or choose a script
  fallback for `noexec`/application-control restrictions.
- Confirm the transport is in scope.
- Keep the report key separate from the artifact and report path.

Continue with [Target operations](targets.md).
