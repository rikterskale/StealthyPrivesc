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

Published releases contain:

- Linux x86-64 and aarch64 GNU kits and a Windows x86-64 MSVC kit;
- the native binary, platform fallback scripts, selected operator docs,
  `RELEASE-MANIFEST.json`, and internal checksums in each kit;
- one SPDX JSON SBOM per kit; and
- a top-level `SHA256SUMS`, `RELEASE-EVIDENCE.json`, plus GitHub artifact
  attestations.

Use the matching full kit or `scripts/release/package.py` for a local kit. Do
not place reports, keys, or target data in the package. See the
[Support Policy](../support-policy.md) for the supported artifact matrix.

## Before deployment

- Confirm the artifact matches the target OS and architecture.
- Confirm the target drop path is approved and executable, or choose a script
  fallback for `noexec`/application-control restrictions.
- Confirm the transport is in scope.
- Keep the report key separate from the artifact and report path.

Continue with [Delivery](delivery.md) to stage the bundle and copy it, then
[Target operations](targets.md) to run it.

Before treating a locally built kit as production-eligible, complete the
[production-readiness acceptance criteria](../production-readiness.md) and
retain the command results with the release record. The
[workspace hygiene policy](../workspace-hygiene.md) explains why release work
must use a clean checkout.
