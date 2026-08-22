# Build instructions

## Prerequisites

- Rust stable (1.70+ recommended) via [rustup](https://rustup.rs/)
- For Windows cross-builds from Linux: `mingw-w64` or `cargo-xwin` / `cargo-zigbuild`

## Native Linux build

```bash
cargo build -p stealthy --release
./target/release/stealthy --help
```

Release profile settings (workspace crate):

- `lto = true`
- `codegen-units = 1`
- `opt-level = "z"`
- `strip = true`
- `panic = "abort"`

## Cross-compile: Linux aarch64

```bash
rustup target add aarch64-unknown-linux-gnu
cargo build -p stealthy --release --target aarch64-unknown-linux-gnu
```

You may need a matching linker (`aarch64-linux-gnu-gcc`) or zigbuild.

## Cross-compile: Windows x64 (from Linux)

```bash
rustup target add x86_64-pc-windows-gnu
# Debian/Ubuntu example:
# sudo apt install mingw-w64
cargo build -p stealthy --release --target x86_64-pc-windows-gnu
```

MSVC target (`x86_64-pc-windows-msvc`) is best built on a Windows agent or via `cargo-xwin`.

## Tests

```bash
cargo test -p stealthy
```

## Script fallbacks (no Rust required)

```bash
bash -n scripts/linux/enum.sh
python3 scripts/linux/enum.py
```

On Windows, parse-check PowerShell:

```powershell
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path scripts\windows\enum.ps1), [ref]$null, [ref]$null)
```
