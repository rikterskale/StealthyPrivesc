# Installation Guide

This guide gets an authorized operator from zero to a verified `stealthy`
executable. The shortest path is: install a published release, verify the
binary, then follow the [guided first-user journey](first-user-journey.md).

StealthyPrivesc is a Rust command-line program for authorized Linux and
Windows security assessments. It does not require a server, database, agent,
or runtime service.

## Before you begin

Have these ready:

- Written authorization covering the target host, local privilege-escalation
  enumeration, evidence handling, and any optional reversible probes.
- A supported Linux or Windows operator/target environment.
- An approved place for reports and, for sealed reports, a separate secret
  store for the decryption key.
- A decision about whether the first run may write any evidence to disk. The
  guided first run below is memory-only.

Do not place reports, keys, or target data in Git. Do not run host-enumerating
commands until the authorization step is complete.

## Choose one installation path

### Path A — published release (recommended)

Use this when you want the quickest operator setup and do not need to modify
the source.

#### Linux

Download the installer, review it, run it, and add its default location to the
current shell's `PATH`:

```bash
set -euo pipefail
INSTALLER="$(mktemp)"
curl -fsSL \
  https://raw.githubusercontent.com/rikterskale/StealthyPrivesc/main/scripts/install.sh \
  -o "$INSTALLER"
if command -v less >/dev/null 2>&1; then less "$INSTALLER"; else sed -n '1,240p' "$INSTALLER"; fi
bash "$INSTALLER"
rm -f "$INSTALLER"

export PATH="$HOME/.local/bin:$PATH"
command -v stealthy
stealthy --version
```

The installer verifies the release SHA-256 checksum and installs to
`$HOME/.local/bin/stealthy` by default. The `PATH` change above affects the
current shell only. Add the same directory through your normal shell profile
process if you want it available in future terminals.

If `curl` is unavailable, download the installer with an approved alternative
and still review it before execution. If the release installer cannot be used,
use Path B or the script fallback described in the
[Operator Runbook](operator-runbook.md).

#### Windows PowerShell

Download to a temporary file, review it, run it, and use the installed path
explicitly. This avoids depending on a new terminal seeing an updated `PATH`:

```powershell
$ErrorActionPreference = 'Stop'
$Installer = Join-Path $env:TEMP 'stealthy-install.ps1'
Invoke-WebRequest `
  -Uri 'https://raw.githubusercontent.com/rikterskale/StealthyPrivesc/main/scripts/install.ps1' `
  -OutFile $Installer
Get-Content $Installer
& $Installer
Remove-Item -Force $Installer

$Stealthy = Join-Path $env:LOCALAPPDATA 'StealthyPrivesc\stealthy.exe'
Get-Item $Stealthy
& $Stealthy --version
```

The installer verifies the release SHA-256 checksum and installs to
`$env:LOCALAPPDATA\StealthyPrivesc\stealthy.exe` by default. If you prefer to
call `stealthy` without its full path, add that directory to your user `PATH`
through your normal Windows administration process, then open a new terminal.

### Path B — build from source

Use this when you need a reviewed revision, a local change, or a build artifact
for a target. Build on the operator/build machine, not on the target unless the
ROE explicitly allows that.

Prerequisites:

- Rust stable and Cargo from [rustup](https://rustup.rs/)
- Git, if cloning the repository
- Linux or Windows build host

Linux:

```bash
git clone https://github.com/rikterskale/StealthyPrivesc.git
cd StealthyPrivesc
cargo build --locked --workspace --release
STEALTHY="$PWD/target/release/stealthy"
"$STEALTHY" --version
```

Windows PowerShell:

```powershell
git clone https://github.com/rikterskale/StealthyPrivesc.git
Set-Location .\StealthyPrivesc
cargo build --locked --workspace --release
$Stealthy = (Resolve-Path .\target\release\stealthy.exe).Path
& $Stealthy --version
```

For cross-compilation, release packaging, and script-only fallbacks, see
[Build Instructions](build.md) and the [Operator Runbook](operator-runbook.md).

## Verify before the first host action

These checks are local and do not require authorization or enumerate a host:

Linux:

```bash
"$STEALTHY" doctor
"$STEALTHY" doctor --json
"$STEALTHY" guide
"$STEALTHY" disclaimer
```

Windows PowerShell:

```powershell
& $Stealthy doctor
& $Stealthy doctor --json
& $Stealthy guide
& $Stealthy disclaimer
```

A healthy `doctor` result reports a supported OS, at least one compiled
plugin, and a usable working directory. If it fails, stop and fix the local
environment before using `--authorized`.

## Continue with the guided first run

Do not invent the next command. Continue to the
[First-User Journey](first-user-journey.md), which provides the exact
authorization, plugin discovery, first scan, output, and recovery sequence.

For a shorter explanation of the same workflow, use the
[User Guide](user-guide.md). For deployment to another Linux or Windows host,
use the [Operator Runbook](operator-runbook.md).

## Guided troubleshooting

Troubleshoot in this order. Stop as soon as a step succeeds; do not run host
enumeration while diagnosing installation.

### Step 1 — identify the failure stage

| Stage | Typical symptom | Start here |
| --- | --- | --- |
| Download | DNS, TLS, HTTP status, or release-not-found error | Network and release checks below |
| Checksum | SHA-256 mismatch or incomplete archive | Stop; do not run the artifact |
| Install | Permission denied or cannot create destination | Check the exact install directory and user permissions |
| Path lookup | `command not found` / `not recognized` | Use the absolute path and refresh `PATH` |
| Source build | Cargo, compiler, linker, or lock-file error | Run the build diagnostics below |
| Local verification | `doctor` unhealthy or no plugins | Check OS/architecture and working directory |
| Execution policy | Windows executable/script is blocked | Record the control; use an approved fallback |

### Step 2 — collect safe local diagnostics

These commands do not enumerate a target host. Keep the output with the
installation record, but remove usernames, local paths, or network details if
the record is shared outside the approved team.

Linux:

```bash
printf 'os='; uname -s
printf 'kernel='; uname -sr
printf 'arch='; uname -m
printf 'user='; id -un
printf 'cwd='; pwd
printf 'shell=%s\n' "${SHELL:-unknown}"
printf 'stealthy-on-path='; command -v stealthy || true
printf 'install-dir='; ls -ld "$HOME/.local/bin" 2>&1 || true
printf 'installed-file='; ls -l "$HOME/.local/bin/stealthy" 2>&1 || true
```

Windows PowerShell:

```powershell
$ErrorActionPreference = 'Continue'
Write-Host "os=$([Environment]::OSVersion.Version)"
Write-Host "arch=$env:PROCESSOR_ARCHITECTURE"
Write-Host "user=$([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Host "cwd=$((Get-Location).Path)"
Write-Host "install-dir=$env:LOCALAPPDATA\StealthyPrivesc"
Get-Command stealthy, stealthy.exe -All -ErrorAction SilentlyContinue |
  Select-Object Name, Source, CommandType
Get-Item (Join-Path $env:LOCALAPPDATA 'StealthyPrivesc\stealthy.exe') `
  -ErrorAction SilentlyContinue |
  Select-Object FullName, Length, LastWriteTime
```

### Step 3 — repair path and stale-binary problems

Linux:

```bash
export PATH="$HOME/.local/bin:$PATH"
hash -r 2>/dev/null || true
command -v stealthy
type -a stealthy
"$HOME/.local/bin/stealthy" --version
```

If `type -a` shows multiple copies, use the absolute path for the approved
artifact and remove stale copies only through the normal change/retention
process. Do not assume the first `PATH` entry is the reviewed binary.

Windows PowerShell:

```powershell
$InstallDir = Join-Path $env:LOCALAPPDATA 'StealthyPrivesc'
$Stealthy = Join-Path $InstallDir 'stealthy.exe'
Test-Path $Stealthy
& $Stealthy --version
Get-Command stealthy.exe -All -ErrorAction SilentlyContinue
```

If the absolute path works but `stealthy` does not, the installation is fine;
the current terminal simply does not have the install directory in `PATH`.
Use `$Stealthy` for this session or add the directory through the approved
user-environment process and open a new terminal.

### Step 4 — verify the artifact itself

Linux:

```bash
BIN="$HOME/.local/bin/stealthy"
test -f "$BIN" && test -x "$BIN"
file "$BIN"
sha256sum "$BIN"
"$BIN" --version
"$BIN" doctor --json
```

Windows PowerShell:

```powershell
$Bin = Join-Path $env:LOCALAPPDATA 'StealthyPrivesc\stealthy.exe'
Get-Item $Bin | Select-Object FullName, Length, LastWriteTime
Get-FileHash $Bin -Algorithm SHA256
& $Bin --version
& $Bin doctor --json
```

The file type and architecture must match the host. An `Exec format error`, a
Windows launch failure, or a `doctor` result with no plugins usually means the
wrong release or cross-build was selected. Obtain the matching artifact; do
not bypass the platform check.

### Step 5 — diagnose download and checksum failures

For a failed published-release install:

1. Record the HTTP error, release version, asset name, and local timestamp.
2. Confirm the approved network path can reach the repository release endpoint.
3. Retry only with the same approved version or a specifically approved
   version; do not substitute an untrusted mirror.
4. If the checksum differs, stop. Delete only the identified temporary
   download, preserve the mismatch evidence, and obtain a trusted artifact.

Linux connectivity check:

```bash
curl -fsSI https://api.github.com/repos/rikterskale/StealthyPrivesc/releases/latest
```

Windows PowerShell connectivity check:

```powershell
Invoke-WebRequest `
  -Uri 'https://api.github.com/repos/rikterskale/StealthyPrivesc/releases/latest' `
  -Method Head
```

A `401`, `403`, proxy error, TLS error, or DNS failure is a network/policy
issue, not a reason to disable certificate verification or use an unapproved
download channel.

### Step 6 — diagnose source-build failures

Run these on the build machine from the repository root:

```bash
git status --short
rustc --version
cargo --version
cargo metadata --locked --no-deps --format-version 1 >/dev/null
cargo build --locked --workspace --release
```

Interpret common failures as follows:

| Build output | Safe next step |
| --- | --- |
| `cargo: command not found` / `rustc: command not found` | Install Rust through the approved [rustup](https://rustup.rs/) process, open a new shell, and rerun the version checks. |
| Lock-file or dependency update requested | Keep `--locked`; inspect the reviewed `Cargo.lock` and do not run `cargo update` during the engagement build. |
| C compiler/linker not found | Install the approved platform build tools or use a prepared build machine; record the toolchain used. |
| Permission denied in `target/` | Build in a user-writable reviewed checkout; do not build as root merely to bypass permissions. |
| Network failure fetching crates | Use the approved Cargo proxy/cache or a prepared offline environment; do not silently change dependency sources. |
| Build succeeds but artifact will not run | Recheck target OS/architecture with `file`, `uname -m`, or PowerShell environment data. |

If a failed build modified tracked files, inspect `git status` and the diff
before retrying. Do not discard unrelated working-tree changes.

### Step 7 — diagnose `doctor` and execution-policy failures

`doctor` is a local readiness check. It returns a nonzero result when the OS is
unsupported, no plugins are compiled, or the current working directory is not
usable. Fix the reported condition and rerun:

```bash
"$STEALTHY" doctor --json
```

```powershell
& $Stealthy doctor --json
```

If the executable is blocked by SmartScreen, AppLocker, WDAC, antivirus, AppArmor,
`noexec`, or a similar control, record the exact message, policy, and timestamp.
Prefer the documented script-only fallback and record the reduced coverage.

This product **detects** those controls (`linux.endpoint_controls` /
`windows.endpoint_controls` and the script fallbacks). It does **not** disable,
unhook, or kill them. `--allow-techniques endpoint-bypass` records
alternate-path intent and approved-fixture validation guidance when ROE
permits (use `--artifact` and/or `controls --execute` for benign allow/block
observation). See `docs/techniques.md`.

### Approved paths when a custom binary cannot run

**Linux** (ELF blocked, `noexec` drop path, AppArmor/SELinux constraint):

```bash
bash scripts/linux/enum.sh --authorized | tee enum-shell.txt
python3 scripts/linux/enum.py --authorized | tee enum-python.txt
```

**Windows** (PE blocked by AppLocker/WDAC/SmartScreen; prefer allowlisted hosts):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows\enum.ps1 -Authorized
cscript //nologo scripts\windows\enum.js --authorized
msbuild scripts\windows\EnumTasks.csproj
```

After a successful PE run on Windows/Linux, still collect control inventory:

```bash
"$STEALTHY" --authorized enum --plugins linux.endpoint_controls
```

```powershell
& $Stealthy --authorized enum --plugins windows.endpoint_controls
```

## Common installation problems

| Symptom | Fix |
| --- | --- |
| `stealthy: command not found` | Use the absolute path shown above, or add `$HOME/.local/bin` to `PATH` on Linux / the install directory to `PATH` on Windows and open a new terminal. |
| Installer cannot resolve a release | Check the approved network path, set `STEALTHY_VERSION` to an approved release, or build from source. |
| SHA-256 mismatch | Stop. Do not run the artifact; preserve the error and obtain a trusted artifact. |
| `doctor` reports unsupported OS | Stop and use an approved matching build or script fallback; do not bypass the platform check. |
| `doctor` reports no plugins | Confirm that the binary matches the target OS and architecture, then use `list-plugins` only after authorization. |
| Windows executable is blocked | Record SmartScreen/AppLocker/WDAC; run `enum.ps1` / `enum.js` / `EnumTasks.csproj` if ROE permits. |
| Linux ELF fails with `Permission denied` on `noexec` | Record the mount; run `enum.sh` / `enum.py` from an executable path. |
| Build fails with a locked dependency error | Run from the reviewed repository with the existing `Cargo.lock`; do not silently update dependencies during an engagement build. |

### Quick recovery ladder

If you need the shortest possible recovery path:

1. Use the absolute binary path from the install/build step.
2. Run `--version` and `doctor --json`.
3. Check the file type, architecture, and SHA-256 hash.
4. Fix `PATH`, permissions, or build tools based on the stage table above.
5. Re-run the local verification checks before using `--authorized`.
6. If still blocked, preserve the diagnostics, switch to the approved
   script fallback, and optionally record `--allow-techniques endpoint-bypass`
   (alternate-path + approved-fixture validation) when ROE permits.

Never treat a successful download, a zero-byte report, or a process that exits
without a visible error as proof that installation is complete. The final
installation checkpoint is a matching artifact, a healthy `doctor` result,
and a successful `--version` command.

## Uninstall

Remove only the explicitly installed binary and any explicitly created report
files. On Linux, the default binary is `$HOME/.local/bin/stealthy`. On Windows,
the default binary is `$env:LOCALAPPDATA\StealthyPrivesc\stealthy.exe`.

Encrypted reports cannot be opened without their separate operator key. Remove
reports and keys according to the engagement retention policy, and preserve
the engagement log and approved evidence hashes as required.
