# Installation Guide

StealthyPrivesc is a Rust command-line program for authorized Linux and
Windows security assessments. It does not require a server, database, agent,
or runtime service.

## Before installing

Use the tool only when written rules of engagement authorize local privilege-
escalation enumeration on the target. The default scan is enumeration-only.
Do not place reports, keys, or target data in Git.

## Install a published release

The install scripts download the release binary and verify its SHA-256
checksum. Review the script first in high-assurance environments.

Linux:

```bash
curl -fsSLO https://raw.githubusercontent.com/rikterskale/StealthyPrivesc/main/scripts/install.sh
less install.sh
bash install.sh
```

Windows PowerShell:

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/rikterskale/StealthyPrivesc/main/scripts/install.ps1 -OutFile install.ps1
Get-Content .\install.ps1
.\install.ps1
```

Run `stealthy doctor` after installation.

## Build from source

Prerequisites:

- Rust stable and Cargo from [rustup](https://rustup.rs/)
- A supported host: Linux or Windows
- Git, if cloning the repository

```bash
git clone https://github.com/rikterskale/StealthyPrivesc.git
cd StealthyPrivesc
cargo build --locked --workspace --release
./target/release/stealthy doctor
```

On Windows PowerShell:

```powershell
git clone https://github.com/rikterskale/StealthyPrivesc.git
Set-Location .\StealthyPrivesc
cargo build --locked --workspace --release
.\target\release\stealthy.exe doctor
```

For cross-compilation and script-only fallbacks, see [Build Instructions](build.md).

## Verify the installation

These commands do not enumerate the host and do not require authorization:

```text
stealthy --version
stealthy --help
stealthy doctor --json
stealthy guide
```

`doctor --json` is suitable for automation. A healthy result reports a
supported OS, a usable working directory, and at least one compiled plugin.

## Uninstall

Delete the installed binary and any explicitly created report files. Encrypted
reports cannot be opened without their separate operator key. Remove reports
and keys according to the engagement retention policy.
