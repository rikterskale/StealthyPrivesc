# StealthyPrivesc

Modular, cross-platform privilege-escalation **enumeration** framework for **authorized** red team engagements and internal security assessments.

Documentation hub: [`docs/README.md`](docs/README.md).

Start here: [Installation](docs/installation.md) · [User Guide](docs/user-guide.md) · [CLI Reference](docs/cli-reference.md) · [Architecture Diagram](docs/architecture-diagram.md)

## Legal / ethical disclaimer

**Authorized use only.**

This tool exists solely for:

- Red team engagements with explicit written permission
- Internal security assessments under an approved charter
- Defensive research in lab environments you own or are authorized to test

Unauthorized reconnaissance, evasion, or privilege escalation is illegal and unethical. By running the binary you must pass `--i-understand-authorized-use-only` (or set `STEALTHY_AUTHORIZED=1`) to acknowledge this boundary.

The authors and distributors assume **no liability** for misuse.

## Design posture

| Default | Behavior |
| --- | --- |
| Mode | Enumeration + recommendations only |
| Auto-exploit | Opt-in (`--auto-exploit`), low-noise reversible probes |
| High-impact techniques | Opt-in (`--allow-techniques`); most scaffolded; `endpoint-bypass` = alternate-path + approved-fixture validation |
| Disk writes | Off by default (encrypted in-memory results) |
| Script fallbacks | Provided when a custom binary cannot run |

## Architecture

```text
crates/stealthy/          Rust core (static-friendly release profile)
  src/core/               OS detect, identity, plugin runner, encrypted store, evasion helpers
  src/plugins/linux/      Linux checks (16): sudo, SUID, cron/systemd/timers, containers, groups, polkit, mounts, ssh keys, PATH/LD, CVE hints, NFS, creds, services, wildcards, endpoint controls, app-control assessment
  src/plugins/windows/    Windows checks (12): privileges/Potato hint, services, tasks, AIE, UAC, DLL paths, creds, admins, PATH, autoruns, endpoint controls, app-control assessment
  src/exploit/            Reversible probes + `--allow-techniques` scaffolding
scripts/linux/            Bash + Python fallbacks (no custom binary; includes control checks)
scripts/windows/          PowerShell + JScript + MSBuild host stubs (includes control checks)
docs/                     Architecture, build, technique risk notes
```

## Quick start

### Install a published release

Linux:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/rikterskale/StealthyPrivesc/main/scripts/install.sh \
  -o /tmp/stealthy-install.sh
less /tmp/stealthy-install.sh
bash /tmp/stealthy-install.sh
rm -f /tmp/stealthy-install.sh
```

Windows PowerShell:

```powershell
$Installer = Join-Path $env:TEMP 'stealthy-install.ps1'
Invoke-WebRequest `
  'https://raw.githubusercontent.com/rikterskale/StealthyPrivesc/main/scripts/install.ps1' `
  -OutFile $Installer
Get-Content $Installer
& $Installer
Remove-Item -Force $Installer
```

Both installers verify the release SHA-256 checksum. For high-assurance
environments, download and review the script before execution.

```bash
# Build (Linux host)
cargo build --locked -p stealthy --release

# First-run guide (no auth required)
./target/release/stealthy doctor
./target/release/stealthy guide
./target/release/stealthy disclaimer

# Enumerate (required authorization flag; --authorized is the short alias)
./target/release/stealthy --authorized scan

# High-signal only + live progress
./target/release/stealthy --authorized enum --min-severity high

# OPSEC profile (skips sudo helpers/getcap/getfacl; slim control collect; higher delay)
./target/release/stealthy --authorized --profile quiet enum

# Quiet + select plugins
./target/release/stealthy --authorized -q \
  enum --plugins linux.sudo,linux.containers,linux.suid,linux.groups

# Triage stub for stepwise probe approval
./target/release/stealthy --authorized --checkpoint /tmp/triage.json enum --triage --triage-out decisions.json
./target/release/stealthy --authorized --checkpoint /tmp/triage.json enum --approve-file decisions.json

# Stage a drop bundle on the operator workstation
./target/release/stealthy stage --os linux --out ./drop \
  --binary ./target/release/stealthy

# Run the staged bundle through the policy-bound dispatcher
# (the dispatcher still requires a fresh operator acknowledgment)
bash ./drop/scripts/run.sh --authorized --profile balanced enum

# Markdown / JSON / SARIF console formats
./target/release/stealthy --authorized --format markdown enum > report.md
./target/release/stealthy --authorized --format json -q enum

# Compare two plaintext JSON reports offline
./target/release/stealthy diff baseline.json current.json
./target/release/stealthy --authorized --format sarif -q scan > findings.sarif

# Encrypted file + sidecar Markdown
./target/release/stealthy --authorized \
  --output file --output-path /tmp/findings.seal --also-markdown \
  enum

# Decode a sealed report with the separately handled key
./target/release/stealthy report /tmp/findings.seal \
  --key-hex "$STEALTHY_REPORT_KEY" --format json

# Fail CI/automation if critical findings exist
./target/release/stealthy --authorized enum --fail-on critical; echo exit=$?

# Limited reversible probes
./target/release/stealthy --authorized enum --auto-exploit

# High-impact families (most are scaffold; endpoint-bypass = alternate-path +
# approved-fixture validation — never AMSI/ETW/EDR disable; see docs/techniques.md)
./target/release/stealthy --authorized enum \
  --allow-techniques kernel-exploit,potato,msi
```

### Script-only fallbacks

Use the staged dispatcher as the normal entrypoint. It verifies the approved
manifest, stages the bundle, tries the primary executable, and automatically
selects an approved script fallback only when the executable cannot launch.
The manifest carries inherited ROE context and binds execution to the current
host; it does not grant permission or override host policy. The dispatcher
requires a fresh authorization acknowledgment and forwards it to the selected
execution path.

```bash
bash ./drop/scripts/run.sh --authorized --profile balanced enum
```

On Windows:

```powershell
& .\drop\scripts\run.ps1 --authorized --profile balanced enum
```

The dispatcher and direct scripts both require a fresh `--authorized` flag or
`STEALTHY_AUTHORIZED=1`; the manifest approves the fallback path but is not an
authorization acknowledgment.

Use direct scripts only for troubleshooting or when the dispatcher itself is
not an approved execution path.

```bash
# Linux
bash scripts/linux/enum.sh --authorized
python3 scripts/linux/enum.py --authorized

# Windows — prefer staged dispatcher (PE → powershell → jscript → msbuild)
# & .\drop\scripts\run.ps1 --authorized enum
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows\enum.ps1 -Authorized
cscript //nologo scripts\windows\enum.js --authorized --json
```

On Defender-on hosts, keep kits out of `%TEMP%`, prefer an org-signed PE when
available, and rely on `run.ps1` fallbacks if the PE is quarantined. See
[`docs/operator-runbook.md`](docs/operator-runbook.md) and
[`docs/techniques.md`](docs/techniques.md).

## CLI flags

For the complete command and option reference, see [`docs/cli-reference.md`](docs/cli-reference.md).

| Flag | Purpose |
| --- | --- |
| `--authorized` / `--i-understand-authorized-use-only` | Required acknowledgment (`STEALTHY_AUTHORIZED=1`) |
| `-q` / `--quiet` | Less console noise |
| `-v` / `--verbose` | Per-finding progress detail |
| `--no-color` | Disable ANSI colors (also honors `NO_COLOR`) |
| `--format human\|json\|markdown\|sarif` | Console report shape (default `human`) |
| `--min-severity info\|low\|medium\|high\|critical` | Filter displayed findings |
| `--fail-on <severity>` | Exit `4` if max finding severity reaches threshold |
| `--delay-ms N` | Low-and-slow jitter between plugins (default 50) |
| `--profile quiet\|balanced\|thorough\|ci` | Named engagement/OPSEC profile |
| `--plugin-timeout-ms N` | Per-plugin isolated-process timeout; `0` disables |
| `--checkpoint PATH` | Write a resumable plaintext checkpoint |
| `--ledger-dir PATH` | Artifact ledger location for explicit artifacts/checkpoints |
| `--artifact PATH` | Read-only hash/provenance/trust prediction for an approved test artifact; never executes it |
| `--output memory\|file\|remote` | Result destination (default `memory`) |
| `--output-path PATH` | Destination for `--output file` |
| `--plaintext-file` | Write JSON instead of sealed blob |
| `--also-markdown` | Also write `PATH.md` evidence report |
| `--exfil-url URL` | Operator-configured HTTPS target for `--output remote` (v1 prints sealed body; no silent client) |
| `guide` | First-run operator guide (no auth) |
| `doctor` | Local readiness checks (no auth) |
| `report PATH --key-hex KEY` | Decode a sealed report (no host access) |
| `disclaimer` | Print legal text (no auth) |
| `list-plugins` / `plugins` | Table of compiled plugin IDs |
| `controls` / `validate-controls` | Run disposable application-control validation cases |
| `live-controls` / `collect-controls` | Collect live read-only policy, sensor, and audit state |
| `resume --checkpoint PATH` | Resume an interrupted enumeration |
| `ingest PATH` | Normalize script JSON to report schema v2 |
| `artifacts` / `cleanup` | Inspect or remove ledger-recorded artifacts |
| `stage` / `verify` / `one-liners` | Package and verify approved delivery bundles |
| `enum --auto-exploit` | Opt-in reversible probes |
| `enum --allow-techniques a,b` | Opt-in high-impact families (`endpoint-bypass` documented in `docs/techniques.md`) |
| `enum --plugins a,b` | Enable listed plugins |
| `enum --skip a,b` | Skip listed plugins |

Exit codes: `0` ok · `2` missing authorization · `3` doctor readiness failure · `4` `--fail-on` triggered

## Technique risk notes (summary)

| Class | Risk | Notes |
| --- | --- | --- |
| File reads (`/proc`, sudoers, registry) | Low | Preferred |
| `sudo -l` / `whoami /priv` | Medium | Often audited |
| Write probes | Medium | Only with `--auto-exploit`; marker deleted |

See [`docs/techniques.md`](docs/techniques.md) for detail.

## Build / cross-compile

See [`docs/build.md`](docs/build.md).

## Operator docs

- [`docs/operator-runbook.md`](docs/operator-runbook.md) — comprehensive copy-paste deploy & run steps (Linux + Windows)
- [`docs/architecture.md`](docs/architecture.md) — module layout and data flow
- [`docs/architecture-diagram.md`](docs/architecture-diagram.md) — end-to-end visual architecture
- [`docs/build.md`](docs/build.md) — toolchain and cross targets
- [`docs/installation.md`](docs/installation.md) — release installation and source builds
- [`docs/user-guide.md`](docs/user-guide.md) — simple operator workflow
- [`docs/cli-reference.md`](docs/cli-reference.md) — complete commands, flags, output modes, and exit codes
- [`docs/techniques.md`](docs/techniques.md) — per-class risk notes
- [`docs/design.md`](docs/design.md) — design decisions
- [`docs/capabilities.md`](docs/capabilities.md) — capability matrix
- [`docs/first-user-journey.md`](docs/first-user-journey.md) — first-run contract

## Configuration

Environment variables:

- `STEALTHY_AUTHORIZED=1` — same as the authorization CLI flag
- `STEALTHY_EXFIL_URL` — default for `--exfil-url`

## Safety guarantees (v1)

1. Refuses to run without authorization acknowledgment
2. Default = enumerate + recommend
3. High-impact families require `--allow-techniques` (not hard-refused; see `docs/techniques.md`)
4. Findings stay encrypted in memory; memory mode does not create an artifact
   ledger. Explicit file, checkpoint, or staging operations write tracked files.
5. Comments warn where techniques create artifacts or EDR telemetry
