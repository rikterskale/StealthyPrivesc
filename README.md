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
| High-impact techniques | Opt-in (`--allow-techniques`); scaffolded in this build |
| Disk writes | Off by default (encrypted in-memory results) |
| Script fallbacks | Provided when a custom binary cannot run |

## Architecture

```text
crates/stealthy/          Rust core (static-friendly release profile)
  src/core/               OS detect, identity, plugin runner, encrypted store, evasion helpers
  src/plugins/linux/      Linux checks (15): sudo, SUID, cron/systemd/timers, containers, groups, polkit, mounts, ssh keys, PATH/LD, CVE hints, NFS, creds, services, wildcards, endpoint controls
  src/plugins/windows/    Windows checks (11): privileges/Potato hint, services, tasks, AIE, UAC, DLL paths, creds, admins, PATH, autoruns, endpoint controls
  src/exploit/            Reversible probes + `--allow-techniques` scaffolding
scripts/linux/            Bash + Python fallbacks (no custom binary; includes control checks)
scripts/windows/          PowerShell + JScript + MSBuild host stubs (includes control checks)
docs/                     Architecture, build, technique risk notes
```

## Quick start

### Install a published release

Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/rikterskale/StealthyPrivesc/main/scripts/install.sh | bash
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/rikterskale/StealthyPrivesc/main/scripts/install.ps1 | iex
```

Both installers verify the release SHA-256 checksum. For high-assurance
environments, download and review the script before execution.

```bash
# Build (Linux host)
cargo build -p stealthy --release

# First-run guide (no auth required)
./target/release/stealthy doctor
./target/release/stealthy guide
./target/release/stealthy disclaimer

# Enumerate (required authorization flag; --authorized is the short alias)
./target/release/stealthy --authorized scan

# High-signal only + live progress
./target/release/stealthy --authorized enum --min-severity high

# OPSEC profile (skips audited sudo -l; higher delay)
./target/release/stealthy --authorized --profile quiet enum

# Quiet + select plugins
./target/release/stealthy --authorized -q \
  enum --plugins linux.sudo,linux.containers,linux.suid,linux.groups

# Triage stub for stepwise probe approval
./target/release/stealthy --authorized enum --triage --triage-out decisions.json

# Stage a drop bundle on the operator workstation
./target/release/stealthy stage --os linux --out ./drop \
  --binary ./target/release/stealthy

# Run the staged bundle through the policy-bound dispatcher
# (the staged manifest carries the primary-run authorization context)
bash ./drop/scripts/run.sh --profile balanced enum

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

# High-impact families (scaffold; payloads land in follow-up work)
./target/release/stealthy --authorized enum \
  --allow-techniques kernel-exploit,potato,msi
```

### Script-only fallbacks

Use the staged dispatcher as the normal entrypoint. It verifies the approved
manifest, stages the bundle, tries the primary executable, and automatically
selects an approved script fallback only when the executable cannot launch.
It injects the authorization acknowledgment required by the primary binary;
the manifest carries the inherited ROE context and binds execution to the
current host without granting permission or overriding host policy.

```bash
bash ./drop/scripts/run.sh --profile balanced enum
```

On Windows:

```powershell
& .\drop\scripts\run.ps1 --profile balanced enum
```

Use direct scripts only for troubleshooting or when the dispatcher itself is
not an approved execution path.

```bash
# Linux
bash scripts/linux/enum.sh
python3 scripts/linux/enum.py

# Windows (examples)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows\enum.ps1
cscript //nologo scripts\windows\enum.js
```

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
| `enum --auto-exploit` | Opt-in reversible probes |
| `enum --allow-techniques a,b` | Opt-in high-impact families (scaffold) |
| `enum --plugins a,b` | Enable listed plugins |
| `enum --skip a,b` | Skip listed plugins |

Exit codes: `0` ok · `2` missing authorization · `4` `--fail-on` triggered

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
3. High-impact families require `--allow-techniques` (scaffolded; not hard-refused)
4. Results stay in memory unless you explicitly request file/remote output
5. Comments warn where techniques create artifacts or EDR telemetry
