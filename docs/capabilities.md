# StealthyPrivesc Capabilities

## Capability status

Implementation is active: Rust core, Linux/Windows plugins, and script fallbacks land in this repository revision. Historical note: earlier drafts described a greenfield docs-only tree; that is no longer accurate.

Source design: [`docs/design.md`](design.md)

Implemented phase scope: [`docs/phases.md`](phases.md)

First-user journey contract: [`docs/first-user-journey.md`](first-user-journey.md)

Operator deploy/runbook: [`docs/operator-runbook.md`](operator-runbook.md)

## Initial MVP capabilities

| Area | Status |
| --- | --- |
| Authorization gate | Done |
| OS + identity enumeration | Done |
| Encrypted in-memory store | Done |
| Linux plugins (14) | Done |
| Windows plugins (10) | Done |
| Script fallbacks | Done (extended for new checks) |
| Limited `--auto-exploit` probes | Done (non-kernel; PATH/polkit/timer/unquoted-parent) |
| Windows service/task ACL context | Native token-aware `AccessCheck` with read-only `icacls` fallback |
| Silent network C2 client | Deferred (operator-printed sealed blob) |

### Linux plugin IDs

`linux.sudo`, `linux.suid`, `linux.systemd_cron`, `linux.containers`, `linux.groups`, `linux.polkit`, `linux.mounts`, `linux.ssh_keys`, `linux.path_ld`, `linux.kernel_cve`, `linux.nfs`, `linux.credentials`, `linux.services`, `linux.wildcard_cron`

Note: `linux.docker` was renamed to **`linux.containers`** (docker/podman/containerd/LXD).

### Windows plugin IDs

`windows.privileges`, `windows.services`, `windows.scheduled_tasks`, `windows.always_install_elevated`, `windows.uac`, `windows.dll_hijack`, `windows.credentials`, `windows.admin_sessions`, `windows.env_path`, `windows.autoruns`

## Planned command surface

| Command | Purpose |
| --- | --- |
| `stealthy guide` | First-run operator guide (no auth) |
| `stealthy disclaimer` | Print legal / ethical text (no auth) |
| `stealthy list-plugins` | List compiled plugin IDs (table or `--tsv`) |
| `stealthy enum` | Run enumeration (default mode) |
| `stealthy enum --auto-exploit` | Add reversible probes only |
| `stealthy enum --plugins ...` | Select plugins |
| `stealthy enum --skip ...` | Skip plugins |
| `stealthy diff BASELINE CURRENT` | Compare plaintext JSON reports offline |

Global: `--authorized` (alias), `-q`, `-v`, `--no-color`, `--format`, `--min-severity`, `--fail-on`, `--delay-ms`, `--output`, `--output-path`, `--plaintext-file`, `--also-markdown`, `--exfil-url`.

## Artifact workflow

Default: no artifacts.

Optional:

1. Encrypted seal file via `--output file --output-path PATH`
2. Plaintext JSON via `--plaintext-file`
3. Operator-driven remote POST instructions via `--output remote --exfil-url URL`

## Security, privacy, and operational controls

- Required authorization acknowledgment
- Kernel exploits blocked
- Noisy techniques labeled in findings
- Effective Linux owner/group/other permission evaluation for service, systemd, and cron paths
- Sudoers findings filtered against the current username and supplementary groups
- Windows service-account context, token-aware read-only ACL checks, and Winlogon persistence coverage
- Low-and-slow delay knob
- Script fallbacks when binaries are blocked

## Explicitly out of scope for v1

- Kernel exploit execution
- Automatic MSI / service binary replacement
- Built-in AMSI/ETW patching in the Rust core
- Fully autonomous multi-host C2

## Phase 2 coverage

- POSIX ACL-aware writable-path evaluation with conservative `getfacl` fallback
- Windows token-context metadata, read-only ACL evaluation, machine PATH, and Winlogon coverage
- Machine-readable finding assessments for confidence, applicability, and evidence quality
- User-level systemd and current-user crontab inspection

## Phase 3 coverage

- Run provenance and per-plugin timing telemetry
- Offline baseline comparison and finding drift detection
- Markdown/SARIF provenance fields for evidence workflows
- Backward-compatible report loading
- Rust LCOV coverage artifact published by CI for every validated revision
