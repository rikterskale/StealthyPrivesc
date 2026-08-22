# StealthyPrivesc Capabilities

## Capability status

This document describes the implemented product on the current `main` revision.
The Rust core, Linux/Windows plugins, reversible-probe gate, evidence outputs,
and script fallbacks are present in this repository. The command surface below
is implemented, not a future roadmap; historical design notes belong in
[`docs/design.md`](design.md) or the project history.

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
| Linux plugins (16) | Done |
| Windows plugins (12) | Done |
| Endpoint-control detection | Done (`linux.endpoint_controls`, `windows.endpoint_controls`) |
| Application-control / EDR assessment | Done (`linux.app_control`, `windows.app_control`; read-only policy, provenance, sensor, audit, fixture validation, baseline drift, and detection-exposure inventory) |
| Script fallbacks | Done (includes endpoint-control checks) |
| Limited `--auto-exploit` probes | Done (PATH/polkit/timer/unquoted-parent) |
| `--allow-techniques` scaffolding | Done (flags + findings; no disable/evasion payloads) |
| Windows service/task ACL context | Native token-aware `AccessCheck` with read-only `icacls` fallback |
| Silent network C2 client | Deferred (operator-printed sealed blob) |
| Engagement profiles | Done (`quiet`, `balanced`, `thorough`, `ci`) |
| Stable finding IDs + attack paths | Done (schema v2) |
| MITRE / technique catalog | Done (engine-enriched) |
| Plugin timeouts + checkpoint/resume | Done |
| Artifact ledger + cleanup | Done |
| Triage approve-file + TTY | Done |
| Script JSON parity + ingest | Done (`enum.py --json`, `stealthy ingest`) |
| Delivery kit | Done (`stage`, `verify`, `one-liners`) |
| Fixture validation harness | Done (`controls` / `validate-controls`; disposable fixtures, optional benign probes, and structured case results) |

### Linux plugin IDs

`linux.sudo`, `linux.suid`, `linux.systemd_cron`, `linux.containers`, `linux.groups`, `linux.polkit`, `linux.mounts`, `linux.ssh_keys`, `linux.path_ld`, `linux.kernel_cve`, `linux.nfs`, `linux.credentials`, `linux.services`, `linux.wildcard_cron`, `linux.endpoint_controls`, `linux.app_control`

Note: `linux.docker` was renamed to **`linux.containers`** (docker/podman/containerd/LXD).

### Windows plugin IDs

`windows.privileges`, `windows.services`, `windows.scheduled_tasks`, `windows.always_install_elevated`, `windows.uac`, `windows.dll_hijack`, `windows.credentials`, `windows.admin_sessions`, `windows.env_path`, `windows.autoruns`, `windows.endpoint_controls`, `windows.app_control`

## Implemented command surface

| Command | Purpose |
| --- | --- |
| `stealthy guide` | First-run operator guide (no auth) |
| `stealthy doctor` | Local platform, plugin, and working-directory readiness check (no auth) |
| `stealthy disclaimer` | Print legal / ethical text (no auth) |
| `stealthy list-plugins` | List compiled plugin IDs (table or `--tsv`) |
| `stealthy enum` / `stealthy scan` | Run enumeration (default mode) |
| `stealthy enum --auto-exploit` | Add reversible probes |
| `stealthy enum --allow-techniques ...` | Opt into high-impact families (scaffold) |
| `stealthy enum --plugins ...` | Select plugins |
| `stealthy enum --skip ...` | Skip plugins |
| `stealthy report PATH --key-hex KEY` | Decode a sealed report locally (no host access) |
| `stealthy diff BASELINE CURRENT` | Compare plaintext JSON reports offline |
| `stealthy live-controls` / `collect-controls` | Collect live application-control, provenance, EDR, integrity, MAC, kernel, mount, container, and audit state |

Authorization is required for `list-plugins`, `enum`, and `scan`; it is not
required for `guide`, `doctor`, `disclaimer`, `report`, or `diff`. The visible
`--authorized` flag is an alias for the full acknowledgment flag, and
`STEALTHY_AUTHORIZED=1` is the supported environment equivalent.

## Live control capability matrix

Every requested live capability is tracked below. The collection command is
read-only and writes each result into the structured `ControlAssessment` JSON.

| # | Capability | Status | Collector/report location |
| ---: | --- | --- | --- |
| 1 | AppLocker/WDAC policy-file parsing and publisher/product/version rule evaluation | Implemented | Windows effective-policy snapshots, parsed `policies[].rules`, and artifact `policy_rule` |
| 2 | Static DLL/MSI/.NET/plugin fixture analysis and policy classification | Implemented | Artifact `static_analysis`, `kind`, `signature_status`, and `policy_rule` |
| 3 | ACL snapshot parsing and user-writable vs administrator-controlled classification | Implemented | Artifact `access_control` and `path_class` |
| 4 | Exported Windows/Linux event-log collection and correlation | Implemented | `audit_sources[]` recent counts, denial counts, artifact matches, last event, and snapshot hash |
| 5 | Managed-installer policy/provenance evidence | Implemented | Managed-installer/ISG policy rules, Defender preference evidence, artifact origin and signer metadata |
| 6 | Driver/module signature and HVCI/lockdown compatibility metadata | Implemented | Windows driver inventory; Linux `modinfo`, `modprobe --dry-run`, lockdown, and artifact signature evidence |
| 7 | RPM/DEB metadata, repository-signature, fapolicyd-rule, and custom-trust collection | Implemented | Package-manager policy, package trust evidence, fapolicyd rules/trust entries, and effective trust check |
| 8 | IMA xattr and fs-verity metadata/digest collection | Implemented | Artifact `integrity_status` and IMA/fs-verity evidence |
| 9 | SELinux/AppArmor profile and denial-log collection/correlation | Implemented | MAC policy/context notes plus live audit-source denial correlation |
| 10 | Mount, SUID, and file-capability metadata/policy classification | Implemented | Mount summary, artifact `mount_options`, POSIX mode/owner, and `getcap` evidence |
| 11 | Host/container identity and baseline comparison | Implemented | Namespace/container notes plus `controls --baseline` drift comparison |
| 12 | EDR inventory normalization from native host state | Implemented | Defender/Sense/SecurityCenter, MDE Linux, known sensor processes, prevention rules, and log availability |
| 13 | Deterministic live telemetry scoring | Implemented | `live_telemetry_score`, `live_telemetry_label`, and per-source event measurements |

Primary implementation: `crates/stealthy/src/core/controls.rs`. Primary command:
`stealthy --authorized live-controls --format json`.

Global options: `-q`, `-v`, `--no-color`, `--format`, `--min-severity`,
`--fail-on`, `--delay-ms`, `--output`, `--output-path`, `--plaintext-file`,
`--also-markdown`, and `--exfil-url`.

## Artifact workflow

Default: no artifacts.

Optional:

1. Encrypted seal file via `--output file --output-path PATH`
2. Plaintext JSON via `--plaintext-file`
3. Operator-driven remote POST instructions via `--output remote --exfil-url URL`

## Security, privacy, and operational controls

- Required authorization acknowledgment
- High-impact techniques off by default; require `--allow-techniques`
- Noisy techniques labeled in findings
- Effective Linux owner/group/other permission evaluation for service, systemd, and cron paths
- Sudoers findings filtered against the current username and supplementary groups
- Windows service-account context, token-aware read-only ACL checks, and Winlogon persistence coverage
- Low-and-slow delay knob
- Script fallbacks when binaries are blocked

## Explicitly out of scope for v1
- Fully autonomous multi-host C2 without operator-driven orchestration

## Phase 2 coverage (implemented)

- POSIX ACL-aware writable-path evaluation with conservative `getfacl` fallback
- Windows token-context metadata, read-only ACL evaluation, machine PATH, and Winlogon coverage
- Machine-readable finding assessments for confidence, applicability, and evidence quality
- User-level systemd and current-user crontab inspection

## Phase 3 coverage (implemented)

- Run provenance and per-plugin timing telemetry
- Offline baseline comparison and finding drift detection
- Markdown/SARIF provenance fields for evidence workflows
- Backward-compatible report loading
- Rust LCOV coverage artifact published by CI for every validated revision
