# StealthyPrivesc Capabilities

## Capability status

This document describes the shared implementation under development. Supported
deployment behavior is tied to tagged releases under the
[support policy](support-policy.md), not to an arbitrary `main` revision.
The Rust core, Linux/Windows plugins, reversible-probe gate, evidence outputs,
and script fallbacks are present in this repository. The command surface below
is implemented. Deferred and contract-gated ideas live in **Planned future
enhancements** below and in [`docs/techniques.md`](techniques.md); historical
design notes belong in [`docs/design.md`](design.md) or the project history.

Source design: [`docs/design.md`](design.md)

Implemented phase scope: [`docs/phases.md`](phases.md)

First-user journey contract: [`docs/first-user-journey.md`](first-user-journey.md)

Report contract: [`docs/report-schema.md`](report-schema.md)

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
| `--allow-techniques` scaffolding | Done (most families: flags + findings; `endpoint-bypass`: alternate-path + approved-fixture validation; AMSI/ETW/EDR disable and quarantine tamper are Planned separate families) |
| Windows service/task ACL context | Native service-object DACL evaluation, registry-backed Task Scheduler descriptor checks for `WRITE_DAC`/`WRITE_OWNER`/`DELETE`, token-aware service/task file ACL checks, and read-only `icacls` fallback |
| Silent network C2 client | Deferred (operator-printed sealed blob) |
| Engagement profiles | Done (`quiet`, `balanced`, `thorough`, `ci`) |
| Stable finding IDs + attack paths | Done (schema v2) |
| MITRE / technique catalog | Done (engine-enriched) |
| Plugin timeouts + checkpoint/resume | Done |
| Artifact ledger + cleanup | Done |
| Triage approve-file + TTY | Done; approve files are checkpoint/run-bound and reversible probes are scoped to exact finding IDs |
| Script JSON parity + ingest | Done (`enum.py --json`, `stealthy ingest`) |
| Delivery kit | Done (`stage`, `verify`, `one-liners`; tagged release kits also include binary, scripts, selected docs, manifest, checksums, SBOM, and attestation) |
| Fixture validation harness | Done (`controls` / `validate-controls`; disposable fixtures, optional benign probes, and structured case results) |
| Release provenance | Done (GitHub attestations, SHA-256 manifest, and SPDX JSON SBOMs) |
| Published architectures | Linux x86-64 GNU, Linux aarch64 GNU, Windows x86-64 MSVC |
| Tag release gate | Done (fmt, Clippy, tests, release/flavor builds, 80% coverage floor, script checks, Gitleaks, cargo-deny) |
| Nightly safe fixture lab | Done (Linux/Windows local fixtures and enum-only authorization contract; no destructive exploit lab) |
| Build flavors | Done (`full`, `enum-only`, `opsec-string-strip`; constrained flavors retain authorization/disclaimer/audit fields) |

### Detection-depth status

- `linux.suid` uses a bounded, cancellation-aware, same-filesystem walker that
  does not follow symlinks. Operators can set `STEALTHY_SUID_ROOTS`,
  `STEALTHY_SUID_MAX_DEPTH`, and `STEALTHY_SUID_MAX_ENTRIES`; the active
  profile's walk budget remains an upper bound. Capability xattrs are parsed
  directly without recursive `getcap` execution.
- Linux sudo, SUID/SGID, and selected wildcard-cron findings can carry
  structured `gtfobins.binary`, `gtfobins.functions`, and
  `gtfobins.url` annotations from a local allowlist. Windows service images,
  scheduled-task actions, and autoruns can carry allowlisted, machine-readable
  `lolbas.*` metadata. Both catalogs set `recommend_only=true`; no catalog
  technique is executed.
- Kernel CVE findings parse kernel versions and combine `/etc/os-release`,
  Ubuntu signature data, and bounded dpkg package metadata. Matches are
  version-range hints, explicitly account for distro backport uncertainty, and
  are not proof that a host is vulnerable.
- `windows.services` evaluates service-object DACLs and service/image-path
  filesystem ACLs. `windows.scheduled_tasks` evaluates task/action files and
  registry-backed task descriptors for `WRITE_DAC`, `WRITE_OWNER`, and
  `DELETE`. A descriptor that cannot be read is reported unavailable.
- `windows.dll_hijack` performs read-only search/app-directory ACL enumeration
  without `--auto-exploit`; reversible marker confirmation remains
  finding-scoped or available under explicit blanket `--auto-exploit`.
- PowerShell fallback JSON has per-plugin findings, coverage, error state, and
  capability delta, but explicitly omits service/task object DACLs and native
  ACL parity. JScript collects only AIE, credential-file presence, and selected
  endpoint-control registry signals; every other native plugin is marked
  skipped. No Windows fallback contains AMSI/ETW/AV-EDR interference.

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
| `stealthy enum --allow-techniques ...` | Opt into high-impact families (`endpoint-bypass` = alternate-path + approved-fixture validation; others mostly scaffold) |
| `stealthy enum --plugins ...` | Select plugins |
| `stealthy enum --skip ...` | Skip plugins |
| `stealthy controls` / `validate-controls` | Run disposable control-validation cases; authorization required |
| `stealthy live-controls` / `collect-controls` | Collect live read-only policy, sensor, provenance, and audit state; authorization required |
| `stealthy resume --checkpoint PATH` | Resume an interrupted run |
| `stealthy ingest PATH` | Normalize script JSON into report schema v2 |
| `stealthy artifacts` / `cleanup` | Inspect or remove ledger-recorded artifacts |
| `stealthy stage` / `verify` / `one-liners` | Package, verify, and print approved transport snippets |
| `stealthy report PATH --key-file KEY_PATH` | Decode a sealed report locally using the preferred protected key-file source (no host access) |
| `stealthy diff BASELINE CURRENT` | Compare plaintext JSON reports offline |
| `stealthy quickstart` / `demo` / `security-lab` | Guided first run, inert demo, and disposable local fixtures |
| `stealthy html-report` / `explain-finding` / `playbook` | Beginner report, finding explanation, and remediation guidance |
| `stealthy completions` / `plugin-picker` / `explain-plugin` | Shell UX and plugin discovery |
| `stealthy coverage-compare` / `disposition` | Fallback coverage gaps and review state tracking |
| `stealthy live-controls` / `collect-controls` | Collect live application-control, provenance, EDR, integrity, MAC, kernel, mount, container, and audit state |

Authorization is required for `list-plugins`, `enum`, `scan`, `controls`, and
`live-controls`; it is not required for `guide`, `doctor`, `disclaimer`,
`report`, `diff`, `ingest`, `artifacts`, `cleanup`, `stage`, `verify`, or
`one-liners`. The visible
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

Enumeration global options include `-q`, `-v`, `--no-color`, `--format`,
`--min-severity`, `--fail-on`, `--delay-ms`, `--plugin-timeout-ms`,
`--profile`, `--checkpoint`, `--ledger-dir`, `--output`, `--output-path`,
`--key-output-path`, `--plaintext-file`, `--also-markdown`, and `--exfil-url`. `controls` and
`live-controls` print directly and support JSON/Markdown/human formats;
SARIF, file output, remote output, and `--fail-on` are unsupported for those
reports.

## Artifact workflow

Default: no artifacts.

Optional:

1. Encrypted seal file via `--output file --output-path PATH --key-output-path KEY_PATH`
2. Plaintext JSON via `--plaintext-file`
3. Operator-driven remote POST instructions via `--output remote --exfil-url URL`

## Security, privacy, and operational controls

- Required authorization acknowledgment
- High-impact techniques off by default; require `--allow-techniques`
- Noisy techniques labeled in findings
- Effective Linux owner/group/other permission evaluation for service, systemd, and cron paths
- Sudoers findings filtered against the current username and supplementary groups
- Windows service-account context, native service-object DACL checks,
  registry-backed Task Scheduler security-descriptor checks, token-aware
  service/task file ACL checks, and Winlogon persistence coverage
- Profile-specific noise budgets for helper use, walk entries, and helper records
- Script fallbacks when binaries are blocked
- `control_assessment` during `enum` only when `*.app_control` is selected (`live-controls` always collects)
- `--profile quiet` disables external helpers and applies the smallest walk and
  helper-record budgets; balanced/CI remain bounded, while thorough permits
  external helpers and larger caps
- Findings sealed at rest in the in-memory store; memory-only runs do not create
  a ledger. Explicit checkpoints, file outputs, and staged bundles are tracked
  under the selected ledger directory (default `.cache-run`).
- Plugin timeouts cooperatively cancel Rust-side walks (helper child processes may still finish)
- Residual static signature risk remains (cleartext brand/plugin strings); rename via `stage --name` when ROE requires
- `doctor` returns exit code `3` when readiness checks fail; `2` remains the
  missing-authorization code and `4` remains the `--fail-on` code.

## Explicitly out of scope for v1
- Fully autonomous multi-host C2 without operator-driven orchestration
- Folding AMSI / ETW / EDR / AppLocker / WDAC disable, quarantine tamper, or
  evasion payloads into the current `endpoint-bypass` ID (see `docs/techniques.md`)

## Planned future enhancements

Intentional backlog. Items that change host protections require a distinct
technique-family ID, ROE gate, and contract revision — they must not ship under
today's `endpoint-bypass` meaning (alternate-path + approved-fixture
validation). The three listed evasion IDs already exist as scaffold markers;
dormant prototypes are retained in source but excluded from declaration,
compilation, dispatch, and release packaging.

| Enhancement | Status | Gate / notes |
| --- | --- | --- |
| Silent in-process HTTPS exfil client | Deferred | Operator-printed sealed blob today |
| AMSI bypass / patching / blinding | Scaffold/planned only | Separately confirmed ID; dormant prototype is not compiled, dispatched, or packaged |
| ETW unhooking / patching / provider disablement | Scaffold/planned only | Separately confirmed ID; dormant prototype is not compiled, dispatched, or packaged |
| AV / EDR service stop or sensor unload | Scaffold/planned only | Separately confirmed ID; dormant prototype is not compiled, dispatched, or packaged |
| AppLocker / WDAC / SmartScreen policy weakening or removal | Planned (contract change required) | New family; not validation |
| Quarantine restore / quarantine-tamper helpers | Planned (contract change required) | New family; delivery-PE recovery / inspection |
| Automated path-exclusion helpers | Planned (contract change required) | New family; kit-path exclusions ≠ disable realtime |
| Generic control-disable / "hide from sensor" payloads | Planned (contract change required) | New family; ROE-gated product decision |
| Auto-chain enum → `live-controls --artifact` / `controls --execute` when `endpoint-bypass` is allowlisted | Planned (UX) | Builds on current `next_command` wiring; still alternate-path only under `endpoint-bypass` |
| Additional high-impact family payload execution (`kernel-exploit`, `potato`, …) | Scaffold today | Existing allowlist IDs; follow-up revisions |

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
