# Technique risk notes

All techniques assume **written authorization**. Default mode only enumerates and recommends.
Direct script fallbacks enforce the same operator acknowledgment as the Rust
binary: pass `--authorized` (or the full acknowledgment flag) or set
`STEALTHY_AUTHORIZED=1`. A staged manifest approves the fallback path but does
not itself grant authorization.

## Technique contract (endpoint / application controls)

This section is the authoritative contract for how Stealthy interacts with
AppLocker, WDAC/CI, SmartScreen, AMSI, ETW-related posture signals, Defender/AV,
EDR sensors, AppArmor, SELinux, fapolicyd, and `noexec` mounts.

### In scope

| Layer | Behavior | Gate |
| --- | --- | --- |
| Detect | Read-only inventory of policy, provenance, sensor, and audit signals | Default enum plugins / `live-controls` |
| Alternate path | Recommend approved script hosts and signed packaging when a custom binary cannot run | Default recommendations |
| Opt-in tracking | Record that endpoint alternate-path work is ROE-approved for this run | `--allow-techniques endpoint-bypass` |
| Approved-fixture validation | Predict trust/policy outcome for an operator-supplied artifact, and optionally run **benign, disposable fixture probes** to observe allow / audit / block telemetry | `--artifact` (read-only prediction); `controls` / `validate-controls --execute` for opt-in probes; pair with `endpoint-bypass` when ROE covers validation |

### Not under `endpoint-bypass` (current contract)

`--allow-techniques endpoint-bypass` means **alternate-path + approved validation**
only. It does **not** authorize control disable, unhook, kill, quarantine
tamper, or evasion. Those behaviors are tracked as **planned, separately gated
technique families** below. AMSI, ETW, and AV/EDR already have distinct IDs,
but they are scaffold markers only. Any future execution requires an explicit
ROE gate, tests, safety/restoration review, and a contract rewrite.

Until those families ship, the supported response when a custom binary is
blocked is detect → recommend → script/dispatcher fallback (and optional
approved-fixture validation).

### Operator workflow when a binary is constrained

| Constraint | Approved path (today) |
| --- | --- |
| Linux ELF blocked / `noexec` / AppArmor | staged `run.sh` (`python → bash → sh → perl`) or direct `enum.py` / `enum.sh` / `enum-posix.sh` / `enum.pl` |
| Windows PE blocked (AppLocker/WDAC/SmartScreen/AV) | Dispatcher `run.ps1` chain, or `enum.ps1` / `enum.js` / `EnumTasks.csproj` |
| Defender/AV quarantines the staged PE | Prefer non-`TEMP` drop path + lab exclusion/signing; use dispatcher fallback. Stronger interference is Planned (separate family) |
| PowerShell constrained but `cscript` allowed | `enum.js` |
| ROE permits alternate-path tracking | `--allow-techniques endpoint-bypass` |
| ROE permits policy outcome validation | `--artifact PATH` and/or `stealthy --authorized controls --execute` with disposable fixtures |

```bash
# Record ROE-approved alternate-path / validation intent during enum
stealthy --authorized enum --allow-techniques endpoint-bypass \
  --plugins linux.endpoint_controls,linux.app_control \
  --artifact /approved/test/artifact

# Separate control-validation harness (benign fixtures; optional --execute)
stealthy --authorized controls --execute
```

### Enum-time wiring to validation commands

When `endpoint-controls` reports a blocking constraint, or when
`--allow-techniques endpoint-bypass` is opted in, findings set
`technique_id=endpoint-bypass` and populate **What's next** / `next_command`
with concrete validation steps:

| State | Primary `next_command` |
| --- | --- |
| Opted in + `--artifact PATH` | `stealthy --authorized live-controls --format json --artifact PATH` |
| Opted in, no artifact | `stealthy --authorized controls --execute` |
| Not opted in | `stealthy --authorized enum --allow-techniques endpoint-bypass --plugins …endpoint_controls,…app_control` |

What's-next text also lists the secondary step (artifact prediction ↔ fixture
`--execute`) and reminds operators that `endpoint-bypass` is alternate-path +
validation only.

---

## Evasion technique families (scaffold/planned only)

These IDs are **explicitly gated** and require `--authorized`, the exact
`--allow-techniques <id>`, and `--confirm-evasion`. Passing all gates records a
`scaffold` finding only. Dormant source prototypes are retained for future
review, but they are not declared, compiled, dispatched, or included in release
kits. No executable payload is available through the current product surface.

| Technique ID | Contract in this build | Gate |
|--------------|------------------------|------|
| `amsi-bypass` | Planned marker; no AMSI patching or weakening | `--allow-techniques amsi-bypass --confirm-evasion` |
| `etw-unhook` | Planned marker; no ETW patching, unhooking, or provider disablement | `--allow-techniques etw-unhook --confirm-evasion` |
| `av-edr-service` | Planned marker; no service/driver/sensor manipulation | `--allow-techniques av-edr-service --confirm-evasion` |

The extra confirmation records that the planned family is inside the ROE; it
does not make an implementation available. See [Evasion-family status](evasion.md).

---

## Linux

| Technique | Plugin / script | MITRE (default) | Noise | Artifacts | Auto-exploit |
| --- | --- | --- | --- | --- | --- |
| Readable sudoers / NOPASSWD | `linux.sudo` | T1548.003 | Low | None | Recommend only |
| `sudo -l` / `sudo --version` | `linux.sudo` | T1548.003 | Medium | Audit logs | Skipped under `--profile quiet`; never auto-run abuse |
| SUID/SGID / capabilities | `linux.suid` | T1548.001 | Low–Medium | None | Never execute abuse |
| Writable systemd/cron/timers | `linux.systemd_cron` | Low | Probe marker if auto | Reversible probe only |
| Container sockets / groups | `linux.containers` | Low | None | Never start containers |
| Interesting groups | `linux.groups` | Low | None | Recommend only |
| Polkit / pkexec | `linux.polkit` | Low | Probe marker if auto | Reversible dir probe only |
| Mounts / writable passwd | `linux.mounts` | Low | None | Never modify passwd |
| SSH private keys / authorized_keys | `linux.ssh_keys` | Low | None | Never print key bytes |
| Writable PATH / LD_* | `linux.path_ld` | Low | Probe marker if auto | Reversible probe only |
| Distro/package-aware kernel CVE hints | `linux.kernel_cve` | Low | None | Version-range hint with distro-backport uncertainty; kernel execution remains scaffolded |
| NFS `no_root_squash` | `linux.nfs` | Low | None | Recommend only |
| Readable shadow/backups | `linux.credentials` | Low | None | Presence/readability evidence only; `credential-dump` is scaffold-only |
| Writable service configs | `linux.services` | Low | None | Recommend only |
| Cron wildcard hints | `linux.wildcard_cron` | Low | None | Recommend only |
| AppArmor / SELinux / noexec / audit signals | `linux.endpoint_controls` | Low–Medium | None | Script fallbacks; `endpoint-bypass` = alternate-path + approved-fixture validation |

## Windows

| Technique | Plugin / script | Noise | Artifacts | Auto-exploit |
| --- | --- | --- | --- | --- |
| Token privileges / Potato hint | `windows.privileges` | Low | None | Opt-in via `--allow-techniques potato` (scaffold) |
| Unquoted / writable services + parent dirs | `windows.services` | Low–Medium | Probe marker if auto | Parent-dir probe; replace via `service-replace` |
| Scheduled task XML / writable actions | `windows.scheduled_tasks` | Low | None | Recommend only |
| AlwaysInstallElevated | `windows.always_install_elevated` | Low | MSI would be high | Opt-in via `--allow-techniques msi` (scaffold) |
| UAC policy | `windows.uac` | Low | None | Recommend only |
| DLL search/app-directory ACL candidates | `windows.dll_hijack` | Low read-only; medium if probing | None by default; temporary marker only when approved | Read-only enumeration is default; write confirmation is finding-scoped via approval or explicit `--auto-exploit` |
| Unattend / SAM backups | `windows.credentials` | Low | None | Presence evidence only; `credential-dump` is scaffold-only |
| Local admins / sessions | `windows.admin_sessions` | Low | None | Recommend only |
| PATH hijack candidates | `windows.env_path` | Low–Medium | Probe marker if auto | Reversible probe only |
| Autoruns / Startup | `windows.autoruns` | Low–Medium | Probe marker if auto | Startup dir probe; persistence via `persistence` |
| Service/task ACLs | `windows.services`, `windows.scheduled_tasks` | Low | None | Service-object DACL, registry-backed task security descriptors for `WRITE_DAC`/`WRITE_OWNER`/`DELETE`, and service/task file ACLs |
| AppLocker / WDAC / SmartScreen / AMSI / AV-EDR signals | `windows.endpoint_controls` | Low–Medium (AV scan noisy) | None | Script fallbacks; `endpoint-bypass` = alternate-path + approved-fixture validation |

Linux sudo/SUID/wildcard-cron findings can carry allowlisted `gtfobins.*`
metadata. Windows service-image, scheduled-task-action, and autorun findings can
carry allowlisted `lolbas.*` metadata. These annotations are machine-readable,
set `recommend_only=true`, and never execute a catalog technique.

## High-impact opt-in (`--allow-techniques`)

These families are off by default and require an explicit CLI opt-in when ROE
permits. Most families still record scaffold findings only in this revision;
payload execution for those families lands in follow-up work.

**Exception — `endpoint-bypass`:** the contract is fully defined here as
detect + alternate-path + approved-fixture validation. Control disable,
quarantine tamper, and related interference are **planned separate families**
(see above), not part of this ID.

| ID | Family | Contract in this build |
| --- | --- | --- |
| `persistence` | Persistence without separate consent prompts | Scaffold findings only |
| `host-crash` | Host-crash testing | Scaffold findings only |
| `potato` | Automatic Potato / named-pipe abuse | Scaffold findings only |
| `kernel-exploit` | Kernel exploit execution | Scaffold findings only |
| `service-replace` | Service binary replacement | Scaffold findings only |
| `msi` | MSI payload construction/execution | Scaffold findings only |
| `credential-dump` | Credential dumping/exfiltration | Scaffold findings only |
| `endpoint-bypass` | Endpoint alternate-path + approved-fixture validation | Opt-in tracking during enum; use `--artifact` and/or `controls --execute` for benign validation. Does not include AMSI/ETW/EDR/AppLocker/WDAC disable or quarantine tamper (those are Planned separate families) |
| `amsi-bypass` | AMSI interference | Separately confirmed scaffold/planned marker only; no execution |
| `etw-unhook` | ETW interference | Separately confirmed scaffold/planned marker only; no execution |
| `av-edr-service` | AV/EDR service or driver interference | Separately confirmed scaffold/planned marker only; no execution |

Example:

```bash
stealthy --authorized enum --allow-techniques kernel-exploit,potato,msi
stealthy --authorized enum --allow-techniques endpoint-bypass --artifact /approved/test/artifact
```
