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
technique families** below — they require new `--allow-techniques` IDs, an
explicit ROE gate, tests, and a contract rewrite before shipping.

Until those families ship, the supported response when a custom binary is
blocked is detect → recommend → script/dispatcher fallback (and optional
approved-fixture validation).

### Operator workflow when a binary is constrained

| Constraint | Approved path (today) |
| --- | --- |
| Linux ELF blocked / `noexec` / AppArmor | `scripts/linux/enum.sh` or `enum.py` |
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

## Planned future enhancements

These items are **roadmap work for this repository** and are **not** part of
today's `endpoint-bypass` contract. Shipping any of them requires a **new**
`--allow-techniques` family ID (or IDs), an explicit ROE gate, tests, and a
contract rewrite — they must not silently land under `endpoint-bypass`.

| Enhancement | Notes |
| --- | --- |
| AMSI bypass / patching / blinding | New family; never under `endpoint-bypass` |
| ETW unhooking / patching / provider disablement | New family; never under `endpoint-bypass` |
| AppLocker / WDAC / SmartScreen policy weakening or removal | New family; policy-change is not validation |
| AV / EDR service stop or sensor unload | New family; opt-in interference when ROE allows |
| Quarantine restore / quarantine-tamper helpers | New family; recover or inspect quarantined delivery artifacts |
| Automated path-exclusion helpers | New family; lab/kit path exclusions distinct from disabling realtime |
| Generic control-disable / “hide from sensor” payloads | New family; ROE-gated product decision |
| Silent in-process HTTPS exfil client | Separate deferred item (see `docs/capabilities.md`) |
| Tighter enum→validation automation (auto-chain `controls --execute` when allowlisted + artifact present) | Optional UX; still alternate-path only under `endpoint-bypass` |

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
| Kernel CVE hints | `linux.kernel_cve` | Low | None | Opt-in via `--allow-techniques kernel-exploit` (scaffold) |
| NFS `no_root_squash` | `linux.nfs` | Low | None | Recommend only |
| Readable shadow/backups | `linux.credentials` | Low | None | Opt-in dump via `--allow-techniques credential-dump` |
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
| DLL search-path writability | `windows.dll_hijack` | Medium if probing | Temporary probe file | Only with `--auto-exploit` |
| Unattend / SAM backups | `windows.credentials` | Low | None | Opt-in dump via `--allow-techniques credential-dump` |
| Local admins / sessions | `windows.admin_sessions` | Low | None | Recommend only |
| PATH hijack candidates | `windows.env_path` | Low–Medium | Probe marker if auto | Reversible probe only |
| Autoruns / Startup | `windows.autoruns` | Low–Medium | Probe marker if auto | Startup dir probe; persistence via `persistence` |
| Service/task ACLs | `windows.services`, `windows.scheduled_tasks` | Low | None | Native read-only ACL check when available; replace via opt-in |
| AppLocker / WDAC / SmartScreen / AMSI / AV-EDR signals | `windows.endpoint_controls` | Low–Medium (AV scan noisy) | None | Script fallbacks; `endpoint-bypass` = alternate-path + approved-fixture validation |

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

Example:

```bash
stealthy --authorized enum --allow-techniques kernel-exploit,potato,msi
stealthy --authorized enum --allow-techniques endpoint-bypass --artifact /approved/test/artifact
```
