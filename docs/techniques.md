# Technique risk notes

All techniques assume **written authorization**. Default mode only enumerates and recommends.

## Linux

| Technique | Plugin / script | Noise | Artifacts | Auto-exploit |
| --- | --- | --- | --- | --- |
| Readable sudoers / NOPASSWD | `linux.sudo` | Low | None | Recommend only |
| `sudo -l` / `sudo --version` | `linux.sudo` | Medium | Audit logs | Never auto-run abuse |
| SUID/SGID / capabilities | `linux.suid` | Low–Medium | None | Never execute abuse |
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
| AppArmor / SELinux / noexec / audit signals | `linux.endpoint_controls` | Low–Medium | None | Recommend script fallbacks; `endpoint-bypass` scaffold only |

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
| AppLocker / WDAC / SmartScreen / AMSI / AV-EDR signals | `windows.endpoint_controls` | Low–Medium (AV scan noisy) | None | Recommend script fallbacks; `endpoint-bypass` scaffold only |

## High-impact opt-in (`--allow-techniques`)

These families are no longer hard-refused. They remain off by default and require
an explicit CLI opt-in when ROE permits. In this revision the flag is accepted
and recorded as scaffold findings; payload execution lands in follow-up work.

| ID | Family |
| --- | --- |
| `persistence` | Persistence without separate consent prompts |
| `host-crash` | Host-crash testing |
| `potato` | Automatic Potato / named-pipe abuse |
| `kernel-exploit` | Kernel exploit execution |
| `service-replace` | Service binary replacement |
| `msi` | MSI payload construction/execution |
| `credential-dump` | Credential dumping/exfiltration |
| `endpoint-bypass` | Alternate-path scaffolding when controls constrain custom binaries (no disable/evasion payloads) |

### Endpoint controls: detection vs alternate paths

Stealthy **detects and reports** AppLocker, WDAC/CI, SmartScreen, AMSI providers,
Defender/AV-EDR registry signals, AppArmor, SELinux, and `noexec` drop mounts.
It does **not** disable or evade those controls.

When a custom binary cannot run, use approved fallbacks:

| Constraint | Approved path |
| --- | --- |
| Linux ELF blocked / `noexec` / AppArmor | `scripts/linux/enum.sh` or `enum.py` |
| Windows PE blocked (AppLocker/WDAC/SmartScreen) | `scripts/windows/enum.ps1`, `enum.js`, or `EnumTasks.csproj` |
| PowerShell constrained but `cscript` allowed | `enum.js` |
| ROE permits recording alternate-path intent | `--allow-techniques endpoint-bypass` (scaffold findings only) |

Example:

```bash
stealthy --authorized enum --allow-techniques kernel-exploit,potato,msi
```
