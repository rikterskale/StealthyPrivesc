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
| Kernel CVE hints | `linux.kernel_cve` | Low | None | **Blocked** |
| NFS `no_root_squash` | `linux.nfs` | Low | None | Recommend only |
| Readable shadow/backups | `linux.credentials` | Low | None | Never dump hashes to disk |
| Writable service configs | `linux.services` | Low | None | Recommend only |
| Cron wildcard hints | `linux.wildcard_cron` | Low | None | Recommend only |

## Windows

| Technique | Plugin / script | Noise | Artifacts | Auto-exploit |
| --- | --- | --- | --- | --- |
| Token privileges / Potato hint | `windows.privileges` | Low | None | Recommend Potato-class only |
| Unquoted / writable services + parent dirs | `windows.services` | Low–Medium | Probe marker if auto | Parent-dir probe only |
| Scheduled task XML / writable actions | `windows.scheduled_tasks` | Low | None | Recommend only |
| AlwaysInstallElevated | `windows.always_install_elevated` | Low | MSI would be high | Never build/run MSI |
| UAC policy | `windows.uac` | Low | None | Recommend only |
| DLL search-path writability | `windows.dll_hijack` | Medium if probing | Temporary probe file | Only with `--auto-exploit` |
| Unattend / SAM backups | `windows.credentials` | Low | None | Never exfil beyond ROE |
| Local admins / sessions | `windows.admin_sessions` | Low | None | Recommend only |
| PATH hijack candidates | `windows.env_path` | Low–Medium | Probe marker if auto | Reversible probe only |
| Autoruns / Startup | `windows.autoruns` | Low–Medium | Probe marker if auto | Startup dir probe only |
| Service/task ACLs | `windows.services`, `windows.scheduled_tasks` | Low | None | Native read-only ACL check when available; no replacement |

## Explicitly refused

- Kernel exploits (any OS)
- Silent AMSI/ETW patching in the Rust core (script-path opt-in is documented as operator-controlled, not default)
- Persistence without explicit consent
- Crashing the host to prove a bug
- Automatic Potato / named-pipe abuse execution
