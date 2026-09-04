# Runbook pre-flight

Complete this page before every target. It is intentionally short; use the
[full pre-flight reference](../operator-runbook.md#0-pre-flight-do-this-every-time)
for expanded transport and evidence notes.

## Required decisions

- Written ROE covers the target, account/context, local enumeration, and
  evidence handling.
- The target identifier, approved transport, drop path, and cleanup owner are
  known. How the kit reaches the host is documented in
  [Delivery](delivery.md).
- The first run will be enumerate-only and memory-only unless evidence policy
  requires otherwise.
- Any `--auto-exploit` use has separate approval, maintenance awareness, and a
  rollback owner.
- The selected binary, target triple, and expected SHA-256 are recorded.

## Operator worksheet

```text
Engagement / case ID:       ______________________________
ROE / authorization ref:    ______________________________
Target identifier:          ______________________________
Approved account/context:   ______________________________
Approved transport:         ______________________________
Approved drop path:         ______________________________
Approved plugin scope:      all / _________________________
Output policy:              memory / sealed / approved JSON
Evidence classification:   ______________________________
Stop contact:               ______________________________
Cleanup owner:              ______________________________
```

## Read-only context checks

Run only the checks appropriate to the approved access method. Record unexpected
elevation; root/SYSTEM visibility is not equivalent to a standard-user run.

Linux:

```bash
set -eu
printf 'host='; hostname
printf 'user='; id -un
printf 'uid='; id -u
printf 'arch='; uname -m
printf 'kernel='; uname -sr
```

Windows PowerShell:

```powershell
$ErrorActionPreference = 'Stop'
Write-Host "host=$env:COMPUTERNAME"
Write-Host "user=$([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Host "arch=$env:PROCESSOR_ARCHITECTURE"
Write-Host "os=$([Environment]::OSVersion.Version)"
Get-ExecutionPolicy -List
```

## Stop conditions

Stop and contact the engagement owner if the host, account, scope, binary hash,
or execution context is unexpected; a requested action would exceed the ROE;
the target becomes unstable; a report key is exposed; or a required plugin
fails and the missing coverage affects the conclusion.

Use the authorization gate only after this review:

```bash
STEALTHY_AUTHORIZED=1
```

The gate does not replace written authorization.
