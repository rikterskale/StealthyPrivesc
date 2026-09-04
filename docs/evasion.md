# Evasion-family status

StealthyPrivesc gates AMSI bypass, ETW unhooking, and AV/EDR work behind
explicit operator opt-in. The IDs `amsi-bypass`, `etw-unhook`, and
`av-edr-service` are allowlisted technique families for authorized assessments.

Windows kits ship `scripts/evasion.ps1` under the `windows-evasion` feature
(`status=ready`, or `status=observed` for AV/EDR product matches). The module
applies the same three gates and is not invoked by the enumeration dispatcher
unless an operator opts into the family. The Rust companion modules in
`crates/stealthy/src/exploit/` are the matching entry points.

## Gates and resulting behavior

All three IDs require:

1. `--authorized` or `STEALTHY_AUTHORIZED=1`;
2. the exact family in `--allow-techniques`; and
3. `--confirm-evasion` or `STEALTHY_EVASION_CONFIRMED=1`.

```bash
stealthy --authorized --confirm-evasion enum \
  --allow-techniques amsi-bypass,etw-unhook,av-edr-service
```

## Family IDs

| ID | Purpose |
| --- | --- |
| `amsi-bypass` | Gated AMSI family entry point |
| `etw-unhook` | Gated ETW family entry point |
| `av-edr-service` | Read-only AV/EDR product observation plus a thorough operator playbook |

### `av-edr-service` (non-executing)

After the three gates pass, Rust:

- matches known products from read-only uninstall / Defender feature / process
  identity signals;
- emits `Enumeration` findings with `condition=av-edr-product-observed` (high)
  when a product is present;
- emits `av-edr-collection-limited` when signals are missing or unreadable;
- always emits `av-edr-playbook-ready` with comprehensive What's-next guidance.

The playbook covers ROE reconfirmation, live-controls / endpoint / app-control
inventory commands, host-local read-only verification, SOC telemetry
correlation, approved alternate paths (`endpoint-bypass`, signed staging,
dispatcher fallbacks, `controls --execute`), change-control exclusions /
quarantine restore via the asset owner, evidence capture, and hard-stop
conditions.

**This family does not stop services, patch memory, unload drivers, change
Defender preferences, or tamper with quarantine.** Primary next command:

```bash
stealthy --authorized live-controls --format json
```

Windows `evasion.ps1 -Technique av-edr-service` performs the same gate check and
optional read-only `Get-Service` / SecurityCenter2 observation. It always sets
`executed=false` and `modifies_controls=false`.

## `endpoint-bypass` remains separate

`--allow-techniques endpoint-bypass` covers alternate-path tracking plus
approved-fixture validation. Use the evasion-family IDs above for AMSI, ETW, or
AV/EDR-scoped work rather than folding that behavior into `endpoint-bypass`.

See [Technique risk notes](techniques.md) for the broader technique-family
notes.

## Script fallbacks

Windows Python, PowerShell 7, Windows PowerShell, Git-bash, JScript, and
MSBuild-hosted enumeration fallbacks are reduced, enumerate-only collectors
by default. Their JSON must report the data
actually collected and make native coverage gaps explicit. Opt-in evasion
modules remain separate from those collectors.

## Related documentation

- [Technique risk notes](techniques.md)
- [CLI reference](cli-reference.md)
- [Capabilities](capabilities.md)
- [Support policy](support-policy.md)
