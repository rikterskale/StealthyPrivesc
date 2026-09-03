# Evasion-family status

StealthyPrivesc does not execute AMSI bypasses, ETW unhooking, or AV/EDR
service manipulation. The IDs `amsi-bypass`, `etw-unhook`, and
`av-edr-service` are retained as separately gated, scaffold/planned technique
families so an operator can record ROE intent without running a payload.

Windows kits ship `scripts/evasion.ps1` as the separately reviewed
`windows-evasion-scaffolds` feature. The module applies the same three gates and
returns structured `planned`, `executed=false`, and `modifies_controls=false`
status. It contains no control-interference implementation and is not invoked
by the enumeration dispatcher. An allowlisted family produces a `scaffold`
finding with low-confidence scaffold evidence; it is not an `exploit_attempt`,
does not patch memory, does not alter providers, and does not change service
state.

The Rust companion modules in `crates/stealthy/src/exploit/` are compiled and
test-covered status gates. They contain no memory-patching, telemetry-unhooking,
or service-control APIs.

## Gates and resulting behavior

All three IDs require:

1. `--authorized` or `STEALTHY_AUTHORIZED=1`;
2. the exact family in `--allow-techniques`; and
3. `--confirm-evasion` or `STEALTHY_EVASION_CONFIRMED=1`.

The third gate is an explicit acknowledgment for the planned family. It does
not enable an implementation.

```bash
stealthy --authorized --confirm-evasion enum \
  --allow-techniques amsi-bypass,etw-unhook,av-edr-service
```

The command records scaffold findings only. There is no restoration workflow
because no protection or service is modified.

## Family contracts

| ID | Current contract | Explicitly not performed |
| --- | --- | --- |
| `amsi-bypass` | Separately gated scaffold/planned marker | AMSI patching, registry weakening, COM hijacking, or blinding |
| `etw-unhook` | Separately gated scaffold/planned marker | `NtTraceEvent`/`EtwEventWrite` patching, provider disablement, or unhooking |
| `av-edr-service` | Separately gated scaffold/planned marker | Service stop/pause/disable, driver unload, sensor tamper, or quarantine interference |

Any future implementation would require a new safety and restoration review,
tests, explicit release notes, and an update to this contract. The existence of
an allowlist ID must never be interpreted as payload availability.

## `endpoint-bypass` remains separate

`--allow-techniques endpoint-bypass` means alternate-path tracking plus
approved-fixture validation only. It can direct an operator to script
fallbacks, read-only artifact trust prediction, and benign disposable control
fixtures. It never authorizes or performs AMSI/ETW/AV/EDR/AppLocker/WDAC
disablement, unhooking, killing, or quarantine tampering.

See [Technique risk notes](techniques.md) for the authoritative endpoint and
high-impact-family contract.

## Script fallbacks

Windows PowerShell, JScript, and MSBuild-hosted enumeration fallbacks are
reduced, enumerate-only collectors. The dispatcher and enumeration scripts do
not import or invoke the separately shipped scaffold module. Their JSON must
report the data actually collected and make native coverage gaps explicit.

## Related documentation

- [Technique risk notes](techniques.md)
- [CLI reference](cli-reference.md)
- [Capabilities](capabilities.md)
- [Support policy](support-policy.md)
