# Evasion Techniques

This document describes the evasion technique families implemented in Stealthy. These techniques are **explicitly gated** and require both `--authorized` and `--allow-techniques <id>` plus `--confirm-evasion` for use.

## ⚠️ Warning

**These techniques are for authorized red team engagements only** and require explicit Rules of Engagement (ROE) approval. They may:

- Trigger security alerts
- Leave forensic artifacts  
- Crash systems or services
- Violate compliance requirements if not properly authorized

## Technique Families

### AMSI Bypass (`amsi-bypass`)

**What it does**: Disables Microsoft's Antimalware Scan Interface (AMSI) for the current process via memory patching.

**Implementation**: Patches the `AmsiScanBuffer` function in `amsi.dll` to return success immediately.

**Methods**:
- **Memory patching**: Modifies the first bytes of `AmsiScanBuffer` to `mov al, 0x01; ret`
- Future: COM-based bypass, registry manipulation

**Gate**: `--allow-techniques amsi-bypass --confirm-evasion`

**Risk**: High - evasion technique that will be detected by EDR sensors monitoring memory modifications.

**Restoration**: Original bytes are backed up and should be restored after completing authorized actions.

**Detection risks**:
- Memory protection changes (VirtualProtect calls)
- DLL function hooking/unhooking
- AMSI integrity checks
- EDR behavioral analysis

---

### ETW Unhooking (`etw-unhook`)

**What it does**: Disables Event Tracing for Windows (ETW) for the current process by patching ETW-related functions.

**Implementation**: Patches `NtTraceEvent` or `EtwEventWrite` in `ntdll.dll` to return `STATUS_SUCCESS` immediately.

**Methods**:
- **NtTraceEvent patch**: `xor eax, eax; ret`
- **EtwEventWrite patch**: Alternative target

**Gate**: `--allow-techniques etw-unhook --confirm-evasion`

**Risk**: High - evasion technique that disables audit logging.

**Restoration**: Original bytes are backed up and should be restored after completing authorized actions.

**Detection risks**:
- Memory protection changes
- Function integrity verification
- Out-of-process ETW providers
- Alternative logging paths

---

### AV/EDR Service Manipulation (`av-edr-service`)

**What it does**: Suspends, disables, or unloads AV/EDR services and drivers.

**Implementation**: Uses Windows Service Control Manager APIs to manipulate security services.

**Methods**:
- **Service suspend**: Pause service execution (if supported)
- **Service stop**: Terminate service completely
- **Service restore**: Restart previously stopped services

**Known targets**:
- `WinDefend` - Windows Defender
- `WdNisSvc` - Windows Defender Network Inspection
- `SecurityHealthService` - Windows Security Health
- `Sense` - Windows Defender ATP
- `WdFilter` - Windows Defender Filter

**Gate**: `--allow-techniques av-edr-service --confirm-evasion`

**Risk**: Critical - may crash systems, trigger immediate alerts, or leave system unprotected.

**Restoration**: Services should be restarted immediately after completing authorized actions.

**Detection risks**:
- Service control events logged in Security event log
- Protected Process Light (PPL) restrictions
- Driver signature enforcement
- Watchdog timers and service recovery

**Privilege requirements**: 
- `SeDebugPrivilege` often required
- Administrative privileges typically needed
- Some services may be protected (PPL)

---

## Usage

```bash
# Enable single evasion technique
stealthy --authorized --confirm-evasion enum --allow-techniques amsi-bypass

# Enable multiple evasion techniques
stealthy --authorized --confirm-evasion enum \
  --allow-techniques amsi-bypass,etw-unhook,av-edr-service

# Using environment variable for confirmation
export STEALTHY_EVASION_CONFIRMED=1
stealthy --authorized enum --allow-techniques amsi-bypass
```

## Approval Gates

Evasion techniques require three layers of approval:

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| 1. Global Auth | `--authorized` / `STEALTHY_AUTHORIZED=1` | Acknowledge authorized use |
| 2. Technique Opt-in | `--allow-techniques <id>` | Explicitly opt into the technique family |
| 3. Evasion Confirmation | `--confirm-evasion` / `STEALTHY_EVASION_CONFIRMED=1` | Extra acknowledgment for evasion techniques |

## Best Practices

1. **Document everything**: Record timestamps, techniques used, and restoration steps
2. **Restore immediately**: Always restore original state after completing authorized actions
3. **Test in lab**: Validate techniques in a controlled environment before production use
4. **Monitor alerts**: Have Blue Team monitor for expected detections
5. **Have rollback plan**: Know how to manually restore if automated restoration fails
6. **Check ROE**: Ensure Rules of Engagement explicitly permit these techniques

## Integration Points

### Rust API

```rust
use stealthy::exploit::{amsi_bypass, etw_unhook, av_edr_service};

// Check gates first
amsi_bypass::check_evasion_gate(authorized, allowed, confirm_evasion)?;

// Execute bypass
let result = amsi_bypass::amsi_bypass_patch()?;

// ... perform authorized actions ...

// Restore original state
result.restore()?;
```

### PowerShell Fallbacks

See `scripts/windows/evasion.ps1` for PowerShell equivalents when the Rust binary cannot run.

## Related Documentation

- [`docs/techniques.md`](techniques.md) - Overall technique catalog
- [`docs/cli-reference.md`](cli-reference.md) - CLI options including `--allow-techniques`
- [`docs/capabilities.md`](capabilities.md) - Capability matrix
