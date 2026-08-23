# Evidence and recovery

Handle output validation, key custody, cleanup, and interruption recovery.
The [full runbook](../operator-runbook.md) contains expanded procedures for
sealed output, baseline comparison, review checklists, and multi-host batch
operations.

## Validate output

1. Confirm the report identifies the expected hostname, user, architecture,
   and elevation context.
2. Confirm the expected plugins ran and no material plugin has `status=error`.
3. Verify the mode is `enumerate-only` unless probe approval says otherwise.
4. Parse machine output before treating it as evidence:

   ```bash
   python3 -m json.tool findings.json >/dev/null
   ```

## Sealed output and key custody

Use `--verbose` without `--quiet` so the key is printed to stderr. Move the
key immediately into the approved secret store. Do not store the key beside
the sealed file, in shell history, or in an ordinary ticket.

```bash
BIN=/approved/drop/stealthy
OUT=/approved/evidence/findings.seal
STEALTHY_AUTHORIZED=1 "$BIN" --verbose \
  --output file --output-path "$OUT" --also-markdown enum \
  2> /approved/evidence/run.stderr.txt
sha256sum "$OUT"
```

Decrypt sealed reports on an approved operator workstation:

```bash
"$BIN" report "$SEALED" --key-hex "$KEY_HEX" --format json > findings.json
"$BIN" report "$SEALED" --key-hex "$KEY_HEX" --format markdown > review.md
```

## Cleanup

Complete evidence capture and validation before removing artifacts. Inspect the
approved drop directory before deletion.

Linux:

```bash
rm -f "$BIN" /tmp/findings.seal /tmp/findings.json /tmp/enum.sh /tmp/enum.py
rm -rf /tmp/.cache-update
```

Windows:

```powershell
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $Dir
```

Preserve shell history, event logs, and host telemetry unless the ROE
explicitly defines a separate auditable handling procedure.

## Recovery after interruption

If the process is interrupted, treat the run as incomplete until checked:

1. Record the UTC time, host, command, and observed interruption.
2. Check whether a report was fully written and whether its hash can be read.
3. Inspect the approved drop directory for partial binaries, scripts, sealed
   files, plaintext reports, or temporary archives.
4. Confirm no unexpected child process, service, or listener remains.
5. Either resume with a new run ID or close the host as incomplete; do not
   append new output to a partial report.

Linux check:

```bash
ps -eo pid,ppid,user,args | grep -E '[s]tealthy|[e]num\.(sh|py)' || true
ls -la /tmp/.cache-update 2>/dev/null || true
```

Windows check:

```powershell
Get-Process stealthy -ErrorAction SilentlyContinue |
  Select-Object Id, ProcessName, StartTime, Path
Get-ChildItem $Dir -Force -ErrorAction SilentlyContinue
```

## Review checklist

Before leaving the host, confirm:

- Report identity, mode, timestamp, and plugin coverage are correct.
- Findings tagged `noisy` or `artifacts` are called out in the engagement log.
- Output hashes, report run ID, and key custody are recorded off-host.
- The approved drop path has been inspected before cleanup.
- Any write probe has a recorded rollback or cleanup result.
