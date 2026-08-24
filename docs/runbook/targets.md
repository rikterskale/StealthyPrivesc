# Target operations

Choose the smallest approved deployment and execution path. The [full runbook](../operator-runbook.md)
contains the complete SCP, rsync, SFTP, WinRM, SMB, HTTP, constrained-channel,
and script-only variants.

## Linux

Detailed procedures: [deploy](../operator-runbook.md#2-deploy-to-a-linux-target)
and [run](../operator-runbook.md#3-run-on-a-linux-target).

1. Create the approved remote drop directory.
2. Copy the target-matched binary over the approved transport.
3. Set the minimum required mode and verify `--help`, file type, and SHA-256.
4. Run local `guide`, `doctor`, and `disclaimer` if the artifact is new.
5. After the authorization pause, list plugins and run one visible baseline:

   ```bash
   BIN=/approved/drop/stealthy
   "$BIN" doctor
   "$BIN" --authorized list-plugins
   "$BIN" --authorized enum
   ```

6. Inspect identity, mode, plugin coverage, and errors before narrowing scope.
7. Run the staged dispatcher. It reuses the approved manifest, tries the
   binary, and walks approved script hosts if the binary cannot launch
   (`python → bash → sh → perl`). Record reduced coverage rather than
   bypassing the control. Script tiers only forward auth and `--json`.

## Windows

Detailed procedures: [deploy](../operator-runbook.md#4-deploy-to-a-windows-target)
and [run](../operator-runbook.md#5-run-on-a-windows-target).

1. Create the approved remote drop directory through the approved channel.
2. Copy the target-matched `.exe` and verify it with `Get-FileHash`.
3. Run `doctor`, `guide`, and `disclaimer` before authorization.
4. After the authorization pause, list plugins and run one visible baseline:

   ```powershell
   $Stealthy = 'C:\approved\drop\stealthy.exe'
   & $Stealthy doctor
   & $Stealthy --authorized list-plugins
   & $Stealthy --authorized enum
   ```

5. Run `scripts\run.ps1` from the staged bundle. If SmartScreen, AppLocker,
   WDAC, or another policy blocks the executable, the dispatcher records the
   launch failure and walks the manifest-approved hosts in order:
   **powershell → jscript → msbuild**. Each blocked tier continues to the
   next; script coverage is reduced and only auth / `--json` are forwarded.
   Use `--allow-techniques endpoint-bypass` only when ROE explicitly permits
   alternate-path tracking and approved-fixture validation — this tool does
   not disable, unhook, or kill those controls (see `docs/techniques.md`).

## Follow-up choices

- `--min-severity high` for triage; it filters display, not coverage.
- `--plugins ID1,ID2` for an approved focused question.
- `--skip ID1,ID2` only when the reduced coverage is recorded.
- `--delay-ms 250` for pacing; it is not a telemetry or permission boundary.
- `--auto-exploit` only after separate ROE approval for reversible probes.
- `--allow-techniques ...` only after ROE approval for high-impact families.

Never treat an empty finding list or exit code `0` as proof of a clean host
until coverage, identity, platform, and filters have been reviewed.
