# Target operations

Choose the smallest approved deployment and execution path.

**Get the kit onto the host first:** [Delivery](delivery.md) is the operator
catalog (two-machine model, `stage`, every Linux/Windows transport, after-drop
verify). This page is the run sequence after the kit is present.

The [full runbook](../operator-runbook.md) contains the complete SCP, rsync,
SFTP, WinRM, SMB, HTTP, constrained-channel, PsExec, and script-only recipes.

Do not run `scripts/install.sh` or `scripts/install.ps1` on a target. Those
installers are for the operator workstation.

## Linux

Detailed procedures: [stage](../operator-runbook.md#17-stage-a-drop-bundle-preferred-unit-of-copy),
[deploy](../operator-runbook.md#2-deploy-to-a-linux-target),
[run](../operator-runbook.md#3-run-on-a-linux-target).

1. Stage a bundle on the operator box (`stealthy stage --os linux ...`).
2. Create the approved remote drop directory (prefer `$HOME/.cache/...` over
   `/tmp` when `noexec` or monitoring is a concern).
3. Copy the staged directory over the approved transport (SCP/rsync of the
   folder is the default; see [delivery](delivery.md) for SFTP, ProxyJump,
   stdin, HTTP, netcat, mounts, containers, base64, and script-only).
4. Verify SHA-256, file type, and `--help`.
5. Run local `guide`, `doctor`, and `disclaimer` if the artifact is new.
6. After the authorization pause, list plugins and run one visible baseline:

   ```bash
   BIN=$HOME/.cache/cache-update/cache-update
   "$BIN" doctor
   "$BIN" --authorized list-plugins
   "$BIN" --authorized --profile quiet enum
   ```

7. Inspect identity, mode, plugin coverage, and errors before narrowing scope.
8. If the ELF cannot launch, run the staged dispatcher once
   (`python → bash → sh → perl`). Do not retry a blocked hash. Record reduced
   coverage. Script tiers only forward auth and `--json`.

```bash
bash $HOME/.cache/cache-update/scripts/run.sh --authorized enum
```

## Windows

Detailed procedures: [stage](../operator-runbook.md#17-stage-a-drop-bundle-preferred-unit-of-copy),
[deploy](../operator-runbook.md#4-deploy-to-a-windows-target),
[run](../operator-runbook.md#5-run-on-a-windows-target).

1. Stage a bundle on the operator box (`stealthy stage --os windows ...`).
   Org-sign the PE before `--binary` when SmartScreen/publisher policy applies.
2. Create the approved remote drop directory. Keep the PE out of `%TEMP%`.
3. Copy the staged directory (OpenSSH `scp -r`, WinRM `Copy-Item -ToSession`,
   or SMB). See [delivery](delivery.md) for HTTP, RDP, PsExec, Impacket,
   base64, FTP/WebDAV, and script-only.
4. Verify with `Get-FileHash`. Run `doctor`, `guide`, and `disclaimer` before
   authorization.
5. After the authorization pause, list plugins and run one visible baseline:

   ```powershell
   $Stealthy = 'C:\Users\Public\Documents\cache-update\cache-update.exe'
   & $Stealthy doctor
   & $Stealthy --authorized list-plugins
   & $Stealthy --authorized --profile quiet enum
   ```

6. If SmartScreen, AppLocker, WDAC, or AV blocks the executable, do not retry
   that hash. Run `scripts\run.ps1` so the dispatcher walks
   **powershell → jscript → msbuild**. Script coverage is reduced; only auth /
   `--json` are forwarded. `--allow-techniques endpoint-bypass` records
   alternate-path tracking and approved-fixture validation only — this tool
   does not disable those controls (see `docs/techniques.md`).

```powershell
& C:\Users\Public\Documents\cache-update\scripts\run.ps1 --authorized enum
```

## Follow-up choices

- `--min-severity high` for triage; it filters display, not coverage.
- `--plugins ID1,ID2` for an approved focused question.
- `--skip ID1,ID2` only when the reduced coverage is recorded.
- `--delay-ms 250` for pacing; it is not a telemetry or permission boundary.
- `--auto-exploit` only after separate ROE approval for reversible probes.
- `--allow-techniques ...` only after ROE approval for high-impact families.

Never treat an empty finding list or exit code `0` as proof of a clean host
until coverage, identity, platform, and filters have been reviewed.
