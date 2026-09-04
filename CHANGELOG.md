# Changelog

## Unreleased

- Staged dispatchers default to `script_first=auto`: skip the PE/ELF when a
  live endpoint sensor (or a Linux `noexec` drop mount) is observed, and start
  on approved script hosts instead. Set `script_first=false` or
  `STEALTHY_SCRIPT_FIRST=false` to try the primary first. Inbox Defender AV
  alone does not skip a Windows PE.
- Windows live-controls Authenticode collection uses WinVerifyTrust, version
  resources, and Zone.Identifier in-process instead of spawning
  `powershell.exe` for signature inspection. AppLocker effective tests and
  HVCI inventory still use read-only PowerShell.
- `opsec-string-strip` omits product brand, GTFOBins/LOLBAS URLs, the GitHub
  repository URL, and third-party vendor catalog text from the binary.
- Windows dispatcher default walk is now `python → pwsh → powershell → git →
  jscript → msbuild`. New `enum.py` and `enum-git.sh` collectors; MSBuild is
  skipped unless it lives under Program Files.
- Linux `run.sh` runs the staged ELF in place when `drop_dir` is empty,
  matching Windows and avoiding a second write+exec under `.run-cache`.
- Quiet and balanced profiles run plugins in-process by default (no
  `__plugin-worker` child per plugin). Pass `--plugin-timeout-ms N` to isolate.
- Documented the operator delivery catalog: stage-first drop bundles and every
  Linux/Windows host-copy method in `docs/runbook/delivery.md`.
- Added concise `--summary` output and machine-readable `--progress-json` events.
- Added disposition audit metadata: operator, timestamp, rationale, and previous status.
- Added remediation prerequisites, verification commands, rollback guidance, and baseline comparison warnings.
- Added installer dry-run and rollback guidance plus local HTML and release-contract checks.

User-visible behavior changes should be recorded here before release, including
migration impact for report schema or automation consumers.
