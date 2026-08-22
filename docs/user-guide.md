# User Guide

This is the guided, low-friction workflow for a first-time operator. It
assumes the binary is already installed or built. If it is not, start with the
[Installation Guide](installation.md). For remote deployment, use the
[Operator Runbook](operator-runbook.md).

The workflow has one deliberate pause: confirm written authorization before
the first host-enumerating command. Everything before that point is local and
safe. The first scan is visible, enumerate-only, and memory-only so the user
gets useful feedback without accidentally creating a report artifact.

## 0. Set the executable path

Use exactly one of these blocks.

### Installed Linux

```bash
export PATH="$HOME/.local/bin:$PATH"
STEALTHY="$(command -v stealthy)"
```

### Built Linux

```bash
STEALTHY="$PWD/target/release/stealthy"
```

### Installed Windows PowerShell

```powershell
$Stealthy = Join-Path $env:LOCALAPPDATA 'StealthyPrivesc\stealthy.exe'
```

### Built Windows PowerShell

```powershell
$Stealthy = (Resolve-Path .\target\release\stealthy.exe).Path
```

If the path does not exist, return to [Installation](installation.md) rather
than guessing a location.

## 1. Run local readiness checks

These commands do not enumerate the host and do not require authorization.

Linux:

```bash
"$STEALTHY" --version
"$STEALTHY" doctor
"$STEALTHY" guide
"$STEALTHY" disclaimer
```

Windows PowerShell:

```powershell
& $Stealthy --version
& $Stealthy doctor
& $Stealthy guide
& $Stealthy disclaimer
```

Expected result: `doctor` ends with `Ready for an authorized scan.`. If it
reports an unsupported OS, no plugins, or an unusable working directory, stop
and fix that issue before continuing.

## 2. Confirm authorization before host enumeration

Confirm that the ROE covers this host, the current account/context, local
privilege-escalation enumeration, evidence handling, and any optional
reversible probes. Then use the explicit flag for the first run:

Linux:

```bash
"$STEALTHY" --authorized list-plugins
```

Windows PowerShell:

```powershell
& $Stealthy --authorized list-plugins
```

The authorization acknowledgment is required for `list-plugins` and all host
enumeration. It is not a substitute for written permission. If you prefer an
environment variable for a controlled session, use
`STEALTHY_AUTHORIZED=1`; avoid leaving it set in an unrelated shell.

Expected result: a table of plugins compiled for the current OS. Linux builds
do not contain Windows plugins, and Windows builds do not contain Linux
plugins. Save the plugin list in the engagement log when repeatability matters.

## 3. Run the first scan

Use the normal human format for the first run. Do not add `--quiet`: in human
format, quiet mode suppresses the report and can make a successful scan look
like it did nothing.

Linux:

```bash
"$STEALTHY" --authorized enum
```

Windows PowerShell:

```powershell
& $Stealthy --authorized enum
```

This default run is enumerate-only. Findings remain in the encrypted
in-memory store and are rendered for review; no report file is created unless
you explicitly choose an output mode or redirect console output yourself.

Expected result:

- A host, user, OS, architecture, and mode summary
- Findings sorted by severity with recommendations
- Notes and plugin coverage
- A statement that the findings remain in memory

An empty finding list is not proof that the host is clean. Check that the
expected plugins ran and that coverage contains no material errors.

## 4. Choose the next action

| Need | Use | Important detail |
| --- | --- | --- |
| See only urgent findings | `--min-severity high` | This filters display; it does not improve coverage |
| Investigate one area | `--plugins ID1,ID2` | IDs must come from `list-plugins` on this build |
| Exclude a known irrelevant check | `--skip ID1,ID2` | Record the reduced coverage |
| Slow plugin pacing | `--delay-ms 250` | Pacing is not a permission or telemetry boundary |
| Produce clean machine output | `--quiet --format json` | Redirect stdout only when you intentionally want plaintext JSON |

Examples:

```bash
"$STEALTHY" --authorized enum --min-severity high
"$STEALTHY" --authorized enum --plugins linux.sudo,linux.suid
"$STEALTHY" --authorized --delay-ms 250 enum
```

On Windows, use the same arguments after `& $Stealthy`.

Unknown plugin IDs fail with an actionable error. Copy the exact ID from the
plugin table rather than translating names between operating systems.

## 5. Export a clean report when needed

### Machine-readable JSON in a deliberate plaintext file

Use this only when the evidence policy permits plaintext. `--format` controls
what is printed; `--output` controls where findings are stored.

Linux:

```bash
"$STEALTHY" --authorized --quiet --no-color --format json \
  --output memory enum > findings.json
```

Windows PowerShell:

```powershell
& $Stealthy --authorized --quiet --no-color --format json `
  --output memory enum > findings.json
```

Keep the file access-controlled and validate it before sharing. The JSON
contains identity, host, plugin coverage, findings, and recommendations.

### Encrypted sealed evidence

Use sealed file output for persistent evidence when the policy supports it:

```bash
"$STEALTHY" --authorized --verbose --output file \
  --output-path ./findings.seal --also-markdown enum
```

With `--verbose` and without `--quiet`, the binary prints the decryption key to
stderr. Move that key immediately into the approved secret store. Keep it
separate from `findings.seal`, its Markdown sidecar, shell history, and any
ordinary ticket. If the key is lost, the sealed report cannot be recovered.

The Markdown sidecar is plaintext evidence even though the `.seal` file is
encrypted. Treat both as sensitive.

To decode on an approved operator workstation:

```bash
"$STEALTHY" report ./findings.seal \
  --key-hex "$STEALTHY_REPORT_KEY" --format markdown > findings.review.md
```

The `report` command is offline and does not enumerate the host.

## 6. Compare two runs

`diff` is offline and compares plaintext JSON reports. It does not require the
authorization gate or host access:

```bash
"$STEALTHY" diff baseline.json current.json --format markdown > diff.md
```

Before calling a finding remediated, compare the two reports' host, identity,
mode, plugin set, coverage, and severity filter. A finding can disappear
because the plugin was skipped or errored, the account changed, or the report
was filtered.

## 7. Optional reversible probes

Do this only when the ROE explicitly permits the action and the operator has a
rollback/cleanup owner:

```bash
"$STEALTHY" --authorized enum --auto-exploit
```

This mode is limited to supported low-noise reversible probes. It never runs
kernel exploits, replaces service binaries, builds or runs MSI payloads,
abuses token impersonation, or creates persistence. Record every probe and
artifact in the engagement log.

## 8. Automation without hidden output

Use JSON for integrations and keep diagnostics separate from stdout:

```bash
set -o pipefail
"$STEALTHY" --authorized --quiet --no-color --format json \
  --output memory enum > findings.json 2> findings.stderr.txt
status=$?
case "$status" in
  0) echo 'scan completed' ;;
  2) echo 'authorization acknowledgment missing' >&2 ;;
  4) echo 'fail-on threshold reached; inspect findings.json' >&2 ;;
  *) echo "operational failure: $status" >&2 ;;
esac
exit "$status"
```

`--fail-on` evaluates findings after `--min-severity` filtering. Do not hide a
condition with a severity filter and expect the gate to catch it. Also inspect
JSON coverage: a successful process can still contain plugin errors.

## 9. Finish the run

Before closing the host, confirm:

- The report identifies the expected host, account, OS, architecture, and
  elevated/non-elevated state.
- The expected plugins ran and material coverage errors are recorded.
- The mode is `enumerate-only` unless a separate probe decision was approved.
- Any file, script, report, or probe artifact is handled under the ROE.
- Sealed-report keys are stored separately from sealed files.
- The approved drop/output paths are inspected before cleanup.
- The run ID, artifact hash, command line, result hash, and cleanup status are
  captured in the engagement log.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `command not found` / path not found | Return to [Installation](installation.md) and set the executable path in step 0. |
| Authorization required | Add `--authorized` or set `STEALTHY_AUTHORIZED=1` only for the approved session. |
| First scan appears blank | Remove `--quiet` when using human format, or use `--quiet --format json` and inspect the JSON. |
| No plugins matched | Run `--authorized list-plugins`; use exact OS-specific IDs. |
| Output path error | Add `--output-path` with `--output file`; verify the parent directory is approved and writable. |
| Sealed report will not open | Use the exact key from that run; if it was never captured, the file is unrecoverable. |
| Binary blocked | Record the control and use an approved script fallback; do not bypass controls outside the ROE. |
| Plugin error | Preserve the error/coverage record and rerun only the affected plugin if approved. |

For transport, cross-compilation, and script-only deployment, continue with the
[Operator Runbook](operator-runbook.md).
