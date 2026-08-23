# First-User Journey

This is the product-level first-run contract: an authorized operator should
be able to install or build the tool, understand what will happen, run one
useful scan, and know what to do next without guessing.

For installation details, use [Installation](installation.md). For command
choices and evidence handling, use the [User Guide](user-guide.md). For remote
deployment, use the [Operator Runbook](operator-runbook.md).

## Goals

The first-user path must be:

- Explicit about authorization before any host enumeration
- Useful on the first visible scan
- Enumeration-only by default
- Memory-only until the operator deliberately chooses an output mode
- Clear about expected output, exit codes, and recovery
- Consistent on Linux and Windows

The path does not enable `--auto-exploit`, `--allow-techniques`, or silently
send findings over the network.

## Entry points

- [Installation](installation.md) — install a release or build from source
- [User Guide](user-guide.md) — follow the guided operator workflow
- [Operator Runbook](operator-runbook.md) — deploy to a remote Linux or Windows host
- `stealthy guide` — print the in-product first-run guide
- `scripts/` — approved script fallbacks when the binary cannot run

## Journey stages

The journey is: select the binary, run safe local checks, confirm
authorization, list OS-valid plugins, complete a visible memory-only baseline,
choose any approved follow-up, and finish with evidence/cleanup handling.

## Prerequisites

Before starting, the operator has:

1. Written ROE covering the target host and local privilege-escalation
   enumeration
2. An installed release or a successful source build
3. An approved evidence policy if results will be retained
4. The correct account and target context

If any of these is missing, stop at that point and resolve it. The tool's
authorization flag is an acknowledgment, not a replacement for the ROE.

### Stage 0 — select the binary

Choose one block and keep the variable for the rest of the session.

Linux, published release:

```bash
export PATH="$HOME/.local/bin:$PATH"
STEALTHY="$(command -v stealthy)"
```

Linux, source build:

```bash
STEALTHY="$PWD/target/release/stealthy"
```

Windows PowerShell, published release:

```powershell
$Stealthy = Join-Path $env:LOCALAPPDATA 'StealthyPrivesc\stealthy.exe'
```

Windows PowerShell, source build:

```powershell
$Stealthy = (Resolve-Path .\target\release\stealthy.exe).Path
```

Confirm that the path resolves before continuing. If it does not, return to
[Installation](installation.md); do not guess a path or download an
unreviewed executable.

### Stage 1 — safe local checks

These commands do not require authorization and do not enumerate a host.

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

Checkpoint: `doctor` should report a supported OS, one or more compiled
plugins, a usable working directory, and `Ready for an authorized scan.`.
Nothing should have been written to disk by these checks.

### Stage 2 — authorization pause

Pause and confirm all of the following:

- The hostname/asset is in scope.
- The current user and elevation context are approved.
- Local privilege-escalation enumeration is permitted.
- The intended evidence handling is permitted.
- Optional reversible probes are either approved or will remain disabled.

Only after that confirmation, run the authorization-gated plugin listing.

Linux:

```bash
"$STEALTHY" --authorized list-plugins
```

Windows PowerShell:

```powershell
& $Stealthy --authorized list-plugins
```

Checkpoint: the output lists plugin IDs for the current OS. Record the list if
the run must be reproducible. If the command exits `2`, authorization was not
acknowledged; no host enumeration should have occurred.

### Stage 3 — first useful scan

Run the default human report. This is intentionally not quiet: quiet human
output is suppressed, which can make a successful first run look blank.

Linux:

```bash
"$STEALTHY" --authorized enum
```

Windows PowerShell:

```powershell
& $Stealthy --authorized enum
```

The first scan is enumerate-only and memory-only. The operator should see:

1. Host, user, OS, architecture, and elevation context
2. Mode `enumerate-only`
3. Severity summary and findings, if present
4. Recommendations and any noisy/artifact indicators
5. Plugin coverage and errors

Checkpoint: a blank or empty finding list is not automatically a clean result.
Confirm the expected plugins ran and that material coverage errors are absent.

### Stage 4 — choose a guided follow-up

After reviewing the first scan, choose exactly one next step:

| Goal | Command | Result |
| --- | --- | --- |
| Prioritize urgent findings | `"$STEALTHY" --authorized enum --min-severity high` | Human report filtered to high and critical findings |
| Recheck one area | `"$STEALTHY" --authorized enum --plugins ID1,ID2` | Focused enumeration using IDs from `list-plugins` |
| Produce integration output | `"$STEALTHY" --authorized --quiet --format json enum` | Clean JSON on stdout; redirect only intentionally |
| Slow plugin pacing | `"$STEALTHY" --authorized --delay-ms 250 enum` | Same checks with a larger delay budget |
| Retain evidence | See Stage 5 | Sealed report with separately handled key |

On Windows PowerShell, replace the executable prefix with `& $Stealthy` and
use PowerShell's backtick for multiline commands. Unknown plugin IDs fail
clearly; copy them exactly from the listing.

### Stage 5 — deliberately export evidence

Do not export during the first scan unless the evidence policy requires it.
When it does, prefer sealed output:

```bash
"$STEALTHY" --authorized --verbose --output file \
  --output-path ./findings.seal --also-markdown enum
```

The key is printed to stderr only when `--verbose` is used without `--quiet`.
Move it immediately to the approved secret store. Keep it separate from the
sealed file and Markdown sidecar. The sidecar is plaintext evidence.

If plaintext JSON is explicitly approved:

```bash
"$STEALTHY" --authorized --quiet --format json \
  --output memory enum > findings.json
```

Treat `findings.json` as sensitive. `--format json` controls console output;
it does not encrypt a file.

### Stage 6 — finish and hand off

The first-user journey is complete when the operator has:

- Verified the binary version and `doctor` result
- Recorded authorization, target, account/context, and plugin coverage
- Completed one visible enumerate-only baseline
- Reviewed findings, notes, and plugin errors
- Chosen memory-only, plaintext, or sealed evidence intentionally
- Stored any sealed-report key separately
- Recorded the run ID, artifact hash, command, and cleanup decision

For remote targets, continue with the deployment and cleanup checklists in the
[Operator Runbook](operator-runbook.md).

## CI contract

CI should validate the same first-user contract across supported platforms:

- Validate Markdown structure, required headings, local links, and pinned
  workflow actions.
- Run Rust format, clippy, tests, release builds, and CLI smoke checks on Linux.
- Run the Rust tests and release build on Windows using Windows-valid plugin
  IDs for host-dependent CLI fixtures.
- Check Linux/Python and Windows PowerShell fallback syntax.
- Run security/supply-chain checks and fail the final readiness gate if any
  required gate fails.

## Non-interactive contract

The following contract is safe for an approved Linux CI or automation job. It
does not enable probes and keeps JSON on stdout:

```bash
set -o pipefail
"$STEALTHY" --authorized --quiet --no-color --format json \
  --output memory enum > findings.json 2> findings.stderr.txt
status=$?
case "$status" in
  0) echo 'scan completed' ;;
  2) echo 'authorization acknowledgment missing' >&2 ;;
  4) echo 'fail-on threshold reached' >&2 ;;
  *) echo "operational failure: $status" >&2 ;;
esac
exit "$status"
```

Exit codes:

- `0`: completed without crossing the selected `--fail-on` threshold
- `2`: authorization acknowledgment missing
- `4`: selected severity threshold reached
- Other nonzero: invalid arguments, unavailable input, or operational failure

Automation must also inspect JSON `coverage`. A process can exit `0` while a
plugin reports an error, and `--fail-on` evaluates findings after any
`--min-severity` filter.

## Recovery when the journey stops

| Point of failure | Recovery |
| --- | --- |
| Binary path missing | Return to Installation and set `STEALTHY` / `$Stealthy` explicitly. |
| `doctor` fails | Fix OS, working-directory, or build/plugin issues before authorization. |
| Authorization error | Confirm the ROE, then rerun with `--authorized`; exit `2` is expected without it. |
| First scan appears blank | Remove `--quiet` for human output; use `--quiet --format json` only for machine output. |
| No plugins or unknown IDs | Run `list-plugins` for this build and copy exact IDs. |
| Execution blocked | Record the control and use an approved script fallback, or `--allow-techniques endpoint-bypass` (alternate-path + approved-fixture validation) only when ROE permits. |
| Sealed report cannot open | Use the exact key from that run. A lost key cannot be recovered by the tool. |
| Plugin coverage error | Preserve the error, rerun the affected plugin if approved, and label conclusions as limited until resolved. |

## Safety boundary

The first-user journey never silently changes scope, hides a failed check,
enables `--auto-exploit` or `--allow-techniques`, or clears host telemetry.
If the ROE and this document conflict, the ROE wins.
