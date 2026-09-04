# StealthyPrivesc User Journey

This document defines the verified, end-to-end product journey that Phase 5
user-acceptance testing must exercise. It covers the native command-line
application and its approved recovery paths. It does not grant authorization,
expand Rules of Engagement (ROE), or enable optional techniques.

## Product overview

StealthyPrivesc is a cross-platform command-line tool for authorized red-team
and internal security assessments. It inventories local privilege-escalation
exposures on Linux and Windows, records which checks completed, and gives the
operator concrete follow-up guidance. Its normal operating mode is
`enumerate-only`: the tool inspects and recommends but does not exploit a
finding.

The product is designed for operators who need a repeatable baseline with an
explicit safety boundary. Host actions require `--authorized` or
`STEALTHY_AUTHORIZED=1`; without that acknowledgment the process refuses to
enumerate and exits with code `2`. Results remain in memory by default. File
or remote output, reversible probes, and separately gated technique families
require additional explicit choices.

The supported experience includes readiness diagnostics, platform-specific
plugin discovery, human and machine-readable reports, focused rescans,
encrypted evidence, offline report handling, staging, integrity verification,
and reduced-coverage script fallbacks. Operators must treat incomplete plugin
coverage as a limitation even when the process exits successfully.

## Personas

| Persona | Goal | Entry point |
| --- | --- | --- |
| First-time authorized operator | Confirm the tool is safe to start, run one useful baseline, and understand the result without guessing at flags. | `stealthy guide`, then `stealthy doctor` |
| Red-team or penetration-test operator | Run a reproducible, scope-limited enumeration and prioritize findings for approved follow-up. | `stealthy --authorized list-plugins`, then `stealthy --authorized enum` |
| Triage or remediation lead | Convert observed findings into explicit defer, validate, out-of-scope, or separately approved reversible-probe decisions. | `stealthy --authorized --checkpoint PATH enum --triage --triage-out decisions.json` |
| CI or fleet-assessment engineer | Produce stable JSON or SARIF, inspect coverage, and enforce a severity threshold through exit status. | `stealthy --authorized --quiet --no-color --format json --output memory enum` |
| Evidence custodian or reviewer | Retain a sealed report, keep its key separate, and render the evidence offline. | `stealthy report REPORT.seal --key-file REPORT.key` |
| Deployment operator | Package and verify a target-specific kit, then use the native binary or an approved reduced-coverage fallback. | `stealthy stage`, `stealthy verify`, and the generated `OPERATOR.txt` |

## Preconditions and stop conditions

Before the first host action, the operator has written ROE covering the exact
host, account, local enumeration scope, evidence handling, and stop contact.
The operator stops if the host or identity is unexpected, the binary hash is
not approved, `doctor` is blocked, the required plugin coverage is missing, or
a defensive control begins containment. The authorization flag acknowledges
that review; it is not authorization by itself.

The commands below use a Linux source build as the primary concrete path. A
published, verified release may be substituted by setting `STEALTHY` to the
installed executable. Windows equivalents are listed after the primary
journey.

## Primary journey

### 1. Build the reviewed revision

From the repository root:

```bash
cargo build --locked --workspace --release
STEALTHY="$PWD/target/release/stealthy"
```

Observable result: Cargo exits `0` and `$STEALTHY` is an executable file. No
target host has been enumerated.

### 2. Confirm product identity

```bash
"$STEALTHY" --version
```

Observable result: exit `0` and a line beginning with `stealthy ` followed by
the compiled version.

### 3. Check local readiness

```bash
"$STEALTHY" doctor --json
```

Observable result: exit `0` and valid JSON with `schema_version` equal to
`"1"`, `healthy` equal to `true`, a supported `os`, and `plugins` greater than
zero. `doctor` performs readiness checks without host enumeration and does not
require `--authorized`.

### 4. Read the operating boundary

```bash
"$STEALTHY" guide
"$STEALTHY" disclaimer
```

Observable result: both commands exit `0`. The guide includes the first safe
scan `stealthy --authorized scan`; the disclaimer states that use is limited
to authorized assessments.

### 5. Confirm scope and discover this build's plugins

After confirming the ROE, target, account, output policy, and stop conditions:

```bash
"$STEALTHY" --authorized list-plugins
```

Observable result: exit `0`, a non-empty platform-specific plugin table, and a
tip showing `stealthy --authorized enum --plugins id1,id2`. Plugin IDs use the
current platform namespace, such as `linux.kernel_cve` on Linux or
`windows.uac` on Windows.

### 6. Deliver core value with a visible baseline

```bash
"$STEALTHY" --authorized enum
```

Observable result: exit `0` unless a separately requested failure threshold
or an operational error applies. The human report identifies the host,
identity, OS and architecture; states `enumerate-only`; summarizes findings;
and shows plugin coverage. The default output mode is memory-only, so a normal
run does not create a report file or `.cache-run` ledger.

Success is not defined as “no findings.” The operator verifies that the
expected plugins ran and that no material coverage entry reports an error.

### 7. Produce a reproducible focused result

On Linux:

```bash
"$STEALTHY" --authorized --quiet --no-color --format json \
  --output memory enum --plugins linux.kernel_cve > findings.json
```

Observable result: exit `0` and `findings.json` parses as JSON schema `"2"`.
It has `authorized_use_ack: true`, `mode: "enumerate-only"`,
`coverage_mode: "native"`, `plugins_run: ["linux.kernel_cve"]`, and a matching
coverage entry. Finding count is host-dependent.

Use an ID copied from Step 5 when a different question is in scope. The shell
redirection is an intentional plaintext evidence write; handle the file under
the engagement evidence policy.

### 8. Triage findings when a decision record is required

Skip this step when the baseline report alone satisfies the engagement record.
To create a checkpoint and a decisions template without enabling any probe:

```bash
"$STEALTHY" --authorized --checkpoint ./triage-checkpoint.json \
  enum --triage --triage-out ./decisions.json
```

Observable result: the scan completes, `triage-checkpoint.json` contains the
run report, and `decisions.json` contains schema version `"1"`, the same run
ID, and eligible findings initially marked `defer`. In an interactive terminal,
the command also accepts `probe`, `validate`, `defer`, `out_of_scope`, and
`skip` decisions. In a non-interactive process it does not block waiting for
input.

Review and edit the decisions file under the ROE. Apply it only with its
matching checkpoint:

```bash
"$STEALTHY" --authorized --checkpoint ./triage-checkpoint.json \
  enum --approve-file ./decisions.json
```

Observable result: the command rejects unknown finding IDs or a mismatched run
ID. `defer`, `validate`, and `out_of_scope` remain decisions rather than probe
authorization. Only a `probe` decision for a known finding can authorize that
finding's supported reversible probe.

### 9. Retain sealed evidence when policy requires it

Skip this step when the approved output policy is memory-only. Otherwise use
separate approved paths for the report and key:

```bash
"$STEALTHY" --authorized --output file \
  --output-path ./findings.seal \
  --key-output-path ./findings.key enum
```

Observable result: exit `0`; both files exist; the report is a sealed blob;
and the full key is not printed to stderr. Move `findings.key` to the approved
secret store and do not retain it beside the report.

Confirm offline access before handoff:

```bash
"$STEALTHY" report ./findings.seal --key-file ./findings.key --format json
```

Observable result: exit `0` and valid report JSON. A key from another run, a
modified sealed file, or a lost key cannot be recovered by the tool.

### 10. Close out deliberately

For a memory-only run, record that no tool-managed artifact requires cleanup.
If the workflow created a stage, checkpoint, or recorded output, inspect the
ledger and remove only its recorded removable artifacts:

```bash
"$STEALTHY" artifacts --latest
"$STEALTHY" cleanup --latest --secure-delete
```

Observable result: `artifacts` lists the latest run's ledger entries and
`cleanup` reports removal or an explicit already-missing outcome. Secure
deletion is best effort. Preserve the command, run ID, plugin coverage,
evidence disposition, cleanup result, and any limitations in the engagement
record.

## Windows command equivalents

Use the following substitutions from a PowerShell session:

```powershell
cargo build --locked --workspace --release
$Stealthy = (Resolve-Path .\target\release\stealthy.exe).Path
& $Stealthy --version
& $Stealthy doctor --json
& $Stealthy guide
& $Stealthy disclaimer
& $Stealthy --authorized list-plugins
& $Stealthy --authorized enum
& $Stealthy --authorized --quiet --no-color --format json --output memory enum --plugins windows.uac |
  Set-Content -LiteralPath .\findings.json -Encoding utf8
```

The same success criteria apply. The focused report must identify
`windows.uac` in `plugins_run` and its coverage entry. For sealed output, use
PowerShell paths with the same `--output file`, `--output-path`, and
`--key-output-path` flags.

## Alternate and error paths

| Journey point | What the user sees | Recovery |
| --- | --- | --- |
| Build or binary selection fails | Cargo returns nonzero, or the selected path does not exist. | Stop before host action. Restore the reviewed source/toolchain or use a verified published release; then repeat Steps 1–3. |
| `doctor` is not healthy | JSON has `healthy: false`, `blocking: true`, or failed check details with remediation text. | Follow the reported remediation for OS, plugins, working directory, or fallback availability and rerun `doctor`. Do not continue while blocking checks remain. |
| Authorization acknowledgment is missing | A host command prints `Authorization required`, explains the next steps, and exits `2`. | Confirm written ROE, then rerun the same command with `--authorized` or `STEALTHY_AUTHORIZED=1`. |
| Plugin ID is wrong or belongs to another OS | The command exits `1` with `unknown plugin ID(s) for <os>` and directs the user to `stealthy --authorized list-plugins`. | Rerun the listing on that binary and copy an exact platform-valid ID. |
| Human output appears blank | A successful human run used `--quiet`, which suppresses the detailed human report. | Remove `--quiet`, or request `--quiet --format json` and parse stdout. |
| Findings are empty | The report has no findings, but coverage may still be partial or failed. | Inspect every expected `coverage` entry. Rerun an affected plugin if approved and describe the conclusion as limited until material errors are resolved. |
| A severity gate is crossed | With `--fail-on LEVEL`, the report is emitted and the process exits `4`. | Preserve and review the report; treat exit `4` as the configured policy outcome rather than an authorization or parser failure. |
| Encrypted output has no protected key destination | The command exits `1`, says encrypted output requires `--key-output-path` or `STEALTHY_KEY_OUTPUT_PATH`, and creates no sealed report. | Create an approved protected destination and rerun with `--key-output-path`. Never put the key in the same evidence channel as the report. |
| A sealed report cannot be opened | `report` exits nonzero for a wrong key, tampered blob, missing file, or malformed input. | Confirm the exact report/key pair and approved paths. Do not alter the original evidence; a lost key is not recoverable. |
| The native binary is blocked after staging | The generated dispatcher reports the failed primary launch and tries only manifest-approved script hosts. Script output identifies `coverage_mode: "script"` and lists `capability_delta`. | Record the control and reduced coverage. Use the approved fallback; do not claim native equivalence. On Windows, prefer a reviewed non-`%TEMP%` path or organization-signed binary. |
| A stage destination is unsafe | `stage` exits nonzero when `--out` exists and is non-empty or is not a directory. | Choose a new empty approved directory. Do not delete or overwrite an ambiguous path merely to make staging pass. |
| A run is interrupted | A checkpointed run stops before all plugins complete. | Preserve the checkpoint and run `stealthy --authorized resume --checkpoint PATH`; completed `ok` plugins are skipped. Reject a corrupt or unrelated checkpoint. |
| A triage decision references the wrong run or finding | The apply command exits nonzero and reports the mismatched run or unknown finding ID. | Keep the original checkpoint and decision file, correct the decision source, and rerun with the checkpoint that produced those finding IDs. Do not translate IDs by hand between runs. |
| Interactive triage receives an empty or unrecognized answer | The candidate is recorded as `defer`; `skip` omits it from the decision list. | Review the resulting decision file. Rerun triage if the recorded action does not reflect the operator's intent. |
| An evasion family is requested without the extra confirmation | The command exits nonzero instead of running the gated family. | Confirm that the ROE explicitly covers the named family, review its emitted/operator documentation, and rerun only with both `--allow-techniques ID` and `--confirm-evasion`. Otherwise leave it disabled. |

## Journey map

Every success criterion below is binary and is the acceptance contract for
Phase 5.

| Step | User action | System response | Success criterion |
| --- | --- | --- | --- |
| J1 — Build | Run `cargo build --locked --workspace --release`. | Cargo builds the release executable. | Exit code is `0` and `target/release/stealthy` (or `.exe`) exists. |
| J2 — Identify | Run `"$STEALTHY" --version`. | CLI prints product name and version. | Exit code is `0` and stdout matches `^stealthy [0-9]+\.[0-9]+\.[0-9]+`. |
| J3 — Readiness | Run `"$STEALTHY" doctor --json`. | CLI prints machine-readable readiness without requiring authorization. | Exit code is `0`; JSON parses; `schema_version == "1"`; `healthy == true`; `plugins > 0`. |
| J4 — Guidance | Run `guide` and `disclaimer`. | CLI prints first-run instructions and legal boundary. | Both exit `0`; guide contains `stealthy --authorized scan`; disclaimer contains `authorized`. |
| J5 — Authorization gate | Run `"$STEALTHY" enum` without either acknowledgment. | CLI refuses host enumeration and provides recovery text. | Exit code is `2`; stderr contains `Authorization required`; no report or ledger is created. |
| J6 — Plugin discovery | Run `"$STEALTHY" --authorized list-plugins`. | CLI prints plugins compiled for the current OS. | Exit code is `0`; output contains at least one correctly namespaced plugin ID. |
| J7 — Visible baseline | Run `"$STEALTHY" --authorized enum`. | CLI emits the human enumerate-only report. | Exit code is `0`; output contains identity, `enumerate-only`, findings summary, and coverage; a clean working directory gains no `.cache-run`. |
| J8 — Focused JSON | Run the Step 7 JSON command with one ID from J6. | CLI runs only the selected plugin and emits JSON to stdout. | Exit code is `0`; JSON schema is `"2"`; `authorized_use_ack == true`; `mode == "enumerate-only"`; `plugins_run` and `coverage` contain the selected ID. |
| J9 — Triage | Run with a checkpoint, `--triage`, and `--triage-out`; then apply a matching all-defer decisions file. | CLI writes a schema-1 decision record and applies it without enabling probes. | Both commands exit `0`; checkpoint and decision files exist; run IDs match; all template actions are `defer`; the applied report records the decisions. |
| J10 — Sealed evidence | Run with `--output file`, report path, and separate key path. | CLI writes the sealed report and protected key without printing the key. | Exit code is `0`; both files exist; stderr does not contain the key; `report --key-file` decodes valid JSON. |
| J11 — Closeout | Run `artifacts --latest` and, when a removable ledger exists, `cleanup --latest --secure-delete`. | CLI lists recorded artifacts and removes only ledger-recorded removable paths. | Listing exits `0`; cleanup exits `0`; each targeted artifact is absent or explicitly reported already missing. |
| E1 — Missing authorization | Run `enum` without the flag or environment acknowledgment. | CLI refuses host enumeration and prints recovery guidance. | Exit code is `2`; stderr contains `Authorization required`; no report or ledger is created. |
| E2 — Invalid plugin | Run authorized enumeration with an unknown plugin ID. | CLI rejects the ID and points to plugin discovery. | Exit code is `1`; stderr names the unknown ID and contains `list-plugins`. |
| E3 — Blocking readiness | Run `doctor --json` in an environment where a blocking prerequisite is false. | CLI emits diagnostic JSON and fails readiness. | Exit code is `3`; JSON parses; `healthy == false`; `blocking == true`; at least one check detail has status `block`. |
| E4 — Severity policy | Run a fixture/report-producing scan with `--fail-on` at or below its maximum finding severity. | CLI emits the report and signals the policy threshold. | Exit code is `4`, and the emitted report remains parseable. |
| E5 — Missing key destination | Request encrypted file output without a key destination. | CLI refuses to create unrecoverable encrypted output. | Exit code is `1`; stderr mentions `--key-output-path` or `STEALTHY_KEY_OUTPUT_PATH`; no sealed report exists. |
| E6 — Wrong report key | Decode a sealed report using a different valid-length key. | Authentication fails without returning plaintext. | Exit code is nonzero and stdout does not contain report JSON. |
| E7 — Unsafe stage destination | Stage into an existing non-empty directory. | CLI refuses to overwrite the directory. | Exit code is nonzero and the pre-existing file remains byte-for-byte unchanged. |
| E8 — Corrupt checkpoint | Resume from malformed or integrity-invalid checkpoint content. | CLI refuses to resume or run plugins. | Exit code is nonzero and no completed-plugin output is emitted as a new report. |
| E9 — Invalid triage decision | Apply a decision containing an unknown finding ID or mismatched run ID. | CLI refuses the approval file before executing a probe. | Exit code is nonzero; stderr identifies the mismatch/unknown ID; no probe artifact is created. |
| E10 — Missing evasion confirmation | Allow an evasion family without `--confirm-evasion`. | CLI enforces the second gate. | Exit code is nonzero; stderr mentions `--confirm-evasion`; no evasion action is reported as executed. |

## Verified boundaries

- Default host behavior is enumeration and recommendation, not exploitation.
- Memory is the default output destination.
- High-impact families are not part of this journey.
- `endpoint-bypass` means alternate-path and approved-fixture validation only.
- AMSI, ETW, AV/EDR, AppLocker, or WDAC disabling and telemetry/quarantine
  tampering are not silently included in any fallback or default path.
- Script fallbacks require a fresh authorization acknowledgment, report reduced
  coverage, and do not claim native equivalence.

For shorter onboarding, see [First-User Journey](first-user-journey.md). For
getting a kit onto a host, see [Delivery](runbook/delivery.md). For full
deployment recipes and incident-safe stop conditions, see the
[Operator Runbook](operator-runbook.md).
