# Evidence, cleanup, and recovery

Use this page after a baseline or when a run is interrupted. The [full runbook](../operator-runbook.md)
contains the detailed evidence, automation, review, and cleanup procedures.

## Choose output deliberately

| Need | Recommended mode | Handling |
| --- | --- | --- |
| Immediate review | Memory output | No file is created by the tool |
| Persistent sensitive evidence | Sealed file | Store the key separately and immediately |
| Approved integration | JSON or SARIF | Treat output as plaintext sensitive evidence |
| Remote handoff | Operator-controlled remote mode | Transmit only through approved infrastructure |

For a sealed report:

```bash
STEALTHY_AUTHORIZED=1 stealthy --verbose \
  --output file --output-path ./findings.seal --also-markdown enum \
  2> ./run.stderr.txt
```

Move the key from stderr into the approved secret store. Keep it separate from
the sealed file, Markdown sidecar, shell history, transcripts, and tickets. A
lost key cannot be recovered by the tool.

## Validate and compare

For machine output, keep stdout clean and diagnostics separate:

```bash
set -o pipefail
STEALTHY_AUTHORIZED=1 stealthy --quiet --no-color --format json \
  --output memory enum > current.json 2> current.stderr.txt
python3 -m json.tool current.json >/dev/null
```

Review `run_id`, host, identity, mode, `plugins_run`, `coverage`, findings,
assessments, and filters. Compare only reports with compatible scope:

```bash
stealthy diff baseline.json current.json --format markdown > diff.md
```

`diff` is offline and does not require authorization.

## Closeout checklist

- Report identity and target match the ROE.
- Expected plugins ran and material coverage errors are recorded.
- Any noisy checks, artifacts, or reversible probes are documented.
- Sealed report keys are stored separately and access-controlled.
- Output hashes, run ID, exact command, and evidence location are recorded.
- Approved drop paths and temporary files are inspected before cleanup.
- Shell history and host telemetry are preserved unless the ROE explicitly
  authorizes a separate, auditable handling process.

## Recovery after interruption

Treat an interrupted process as incomplete:

1. Record UTC time, host, command, and observed interruption.
2. Check whether the report is complete and hashable.
3. Inspect the approved drop directory for partial artifacts.
4. Confirm no unexpected child process, service, task, or listener remains.
5. Resume with `stealthy --authorized resume --checkpoint PATH` when a
   checkpoint exists and the same scope remains approved, or close the host as
   incomplete; never append to a partial report.

See [exit-code triage](../operator-runbook.md#8-exit-codes-and-failure-triage)
and [finding review](../operator-runbook.md#9-finding-review-and-disposition)
for disposition guidance.
