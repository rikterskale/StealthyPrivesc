# Report schema

Rust enumeration reports and normalized script reports use schema version `2`.
The schema is a transport contract, not proof that every platform has identical
coverage. Always inspect `coverage`, `plugins_run`, `coverage_mode`, and
`capability_delta` before comparing reports.

## Top-level contract

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | string | Report schema; currently `"2"` for enumeration and ingested script reports |
| `run_id` | string | Unique run identifier |
| `started_at_unix` | integer | Start time in Unix seconds |
| `authorized_use_ack` | boolean | Authorization acknowledgment supplied to the producing command |
| `mode` | string | Usually `enumerate-only` or `enumerate+allow-techniques` |
| `profile` | string | Effective engagement profile (`quiet`, `balanced`, `thorough`, `ci`, or `script`) |
| `coverage_mode` | string | `native` for the Rust engine or `script` for a fallback report |
| `os` / `identity` | object | Target platform and execution identity |
| `findings` | array | Observations and recommendations |
| `assessments` | array | Finding assessment metadata; normally one entry per finding |
| `coverage` | array | Per-plugin status, duration, finding count, and error information |
| `plugins_run` | array | Plugin IDs attempted by the producer |
| `notes` | array | Operator-visible limitations and warnings |
| `capability_delta` | array | Coverage/features not equivalent to the native engine |
| `attack_paths` | array | Enriched relationships between findings and possible paths |
| `triage_decisions` | array | Recorded operator decisions, if triage was enabled |

Native reports may also contain `control_assessment` when an application-control
plugin was selected. `controls` and `live-controls` return control reports rather
than this enumeration envelope; they support human, Markdown, and JSON output,
but not SARIF.

## Finding contract

Native schema-v2 findings include stable `finding_id`, `plugin`, `kind`,
`severity`, `title`, `detail`, `recommendation`, `what_next`, `next_command`,
`noisy`, `leaves_artifacts`, and `mitre_techniques`. Optional fields such as
`object` and `technique_id` are emitted when applicable. Assessment metadata
is emitted in the top-level `assessments` array, aligned by finding index.
Consumers must ignore unknown fields and tolerate absent optional fields.

## Fallback and ingest rules

Fallback scripts require the same fresh authorization acknowledgment as the
Rust binary: `--authorized` (or the full flag) or `STEALTHY_AUTHORIZED=1`.
Their JSON is reduced-coverage schema v2 and must be normalized with:

```bash
stealthy ingest fallback-report.json --format json > normalized-report.json
```

Do not infer native plugin coverage from a script report. Use
`capability_delta` and the coverage arrays, and preserve the original script
report alongside the normalized output. `capability_delta` is the canonical
list of native plugin IDs not attempted by that fallback; reduced structured
evidence within an attempted plugin is described in the report notes.

## Output and persistence

Normal memory-mode enumeration does not create an artifact ledger. A ledger is
created only when the run records an explicit file output, checkpoint, or
staged delivery artifact. Encrypted file output is not plaintext JSON; use
`stealthy report` with the separately handled key to decode it.
