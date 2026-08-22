# CLI Reference

The executable is named `stealthy`. Global options may appear before the
subcommand. Host-enumerating commands require `--authorized` or
`STEALTHY_AUTHORIZED=1`.

## Global options

| Option | Meaning | Default |
| --- | --- | --- |
| `--authorized` | Alias for the full authorization acknowledgment | Off |
| `--i-understand-authorized-use-only` | Required authorization acknowledgment | Off |
| `-q`, `--quiet` | Suppress progress and human summaries | Off |
| `-v`, `--verbose` | Add diagnostic/finding progress; may expose sealed keys for file workflows | Off |
| `--no-color` | Disable ANSI color output; `NO_COLOR` is also honored | Off |
| `--delay-ms N` | Randomized delay budget between plugins | `50` |
| `--format human|json|markdown|sarif` | Console/report format | `human` |
| `--min-severity LEVEL` | Display only findings at or above a level | `info` |
| `--fail-on LEVEL` | Exit `4` when the displayed maximum reaches the level | None |
| `--output memory|file|remote` | Result destination | `memory` |
| `--output-path PATH` | File destination for `--output file` | None |
| `--plaintext-file` | Write JSON instead of an encrypted file | Off |
| `--also-markdown` | Write `PATH.md` beside a file output | Off |
| `--exfil-url URL` | Operator-controlled destination metadata for remote output | None |

Severity levels, from least to greatest, are `info`, `low`, `medium`, `high`,
and `critical`.

## `guide`

```text
stealthy guide
```

Prints the first-run safety and operator guide. No authorization or host
enumeration is required.

## `doctor`

```text
stealthy doctor
stealthy doctor --json
```

Checks supported OS, compiled plugin availability, and working-directory
readiness. JSON output is intended for automation.

## `disclaimer`

```text
stealthy disclaimer
```

Prints the legal and ethical use boundary without host enumeration.

## `list-plugins`

```text
stealthy --authorized list-plugins
stealthy --authorized list-plugins --tsv
```

Lists plugins compiled for the current build. `plugins` is a visible alias.
TSV output contains `id`, `name`, and `description` columns.

## `enum` / `scan`

```text
stealthy --authorized enum
stealthy --authorized scan
stealthy --authorized enum --auto-exploit
stealthy --authorized enum --plugins ID1,ID2
stealthy --authorized enum --skip ID1,ID2
```

`scan` is a visible alias for `enum`. Options:

- `--auto-exploit`: enables only explicitly supported reversible probes.
- `--plugins`: runs the listed IDs; unknown IDs fail.
- `--skip`: excludes the listed IDs; unknown IDs fail.

## `report`

```text
stealthy report REPORT.seal --key-hex KEY
stealthy report REPORT.seal --key-hex KEY --format json
stealthy report REPORT.seal --key-hex KEY --format markdown
stealthy report REPORT.seal --key-hex KEY --format sarif
```

Decrypts a sealed report locally. It does not enumerate the host and does not
require authorization. The key is never inferred or recovered by the tool.

## `diff`

```text
stealthy diff BASELINE.json CURRENT.json
stealthy diff BASELINE.json CURRENT.json --format markdown
```

Compares plaintext JSON reports offline. It reports added, removed, and
changed findings. SARIF is intentionally unsupported for diffs.

## Output modes

### Memory

Default. Findings remain in the encrypted in-memory store and are rendered to
the selected console format. No report file is created.

### File

```text
stealthy --authorized --output file --output-path findings.seal enum
stealthy --authorized --output file --plaintext-file --output-path findings.json enum
```

File mode requires `--output-path`. Sealed output uses an operator-held key;
plaintext output must be approved by the evidence policy.

### Remote

```text
stealthy --authorized --output remote --exfil-url https://operator.example/ingest enum
```

Remote mode is operator-controlled. The tool prints the sealed body and
destination instructions; it does not implement a silent background client.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Success; no selected failure threshold was crossed |
| `2` | Authorization acknowledgment missing |
| `4` | `--fail-on` threshold triggered |
| Other nonzero | Invalid arguments, unavailable input, or operational failure |
