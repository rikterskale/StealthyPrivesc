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
| `--profile quiet\|balanced\|thorough\|ci` | Named OPSEC / engagement posture (explicit flags override) | `balanced` |
| `--plugin-timeout-ms N` | Per-plugin timeout; `0` disables | Profile default |
| `--checkpoint PATH` | Write/update plaintext JSON checkpoint during the run | None |
| `--ledger-dir PATH` | Artifact ledger directory | `.stealthy-artifacts` |

Severity levels, from least to greatest, are `info`, `low`, `medium`, `high`,
and `critical`.

Profiles: `quiet` (skip audited helpers like `sudo -l`, higher delay),
`balanced` (default), `thorough` (no delay, verbose), `ci` (quiet JSON).

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
stealthy --authorized --profile quiet enum
stealthy --authorized enum --auto-exploit
stealthy --authorized enum --allow-techniques kernel-exploit,potato
stealthy --authorized enum --plugins ID1,ID2
stealthy --authorized enum --skip ID1,ID2
stealthy --authorized enum --triage --triage-out decisions.json
stealthy --authorized enum --approve-file decisions.json
stealthy --authorized --checkpoint /tmp/run.json enum
```

`scan` is a visible alias for `enum`. Options:

- `--auto-exploit`: enables supported reversible probes.
- `--allow-techniques`: comma-separated high-impact families when ROE permits.
  Known IDs: `persistence`, `host-crash`, `potato`, `kernel-exploit`,
  `service-replace`, `msi`, `credential-dump`, `endpoint-bypass`.
  This revision accepts the flag and records scaffold findings; payloads land later.
- `--plugins`: runs the listed IDs; unknown IDs fail.
- `--skip`: excludes the listed IDs; unknown IDs fail.
- `--triage` / `--triage-out` / `--approve-file`: stepwise operator approval for probes.

## `resume`

```text
stealthy --authorized resume --checkpoint /tmp/run.json
```

Continues a prior checkpointed run, skipping plugins already marked `ok`.

## `ingest`

```text
stealthy ingest script-report.json --format json
```

Normalizes script-fallback JSON into schema v2 (stable IDs, MITRE, attack paths).

## `artifacts` / `cleanup`

```text
stealthy artifacts --latest
stealthy cleanup --latest --secure-delete
```

List or remove removable paths recorded in the run ledger.

## `stage` / `verify` / `one-liners`

```text
stealthy stage --os linux --arch x86_64 --out ./drop --binary ./target/release/stealthy
stealthy verify --path ./drop/cache-update --expect-sha256 HEX
stealthy one-liners --os linux --transport ssh
```

Operator-workstation delivery helpers (no host enumeration; no auth gate).

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
