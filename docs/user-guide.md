# User Guide

This is the short, practical guide for a first-time operator. For large
deployment workflows, use the [Operator Runbook](operator-runbook.md).

## 1. Confirm authorization

Confirm that the rules of engagement cover the target host, privilege-
escalation enumeration, report handling, optional write probes, and any
operator-controlled remote output. The tool refuses host enumeration unless
you pass `--authorized` or set `STEALTHY_AUTHORIZED=1`.

## 2. Check readiness

```bash
stealthy doctor
stealthy guide
stealthy list-plugins
```

`doctor` checks the local execution environment. `guide` explains the safety
boundary. `list-plugins` shows checks compiled into the current OS build.

## 3. Run the first scan

Start with a quiet, memory-only, enumeration-only scan:

```bash
stealthy --authorized --quiet scan
```

Use normal output when you want progress and severity summaries:

```bash
stealthy --authorized scan
```

The scan reads local state, produces findings and recommendations, and keeps
results in memory unless an output mode is explicitly selected.

## 4. Narrow or prioritize results

```bash
stealthy --authorized scan --min-severity high
stealthy --authorized scan --plugins linux.sudo,linux.suid
stealthy --authorized scan --skip linux.kernel_cve
stealthy --authorized --delay-ms 250 scan
```

Plugin IDs are OS-specific. Unknown IDs fail with an actionable error; use
`list-plugins` on the target build to select valid IDs.

## 5. Choose an output format

```bash
stealthy --authorized --format human scan
stealthy --authorized --format markdown scan > report.md
stealthy --authorized --format json --quiet scan > report.json
stealthy --authorized --format sarif --quiet scan > report.sarif
```

Use JSON for integrations, SARIF for compatible security tooling, and
Markdown for human evidence review. JSON reports include run provenance,
identity context, plugin coverage, assessments, and findings.

## 6. Store evidence safely

Encrypted file output is the preferred persistent format:

```bash
stealthy --authorized --verbose --output file \
  --output-path ./findings.seal --also-markdown scan
```

The decryption key is operator-held and must be stored separately from the
sealed file:

```bash
stealthy report ./findings.seal \
  --key-hex "$STEALTHY_REPORT_KEY" --format markdown
```

Plaintext output is available when the evidence policy permits it:

```bash
stealthy --authorized --output file --plaintext-file \
  --output-path ./findings.json scan
```

## 7. Compare two scans

`diff` is offline and does not require authorization or host access. It
compares plaintext JSON reports:

```bash
stealthy diff baseline.json current.json
stealthy diff baseline.json current.json --format markdown
```

The result classifies findings as added, removed, or changed.

## 8. Optional reversible probes

Only use this mode when explicitly authorized:

```bash
stealthy --authorized scan --auto-exploit
```

The mode is limited to low-noise, reversible write probes. It never runs
kernel exploits, replaces service binaries, builds or runs MSI payloads,
abuses token impersonation, or creates persistence.

## 9. Automation behavior

Use `--quiet` for clean machine-readable output and `--fail-on` for gates:

```bash
stealthy --authorized --quiet --format json scan
stealthy --authorized --quiet scan --fail-on critical
```

Exit `0` means the command completed without crossing the selected failure
threshold. Exit `2` means authorization was missing. Exit `4` means
`--fail-on` was triggered. Invalid arguments and operational errors return a
nonzero error exit.

## 10. Troubleshooting

| Symptom | Action |
| --- | --- |
| Authorization required | Add `--authorized` or set `STEALTHY_AUTHORIZED=1` |
| No plugins matched | Run `list-plugins`; check the target OS and plugin IDs |
| Output path error | Add `--output-path` when using `--output file` |
| Sealed report will not open | Use the exact operator key from the creation run |
| Binary blocked | Use the approved script fallback and record the limitation |
| Plugin error | Re-run with `--verbose` and preserve the coverage/error record |
