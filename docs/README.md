# StealthyPrivesc documentation

Use this page as the navigation hub for the project.

## Choose a path

- New operator: run `stealthy doctor`, then read [First User Journey](first-user-journey.md).
- Assessment operator: read the [Operator Runbook](operator-runbook.md).
- Developer: read [Build](build.md), [Architecture](architecture.md), and [Design](design.md).
- Defender or reviewer: read [Capabilities](capabilities.md) and [Technique Risk Notes](techniques.md).
- CI/integration user: use `--format json` or `--format sarif` and review the [Build](build.md) contract.

## Safe first run

```bash
stealthy doctor
stealthy guide
stealthy --authorized scan --min-severity medium
```

The first command performs local readiness checks. The scan requires explicit
authorization and remains enumeration-only unless `--auto-exploit` is chosen.

## Evidence workflow

Create an encrypted report with a securely handled key:

```bash
stealthy --authorized --verbose --output file \
  --output-path ./findings.seal scan
stealthy report ./findings.seal --key-hex "$STEALTHY_REPORT_KEY" --format sarif
```

Keep the key separate from the sealed report. Do not place keys, reports, or
assessment data in Git.
