# StealthyPrivesc documentation

Use this page as the navigation hub for the project.

## Choose a path

- New operator: read [Installation](installation.md), then the [User Guide](user-guide.md).
- Command lookup: use the [CLI Reference](cli-reference.md).
- Assessment operator: read the [Operator Runbook](operator-runbook.md).
- Fast runbook navigation: use the [Runbook Modules](runbook/README.md).
- Developer: read [Build](build.md), [Architecture](architecture.md), and [Design](design.md).
- System overview: view the [Architecture Diagram](architecture-diagram.md).
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

## Documentation map

| Need | Start here |
| --- | --- |
| Install or build | [Installation](installation.md), [Build](build.md) |
| Learn the workflow | [User Guide](user-guide.md), [First User Journey](first-user-journey.md) |
| Find a command or flag | [CLI Reference](cli-reference.md) |
| Deploy to a target | [Operator Runbook](operator-runbook.md) |
| Choose a focused runbook workflow | [Runbook Modules](runbook/README.md) |
| Understand the design | [Architecture](architecture.md), [Architecture Diagram](architecture-diagram.md), [Design](design.md) |
| Review coverage and risk | [Capabilities](capabilities.md), [Technique Risk Notes](techniques.md) |

## Evidence workflow

Create an encrypted report with a securely handled key:

```bash
stealthy --authorized --verbose --output file \
  --output-path ./findings.seal scan
stealthy report ./findings.seal --key-hex "$STEALTHY_REPORT_KEY" --format sarif
```

Keep the key separate from the sealed report. Do not place keys, reports, or
assessment data in Git.
