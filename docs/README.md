# StealthyPrivesc documentation

Use this page as the navigation hub for the project.

## Choose a path

- New operator: read [Installation](installation.md), then the [User Guide](user-guide.md).
- Command lookup: use the [CLI Reference](cli-reference.md).
- Assessment operator: read the [Operator Runbook](operator-runbook.md).
- Fast runbook navigation: use the [Runbook Modules](runbook/README.md).
- Developer: read [Build](build.md), [Architecture](architecture.md), and [Design](design.md).
- Release owner: follow the [Operations and release runbook](operations.md).
- System overview: view the [Architecture Diagram](architecture-diagram.md).
- Defender or reviewer: read [Capabilities](capabilities.md) and [Technique Risk Notes](techniques.md).
- CI/integration user: use `--format json` or `--format sarif` and review the [Build](build.md) contract.
- Report consumer: use the [Report schema](report-schema.md) and inspect coverage before comparing runs.
- Release consumer: review the [Support Policy](support-policy.md) before selecting a version or artifact.

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
| Learn the workflow | [Verified User Journey](USER_JOURNEY.md), [User Guide](user-guide.md), [First User Journey](first-user-journey.md) |
| Find a command or flag | [CLI Reference](cli-reference.md) |
| Deploy to a target | [Operator Runbook](operator-runbook.md) |
| Choose a focused runbook workflow | [Runbook Modules](runbook/README.md) |
| Understand the design | [Architecture](architecture.md), [Architecture Diagram](architecture-diagram.md), [Design](design.md) |
| Review coverage and risk | [Capabilities](capabilities.md), [Technique Risk Notes](techniques.md) |
| Check supported releases and schemas | [Support Policy](support-policy.md) |

## Evidence workflow

Create an encrypted report with a securely handled key:

```bash
stealthy --authorized --verbose --output file \
  --output-path ./findings.seal \
  --key-output-path /approved/keys/findings.key scan
stealthy report ./findings.seal --key-file /approved/keys/findings.key --format sarif
```

The full key is never printed to stderr. The key file is created with mode
`0600` on Unix; on Windows, inheritance is removed and full control is granted
only to the current SID. Move it into the approved secret store and keep it
separate from the sealed report. Do not place keys, reports, or assessment data
in Git.
