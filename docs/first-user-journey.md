# First-User Journey

Status: planned capability

The first-user journey is a guided, safe path from installation to a useful preview. It is designed for a new authorized operator who has not used StealthyPrivesc before.

The journey must never perform privilege-affecting execution. It may validate configuration, use bundled fixtures, collect explicitly selected recon facts, build graphs, and render reports.

## Goals

- Confirm that the installation is usable.
- Explain the authorized-use requirement before collecting anything.
- Help the operator create or locate authorization metadata.
- Run a safe preview without requiring privileged execution.
- Produce inspectable artifacts and explain where they are stored.
- Detect common setup problems and provide actionable remediation.
- Make the next safe step obvious.

## Entry points

The primary entry point is:

```text
privesc guide
```

Non-interactive environments may use:

```text
privesc guide --non-interactive --fixture
```

The guide must also be reachable from the main help output and from the readiness command:

```text
privesc --help
privesc readiness
```

## Journey stages

### 1. Welcome and authorization notice

Display:

- Authorized-use-only notice
- The distinction between lab and engagement mode
- A statement that the guide does not perform privilege-affecting execution
- A link or path to authorization-file documentation

The guide must stop before recon if authorization metadata is missing or invalid.

### 2. Installation and environment check

Check and explain:

- Operating system and architecture
- Tool version
- Required core runtime availability
- Agent availability for the current platform
- Output-directory writability
- Available disk space where practical
- Whether the command is running interactively
- Whether the current platform is supported or preview-only

Each failure must include a cause and a remediation, for example:

```text
Output directory is not writable: ./privesc-out
Fix: choose a writable directory with --out-dir PATH and retry.
```

### 3. Configuration and authorization setup

Offer to:

- Select lab or engagement mode
- Select an output directory
- Load an existing authorization file
- Generate a clearly marked example authorization template
- Validate the authorization file

The guide must not silently create a valid authorization acknowledgement. Templates must require the operator to fill in engagement metadata and explicitly acknowledge legal authorization.

### 4. Safe preview

After authorization succeeds, the guide offers:

- Fixture-only preview for learning and CI
- Facts-file analysis when the operator already has `facts.v1.json`
- Explicitly selected local recon collection, if supported by the platform

The default path is fixture-only or dry-run. It does not execute plugins, alter services, create persistence, access credential material, or contact a C2 system.

### 5. Artifact walkthrough

Explain and validate the generated artifacts:

```text
facts.v1.json   Collected or fixture facts
graph.v1.json   Materialized attack-path graph
paths.v1.json   Ranked candidate paths
report.v1.json  Machine-readable report
report.md       Human-readable report
audit.jsonl     Operator activity record
```

The guide should display the output directory and provide the next command for each artifact.

### 6. Findings and interpretation

Explain:

- Current privilege context
- Top-ranked paths, if any
- Reliability, stealth, detection-risk, and time scores
- That scores are estimates, not guarantees
- Why a path may have been discarded
- Why no eligible path may be a valid result

The guide must avoid presenting a ranked path as an instruction to execute it.

### 7. Troubleshooting and next steps

Offer context-specific next steps:

- Re-run readiness checks
- Inspect the report
- Review the audit log
- Adjust collector allowlists
- Use a different output directory
- Validate a facts artifact again
- Read the troubleshooting documentation

Do not recommend bypassing authorization, disabling endpoint protection, or using `--force` as a generic fix.

## Non-interactive contract

`privesc guide --non-interactive --fixture` must:

- Never wait for stdin.
- Never execute privilege-affecting actions.
- Use deterministic fixture data.
- Write artifacts to an explicit or temporary output directory.
- Return zero only when installation, fixture processing, schema validation, and report generation succeed.
- Return a documented non-zero code with a remediation on failure.

## CI contract

When the implementation exists, CI must exercise the guide on Ubuntu and Windows and verify:

- Clean installation works.
- `privesc guide --help` works.
- Fixture mode completes without interaction.
- All expected artifacts are created.
- Every artifact validates against its schema.
- Report JSON is parseable.
- The audit log is present.
- No privilege-affecting command is invoked.
- Missing or invalid authorization produces an actionable failure.
- A read-only output directory produces a useful error.

The broader CI user-friction contract also covers clean release-archive installation, executable safe documentation examples, invalid-input troubleshooting, cross-platform agent syntax, artifact round trips, and schema compatibility fixtures.

## Safety boundary

The first-user journey is an onboarding and preview capability. It is not an execution wizard. Any future transition from preview to an on-target plan application must be a separate, explicit command with its own authorization, host-binding, risk, and confirmation gates.
