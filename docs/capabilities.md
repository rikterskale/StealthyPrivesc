# StealthyPrivesc Capabilities

Status: design reference

This document consolidates the capabilities described in the high-level design. The repository is currently greenfield and contains no implemented tool functionality yet. Capabilities marked **planned** are design targets, not available commands.

## Capability status

| Area | Current status |
|---|---|
| Tool implementation | Not started; design-only repository |
| Windows recon | Planned |
| Linux recon | Planned |
| macOS support | Planned, identity/host facts only in v1 |
| Fact, graph, path, plan, and report schemas | Planned |
| Attack-path ranking | Planned |
| Authorization and audit controls | Planned |
| Privilege-affecting execution | Deferred behind on-target plan application and review gates |
| C2 and multi-host orchestration | Deferred to Phase 6+ |

## Initial MVP capabilities

### Authorization and operating modes

- Required authorization/consent metadata before recon or module execution.
- Authorization fields for engagement ID, client, scope, scope hash, operator ID, expiry, mode, and legal acknowledgement.
- RFC 3339 UTC expiry validation.
- Scope hash validation using normalized UTF-8 scope text.
- `lab` and `engagement` modes.
- Fail-closed mode mismatch handling between authorization, CLI, and configuration.
- Lab mode with broader collection and detection-test support when explicitly enabled.
- Engagement mode with high stealth defaults, reduced logging, conservative collection, and confirmation gates.
- `--force` and `--no-interactive` policy handling without bypassing authorization requirements.
- Append-mode JSONL audit events containing engagement, operator, host, action, module, result, risk, dry-run state, and configuration digest information.

The authorization gate is a process and UX control, not cryptographic proof that an engagement is authorized.

### Windows host capabilities

Planned PowerShell 5.1+ agent with native Windows collectors for:

- User and host identity
- Current privileges and elevation state
- Token information
- Services
- Scheduled tasks
- Patches and host configuration
- UAC settings
- AppLocker and related policy presence
- Writable filesystem locations, including program locations
- Credential-store presence markers without emitting secret material by default

Example planned invocation:

```powershell
.\privesc-tool.ps1 -Auto -AuthFile .\auth.json -OutDir .\privesc-out
```

The Windows agent is planned to emit the same shared facts envelope as the Unix agent. An optional `-ApplyPlan` bridge may delegate execution to a local Go core; it must not perform remote elevation itself.

### Linux host capabilities

Planned Bash 4+ Linux-first agent with collectors for:

- User, host, and privilege identity
- `sudo` and NOPASSWD indicators
- SUID files
- File capabilities
- Writable cron configuration
- Writable systemd user units
- Kernel and patch/version hints
- SSH-related configuration markers
- Container indicators
- Optional cloud metadata reachability probes

Example planned invocation:

```bash
./privesc-tool.sh --auto --auth-file ./auth.json --out-dir ./privesc-out
```

Python is not required on target hosts in v1. Optional Python tooling may be used on the operator workstation for research purposes.

### macOS capabilities

macOS support is best-effort in v1 and limited to:

- Host identity
- User identity
- Basic privilege facts
- Optional informational launchd counts

TCC/SIP bypasses and full macOS privilege-model parity are out of scope for v1.

### Shared fact model

Agents are planned to emit `facts.v1.json` with:

- Schema version
- Collection timestamp
- Host identity and OS family
- Agent name and version
- Username, UID/SID, groups, and privilege level
- Typed facts with stable dotted keys
- Confidence values
- Stealth cost values
- Source collector IDs
- Sensitive-value markers
- Optional raw references
- Collection duration, truncation, and error metadata

Facts are intended to be cross-platform contracts. Windows and Linux collectors may differ, but shared keys use consistent types and semantics. macOS emits a reduced subset.

Planned sensitive-data controls include:

- `sensitive` fact markers
- Report redaction by default
- Optional at-rest redaction
- User-only output-directory permissions (`0700` or equivalent ACL)
- Output size limits
- Collector allowlists and category controls

### Graph and attack-path capabilities

The attack-path graph is the primary product differentiator. Planned capabilities include:

- Facts-to-graph materialization
- State, technique, asset, and goal nodes
- Typed edges with preconditions
- Technique eligibility based on hard fact predicates
- Soft fact modifiers for success probability
- Confidence aggregation
- Detection-risk scoring
- Noise and footprint scoring
- Time-cost scoring
- Configurable reliability, stealth, and time weights
- Goal ranking for `goal.local_admin`, `goal.root`, and `goal.system`
- Reserved handling for domain and lateral-movement concepts
- Top-k simple-path ranking using Yen's algorithm or an equivalent algorithm
- Maximum depth and node-visit limits
- Discarded-path explanations
- Stable ranking tie-breakers
- Golden graph profiles for noisy and stealth-oriented behavior

Planned graph artifacts:

- `graph.v1.json`
- `paths.v1.json`

The graph records score snapshots at build time so that ranking is reproducible for a given graph artifact.

### Reporting capabilities

Planned report outputs:

- JSON report (`report.v1.json`)
- Markdown report (`report.md`)
- Colorized CLI view

Reports are planned to include:

- Host and identity summaries
- Current privilege level
- Ranked paths and goals
- Path reliability, stealth, time, and utility scores
- Recommended actions such as validate or dry-run
- Findings and warnings
- Sensitive-value redaction status
- Collection metadata
- Graph/path artifact references
- Audit references
- Authorized-use and stealth-score disclaimers

HTML reporting is deferred unless separately approved.

### Guided first-user journey

Planned `privesc guide` capability for a new authorized operator:

- Installation and environment checks
- Platform and agent availability checks
- Authorization and mode explanation
- Safe fixture-backed preview
- Non-interactive onboarding mode for CI and automation
- Facts, graph, paths, report, and audit artifact walkthrough
- Findings and score interpretation
- Actionable troubleshooting guidance
- Explicit separation between preview and privilege-affecting execution

The detailed contract is documented in [`docs/first-user-journey.md`](first-user-journey.md).

## Planned command surface

These commands are design targets and are not currently implemented:

| Command | Capability |
|---|---|
| `privesc auth check` | Full authorization-file validation |
| `privesc recon collect` | Same-host agent invocation and facts collection |
| `privesc graph build` | Facts to graph materialization |
| `privesc graph rank` | Ranked paths from facts/graph |
| `privesc plugin list` | Static registry introspection |
| `privesc plugin validate` | Plugin precondition validation |
| `privesc plan export` | Dry-run selected path and export `plan.v1.json` |
| `privesc plan apply` | On-target plan validation and gated application |
| `privesc run` | Recon, graph, ranking, and report pipeline |
| `privesc report render` | JSON, Markdown, and color report rendering |
| `privesc guide` | Guided first-user setup and safe preview |

Planned exit-code categories include authorization failure, validation failure, partial collection, configuration/mode mismatch, topology denial, and unavailable or disabled apply bridges.

## Artifact workflow

The intended v1 workflow is:

```text
Target agent
  -> facts.v1.json
  -> operator-host graph build and ranking
  -> graph.v1.json / paths.v1.json
  -> operator-host report and dry-run validation
  -> plan.v1.json
  -> target-local plan apply, if enabled
  -> audit and report artifacts
```

The default artifact directory is planned to contain:

```text
privesc-out/
├── auth.json          # optional working copy
├── facts.v1.json
├── graph.v1.json      # optional debug artifact
├── paths.v1.json
├── plan.v1.json       # required for on-target apply
├── report.v1.json
├── report.md
└── audit.jsonl
```

Agents communicate through files and exit codes in v1. A custom RPC or stdin JSON protocol is not required.

## Plan and execution capabilities

### Operator-host capabilities

The operator-host core is planned to support:

- Facts validation
- Graph construction and ranking
- Report generation
- Plugin metadata inspection
- Plugin validation
- Plugin dry-run
- Plan export
- Plan integrity checks

The operator host must not directly perform privilege-affecting remote execution in v1.

### On-target capabilities

On-target plan application is planned to:

- Revalidate authorization
- Load the plan and matching facts
- Verify the raw-byte `facts_sha256`
- Compute the facts-derived host ID
- Probe the live local host identity
- Require `live_host_id == plan.host_id == facts_host_id`
- Revalidate plugin preconditions
- Apply mode, risk, feature-flag, and confirmation policy
- Execute only when the action is permitted
- Emit audit events

Host binding is intended to prevent accidental application of a target plan to the operator workstation. It is not a cryptographic host-authentication mechanism.

### Planned execution policy

- Validate and dry-run are side-effect-free interfaces.
- Low- and medium-risk lab actions may be allowed subject to confirmation.
- High- and critical-risk lab actions require confirmation.
- High- and critical-risk engagement actions are dry-run-only by default.
- Engagement high-risk execution requires an explicit high-risk flag and confirmation.
- Detection-test plugins are denied in engagement mode.
- Feature flags default to disabled for post-exploitation categories.
- Pure script execution adapters are deferred until later phases.

## Planned plugin capabilities

Plugins are planned as static Go registry entries with adjacent `plugin.meta.v1.yaml` metadata. Early implementations are stubs that validate preconditions and produce dry-run plans without payloads or exploit recipes.

### Exploitation metadata and stubs

Planned Windows categories include:

- Token-related techniques
- Service-related techniques
- DLL and named-pipe technique classes
- UAC-related technique classes
- Kernel-related technique classes

Planned Unix categories include:

- SUID
- `sudo`
- Cron
- File capabilities
- Container-related technique classes
- Kernel-related technique classes

### Credential-access metadata and stubs

Planned categories include:

- Windows credential stores
- LSASS/DPAPI/SAM/Kerberos-related classes
- Linux shadow, SSH, history, environment, and cloud-related classes

The design does not authorize inclusion of credential-dump recipes or secret-extraction payloads in early releases.

### Persistence metadata and stubs

Planned categories include:

- Windows scheduled tasks
- WMI
- Run keys
- Services
- DLL search-order classes
- Linux cron
- systemd
- SSH keys
- Shell profiles

### Evasion and stealth policy

Planned cross-cutting policy capabilities include:

- Collector selection
- Timing and jitter controls
- Detection-risk eligibility caps
- Target-side logging policy
- Cleanup-hook registration
- Lab-only detection-test hooks
- C2 jitter controls in later phases

This category is explicitly not intended to provide AMSI/ETW bypasses or other evasion recipes.

## Security, privacy, and operational controls

Planned controls include:

- Authorized-use notice in README, CLI, and reports
- Required legal acknowledgement
- Authorization expiry
- Mode binding
- Audit logging
- Feature flags
- Confirmation gates
- Dry-run defaults for high-risk engagement actions
- Sensitive fact markers
- Report redaction
- Restricted artifact-directory permissions
- Collector timeouts
- Output caps
- Configurable collector allowlists
- No domain-wide or lateral movement execution in v1
- No unattended worm or blast behavior
- No guarantee of EDR evasion
- Signed releases and checksums as future supply-chain controls

CI is planned to validate the user journey across clean installation, release archives, safe fixture workflows, documented commands, failure messages, shell-agent compatibility, artifact round trips, and schema compatibility.

The design treats audit JSONL as tamper-evident operational history only if an external trusted sink or stronger storage control is added later; local append mode alone does not guarantee integrity.

## Phased capability roadmap

### Phase 1: foundation

- Repository scaffolding
- Authorized-use and policy documentation
- Authorization schema
- Example lab and engagement configurations
- CI and schema-validation skeleton

### Phase 2: contracts and recon

- Shared facts, graph, path, plan, and report schemas
- Windows PowerShell recon
- Linux Bash recon
- macOS identity/host subset
- Fixture-based agent tests

### Phase 3: graph and reporting

- Go core CLI
- Authorization and audit implementation
- Fact-to-graph materialization
- Scoring and ranking
- JSON/Markdown/color reporting
- End-to-end recon-to-report pipeline

### Phase 4: plugin interfaces

- Static plugin registry
- Plugin metadata contracts
- Validate and dry-run interfaces
- Feature flags
- Plan export
- Apply topology and host-binding tests

### Phase 5: category stubs and policy

- Exploitation stubs
- Credential-access stubs
- Persistence stubs
- Evasion/stealth policy
- Lab-only detect-test hooks

### Phase 6 and later

- Optional C2 design spike and eventual orchestration
- Multi-host workflows
- Pure-script execution adapters
- Stronger authorization binding, such as signed authorization files
- Packaging, release checksums, and optional signing
- Interactive UX polish
- Optional HTML reporting

## Explicitly out of scope for v1

- General malware-framework behavior
- Unattended worm or lateral blast behavior
- Domain-wide or forest-wide targeting
- Active Directory and lateral-movement execution
- Remote privilege-affecting execution from the operator host
- TCC/SIP bypasses
- Full macOS privilege-model parity
- Python on target agents
- Dynamic or subprocess plugin loading
- Exploit recipe cookbook
- AMSI/ETW bypass implementations
- LSASS dump recipes
- Ready-to-use persistence payloads
- Guaranteed EDR evasion
- Mandatory C2

## Source design

The authoritative design source for these capabilities is [`docs/design.md`](design.md), particularly its goals, key decisions, proposed design, plugin contracts, API surface, security considerations, open questions, and PR plan.
