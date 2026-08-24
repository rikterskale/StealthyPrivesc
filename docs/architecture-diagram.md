# Architecture Diagram

The diagram shows the normal data flow from an operator command to a report.
Dashed paths are optional or platform-specific. The default path does not
write to disk and does not execute an exploit.

```mermaid
flowchart TD
    A[Operator command] --> B[CLI parser]
    B --> C{Authorization required?}
    C -->|No: guide, doctor, disclaimer, report, diff, ingest, delivery| D[Local safe command]
    C -->|Yes| E{Acknowledgment present?}
    E -->|No| F[Exit 2: authorization required]
    E -->|Yes| G[Engine initialization]

    G --> H[OS and identity detection]
    G --> I[Plugin registry]
    I --> J[Validate --plugins and --skip]
    J --> K[Filter by OS and selection]
    K --> L[Run plugins with delay budget]

    L --> M[Linux plugins]
    L --> N[Windows plugins]
    L --> O[External staged dispatcher selects script fallback]
    M --> P[Finding values]
    N --> P
    O --> P
    L --> Q[Plugin coverage and timing]
    H --> R[Run provenance and token context]

    P --> PW[plugin_worker.rs: findings + notes + error]
    PW --> S[Encrypted in-memory store; worker notes preserved]
    Q --> T[Assessment metadata]
    R --> T
    S --> T
    T --> U{Output mode}
    U -->|memory| V[Human, JSON, Markdown, or SARIF]
    U -->|file| W[Sealed or approved plaintext file]
    U -->|remote| X[Operator-controlled sealed body instructions]

    Y[Baseline JSON] --> Z[Offline diff]
    AA[Current JSON] --> Z
    Z --> AB[Added, removed, changed findings]
```

## Component map

| Component | Responsibility |
| --- | --- |
| CLI parser | Flags, subcommands, defaults, and authorization gate inputs |
| Engine | OS selection, plugin validation, scheduling, checkpoint/triage orchestration |
| Plugin worker | Isolated execution, cancellation/timeout, and finding/note/error return |
| Reporting | Assessment, attack-path, and final report assembly |
| Identity/OS modules | Minimal local platform and execution-context evidence |
| Plugins | Independent Linux or Windows enumeration checks |
| Store | In-memory findings and authenticated encrypted export |
| Output | Human, JSON, Markdown, SARIF, file, and operator-controlled remote modes |
| Diff | Offline comparison of two plaintext JSON reports |
| CI UX gate | Release-binary contract checks across the user-visible command surface |

## Safety boundaries

- Authorization is required before host enumeration.
- Default execution is enumeration-only.
- High-impact families require `--allow-techniques` (scaffolded in this revision;
  AMSI/ETW/AV-EDR families have no execution modules).
- Reversible write probes require an exact finding approval or explicit
  standalone `--auto-exploit`.
- Reports and keys are kept separate when evidence is persisted.
