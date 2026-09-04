# StealthyPrivesc User Acceptance Test Plan

This plan is the Phase 5 acceptance contract for the journey documented in
[`USER_JOURNEY.md`](USER_JOURNEY.md). It tests only local, authorized,
enumeration-first behavior. All generated reports, keys, checkpoints, ledgers,
and staged bundles are created in a disposable directory and removed when the
suite exits.

## Execution record

- Revision under test: `8d30f670ee1e21c73463692d4f4cac1d1508b9fc`
- Execution time: 2026-09-04T11:31:49-04:00
- Platform: Ubuntu 26.04 LTS, Linux x86_64
- Toolchain: Rust/Cargo 1.98.0; Python 3.14.4
- Build: `cargo build --locked --workspace --release` — exit `0`
- Automated command: `python3 scripts/ci/validate_uat.py ./target/release/stealthy --repo-root . --report /tmp/stealthy-phase5-uat-linux.json` — exit `0`
- Captured evidence: 34 automated cases, 41 subprocess records, SHA-256
  `70d7fb887cb40b607689d89e50bfc295b6104f67775b9915e45b640d88807a82`
- Human precondition: the repository owner explicitly authorized the work in
  the task. That acknowledgment does not replace engagement ROE on a target.

The CI `user-readiness` matrix repeats the automated command on current Ubuntu
and Windows runners and uploads both JSON evidence files for 14 days. Each JSON
record contains the exact argument vector, exit code, stdout, stderr, and a
SHA-256 digest for every subprocess. The console summary deliberately avoids
printing host identity and sealed-report material.

## Acceptance cases

`PASS` means the actual result below was captured during the execution record,
not inferred from source or documentation. `UAT-M01` is the only judgment-based
precondition; every product behavior is automated.

| Test ID | Precondition | Steps | Expected result | Actual result | Pass/Fail |
| --- | --- | --- | --- | --- | --- |
| UAT-M01 | Repository owner controls this local checkout. | Confirm the task includes explicit permission; keep execution local and within the documented safety boundary. | An explicit authorization statement exists before host enumeration. | The owner explicitly authorized the implementation and verification work; no remote target was used. | PASS |
| UAT-J01 | Reviewed source and Rust toolchain are present. | Run `cargo build --locked --workspace --release`; verify the release path. | Exit `0`; release binary exists and is executable. | Build exited `0`; `target/release/stealthy` existed and was executable. | PASS |
| UAT-J02 | UAT-J01 passed. | Run `stealthy --version`. | Exit `0`; stdout matches `^stealthy [0-9]+\.[0-9]+\.[0-9]+$`. | Exit `0`; stdout was `stealthy 0.1.0`. | PASS |
| UAT-J03 | Supported local OS. | Run `stealthy doctor --json`. | Exit `0`; valid schema `1`; healthy and nonblocking; plugin count is positive. | Exit `0`; schema `1`; `healthy=true`; `blocking=false`; 16 plugins. | PASS |
| UAT-J04 | Binary is available; authorization is not required. | Run `guide`, then `disclaimer`. | Both exit `0`; guide contains the safe scan and disclaimer contains the authorized-use boundary. | Both exited `0`; `stealthy --authorized scan` and authorized-use markers were present. | PASS |
| UAT-J05 | No authorization flag or environment acknowledgment. | Run `stealthy enum` in a clean disposable directory. | Exit `2`; actionable authorization message; no report, key, or ledger. | Exit `2`; stderr contained `Authorization required`; no evidence or `.cache-run` was created. | PASS |
| UAT-J06 | Authorization acknowledged. | Run `stealthy --authorized list-plugins --tsv`; select a platform ID. | Exit `0`; nonempty, correctly namespaced plugin list. | Exit `0`; selected `linux.kernel_cve` from a nonempty Linux list. | PASS |
| UAT-J07 | Authorization acknowledged; clean disposable working directory. | Run the visible, all-plugin baseline with memory output. | Exit `0`; identity, enumerate-only mode, summary, coverage, and memory disposition are visible; no ledger. | Exit `0`; every marker was captured and no `.cache-run` was created. | PASS |
| UAT-J08 | UAT-J06 selected one valid plugin. | Run quiet JSON memory output for only that plugin. | Exit `0`; schema `2`; authorization true; enumerate-only/native; selected plugin in `plugins_run` and coverage. | Exit `0`; schema `2` native enumerate-only report contained `linux.kernel_cve` and its coverage. | PASS |
| UAT-J09 | Separate disposable report and key paths. | Write encrypted file output; ensure key is not in output; decode with `report --key-file`. | Exit `0`; distinct report/key exist; no key leak; decoded schema is `2`; private modes on Unix. | Report and key were created with mode `0600`; key was absent from output; offline decode returned schema `2`. | PASS |
| UAT-J10 | A staged bundle and its dedicated ledger exist. | Run `artifacts --latest --json`, then `cleanup --latest --secure-delete`. | Listing and cleanup exit `0`; recorded removable stage is absent afterward. | Three ledger entries were listed; cleanup exited `0`; stage directory was absent. | PASS |
| UAT-A01 | A deliberately nonexistent binary path. | Attempt `--version` through that path. | Launch fails before any host action or artifact. | `FileNotFoundError` was captured; no ledger was created. | PASS |
| UAT-A02 | Disposable working directory is marked read-only. | Run `doctor --json` from that directory. | Blocking diagnostic with explicit writable-directory remediation. | Exit `3`; `healthy=false`; `blocking=true`; remediation was present. | PASS |
| UAT-A03 | Authorization acknowledged; nonexistent plugin ID. | Run enum with `not.a.real.plugin`. | Exit `1`; identifies unknown plugin and recommends `list-plugins`. | Exit `1`; both required messages were captured. | PASS |
| UAT-A04 | Valid plugin; human format; `--quiet`. | Run focused enumeration. | Exit `0`; human stdout is empty by design. | Exit `0`; stdout was empty. | PASS |
| UAT-A05 | Bundled empty-findings fallback fixture. | Normalize it with `ingest --format json`. | Exit `0`; zero findings remain distinguishable from reduced or absent coverage. | Zero findings and coverage were retained with `coverage_mode=script` and a nonempty capability delta. | PASS |
| UAT-A06 | Selected plugin deterministically emits at least one informational finding. | Run JSON enum with `--fail-on info`. | Report is emitted and process exits `4`. | One finding was emitted; exit was `4`. | PASS |
| UAT-A07 | File output path supplied without a key path. | Run encrypted output. | Exit `1`; requires `--key-output-path`; no sealed report. | Exit `1`; guidance was present and no report existed. | PASS |
| UAT-A08 | Two valid sealed report/key pairs. | Decode the first report with the second key. | Nonzero exit; no plaintext report. | Wrong pair was rejected with exit `1`. | PASS |
| UAT-A09 | Valid sealed report/key pair. | Flip one ciphertext byte; attempt decode with the correct key. | Nonzero exit; modified evidence is rejected. | Modified ciphertext was rejected with exit `1`. | PASS |
| UAT-A10 | Approved staged fallback; on Linux, primary exits `126`; on Windows, script-only stage. | Invoke the staged dispatcher with authorization. | Exit `0`; blocked/unavailable primary takes an approved fallback; script coverage and capability delta are explicit. | Linux dispatcher reported the blocked primary, used `python-fallback`, and returned script coverage plus capability delta. | PASS |
| UAT-A11 | Stage directory contains a sentinel file. | Attempt `stage --out` to that directory. | Nonzero exit; says destination must be empty; sentinel unchanged. | Exit `1`; must-be-empty error; sentinel content remained unchanged. | PASS |
| UAT-A12 | Stage destination is a sentinel regular file. | Attempt `stage --out` to that path. | Nonzero exit; file remains unchanged. | Exit `1`; non-directory destination remained unchanged. | PASS |
| UAT-A13 | Valid selected plugin and writable checkpoint path. | Run a checkpointed enum; resume the completed checkpoint. | Both exit `0`; selected plugin remains covered with status `ok`. | Checkpoint was created; resume exited `0`; `linux.kernel_cve` coverage remained `ok`. | PASS |
| UAT-A14 | Checkpoint contains malformed JSON. | Run authorized `resume`. | Exit `1`; checkpoint rejected before plugin execution. | Exit `1`; corrupt JSON was rejected before plugin execution. | PASS |
| UAT-B01 | Authorization acknowledged. | Pass an empty `--plugins` value. | Exit `1`; empty plugin lists are rejected with recovery guidance. | Exit `1`; empty value and listing guidance were present. | PASS |
| UAT-B02 | Authorization acknowledged. | Pass an unknown `--allow-techniques` family. | Exit `1`; unknown family is rejected without technique execution. | Exit `1`; unknown family was rejected. | PASS |
| UAT-B03 | File output selected without `--output-path`. | Run a focused enum. | Exit `1`; report-path requirement is explicit. | Exit `1`; `--output=file requires --output-path` was captured. | PASS |
| UAT-B04 | One path supplied as both report and key sink. | Run encrypted file output. | Exit `1`; sinks must differ; path is not created. | Exit `1`; identical paths were rejected before writing. | PASS |
| UAT-B05 | Remote output uses an `http://` loopback URL. | Run a focused remote-output enum with a key path. | Exit `1` before networking; absolute HTTPS is required; no key is created. | Exit `1`; HTTPS requirement was present and no key was created. | PASS |
| UAT-B06 | Stage name contains `../`. | Attempt to stage in a disposable directory. | Nonzero exit; unsafe basename rejected; no path escape. | Exit `1`; path-like name was rejected and no escaped artifact existed. | PASS |
| UAT-B07 | Valid plugin; `--max-findings 1`. | Run focused JSON enumeration. | Exit `0`; retained findings do not exceed one. | Exit `0`; retained finding count was one. | PASS |
| UAT-B08 | Valid plugin; `--max-report-bytes 1`. | Run focused enumeration. | Nonzero exit; oversized report fails closed with the named limit. | Exit `1`; `max-report-bytes` error was present. | PASS |
| UAT-B09 | Valid-format placeholder key; missing sealed input path. | Run offline `report`. | Nonzero exit; missing input is reported. | Exit `1`; missing report was reported as an error. | PASS |
| UAT-B10 | Empty staged target hostname. | Attempt to create a staged bundle. | Nonzero exit; target hostname is required; no usable stage. | Exit `1`; required-hostname error was present. | PASS |

## Automated run output

```text
PASS UAT-J01 — release binary is build-ready
PASS UAT-J02 — product identity
PASS UAT-J03 — healthy readiness
PASS UAT-J04 — guide and disclaimer
PASS UAT-J05 — authorization gate
PASS UAT-J06 — platform plugin discovery
PASS UAT-J07 — visible memory-only baseline
PASS UAT-J08 — focused JSON report
PASS UAT-J09 — sealed evidence round trip
PASS UAT-J10 — artifact listing and cleanup
PASS UAT-A01 — missing binary fails before host action
PASS UAT-A02 — doctor reports a blocking working directory
PASS UAT-A03 — unknown plugin is actionable
PASS UAT-A04 — quiet human output is intentionally blank
PASS UAT-A05 — empty findings preserve coverage limits
PASS UAT-A06 — severity threshold uses exit code 4
PASS UAT-A07 — encrypted output requires a protected key sink
PASS UAT-A08 — wrong report key fails closed
PASS UAT-A09 — tampered sealed report fails closed
PASS UAT-A10 — approved script fallback reports reduced coverage
PASS UAT-A11 — non-empty stage destination is preserved
PASS UAT-A12 — non-directory stage destination is preserved
PASS UAT-A13 — checkpoint resume preserves completed coverage
PASS UAT-A14 — corrupt checkpoint is rejected
PASS UAT-B01 — empty plugin selection is rejected
PASS UAT-B02 — unknown technique family is rejected
PASS UAT-B03 — file output requires a report path
PASS UAT-B04 — report and key paths must differ
PASS UAT-B05 — remote output rejects non-HTTPS URLs
PASS UAT-B06 — stage rejects path-like bundle names
PASS UAT-B07 — finding count is bounded
PASS UAT-B08 — report size is bounded
PASS UAT-B09 — missing sealed report is rejected
PASS UAT-B10 — empty stage hostname is rejected
UAT SUMMARY — total=34 passed=34 failed=0
```

## Result

Total acceptance cases: **35** — **35 passed, 0 failed**. The 34 automated
cases cover every binary journey criterion, documented alternate/error path,
and selected boundary; the remaining case records the explicit human
authorization precondition.

**UAT: passed.**
