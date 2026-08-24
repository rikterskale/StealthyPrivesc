# CI User Readiness Validation

## Overview

The **User Readiness Validation** suite ensures that StealthyPrivesc is production-ready for end users before every commit and release. These checks validate the complete user experience, not just code correctness.

This document is for maintainers and CI operators. For end-user guidance, see [First-User Journey](first-user-journey.md).

## Purpose

User readiness validation prevents:
- ❌ Releases with incomplete documentation
- ❌ Broken installation procedures
- ❌ Unclear error messages
- ❌ Missing examples or broken examples
- ❌ Inconsistent version information
- ❌ Accessibility regressions (color, output formats)

## Validation Categories

### 1. Installation Readiness

**What it checks:**
- Binary builds and runs
- `--version` outputs valid semantic version
- `doctor --json` reports healthy system
- Version format conforms to pre-1.0 versioning scheme

**Why it matters:**
Users' first experience is installation and verification. Broken installation scripts or missing health checks block adoption.

**Related docs:**
- [Installation Guide](installation.md)
- [Support Policy](support-policy.md)

### 2. First-User Journey Contract

**What it checks:**
- `guide` command exists and has content
- `disclaimer` command exists and mentions authorization
- `--version` works without authorization
- Unauthorized `enum` exits with code 2 and clear message
- `--authorized list-plugins` works and lists plugins uniquely

**Why it matters:**
The first-user journey is contractual. Users should be able to:
1. Verify the binary works (`doctor`, `guide`)
2. Read the legal disclaimer
3. Understand authorization is required
4. See what they can enumerate

If any step fails, the user experience is broken.

**Related docs:**
- [First-User Journey](first-user-journey.md)
- [User Guide](user-guide.md)

### 3. Help Text Completeness

**What it checks:**
- `--help` command works and has content
- Help text mentions key commands (`enum`, `doctor`, `guide`, `list-plugins`, `report`, `stage`)
- Help text is not truncated or malformed

**Why it matters:**
Users discover features through `--help`. Incomplete help text limits discoverability.

### 4. Output Formats

**What it checks:**
- All documented output formats work: `human`, `json`, `markdown`, `sarif`
- JSON output has correct schema version (2)
- Markdown output starts with expected header
- SARIF output has correct version (2.1.0)
- All required fields present in reports

**Why it matters:**
Different users need different output formats:
- **JSON** for automation and integration
- **Markdown** for human-readable reports
- **SARIF** for SIEM/aggregation systems
- **Human** for interactive use

If a format breaks, it blocks users who depend on it.

### 5. Error Messages

**What it checks:**
- Unknown plugin errors suggest `list-plugins`
- Authorization errors are clear
- Error messages are actionable (not just "error: invalid")
- Errors go to stderr, success to stdout

**Why it matters:**
Good error messages prevent user frustration and reduce support burden. A user who receives a helpful error message can often self-recover.

### 6. Accessibility

**What it checks:**
- `--no-color` flag works and removes all ANSI codes
- `NO_COLOR` environment variable is respected
- Output is readable in both color and monochrome
- Output is parseable by color-blind users and automation

**Why it matters:**
Not all users run in a color-capable terminal. Some users are color-blind. Automation systems may not parse ANSI codes correctly.

### 7. Documentation References

**What it checks:**
- Required documentation files exist:
  - `docs/cli-reference.md` — complete command reference
  - `docs/user-guide.md` — guided workflow
  - `docs/operator-runbook.md` — deployment instructions
  - `docs/support-policy.md` — version and support guarantees
- Documentation is cross-linked (no orphaned docs)
- All links are resolvable

**Why it matters:**
Users expect complete documentation. Missing docs create support tickets and reduce trust.

### 8. Environment Variables

**What it checks:**
- Documented environment variables work:
  - `STEALTHY_AUTHORIZED=1` — equivalent to `--authorized` flag
  - Others documented in CLI reference

**Why it matters:**
Some users prefer environment variables over CLI flags (shell scripts, Docker, CI/CD). Broken env var support blocks these use cases.

### 9. Plugin Coverage

**What it checks:**
- Both Linux and Windows plugins are available
- Plugin list is consistent across formats (`--json`, `--tsv`)
- No duplicate plugin IDs
- Reasonable number of plugins (>10)

**Why it matters:**
If a platform's plugins are missing, users on that platform cannot enumerate.

### 10. Exit Codes

**What it checks:**
- Unauthorized access exits with code 2
- Successful enum exits with code 0 (or 4 if `--fail-on` triggered)
- Invalid input exits with code 1
- Unknown plugin exits with code 1
- Enumeration failures exit with code 1

**Why it matters:**
Exit codes enable automation. CI/CD systems depend on knowing when to fail or succeed.

### 11. Output Schema

**What it checks:**
- JSON report has required top-level fields:
  - `schema_version` (must be 2)
  - `run_id` (unique per run)
  - `authorized_use_ack` (true/false)
  - `started_at_unix` (epoch timestamp)
  - `mode` (enumerate-only, etc)
  - `plugins_run` (list)
  - `identity` (elevation source, hostname)
  - `assessments` (per-plugin metadata)
  - `findings` (results)
  - `coverage` (per-plugin performance)
- Each finding has required fields:
  - `plugin`, `kind`, `severity`, `title`, `detail`, `recommendation`
- `coverage` has one entry per plugin in `plugins_run`, and all plugin references are valid

**Why it matters:**
External systems parse the JSON report. Missing fields break downstream analysis.

### 12. Installation Script Validation

**What it checks:**
- Install scripts are syntactically valid (bash -n)
- Linux installer mentions artifact attestation and SHA-256 verification
- Windows installer mentions artifact attestation and SHA-256 verification
- Both installers specify correct install locations

**Why it matters:**
Users follow these scripts. Broken or misleading installation procedures are a common failure point.

### 13. Documentation Examples

**What it checks:**
- Key documentation files exist and have examples
- Examples reference correct commands
- Examples are not outdated or broken

**Why it matters:**
Users copy examples from docs. Broken examples waste time and erode trust.

### 14. Version Consistency

**What it checks:**
- Version in `Cargo.toml` follows pre-1.0 format: `0.MINOR.PATCH`
- Version is consistently used across docs
- Support policy is updated for the version

**Why it matters:**
Inconsistent versioning confuses users and makes support difficult. Outdated support policies create false expectations.

### 15. CLI Help References

**What it checks:**
- `--help` output mentions all major commands
- Authorization error messages are clear
- `--help` is not truncated

**Why it matters:**
Users discover commands through help. Truncated or incomplete help limits feature adoption.

## CI Integration

### In `ci.yml`

The `user-readiness` job:
- Runs on every commit to PR branches
- Builds the release binary
- Runs a single validation script (`scripts/ci/validate_user_readiness.py`) on
  both `ubuntu-latest` and `windows-latest` runners
- Enforces strict readiness checks (all listed checks are treated as failures)
- Gates the `production-readiness` aggregate job

The workflow no longer duplicates installation/doc/version validation in shell scripts;
all checks above are centralized in the Python validator.

**Run time:** ~10 minutes

**What it gates:**
- Prevents merged PRs that break user experience
- Catches documentation regressions early
- Validates accessibility features

### In `release.yml`

The user readiness validation also runs in the tag-gate:
- Validates release artifacts before publishing
- Ensures users can install and run the tool
- Confirms all documentation is present

**Run time:** ~5 minutes (after other validations)

**What it gates:**
- Prevents invalid releases
- Confirms users can follow the first-user journey
- Validates the release is production-ready

## Interpreting Results

### All checks pass ✅

**Meaning:** The user experience is production-ready. Users can:
- Install the tool following provided instructions
- Run `doctor` / `guide` / `disclaimer` without issues
- Complete the first-user journey
- Use all documented output formats
- Understand error messages
- Access documentation

**Action:** Safe to merge or release.

### Warnings (compatibility)

**Meaning:** The warning channel is intentionally not used for current readiness
contracts. `--strict-warnings` is retained for compatibility with existing CI scripts.

CI currently enforces all listed checks as errors.

### Errors (blocking) ❌

**Meaning:** Critical issues that must be fixed. The user experience is broken.

**Examples:**
- "doctor command failed" — binary is broken
- "Required documentation missing: cli-reference.md" — docs are incomplete
- "--no-color output contains ANSI color codes" — accessibility broken
- "Report missing required field: findings" — output schema broken

**Action:**
1. Do not merge or release
2. Fix the underlying issue
3. Test locally: `python3 scripts/ci/validate_user_readiness.py ./target/release/stealthy`
4. Commit and push
5. Wait for CI to pass

## Running Locally

### Before committing

```bash
# Build
cargo build --locked -p stealthy --release

# Run user readiness checks
python3 scripts/ci/validate_user_readiness.py ./target/release/stealthy --repo-root .
# Optional strict mode (recommended for merge/readiness confidence)
python3 scripts/ci/validate_user_readiness.py ./target/release/stealthy --repo-root . --strict-warnings
```

### Debugging a failing check

```bash
# Run individual checks manually
./target/release/stealthy doctor --json
./target/release/stealthy guide
./target/release/stealthy disclaimer
./target/release/stealthy --authorized list-plugins
./target/release/stealthy --authorized --quiet --format json enum --plugins linux.kernel_cve
```

### Verifying a fix

After making changes, re-run:

```bash
cargo build --locked -p stealthy --release
python3 scripts/ci/validate_user_readiness.py ./target/release/stealthy --repo-root .
python3 scripts/ci/validate_user_readiness.py ./target/release/stealthy --repo-root . --strict-warnings
```

## Extending the Validator

To add new checks, edit `scripts/ci/validate_user_readiness.py`:

```python
def check_new_feature(self):
    """Validate new_feature works as documented."""
    print("Checking new_feature...")

    # Your test here
    code, stdout, stderr = self.run("your-command")
    if code != 0:
        self.errors.append("your-command failed")

    # Add to validate_all()
```

Then add to `validate_all()`:

```python
def validate_all(self) -> bool:
    # ... existing checks ...
    self.check_new_feature()  # Add this line
```

## Related documents

- [First-User Journey](first-user-journey.md) — user-facing contract
- [Installation Guide](installation.md) — installation procedures
- [User Guide](user-guide.md) — guided workflow
- [Support Policy](support-policy.md) — version and support commitments
- [Design](design.md) — architectural decisions
