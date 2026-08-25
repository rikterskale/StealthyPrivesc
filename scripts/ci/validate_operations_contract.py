#!/usr/bin/env python3
"""Validate the operational contract required for a supported release."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]


def require(text: str, needle: str, label: str, failures: list[str]) -> None:
    if needle not in text:
        failures.append(f"{label}: missing required contract: {needle}")


def main() -> int:
    failures: list[str] = []
    support = (ROOT / "docs/support-policy.md").read_text(encoding="utf-8")
    operations = (ROOT / "docs/operations.md").read_text(encoding="utf-8")
    readiness = (ROOT / "docs/production-readiness.md").read_text(encoding="utf-8")
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    for section in (
        "## Versioning before 1.0",
        "## Supported release window and EOL",
        "## Report-schema compatibility",
        "## Security-fix policy",
    ):
        require(support, section, "support policy", failures)
    for section in (
        "## Release candidate gate",
        "## Rollout",
        "## Rollback and withdrawal",
        "## Incident response",
        "## Manual validation ownership",
        "## Evidence retention",
    ):
        require(operations, section, "operations runbook", failures)
    for token in ("CI run URL", "artifact manifest", "checksum manifest", "SBOM", "attestation", "rollback", "owner"):
        require(readiness.lower(), token.lower(), "readiness evidence", failures)
    for token in (
        "linux-distributions:",
        "ubuntu-22.04",
        "ubuntu-24.04",
        "debian-12",
        "ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc",
        "ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517",
        "debian@sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931",
        "coverage_mode'] == 'native'",
    ):
        require(ci, token, "Linux distribution matrix", failures)
    for token in (
        "generate_evidence.py",
        "RELEASE-EVIDENCE.json",
        "gitleaks/gitleaks-action",
        "cargo-deny-action",
        "validate_worktree_hygiene.py",
        "validate_user_readiness.py",
    ):
        require(release, token, "release workflow", failures)

    commands = re.findall(r"`([^`]+)`", operations)
    if not any("cargo test --locked --workspace" in command for command in commands):
        failures.append("operations runbook: missing locked workspace test command")
    if not any("validate_production_readiness.py" in command for command in commands):
        failures.append("operations runbook: missing production-readiness validator command")
    if failures:
        print(*failures, sep="\n")
        return 1
    print("Operational release contract passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
