#!/usr/bin/env python3
"""Ensure the documented production gate is wired to CI and release jobs."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    failures = []
    checklist = (ROOT / "docs/production-readiness.md").read_text(encoding="utf-8")
    required_headings = [
        "## Build and platform acceptance",
        "## Safety and authorization acceptance",
        "## Evidence and artifact acceptance",
        "## Release and operational acceptance",
        "## Required release evidence",
    ]
    for heading in required_headings:
        if heading not in checklist:
            failures.append(f"checklist missing {heading}")
    if len(re.findall(r"^- \[ \]", checklist, re.MULTILINE)) < 15:
        failures.append("checklist has fewer than 15 acceptance criteria")

    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    for token in (
        "rust-windows:",
        "linux-distributions:",
        "ubuntu-22.04",
        "ubuntu-24.04",
        "debian-12",
        "ubuntu@sha256:",
        "debian@sha256:",
        'coverage_mode\\"] == \\"native\\"',
        "validate_windows_contract.py",
        "validate_release_package.py",
        "validate_worktree_hygiene.py",
        "validate_user_readiness.py",
        "validate_report_compatibility.py",
        "validate_plugin_matrix.py",
        "generate_plugin_coverage.py",
        "--report user-readiness-${{ matrix.os }}.json",
        "Upload user-readiness evidence",
        "cargo test --locked --workspace --all-features",
        'COVERAGE_MIN_LINES: "80"',
        "throw \"quarantine-sim coverage_mode:",
        "throw \"script-only primary_launch mismatch:",
        "throw \"unauthorized JScript fallback exit mismatch:",
        "throw \"JScript coverage_mode mismatch:",
        "evasion feature/status mismatch",
        "MSBuild fallback JSON contract mismatch",
        "test_windows_enum.py",
        "native staged binary unavailable after write",
        "expected 3 high-impact handoffs",
        "incomplete operator handoff",
    ):
        if token not in ci:
            failures.append(f"CI missing production check {token}")
    if re.search(r"quarantine-sim (coverage_mode|primary_launch|execution_path).*Write-Warning", ci):
        failures.append("CI quarantine simulation contract is warning-only")
    if re.search(r"JScript (coverage_mode|elevation_source).*Write-Warning", ci):
        failures.append("CI JScript contract is warning-only")
    for token in (
        "generate_evidence.py",
        "RELEASE-EVIDENCE.json",
        "sha256sum *.tar.gz *.zip *.spdx.json",
        "cargo llvm-cov",
        "gitleaks/gitleaks-action",
        "cargo-deny-action",
        "validate_reproducible_build.py",
        "validate_release_evidence.py",
        "--report readiness-evidence.json",
        "release-user-readiness",
    ):
        if token not in release:
            failures.append(f"release workflow missing production check {token}")

    if failures:
        print(*failures, sep="\n")
        return 1
    print("Production-readiness checklist is wired to CI and release gates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
