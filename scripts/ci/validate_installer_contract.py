#!/usr/bin/env python3
"""Validate installer dry-run and rollback contracts without network access."""

from pathlib import Path
import os
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    env = os.environ.copy()
    env.update({"STEALTHY_REPO": "example/org", "STEALTHY_VERSION": "v-test"})
    result = subprocess.run(
        ["bash", str(ROOT / "scripts/install.sh"), "--dry-run"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    output = result.stdout
    for expected in ("v-test", "example/org", "Binary destination", "SHA256SUMS", "attestation"):
        if expected not in output:
            raise AssertionError(f"installer dry-run omitted {expected!r}")
    ps = (ROOT / "scripts/install.ps1").read_text(encoding="utf-8")
    for expected in ("param([switch]$DryRun)", "if ($DryRun)", "Rollback:"):
        if expected not in ps:
            raise AssertionError(f"PowerShell installer omitted {expected!r}")
    print("Linux and Windows installer dry-run contracts passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
