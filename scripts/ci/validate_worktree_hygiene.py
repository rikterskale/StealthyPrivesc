#!/usr/bin/env python3
"""Reject tracked local state and accidental nested repositories in CI."""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_PARTS = {"target", ".cache-run", ".stealthy-artifacts", "__pycache__"}
FORBIDDEN_NAMES = {".env", ".env.local", ".ledger-key", "report.key", "SHA256SUMS"}
KNOWN_CI_OUTPUTS = {"results.sarif"}


def main() -> int:
    status = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=ROOT,
        text=True,
    ).splitlines()
    tracked = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        text=True,
    ).splitlines()
    failures = [
        f"working tree is not clean: {line}"
        for line in status
        if not (line.startswith("?? ") and Path(line[3:]).as_posix() in KNOWN_CI_OUTPUTS)
    ]
    for nested_git in ROOT.rglob(".git"):
        if nested_git != ROOT / ".git":
            failures.append(f"nested repository metadata found: {nested_git.relative_to(ROOT)}")
    for raw in tracked:
        path = Path(raw)
        if any(part in FORBIDDEN_PARTS for part in path.parts):
            failures.append(f"local state is present in repository inventory: {raw}")
        if path.name in FORBIDDEN_NAMES:
            failures.append(f"sensitive/generated filename is present in repository inventory: {raw}")
        if ".git" in path.parts[1:]:
            failures.append(f"nested repository path is present in repository inventory: {raw}")
    if failures:
        print(*failures, sep="\n")
        return 1
    print(f"Repository hygiene passed for {len(tracked)} tracked/working-tree paths")
    return 0


if __name__ == "__main__":
    sys.exit(main())
