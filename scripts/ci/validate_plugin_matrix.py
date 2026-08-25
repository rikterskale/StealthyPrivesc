#!/usr/bin/env python3
"""Ensure registered platform plugins have test/documentation references."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]


def ids_under(directory: Path, prefix: str) -> set[str]:
    ids: set[str] = set()
    for path in directory.glob("*.rs"):
        ids.update(re.findall(r'"(' + re.escape(prefix) + r'\.[a-z0-9_]+)"', path.read_text(encoding="utf-8")))
    return ids


def main() -> int:
    linux = ids_under(ROOT / "crates/stealthy/src/plugins/linux", "linux")
    windows = ids_under(ROOT / "crates/stealthy/src/plugins/windows", "windows")
    all_ids = linux | windows
    tests = "\n".join(
        path.read_text(encoding="utf-8")
        for path in list((ROOT / "crates/stealthy/tests").rglob("*.rs"))
        + list((ROOT / "crates/stealthy/src/plugins").rglob("*.rs"))
    )
    docs = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "docs").rglob("*.md"))
    missing_tests = sorted(plugin for plugin in all_ids if plugin not in tests)
    missing_docs = sorted(plugin for plugin in all_ids if plugin not in docs)
    if missing_tests or missing_docs:
        if missing_tests:
            print("Plugins without test references:", *missing_tests, sep="\n")
        if missing_docs:
            print("Plugins without documentation references:", *missing_docs, sep="\n")
        return 1
    print(f"Plugin validation matrix passed for {len(all_ids)} referenced plugin IDs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
