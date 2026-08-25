#!/usr/bin/env python3
"""Static browser-facing contract checks for the offline HTML report."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    source = (ROOT / "crates/stealthy/src/core/output.rs").read_text(encoding="utf-8")
    for expected in ("id=search", "id=severity", 'class=\\"finding\\"', "navigator.clipboard", "querySelector('#search').oninput", "querySelector('#severity').onchange", "Expand all"):
        if expected not in source:
            raise AssertionError(f"HTML report interaction contract missing {expected!r}")
    print("HTML report search, severity filter, and copy contracts passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
