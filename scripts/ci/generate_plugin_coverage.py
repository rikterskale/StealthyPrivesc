#!/usr/bin/env python3
"""Emit per-plugin line coverage from an LCOV file."""

import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]


def plugin_ids() -> dict[str, Path]:
    result: dict[str, Path] = {}
    for platform in ("linux", "windows"):
        for path in (ROOT / "crates/stealthy/src/plugins" / platform).glob("*.rs"):
            for plugin in re.findall(r'"((?:linux|windows)\.[a-z0-9_]+)"', path.read_text(encoding="utf-8")):
                result.setdefault(plugin, path)
    return result


def main() -> int:
    if len(sys.argv) not in (2, 3):
        raise SystemExit("usage: generate_plugin_coverage.py LCOV [OUTPUT_JSON]")
    lcov = Path(sys.argv[1]).read_text(encoding="utf-8")
    records: dict[str, tuple[int, int]] = {}
    current = None
    for line in lcov.splitlines():
        if line.startswith("SF:"):
            current = line[3:]
            records.setdefault(current, (0, 0))
        elif line.startswith("DA:") and current is not None:
            _, hits = line[3:].split(",", 1)
            total, covered = records[current]
            records[current] = (total + 1, covered + (int(hits) > 0))
        elif line == "end_of_record":
            current = None

    output = {}
    for plugin, source in sorted(plugin_ids().items()):
        total = covered = 0
        for path, counts in records.items():
            if str(source) in path or str(source.resolve()) in path:
                total += counts[0]
                covered += counts[1]
        output[plugin] = {
            "source": source.relative_to(ROOT).as_posix(),
            "lines": total,
            "covered": covered,
            "percent": round((covered / total) * 100, 2) if total else None,
        }
    body = json.dumps({"schema_version": "1", "plugins": output}, indent=2, sort_keys=True) + "\n"
    if len(sys.argv) == 3:
        Path(sys.argv[2]).write_text(body, encoding="utf-8")
    else:
        print(body, end="")
    print(f"Generated per-plugin coverage for {len(output)} plugins", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
