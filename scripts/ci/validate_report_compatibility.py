#!/usr/bin/env python3
"""Exercise schema compatibility and bounded malformed-input handling."""

import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(binary: Path, *args: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run([str(binary), *args], cwd=ROOT, text=True, capture_output=True, timeout=30)
    if result.returncode != expected:
        raise AssertionError(f"{args}: expected {expected}, got {result.returncode}: {result.stderr}")
    return result


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_report_compatibility.py RELEASE_BINARY")
    binary = Path(sys.argv[1]).resolve()
    fixtures = ROOT / "crates/stealthy/tests/fixtures"
    for fixture in (fixtures / "script_report_min.json", fixtures / "script_report_windows.json"):
        result = run(binary, "ingest", str(fixture), "--format", "json")
        report = json.loads(result.stdout)
        for field in ("schema_version", "coverage_mode", "capability_delta", "coverage", "findings"):
            if field not in report:
                raise AssertionError(f"{fixture.name}: normalized report missing {field}")
        if report["schema_version"] != "2":
            raise AssertionError(f"{fixture.name}: expected normalized schema 2")

    with tempfile.TemporaryDirectory(prefix="stealthy-malformed-") as raw:
        path = Path(raw) / "malformed.json"
        for body in ("[", "{}", '{"schema_version": 2, "findings": "not-an-array"}'):
            path.write_text(body, encoding="utf-8")
            result = run(binary, "ingest", str(path), expected=1)
            if not result.stderr.strip():
                raise AssertionError("malformed input failed without an actionable error")
        source = (fixtures / "script_report_min.json").read_bytes()
        rng = random.Random(0)
        for index in range(32):
            mutated = bytearray(source)
            if index % 3 == 0:
                del mutated[rng.randrange(len(mutated)) : rng.randrange(len(mutated))]
            elif index % 3 == 1:
                position = rng.randrange(len(mutated))
                mutated[position] = ord("[")
            else:
                mutated.extend(b"\x00garbage")
            path.write_bytes(mutated)
            result = subprocess.run(
                [str(binary), "ingest", str(path), "--format", "json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=5,
            )
            if result.returncode < 0:
                raise AssertionError(f"mutated input terminated the process with signal {-result.returncode}")
    print("Report compatibility and malformed-input checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
