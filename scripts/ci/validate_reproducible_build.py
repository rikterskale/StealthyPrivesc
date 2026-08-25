#!/usr/bin/env python3
"""Build two clean release trees and compare the stripped binaries."""

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="stealthy-repro-") as raw:
        root = Path(raw)
        env = {"SOURCE_DATE_EPOCH": "0", "CARGO_INCREMENTAL": "0"}
        first = root / "first"
        second = root / "second"
        for target_dir in (first, second):
            subprocess.run(
                ["cargo", "build", "--locked", "-p", "stealthy", "--release", "--target-dir", str(target_dir)],
                cwd=ROOT,
                env={**__import__("os").environ, **env},
                check=True,
            )
        binary_name = "stealthy.exe" if sys.platform == "win32" else "stealthy"
        first_binary = first / "release" / binary_name
        second_binary = second / "release" / binary_name
        first_hash = digest(first_binary)
        second_hash = digest(second_binary)
        if first_hash != second_hash:
            raise SystemExit(f"non-reproducible release binaries: {first_hash} != {second_hash}")
        print(f"Reproducible release build passed: {first_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
