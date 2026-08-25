#!/usr/bin/env python3
"""Small repeatable local smoke benchmark; it never requires authorization."""

import argparse
from pathlib import Path
import statistics
import subprocess
import time


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--iterations", type=int, default=3)
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("iterations must be positive")
    samples = []
    for _ in range(args.iterations):
        started = time.perf_counter()
        subprocess.run(["cargo", "run", "--locked", "-q", "-p", "stealthy", "--", "demo"], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
        samples.append((time.perf_counter() - started) * 1000)
    print(f"demo_cli_ms median={statistics.median(samples):.1f} min={min(samples):.1f} max={max(samples):.1f} n={len(samples)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
