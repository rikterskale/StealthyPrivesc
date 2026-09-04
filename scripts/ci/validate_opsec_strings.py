#!/usr/bin/env python3
"""Fail if an opsec-string-strip binary still contains brand/catalog/vendor literals."""

from pathlib import Path
import argparse
import sys

FORBIDDEN = (
    b"StealthyPrivesc",
    b"gtfobins.github.io",
    b"lolbas-project.github.io",
    b"github.com/rikterskale",
    b"CrowdStrike",
    b"crowdstrike",
    b"SentinelOne",
    b"Carbon Black",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binary",
        default="target/opsec-string-strip/stealthy",
        help="Path to an opsec-string-strip build",
    )
    args = parser.parse_args()
    path = Path(args.binary)
    if not path.is_file():
        print(f"opsec binary not found: {path} (build the opsec-string-strip flavor first)")
        return 2
    data = path.read_bytes()
    hits = [needle.decode() for needle in FORBIDDEN if needle in data]
    if hits:
        print("opsec-string-strip binary still contains:")
        for hit in hits:
            print(f"  {hit}")
        return 1
    print(f"opsec string policy passed: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
