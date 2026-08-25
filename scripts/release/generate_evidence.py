#!/usr/bin/env python3
"""Generate a machine-readable release evidence record from CI outputs."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[2]


def command(*args: str) -> str:
    try:
        return subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.STDOUT).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        return f"unavailable: {exc}"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--artifact-dir", type=Path, default=Path("dist"))
    parser.add_argument("--ci-run", default="")
    parser.add_argument("--skipped-check", action="append", default=[])
    args = parser.parse_args()

    artifact_dir = args.artifact_dir if args.artifact_dir.is_absolute() else ROOT / args.artifact_dir
    artifacts = []
    if artifact_dir.is_dir():
        for path in sorted(p for p in artifact_dir.rglob("*") if p.is_file()):
            artifacts.append(
                {
                    "path": path.relative_to(artifact_dir).as_posix(),
                    "size": path.stat().st_size,
                    "sha256": sha256(path),
                }
            )

    evidence = {
        "schema_version": "1",
        "project": "StealthyPrivesc",
        "version": args.version,
        "source_commit": args.commit,
        "generated_at_unix": int(time.time()),
        "ci_run": args.ci_run,
        "toolchain": {
            "rustc": command("rustc", "--version"),
            "cargo": command("cargo", "--version"),
        },
        "working_tree": {
            "revision": command("git", "rev-parse", "HEAD"),
            "status": command("git", "status", "--porcelain"),
        },
        "artifacts": artifacts,
        "checks": {
            "acceptance_criteria": "docs/production-readiness.md",
            "release_manifest": True,
            "checksums": True,
            "sbom": any(item["path"].endswith(".spdx.json") for item in artifacts),
            "attestation": "provided by GitHub Actions release job",
        },
        "skipped_checks": args.skipped_check,
        "rollback": "Withdraw the tag/release, revoke distribution links, and return operators to the previous attested release.",
    }
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
