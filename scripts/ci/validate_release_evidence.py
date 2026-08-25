#!/usr/bin/env python3
"""Validate the release evidence record generated from final artifacts."""

import json
from pathlib import Path
import sys


REQUIRED = {
    "schema_version",
    "project",
    "version",
    "source_commit",
    "generated_at_unix",
    "ci_run",
    "toolchain",
    "working_tree",
    "artifacts",
    "checks",
    "skipped_checks",
    "rollback",
}


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_release_evidence.py RELEASE-EVIDENCE.json")
    path = Path(sys.argv[1])
    value = json.loads(path.read_text(encoding="utf-8"))
    missing = REQUIRED - value.keys()
    if missing:
        raise SystemExit(f"release evidence missing fields: {sorted(missing)}")
    if value["project"] != "StealthyPrivesc" or value["schema_version"] != "1":
        raise SystemExit("release evidence identity/schema is invalid")
    if not value["source_commit"] or not value["version"]:
        raise SystemExit("release evidence must identify version and source commit")
    if not isinstance(value["artifacts"], list) or not value["artifacts"]:
        raise SystemExit("release evidence must contain final artifact hashes")
    for item in value["artifacts"]:
        if set(item) != {"path", "size", "sha256"} or len(item["sha256"]) != 64:
            raise SystemExit(f"invalid artifact evidence entry: {item}")
    checks = value["checks"]
    for key in ("acceptance_criteria", "release_manifest", "checksums", "sbom", "attestation"):
        if key not in checks:
            raise SystemExit(f"release evidence checks missing {key}")
    print(f"Release evidence contract passed for {len(value['artifacts'])} artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
