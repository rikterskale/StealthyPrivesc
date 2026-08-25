#!/usr/bin/env python3
"""Build a disposable release kit and validate its manifest and contents."""

from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[2]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_archive(path: Path, platform: str) -> dict[str, bytes]:
    if platform == "linux":
        with tarfile.open(path, "r:gz") as handle:
            return {
                member.name: handle.extractfile(member).read()
                for member in handle.getmembers()
                if member.isfile()
            }
    with zipfile.ZipFile(path) as handle:
        return {name: handle.read(name) for name in handle.namelist() if not name.endswith("/")}


def validate_archive(path: Path, platform: str) -> None:
    payloads = read_archive(path, platform)
    names = set(payloads)
    binary_name = "stealthy.exe" if platform == "windows" else "stealthy"
    required = {binary_name, "RELEASE-MANIFEST.json", "SHA256SUMS", "scripts/stealthy-run.conf.example"}
    required.update(
        f"scripts/{name}"
        for name in (
            ["run.sh", "enum.py", "enum.sh", "enum-posix.sh", "enum.pl"]
            if platform == "linux"
            else ["run.ps1", "enum.ps1", "enum.js", "EnumTasks.csproj"]
        )
    )
    missing = required - names
    if missing:
        raise AssertionError(f"{platform} release kit missing required files: {sorted(missing)}")
    if any(name.endswith(("report.key", ".jsonl", ".sealed")) for name in names):
        raise AssertionError(f"{platform} release kit contains report/key material")
    if "scripts/windows/evasion.ps1" in names:
        raise AssertionError("release kit contains excluded evasion helper material")

    manifest = json.loads(payloads["RELEASE-MANIFEST.json"])
    if manifest["authorization_required"] is not True or manifest["default_execution_mode"] != "enumerate-only":
        raise AssertionError(f"{platform} release manifest safety contract is invalid")
    if manifest["platform"] != platform or manifest["architecture"] != "x86_64":
        raise AssertionError(f"{platform} release manifest target metadata is invalid")
    entries = {item["path"]: item for item in manifest["contents"]}
    if set(entries) != names - {"RELEASE-MANIFEST.json", "SHA256SUMS"}:
        raise AssertionError(f"{platform} manifest contents do not match archive contents")
    for name, item in entries.items():
        data = payloads[name]
        if item["sha256"] != digest(data) or item["size"] != len(data):
            raise AssertionError(f"manifest metadata mismatch for {name}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="stealthy-release-check-") as raw:
        work = Path(raw)
        binary = work / "fixture"
        binary.write_bytes(b"disposable release fixture\n")
        for platform, suffix, target in (
            ("linux", ".tar.gz", "x86_64-unknown-linux-gnu"),
            ("windows", ".zip", "x86_64-pc-windows-msvc"),
        ):
            archive = work / f"kit-{platform}{suffix}"
            source = work / ("fixture.exe" if platform == "windows" else "fixture")
            source.write_bytes(binary.read_bytes())
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/release/package.py"),
                    "--platform",
                    platform,
                    "--arch",
                    "x86_64",
                    "--target",
                    target,
                    "--binary",
                    str(source),
                    "--output",
                    str(archive),
                    "--version",
                    "0.0.0-test",
                    "--commit",
                    "test-commit",
                ],
                cwd=ROOT,
                check=True,
            )
            validate_archive(archive, platform)
        print("Linux and Windows release package contracts passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
