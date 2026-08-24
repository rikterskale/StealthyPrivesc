#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[2]

COMMON_FILES = [
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "docs/installation.md",
    "docs/cli-reference.md",
    "docs/techniques.md",
    "docs/runbook/README.md",
    "docs/runbook/build-and-package.md",
]

PLATFORM_FILES = {
    "linux": [
        "scripts/linux/run.sh",
        "scripts/linux/enum.py",
        "scripts/linux/enum.sh",
        "scripts/linux/enum-posix.sh",
        "scripts/linux/enum.pl",
    ],
    "windows": [
        "scripts/windows/run.ps1",
        "scripts/windows/enum.ps1",
        "scripts/windows/enum.js",
        "scripts/windows/EnumTasks.csproj",
    ],
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_file(relative, stage):
    source = ROOT / relative
    if not source.is_file():
        raise SystemExit(f"required kit file is missing: {relative}")
    destination = stage / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def write_dispatcher_example(stage, platform, binary_name):
    fallback_key = "linux_fallbacks" if platform == "linux" else "windows_fallbacks"
    fallback_value = (
        "python,bash,sh,perl" if platform == "linux" else "powershell,jscript,msbuild"
    )
    content = (
        "# Copy to stealthy-run.conf and set authorization_ack=true only for an approved target.\n"
        "manifest_version=1\n"
        "authorization_ack=false\n"
        "operator_ack_required=true\n"
        "allow_fallback=true\n"
        "roe_ref=SET_APPROVED_ROE_REFERENCE\n"
        "execution_mode=enumerate-only\n"
        "target_hostname=AUTO\n"
        "target_username=\n"
        "drop_dir=\n"
        f"primary_binary={binary_name}\n"
        f"{fallback_key}={fallback_value}\n"
    )
    scripts = stage / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "stealthy-run.conf.example").write_text(content, encoding="utf-8")


def collect_entries(stage):
    return sorted(path for path in stage.rglob("*") if path.is_file())


def make_archive(stage, output, platform):
    output.parent.mkdir(parents=True, exist_ok=True)
    if platform == "linux":
        with tarfile.open(output, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(stage.rglob("*")):
                archive.add(path, arcname=path.relative_to(stage).as_posix(), recursive=False)
    else:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in collect_entries(stage):
                info = zipfile.ZipInfo.from_file(path, path.relative_to(stage).as_posix())
                with path.open("rb") as handle:
                    archive.writestr(info, handle.read(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def main():
    parser = argparse.ArgumentParser(description="Build a complete StealthyPrivesc release kit")
    parser.add_argument("--platform", choices=sorted(PLATFORM_FILES), required=True)
    parser.add_argument("--arch", choices=["x86_64", "aarch64"], required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--build-flavor", default="full")
    args = parser.parse_args()

    binary = args.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"release binary is missing: {binary}")
    if args.platform == "windows" and args.arch != "x86_64":
        raise SystemExit("only Windows x86_64 is supported by the release matrix")

    binary_name = "stealthy.exe" if args.platform == "windows" else "stealthy"
    with tempfile.TemporaryDirectory(prefix="stealthy-kit-") as temporary:
        stage = Path(temporary) / "kit"
        stage.mkdir()
        shutil.copy2(binary, stage / binary_name)
        if args.platform == "linux":
            executable = stage / binary_name
            executable.chmod(
                executable.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )

        for relative in COMMON_FILES:
            copy_file(relative, stage)

        kit_scripts = stage / "scripts"
        for relative in PLATFORM_FILES[args.platform]:
            source = ROOT / relative
            if not source.is_file():
                raise SystemExit(f"required kit file is missing: {relative}")
            kit_scripts.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, kit_scripts / source.name)

        write_dispatcher_example(stage, args.platform, binary_name)
        manifest = {
            "schema_version": "1",
            "project": "StealthyPrivesc",
            "version": args.version,
            "source_commit": args.commit,
            "platform": args.platform,
            "architecture": args.arch,
            "target_triple": args.target,
            "build_flavor": args.build_flavor,
            "authorization_required": True,
            "default_execution_mode": "enumerate-only",
            "contents": [
                {
                    "path": path.relative_to(stage).as_posix(),
                    "sha256": sha256(path),
                    "size": path.stat().st_size,
                }
                for path in collect_entries(stage)
            ],
        }
        (stage / "RELEASE-MANIFEST.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        checksums = "".join(
            f"{sha256(path)}  {path.relative_to(stage).as_posix()}\n"
            for path in collect_entries(stage)
        )
        (stage / "SHA256SUMS").write_text(checksums, encoding="utf-8")
        make_archive(stage, args.output.resolve(), args.platform)
        print(args.output)


if __name__ == "__main__":
    main()
