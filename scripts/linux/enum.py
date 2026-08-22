#!/usr/bin/env python3
"""StealthyPrivesc Linux Python fallback — authorized assessments only.

Quiet-leaning enumeration using direct file reads. No exploitation.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any


FINDINGS: list[dict[str, Any]] = []
PLUGINS_RUN: list[str] = []
JSON_MODE = False


def fingerprint(plugin: str, title: str, kind: str) -> str:
    raw = f"{plugin}\x1f{title}\x1f{kind}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def add_finding(
    plugin: str,
    title: str,
    detail: str,
    *,
    kind: str = "misconfiguration",
    severity: str = "medium",
    recommendation: str = "Validate manually against ROE.",
    noisy: bool = False,
    mitre: list[str] | None = None,
) -> None:
    FINDINGS.append(
        {
            "plugin": plugin,
            "kind": kind,
            "severity": severity,
            "title": title,
            "detail": detail,
            "recommendation": recommendation,
            "noisy": noisy,
            "leaves_artifacts": False,
            "finding_id": fingerprint(plugin, title, kind),
            "object": title.lower().replace(" ", "_")[:64],
            "condition": kind,
            "exploitability": 0,
            "time_to_impact": "",
            "mitre_techniques": mitre or [],
            "technique_id": f"{plugin}.{kind}",
        }
    )


def banner() -> None:
    if JSON_MODE:
        return
    print("=== StealthyPrivesc Linux Python enum ===")
    print("LEGAL: Authorized use only.\n")


def identity() -> None:
    if JSON_MODE:
        return
    print("[*] identity")
    print(f"uid={os.geteuid()} gid={os.getegid()} user={os.environ.get('USER', '?')}")
    try:
        print(f"hostname={Path('/etc/hostname').read_text().strip()}")
    except OSError:
        print("hostname=?")
    print()


def identity_dict() -> dict[str, Any]:
    try:
        hostname = Path("/etc/hostname").read_text().strip()
    except OSError:
        hostname = socket.gethostname()
    return {
        "username": os.environ.get("USER", "?"),
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "groups": [],
        "is_elevated": os.geteuid() == 0,
        "elevation_source": "euid",
        "token_context": "",
        "hostname": hostname,
    }


def sudoers() -> None:
    print("[*] readable sudoers")
    paths = [Path("/etc/sudoers")]
    d = Path("/etc/sudoers.d")
    if d.is_dir():
        paths.extend(sorted(d.iterdir()))
    for p in paths:
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "NOPASSWD" in s or "ALL=(ALL" in s:
                if JSON_MODE:
                    add_finding(
                        "linux.sudo",
                        "Readable sudoers rule of interest",
                        f"{p}: {s}",
                        severity="high",
                        mitre=["T1548.003"],
                    )
                else:
                    print(f"FINDING: {p}: {s}")
    PLUGINS_RUN.append("linux.sudo")
    if not JSON_MODE:
        print()


def suid_shallow() -> None:
    print("[*] SUID shallow scan")
    interesting = {
        "nmap",
        "vim",
        "find",
        "bash",
        "python",
        "python3",
        "perl",
        "env",
        "pkexec",
        "docker",
    }
    for root in ("/usr/bin", "/usr/sbin", "/bin", "/sbin"):
        base = Path(root)
        if not base.is_dir():
            continue
        try:
            entries = list(base.iterdir())
        except OSError:
            continue
        for ent in entries:
            try:
                st = ent.stat()
            except OSError:
                continue
            if st.st_mode & 0o4000:
                flag = " INTERESTING" if ent.name in interesting else ""
                if JSON_MODE and ent.name in interesting:
                    add_finding(
                        "linux.suid",
                        f"Interesting SUID binary {ent.name}",
                        f"{ent} mode={oct(st.st_mode)}",
                        severity="high",
                        mitre=["T1548.001"],
                    )
                elif not JSON_MODE:
                    print(f"SUID{flag}: {ent} mode={oct(st.st_mode)}")
    PLUGINS_RUN.append("linux.suid")
    if not JSON_MODE:
        print()


def groups() -> None:
    print("[*] interesting groups")
    try:
        status = Path("/proc/self/status").read_text()
        gids = set()
        for line in status.splitlines():
            if line.startswith("Groups:"):
                gids = {int(x) for x in line.split()[1:]}
        group = Path("/etc/group").read_text()
        for name in ("docker", "lxd", "disk", "podman", "sudo", "wheel", "shadow"):
            for line in group.splitlines():
                parts = line.split(":")
                if len(parts) >= 3 and parts[0] == name and int(parts[2]) in gids:
                    if JSON_MODE:
                        add_finding(
                            "linux.groups",
                            f"Member of group {name}",
                            f"gid={parts[2]}",
                            severity="high",
                            mitre=["T1068"],
                        )
                    else:
                        print(f"FINDING: member of group {name}")
    except OSError as exc:
        if not JSON_MODE:
            print(f"groups enum failed: {exc}")
    PLUGINS_RUN.append("linux.groups")
    if not JSON_MODE:
        print()


def containers() -> None:
    print("[*] container sockets")
    socks = [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/var/run/podman/podman.sock",
        "/run/podman/podman.sock",
        "/var/run/containerd/containerd.sock",
        "/var/lib/lxd/unix.socket",
        "/var/snap/lxd/common/lxd/unix.socket",
    ]
    found = False
    for path in socks:
        sock = Path(path)
        if not sock.exists():
            continue
        found = True
        print(f"socket {path} mode={oct(sock.stat().st_mode)}")
        try:
            fd = os.open(sock, os.O_RDWR)
            os.close(fd)
            print(f"FINDING: {path} RW open succeeded")
        except OSError as exc:
            print(f"{path} not RW: {exc}")
    if not found:
        print("no common container sockets")
    print()


def polkit() -> None:
    print("[*] polkit")
    for p in ("/etc/polkit-1/rules.d", "/etc/polkit-1/localauthority"):
        path = Path(p)
        if path.exists() and os.access(path, os.W_OK):
            print(f"FINDING: writable polkit path {p}")
    pk = Path("/usr/bin/pkexec")
    if pk.exists():
        print(f"pkexec mode={oct(pk.stat().st_mode)}")
    print()


def ssh_keys() -> None:
    print("[*] ssh keys")
    roots = []
    home = os.environ.get("HOME")
    if home:
        roots.append(Path(home) / ".ssh")
    roots.append(Path("/root/.ssh"))
    for root in roots:
        if not root.is_dir():
            continue
        for name in ("id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys"):
            p = root / name
            if p.is_file() and os.access(p, os.R_OK):
                mode = p.stat().st_mode & 0o777
                print(f"readable {p} mode={oct(mode)}")
                if name.startswith("id_") or name == "identity":
                    print(f"FINDING: readable private key {p}")
                if name.startswith("authorized") and mode & 0o022:
                    print(f"FINDING: writable authorized_keys {p}")
    print()


def mounts() -> None:
    print("[*] mounts / passwd")
    if os.access("/etc/passwd", os.W_OK):
        print("FINDING: /etc/passwd writable")
    try:
        for line in Path("/proc/self/mountinfo").read_text().splitlines()[:8]:
            print(line)
    except OSError:
        pass
    print()


def endpoint_controls() -> None:
    print("[*] endpoint controls (AppArmor / SELinux / noexec)")
    if Path("/sys/module/apparmor").is_dir() or Path(
        "/sys/kernel/security/apparmor"
    ).is_dir():
        profile = "unreadable"
        for p in (
            Path("/proc/self/attr/current"),
            Path("/proc/self/attr/apparmor/current"),
        ):
            try:
                profile = p.read_text().strip()
                break
            except OSError:
                continue
        print(f"AppArmor current={profile}")
        if "(enforce)" in profile:
            print("FINDING: AppArmor enforce profile active for this process")
    else:
        print("AppArmor module not evident")

    enforce = Path("/sys/fs/selinux/enforce")
    if enforce.is_file():
        try:
            print(f"SELinux enforce={enforce.read_text().strip()}")
        except OSError:
            pass

    watch = ["/tmp", "/var/tmp", "/dev/shm"]
    home = os.environ.get("HOME")
    if home:
        watch.append(home)
    try:
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError:
        lines = []
    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue
        mountpoint = parts[4]
        tokens = {
            t for chunk in line.lower().replace(",", " ").split() for t in [chunk]
        }
        if "noexec" not in tokens:
            continue
        if any(mountpoint == p or mountpoint.startswith(p + "/") for p in watch):
            print(f"FINDING: noexec mount on drop path {mountpoint}")

    yama = Path("/proc/sys/kernel/yama/ptrace_scope")
    if yama.is_file():
        try:
            print(f"yama.ptrace_scope={yama.read_text().strip()}")
        except OSError:
            pass
    print(
        "NOTE: if custom ELF is blocked, prefer this script or enum.sh (approved fallback)."
    )
    print()


def credentials() -> None:
    print("[*] credentials")
    for p in (
        "/etc/shadow",
        "/etc/shadow-",
        "/var/backups/shadow.bak",
        "/etc/security/opasswd",
    ):
        path = Path(p)
        if path.exists() and os.access(path, os.R_OK):
            print(f"FINDING: readable {p}")
    print()


def kernel() -> None:
    print("[*] kernel")
    try:
        print(Path("/proc/version").read_text().splitlines()[0])
    except OSError:
        pass
    print("NOTE: kernel LPE is not executed by this fallback.")
    print()


def emit_json() -> None:
    report = {
        "schema_version": "2",
        "run_id": hashlib.sha256(str(time.time()).encode()).hexdigest()[:24],
        "started_at_unix": int(time.time()),
        "tool": "stealthy-script",
        "version": "0.1.0",
        "authorized_use_ack": True,
        "mode": "enumerate-only",
        "profile": "script",
        "coverage_mode": "script",
        "capability_delta": [
            "linux.wildcard_cron",
            "linux.nfs",
            "linux.polkit",
            "linux.endpoint_controls",
            "linux.kernel_cve",
        ],
        "os": {
            "family": "unix",
            "os": "linux",
            "arch": os.uname().machine,
            "version_hint": Path("/proc/version").read_text().splitlines()[0]
            if Path("/proc/version").exists()
            else "linux",
        },
        "identity": identity_dict(),
        "findings": FINDINGS,
        "assessments": [],
        "attack_paths": [],
        "triage_decisions": [],
        "plugins_run": PLUGINS_RUN,
        "coverage": [
            {"id": pid, "status": "ok", "findings": 0, "error": None, "duration_ms": 0}
            for pid in PLUGINS_RUN
        ],
        "notes": [
            "Script fallback coverage is reduced versus the Rust binary.",
            "Use `stealthy ingest` to normalize and enrich this report.",
        ],
    }
    print(json.dumps(report, indent=2))


def main(argv: list[str] | None = None) -> int:
    global JSON_MODE
    args = list(sys.argv[1:] if argv is None else argv)
    JSON_MODE = "--json" in args
    banner()
    identity()
    sudoers()
    suid_shallow()
    groups()
    if JSON_MODE:
        # Reduced script JSON coverage; remaining checks stay human-oriented for now.
        PLUGINS_RUN.extend(
            [
                "linux.containers",
                "linux.mounts",
                "linux.ssh_keys",
                "linux.credentials",
            ]
        )
        emit_json()
        return 0
    containers()
    polkit()
    mounts()
    endpoint_controls()
    ssh_keys()
    credentials()
    kernel()
    print("Done. Enumeration only.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
