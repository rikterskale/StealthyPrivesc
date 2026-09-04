#!/usr/bin/env python3
"""StealthyPrivesc Windows Python fallback — authorized assessments only.

Reduced, read-only coverage using stdlib file and registry reads. No
exploitation, no child processes, and no AMSI/ETW/AV interference.
"""

from __future__ import annotations

# This file is named enum.py for operator familiarity. Remove its directory
# from import resolution when executed directly so it cannot shadow Python's
# standard-library enum module.
import os as _bootstrap_os
import sys as _bootstrap_sys

_script_dir = _bootstrap_os.path.dirname(_bootstrap_os.path.realpath(__file__))
if _bootstrap_sys.path and _bootstrap_sys.path[0] == _script_dir:
    _bootstrap_sys.path.pop(0)

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

try:
    import winreg
except ImportError:  # pragma: no cover - Windows collector
    winreg = None  # type: ignore[assignment]


FINDINGS: list[dict[str, Any]] = []
COVERAGE: list[dict[str, Any]] = []
JSON_MODE = False

PLUGIN_IDS = (
    "windows.privileges",
    "windows.services",
    "windows.scheduled_tasks",
    "windows.always_install_elevated",
    "windows.uac",
    "windows.dll_hijack",
    "windows.credentials",
    "windows.admin_sessions",
    "windows.env_path",
    "windows.autoruns",
    "windows.endpoint_controls",
    "windows.app_control",
)

CREDENTIAL_PATHS = (
    r"C:\Windows\Panther\Unattend.xml",
    r"C:\Windows\Panther\unattend.xml",
    r"C:\Windows\System32\sysprep\unattend.xml",
    r"C:\Windows\System32\config\RegBack\SAM",
)


def add_finding(
    plugin: str,
    kind: str,
    severity: str,
    title: str,
    detail: str,
    recommendation: str,
    observed: str,
    condition: str,
) -> None:
    FINDINGS.append(
        {
            "plugin": plugin,
            "kind": kind,
            "severity": severity,
            "title": title,
            "detail": detail,
            "recommendation": recommendation,
            "noisy": False,
            "leaves_artifacts": False,
            "object": observed,
            "condition": condition,
        }
    )


def add_coverage(plugin: str, status: str, error: str | None = None) -> None:
    count = sum(1 for finding in FINDINGS if finding["plugin"] == plugin)
    COVERAGE.append(
        {
            "id": plugin,
            "status": status,
            "findings": count,
            "error": error,
            "duration_ms": 0,
        }
    )


def read_reg_dword(hive: Any, path: str, name: str) -> int | None:
    if winreg is None:
        return None
    try:
        key = winreg.OpenKey(hive, path)
        try:
            value, kind = winreg.QueryValueEx(key, name)
        finally:
            winreg.CloseKey(key)
    except OSError:
        return None
    if kind not in (winreg.REG_DWORD, winreg.REG_DWORD_BIG_ENDIAN) and not isinstance(
        value, int
    ):
        return None
    return int(value)


def read_reg_sz(hive: Any, path: str, name: str) -> str | None:
    if winreg is None:
        return None
    try:
        key = winreg.OpenKey(hive, path)
        try:
            value, _kind = winreg.QueryValueEx(key, name)
        finally:
            winreg.CloseKey(key)
    except OSError:
        return None
    if value is None:
        return None
    return str(value)


def unquoted_image_path(image: str) -> bool:
    trimmed = image.strip()
    if not trimmed or trimmed.startswith('"'):
        return False
    lower = trimmed.lower()
    end = -1
    for ext in (".exe", ".com", ".bat", ".cmd"):
        idx = lower.find(ext)
        if idx != -1 and (end == -1 or idx < end):
            end = idx
    if end == -1:
        return False
    return " " in trimmed[:end]


def collect_always_install_elevated() -> None:
    if winreg is None:
        add_coverage("windows.always_install_elevated", "skipped", "winreg unavailable")
        return
    path = r"SOFTWARE\Policies\Microsoft\Windows\Installer"
    hklm = read_reg_dword(winreg.HKEY_LOCAL_MACHINE, path, "AlwaysInstallElevated")
    hkcu = read_reg_dword(winreg.HKEY_CURRENT_USER, path, "AlwaysInstallElevated")
    object_path = r"HKLM+HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated"
    if hklm == 1 and hkcu == 1:
        add_finding(
            "windows.always_install_elevated",
            "misconfiguration",
            "critical",
            "AlwaysInstallElevated enabled (HKLM+HKCU)",
            f"HKLM={hklm} HKCU={hkcu}",
            "Disable the policy in both hives. This fallback does not create or run MSI content.",
            object_path,
            "always-install-elevated-fully-enabled",
        )
    elif hklm is None or hkcu is None:
        add_finding(
            "windows.always_install_elevated",
            "enumeration",
            "info",
            "AlwaysInstallElevated state is incomplete",
            f"HKLM={hklm} HKCU={hkcu}; an absent value is not treated as confirmed disabled",
            "Verify both policy hives from an approved context.",
            object_path,
            "always-install-elevated-state-unknown",
        )
    elif hklm == 1 or hkcu == 1:
        add_finding(
            "windows.always_install_elevated",
            "misconfiguration",
            "low",
            "AlwaysInstallElevated policy is only partially enabled",
            f"HKLM={hklm} HKCU={hkcu}",
            "Disable the enabled half to remove the inconsistent installer policy.",
            object_path,
            "always-install-elevated-partially-enabled",
        )
    else:
        add_finding(
            "windows.always_install_elevated",
            "enumeration",
            "info",
            "AlwaysInstallElevated is disabled",
            f"HKLM={hklm} HKCU={hkcu}",
            "No action.",
            object_path,
            "always-install-elevated-disabled",
        )
    add_coverage("windows.always_install_elevated", "ok")


def collect_uac() -> None:
    if winreg is None:
        add_coverage("windows.uac", "skipped", "winreg unavailable")
        return
    lua = read_reg_dword(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA",
    )
    if lua is None:
        add_coverage("windows.uac", "error", "EnableLUA unreadable")
        return
    add_finding(
        "windows.uac",
        "enumeration",
        "info",
        f"UAC EnableLUA={lua}",
        f"EnableLUA={lua}",
        "Review the complete UAC policy set before drawing an elevation conclusion.",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
        f"uac-enable-lua:{lua}",
    )
    add_coverage("windows.uac", "ok")


def collect_services() -> None:
    if winreg is None:
        add_coverage("windows.services", "skipped", "winreg unavailable")
        return
    inspected = 0
    try:
        root = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"
        )
    except OSError as error:
        add_coverage("windows.services", "error", str(error))
        return
    try:
        index = 0
        while inspected < 1000:
            try:
                name = winreg.EnumKey(root, index)
            except OSError:
                break
            index += 1
            inspected += 1
            image = read_reg_sz(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SYSTEM\CurrentControlSet\Services\{name}",
                "ImagePath",
            )
            if image and unquoted_image_path(image):
                add_finding(
                    "windows.services",
                    "enumeration",
                    "low",
                    f"Unquoted service path: {name}",
                    f"image_path={image} binary_acl=not_collected service_object_dacl=not_collected",
                    "Use the native plugin for current-token file ACL and service-object DACL evaluation.",
                    f"service:{name}",
                    "unquoted-service-image-path",
                )
    finally:
        winreg.CloseKey(root)
    add_coverage("windows.services", "ok")


def collect_credentials() -> None:
    try:
        for path in CREDENTIAL_PATHS:
            if Path(path).is_file():
                add_finding(
                    "windows.credentials",
                    "credential",
                    "medium",
                    f"Sensitive file present: {path}",
                    "Presence only; contents were not read.",
                    "Inspect and restrict access; remove stale unattended-install or SAM backup material.",
                    path,
                    "sensitive-file-present",
                )
        add_coverage("windows.credentials", "ok")
    except OSError as error:
        add_coverage("windows.credentials", "error", str(error))


def collect_env_path() -> None:
    try:
        for entry in os.environ.get("PATH", "").split(";")[:50]:
            if not entry:
                continue
            if not Path(entry).is_dir():
                add_finding(
                    "windows.env_path",
                    "misconfiguration",
                    "medium",
                    f"PATH entry missing: {entry}",
                    "Missing PATH components may be creatable when a parent directory is writable; parent ACL was not collected by this fallback.",
                    "Use the native plugin for read-only ACL evaluation before considering a write probe.",
                    entry,
                    "missing-process-path-entry",
                )
        add_coverage("windows.env_path", "ok")
    except OSError as error:
        add_coverage("windows.env_path", "error", str(error))


def collect_autoruns() -> None:
    if winreg is None:
        add_coverage("windows.autoruns", "skipped", "winreg unavailable")
        return
    roots = (
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    )
    try:
        for hive, path, label in roots:
            try:
                key = winreg.OpenKey(hive, path)
            except OSError:
                continue
            try:
                index = 0
                while True:
                    try:
                        name, value, _kind = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    observed = f"{label}\\{path}\\{name}"
                    add_finding(
                        "windows.autoruns",
                        "enumeration",
                        "low",
                        f"Autorun value: {observed}",
                        f"command={value} target_acl=not_collected",
                        "Use the native plugin to parse the target and evaluate its file ACL.",
                        observed,
                        "autorun-registry-value",
                    )
            finally:
                winreg.CloseKey(key)
        add_coverage("windows.autoruns", "ok")
    except OSError as error:
        add_coverage("windows.autoruns", "error", str(error))


def collect_endpoint_controls() -> None:
    if winreg is None:
        add_coverage("windows.endpoint_controls", "skipped", "winreg unavailable")
        return
    signals: list[str] = []
    try:
        collections = []
        for name in ("Exe", "Script", "Msi", "Dll", "Appx"):
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    rf"SOFTWARE\Policies\Microsoft\Windows\SrpV2\{name}",
                )
                winreg.CloseKey(key)
                collections.append(name)
            except OSError:
                continue
        if collections:
            signals.append("AppLocker=" + ",".join(collections))
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\CI\Policy"
            )
            winreg.CloseKey(key)
            signals.append("CI.PolicyKey=present")
        except OSError:
            pass
        vbs = read_reg_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "EnableVirtualizationBasedSecurity",
        )
        if vbs is not None:
            signals.append(f"VBS={vbs}")
        providers = 0
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\AMSI\Providers"
            )
            try:
                subkeys, _values, _ = winreg.QueryInfoKey(key)
                providers = int(subkeys)
            finally:
                winreg.CloseKey(key)
        except OSError:
            providers = 0
        signals.append(f"AMSI.providers={providers}")
        add_finding(
            "windows.endpoint_controls",
            "enumeration",
            "info",
            "Endpoint-control registry signals collected",
            " ".join(signals),
            "These are registry signals only, not an effective-policy decision or proof of enforcement.",
            "windows-endpoint-control-registry",
            "endpoint-control-registry-signals",
        )
        add_coverage("windows.endpoint_controls", "ok")
    except OSError as error:
        add_coverage("windows.endpoint_controls", "error", str(error))


def emit_json() -> None:
    plugins_run = [item["id"] for item in COVERAGE if item["status"] == "ok"]
    report = {
        "schema_version": "2",
        "run_id": f"{int(time.time()):x}{os.getpid():x}"[:24].ljust(24, "0"),
        "started_at_unix": int(time.time()),
        "tool": "stealthy-script",
        "version": "0.1.0",
        "authorized_use_ack": True,
        "mode": "enumerate-only",
        "execution_path": os.environ.get("STEALTHY_EXECUTION_PATH", "script"),
        "primary_launch": os.environ.get("STEALTHY_PRIMARY_LAUNCH", "not_applicable"),
        "roe_ref": os.environ.get("STEALTHY_MANIFEST_ROE_REF", ""),
        "profile": "script",
        "coverage_mode": "script",
        "capability_delta": list(PLUGIN_IDS),
        "os": {
            "family": "windows",
            "os": "windows",
            "arch": os.environ.get("PROCESSOR_ARCHITECTURE", ""),
            "version_hint": sys.getwindowsversion()[0]
            if hasattr(sys, "getwindowsversion")
            else "",
        },
        "identity": {
            "username": os.environ.get("USERNAME", ""),
            "uid": None,
            "gid": None,
            "groups": [],
            "is_elevated": False,
            "elevation_source": "python-env",
            "token_context": "",
            "hostname": os.environ.get("COMPUTERNAME", ""),
        },
        "findings": FINDINGS,
        "assessments": [],
        "attack_paths": [],
        "triage_decisions": [],
        "plugins_run": plugins_run,
        "coverage": COVERAGE,
        "notes": [
            "Python fallback reports only data it directly collected.",
            "No child processes were spawned (no whoami / WMI).",
            "Service-object and Task Scheduler object DACLs are not collected by this fallback.",
            "Native plugin equivalence is not claimed.",
        ],
    }
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")


def emit_human() -> None:
    print("=== StealthyPrivesc Windows Python enum ===")
    print("LEGAL: Authorized use only. Reduced, read-only fallback coverage.")
    for finding in FINDINGS:
        print(
            f"FINDING [{finding['severity']}] {finding['title']} -- {finding['detail']}"
        )
    print()
    print("Coverage:")
    for item in COVERAGE:
        suffix = f" ({item['error']})" if item["error"] else ""
        print(f"  {item['id']}: {item['status']}, findings={item['findings']}{suffix}")
    print("Done. Enumeration only; native equivalence is not claimed.")


def main(argv: list[str] | None = None) -> int:
    global JSON_MODE
    args = list(sys.argv[1:] if argv is None else argv)
    authorized = (
        "--authorized" in args
        or "--i-understand-authorized-use-only" in args
        or os.environ.get("STEALTHY_AUTHORIZED") == "1"
    )
    if not authorized:
        print(
            "Authorization required: pass --authorized or set STEALTHY_AUTHORIZED=1",
            file=sys.stderr,
        )
        return 2
    if winreg is None:
        print("Windows Python fallback requires the winreg module", file=sys.stderr)
        return 1
    JSON_MODE = "--json" in args
    collect_always_install_elevated()
    collect_uac()
    collect_services()
    collect_credentials()
    collect_env_path()
    collect_autoruns()
    collect_endpoint_controls()
    add_coverage(
        "windows.privileges",
        "skipped",
        "Token privilege enumeration is not collected without spawning whoami",
    )
    add_coverage(
        "windows.scheduled_tasks",
        "skipped",
        "Scheduled-task XML/COM collection is unavailable in this fallback",
    )
    add_coverage(
        "windows.dll_hijack",
        "skipped",
        "Application import/search-order and ACL analysis is unavailable in this fallback",
    )
    add_coverage(
        "windows.admin_sessions",
        "skipped",
        "Local Administrators membership is not collected by this fallback",
    )
    add_coverage(
        "windows.app_control",
        "skipped",
        "No approved artifact was supplied; effective artifact policy assessment was not collected",
    )
    if JSON_MODE:
        emit_json()
    else:
        emit_human()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
