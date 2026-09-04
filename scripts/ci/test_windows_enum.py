#!/usr/bin/env python3
"""Deterministic tests for Windows Python fallback registry error reporting."""

from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = ROOT / "scripts" / "windows" / "enum.py"


class RegistryFailure(OSError):
    def __init__(self, winerror: int):
        super().__init__(winerror, f"fixture registry error {winerror}")
        self.winerror = winerror


class FailingRegistry:
    HKEY_LOCAL_MACHINE = object()
    HKEY_CURRENT_USER = object()

    def __init__(self, winerror: int):
        self.winerror = winerror

    def OpenKey(self, *_args):  # noqa: N802 - mirrors winreg API
        raise RegistryFailure(self.winerror)


def load_collector():
    spec = importlib.util.spec_from_file_location("stealthy_windows_enum", COLLECTOR)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load Windows fallback collector")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def endpoint_detail_for(winerror: int) -> str:
    module = load_collector()
    module.FINDINGS.clear()
    module.COVERAGE.clear()
    module.winreg = FailingRegistry(winerror)
    module.collect_endpoint_controls()
    findings = [
        finding
        for finding in module.FINDINGS
        if finding["plugin"] == "windows.endpoint_controls"
    ]
    if len(findings) != 1:
        raise AssertionError(f"expected one endpoint finding, got {findings!r}")
    coverage = [
        item for item in module.COVERAGE if item["id"] == "windows.endpoint_controls"
    ]
    if len(coverage) != 1 or coverage[0]["status"] != "ok":
        raise AssertionError(f"unexpected endpoint coverage: {coverage!r}")
    return findings[0]["detail"]


def main() -> int:
    missing = endpoint_detail_for(2)
    if "CI.PolicyKey=absent" not in missing:
        raise AssertionError(f"missing-key state was not represented: {missing}")
    denied = endpoint_detail_for(5)
    if "CI.PolicyKey=unavailable:5" not in denied:
        raise AssertionError(f"access-denied state was not represented: {denied}")
    if "CI.PolicyKey=absent" in denied:
        raise AssertionError(f"access denial was misreported as absence: {denied}")
    print("Windows Python fallback registry error tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
