#!/usr/bin/env python3
"""Static contract checks for the Windows fallback and gated helper script."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
EVASION = ROOT / "scripts/windows/evasion.ps1"
DISPATCHER = ROOT / "scripts/windows/run.ps1"
FALLBACK = ROOT / "scripts/windows/enum.ps1"


def require(text: str, needle: str, label: str, failures: list[str]) -> None:
    if needle not in text:
        failures.append(f"{label}: missing {needle!r}")


def main() -> int:
    failures: list[str] = []
    evasion = EVASION.read_text(encoding="utf-8")
    dispatcher = DISPATCHER.read_text(encoding="utf-8")
    fallback = FALLBACK.read_text(encoding="utf-8")

    require(evasion, "[switch]$Authorized", "evasion", failures)
    require(evasion, "$Authorized -or ($env:STEALTHY_AUTHORIZED -eq \"1\")", "evasion", failures)
    require(evasion, "function Test-AllowedTechnique", "evasion", failures)
    require(evasion, "-split ','", "evasion", failures)
    require(evasion, "ToLowerInvariant()", "evasion", failures)
    require(evasion, "Test-EvasionAuthorization -Authorized:$Authorized", "evasion", failures)
    require(dispatcher, "$authorizedArg = ($Arguments -contains '--authorized')", "dispatcher", failures)
    require(dispatcher, "$authorizedEnv = $env:STEALTHY_AUTHORIZED -eq '1'", "dispatcher", failures)
    require(dispatcher, "exit 2", "dispatcher", failures)
    require(fallback, "$authorized = $Authorized -or ($env:STEALTHY_AUTHORIZED -eq '1')", "fallback", failures)
    require(fallback, "coverage_mode = 'script'", "fallback", failures)

    if "-like '*amsi-bypass*'" in evasion or "-like '*etw-unhook*'" in evasion or "-like '*av-edr-service*'" in evasion:
        failures.append("evasion: allowlist matching must be exact, not wildcard-based")

    if failures:
        print(*failures, sep="\n")
        return 1
    print("Windows authorization and fallback contract checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
