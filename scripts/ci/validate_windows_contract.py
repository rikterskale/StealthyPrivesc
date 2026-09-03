#!/usr/bin/env python3
"""Static contract checks for the Windows fallback and gated helper script."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
EVASION = ROOT / "scripts/windows/evasion.ps1"
DISPATCHER = ROOT / "scripts/windows/run.ps1"
FALLBACK = ROOT / "scripts/windows/enum.ps1"
JSCRIPT = ROOT / "scripts/windows/enum.js"
MSBUILD = ROOT / "scripts/windows/EnumTasks.csproj"
EXPLOIT_MOD = ROOT / "crates/stealthy/src/exploit/mod.rs"
RUST_EVASION_SCAFFOLDS = (
    ROOT / "crates/stealthy/src/exploit/amsi_bypass.rs",
    ROOT / "crates/stealthy/src/exploit/etw_unhook.rs",
    ROOT / "crates/stealthy/src/exploit/av_edr_service.rs",
)


def require(text: str, needle: str, label: str, failures: list[str]) -> None:
    if needle not in text:
        failures.append(f"{label}: missing {needle!r}")


def main() -> int:
    failures: list[str] = []
    evasion = EVASION.read_text(encoding="utf-8")
    dispatcher = DISPATCHER.read_text(encoding="utf-8")
    fallback = FALLBACK.read_text(encoding="utf-8")
    jscript = JSCRIPT.read_text(encoding="utf-8")
    msbuild = MSBUILD.read_text(encoding="utf-8")
    exploit_mod = EXPLOIT_MOD.read_text(encoding="utf-8")

    require(evasion, "[switch]$Authorized", "evasion", failures)
    require(evasion, "$Authorized -or ($env:STEALTHY_AUTHORIZED -eq \"1\")", "evasion", failures)
    require(evasion, "function Test-AllowedTechnique", "evasion", failures)
    require(evasion, "-split ','", "evasion", failures)
    require(evasion, "ToLowerInvariant()", "evasion", failures)
    require(evasion, "Test-EvasionAuthorization -Authorized:$Authorized", "evasion", failures)
    require(evasion, "feature = 'windows-evasion-scaffolds'", "evasion", failures)
    require(evasion, "status = 'planned'", "evasion", failures)
    require(evasion, "executed = $false", "evasion", failures)
    require(evasion, "modifies_controls = $false", "evasion", failures)
    require(evasion, "throw 'Evasion scaffold requires -Technique'", "evasion", failures)
    require(evasion, "$result | ConvertTo-Json", "evasion", failures)
    require(dispatcher, "$authorizedArg = ($Arguments -contains '--authorized')", "dispatcher", failures)
    require(dispatcher, "$authorizedEnv = $env:STEALTHY_AUTHORIZED -eq '1'", "dispatcher", failures)
    require(dispatcher, "exit 2", "dispatcher", failures)
    require(dispatcher, "$bundleMode", "dispatcher", failures)
    require(dispatcher, "'script-only'", "dispatcher", failures)
    require(fallback, "$authorized = $Authorized -or ($env:STEALTHY_AUTHORIZED -eq '1')", "fallback", failures)
    require(fallback, "coverage_mode = 'script'", "fallback", failures)
    require(jscript, "WScript.Arguments.length", "jscript", failures)
    require(jscript, "function recordCoverageError", "jscript", failures)
    require(jscript, "function isMissingRegistryValue", "jscript", failures)
    require(jscript, '"status":"' , "jscript", failures)
    require(msbuild, "System.DateTime]::Parse('1970-01-01')", "msbuild", failures)
    require(msbuild, "Authorization required", "msbuild", failures)
    require(msbuild, "&quot;coverage_mode&quot;", "msbuild", failures)

    if "WScript.Arguments.Count" in jscript:
        failures.append("jscript: WScript.Arguments.Count is not portable under cscript.exe")
    if "catch (e) {}" in jscript:
        failures.append("jscript: registry errors must be represented in coverage output")
    if "System.DateTime]::new(" in msbuild:
        failures.append("msbuild: timestamp expression is incompatible with .NET Framework MSBuild")

    if "-like '*amsi-bypass*'" in evasion or "-like '*etw-unhook*'" in evasion or "-like '*av-edr-service*'" in evasion:
        failures.append("evasion: allowlist matching must be exact, not wildcard-based")
    for forbidden in ("GetType(", ".SetValue(", "Get-Service", "Stop-Service", "Start-Service", ".Pause()"):
        if forbidden in evasion:
            failures.append(f"evasion: scaffold contains forbidden control action {forbidden!r}")

    for module in ("amsi_bypass", "etw_unhook", "av_edr_service"):
        require(exploit_mod, f"pub mod {module};", "Rust exploit module graph", failures)
    rust_forbidden = (
        "VirtualProtect",
        "GetProcAddress",
        "OpenSCManager",
        "OpenService",
        "ControlService",
        "StartService",
        "copy_nonoverlapping",
        "PAGE_EXECUTE_READWRITE",
    )
    for path in RUST_EVASION_SCAFFOLDS:
        scaffold = path.read_text(encoding="utf-8")
        require(scaffold, "pub fn check_evasion_gate", str(path.relative_to(ROOT)), failures)
        require(scaffold, "pub fn planned_status", str(path.relative_to(ROOT)), failures)
        for forbidden in rust_forbidden:
            if forbidden in scaffold:
                failures.append(
                    f"{path.relative_to(ROOT)}: scaffold contains forbidden action API {forbidden!r}"
                )

    if failures:
        print(*failures, sep="\n")
        return 1
    print("Windows authorization and fallback contract checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
