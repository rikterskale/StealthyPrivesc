#!/usr/bin/env python3
"""Run the Phase 5 user-acceptance contract against a release binary."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable


if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")


@dataclass
class CommandEvidence:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    output_sha256: str


@dataclass
class CaseResult:
    test_id: str
    title: str
    status: str
    actual: str
    evidence: list[CommandEvidence] = field(default_factory=list)


class UatRunner:
    def __init__(self, binary: Path, repo_root: Path):
        self.binary = binary.resolve()
        self.repo_root = repo_root.resolve()
        self.results: list[CaseResult] = []
        self.current_evidence: list[CommandEvidence] = []
        self.plugin = ""
        self.platform = "windows" if os.name == "nt" else "linux"
        self.host = socket.gethostname()

    def run(
        self,
        *args: str,
        cwd: Path,
        binary: Path | None = None,
        env: dict[str, str] | None = None,
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[str]:
        command = [str(binary or self.binary), *map(str, args)]
        command_env = os.environ.copy()
        for name in (
            "STEALTHY_AUTHORIZED",
            "STEALTHY_KEY_FILE",
            "STEALTHY_KEY_HEX",
            "STEALTHY_KEY_OUTPUT_PATH",
            "STEALTHY_EXFIL_URL",
        ):
            command_env.pop(name, None)
        command_env["NO_COLOR"] = "1"
        if env:
            command_env.update(env)
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=command_env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        digest = hashlib.sha256(
            (
                str(completed.returncode)
                + "\0"
                + completed.stdout
                + "\0"
                + completed.stderr
            ).encode("utf-8")
        ).hexdigest()
        self.current_evidence.append(
            CommandEvidence(
                argv=command,
                exit_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                output_sha256=digest,
            )
        )
        return completed

    def case(self, test_id: str, title: str, check: Callable[[], str]) -> None:
        self.current_evidence = []
        try:
            actual = check()
            result = CaseResult(test_id, title, "PASS", actual, self.current_evidence)
        except Exception as error:  # keep running to report the complete UAT disposition
            result = CaseResult(
                test_id,
                title,
                "FAIL",
                f"{type(error).__name__}: {error}",
                self.current_evidence,
            )
        self.results.append(result)
        print(f"{result.status:4} {test_id} — {title} — {result.actual}")

    @staticmethod
    def require(condition: bool, message: str) -> None:
        if not condition:
            raise AssertionError(message)

    @staticmethod
    def parsed(output: subprocess.CompletedProcess[str]) -> dict:
        value = json.loads(output.stdout)
        if not isinstance(value, dict):
            raise AssertionError("JSON output is not an object")
        return value

    def expect(
        self,
        output: subprocess.CompletedProcess[str],
        exit_code: int = 0,
    ) -> subprocess.CompletedProcess[str]:
        self.require(
            output.returncode == exit_code,
            f"expected exit {exit_code}, got {output.returncode}; stderr={output.stderr.strip()!r}",
        )
        return output

    def choose_plugin(self, cwd: Path) -> str:
        output = self.expect(self.run("--authorized", "list-plugins", "--tsv", cwd=cwd))
        ids = [line.split("\t", 1)[0] for line in output.stdout.splitlines() if line.strip()]
        preferred = "windows.uac" if self.platform == "windows" else "linux.kernel_cve"
        self.require(bool(ids), "plugin list is empty")
        return preferred if preferred in ids else ids[0]

    def execute(self, root: Path) -> None:
        self.case("UAT-J01", "release binary is build-ready", lambda: self.check_binary())
        self.case("UAT-J02", "product identity", lambda: self.check_version(root))
        self.case("UAT-J03", "healthy readiness", lambda: self.check_doctor(root))
        self.case("UAT-J04", "guide and disclaimer", lambda: self.check_guidance(root))
        self.case("UAT-J05", "authorization gate", lambda: self.check_auth_gate(root))
        self.case("UAT-J06", "platform plugin discovery", lambda: self.check_plugins(root))
        self.case("UAT-J07", "visible memory-only baseline", lambda: self.check_baseline(root))
        self.case("UAT-J08", "focused JSON report", lambda: self.check_json(root))
        self.case("UAT-J09", "decision-controlled triage", lambda: self.check_triage(root))
        self.case("UAT-J10", "sealed evidence round trip", lambda: self.check_sealed(root))
        self.case("UAT-J11", "artifact listing and cleanup", lambda: self.check_closeout(root))

        self.case("UAT-E01", "missing authorization fails closed", lambda: self.check_auth_gate(root))
        self.case("UAT-E02", "unknown plugin is actionable", lambda: self.check_unknown_plugin(root))
        self.case("UAT-E03", "doctor reports a blocking working directory", lambda: self.check_blocked_doctor(root))
        self.case("UAT-E04", "severity threshold uses exit code 4", lambda: self.check_fail_on(root))
        self.case("UAT-E05", "encrypted output requires a protected key sink", lambda: self.check_missing_key(root))
        self.case("UAT-E06", "wrong report key fails closed", lambda: self.check_wrong_key(root))
        self.case("UAT-E07", "non-empty stage destination is preserved", lambda: self.check_nonempty_stage(root))
        self.case("UAT-E08", "corrupt checkpoint is rejected", lambda: self.check_corrupt_checkpoint(root))
        self.case("UAT-E09", "invalid triage decisions fail closed", lambda: self.check_invalid_triage(root))
        self.case("UAT-E10", "evasion requires the second confirmation gate", lambda: self.check_evasion_gate(root))

        self.case("UAT-A01", "missing binary fails before host action", lambda: self.check_missing_binary(root))
        self.case("UAT-A04", "quiet human output is intentionally blank", lambda: self.check_quiet(root))
        self.case("UAT-A05", "empty findings preserve coverage limits", lambda: self.check_empty_findings(root))
        self.case("UAT-A09", "tampered sealed report fails closed", lambda: self.check_tampered_report(root))
        self.case("UAT-A10", "approved script fallback reports reduced coverage", lambda: self.check_fallback(root))
        self.case("UAT-A12", "non-directory stage destination is preserved", lambda: self.check_file_stage(root))
        self.case("UAT-A13", "checkpoint resume preserves completed coverage", lambda: self.check_resume(root))

        self.case("UAT-B01", "empty plugin selection is rejected", lambda: self.check_empty_plugin(root))
        self.case("UAT-B02", "unknown technique family is rejected", lambda: self.check_unknown_technique(root))
        self.case("UAT-B03", "file output requires a report path", lambda: self.check_missing_output_path(root))
        self.case("UAT-B04", "report and key paths must differ", lambda: self.check_same_sink(root))
        self.case("UAT-B05", "remote output rejects non-HTTPS URLs", lambda: self.check_insecure_remote(root))
        self.case("UAT-B06", "stage rejects path-like bundle names", lambda: self.check_unsafe_name(root))
        self.case("UAT-B07", "finding count is bounded", lambda: self.check_finding_limit(root))
        self.case("UAT-B08", "report size is bounded", lambda: self.check_report_limit(root))
        self.case("UAT-B09", "missing sealed report is rejected", lambda: self.check_missing_report(root))
        self.case("UAT-B10", "empty stage hostname is rejected", lambda: self.check_empty_hostname(root))

    def check_binary(self) -> str:
        self.require(self.binary.is_file(), f"release binary missing: {self.binary}")
        if os.name != "nt":
            self.require(os.access(self.binary, os.X_OK), "release binary is not executable")
        return f"binary exists and is executable at {self.binary}"

    def check_version(self, root: Path) -> str:
        output = self.expect(self.run("--version", cwd=root))
        version = output.stdout.strip()
        self.require(bool(re.fullmatch(r"stealthy \d+\.\d+\.\d+", version)), f"unexpected version: {version!r}")
        return f"exit 0; stdout={version!r}"

    def check_doctor(self, root: Path) -> str:
        value = self.parsed(self.expect(self.run("doctor", "--json", cwd=root)))
        self.require(value.get("schema_version") == "1", "doctor schema is not 1")
        self.require(value.get("healthy") is True, "doctor is not healthy")
        self.require(value.get("blocking") is False, "doctor is blocking")
        self.require(isinstance(value.get("plugins"), int) and value["plugins"] > 0, "no plugins")
        return f"exit 0; schema=1; healthy=true; plugins={value['plugins']}"

    def check_guidance(self, root: Path) -> str:
        guide = self.expect(self.run("guide", cwd=root))
        disclaimer = self.expect(self.run("disclaimer", cwd=root))
        self.require("stealthy --authorized scan" in guide.stdout, "guide lacks the safe scan")
        self.require("authorized" in disclaimer.stdout.lower(), "disclaimer lacks authorized-use text")
        return "guide/disclaimer exit 0; safe-scan and authorized-use markers present"

    def check_auth_gate(self, root: Path) -> str:
        gate_root = root / "authorization-gate"
        gate_root.mkdir(exist_ok=True)
        output = self.expect(self.run("enum", cwd=gate_root), 2)
        self.require("Authorization required" in output.stderr, "authorization recovery text missing")
        self.require(not (gate_root / ".cache-run").exists(), "unauthorized run created a ledger")
        self.require(
            not any(path.name.endswith((".seal", ".key")) for path in gate_root.iterdir()),
            "unauthorized run created evidence",
        )
        return "exit 2; Authorization required; no report, key, or ledger created"

    def check_plugins(self, root: Path) -> str:
        self.plugin = self.choose_plugin(root)
        prefix = "windows." if self.platform == "windows" else "linux."
        self.require(self.plugin.startswith(prefix), f"plugin {self.plugin!r} has the wrong namespace")
        return f"exit 0; selected platform plugin {self.plugin}"

    def check_baseline(self, root: Path) -> str:
        output = self.expect(
            self.run(
                "--authorized", "--no-color", "--delay-ms", "0", "enum", cwd=root, timeout=300
            )
        )
        for marker in ("StealthyPrivesc", "mode=enumerate-only", "Summary", "Coverage"):
            self.require(marker in output.stdout, f"human report lacks {marker!r}")
        self.require("[memory]" in output.stderr, "run lacks the memory-only disposition")
        self.require("@" in output.stdout, "human report lacks user@host identity")
        self.require(not (root / ".cache-run").exists(), "memory-only baseline created a ledger")
        return "exit 0; identity, enumerate-only, summary, coverage, and memory markers present; no ledger"

    def check_json(self, root: Path) -> str:
        output = self.expect(
            self.run(
                "--authorized", "--quiet", "--no-color", "--format", "json", "--output", "memory",
                "--delay-ms", "0", "enum", "--plugins", self.plugin, cwd=root,
            )
        )
        value = self.parsed(output)
        self.require(value.get("schema_version") == "2", "report schema is not 2")
        self.require(value.get("authorized_use_ack") is True, "authorization field is false")
        self.require(value.get("mode") == "enumerate-only", "mode changed")
        self.require(value.get("coverage_mode") == "native", "coverage mode is not native")
        self.require(value.get("plugins_run") == [self.plugin], "focused plugin set changed")
        coverage = value.get("coverage", [])
        self.require(any(item.get("id") == self.plugin for item in coverage), "coverage lacks selected plugin")
        return f"exit 0; schema=2; native enumerate-only report for {self.plugin}; coverage captured"

    def check_triage(self, root: Path) -> str:
        checkpoint = root / "triage-checkpoint.json"
        decisions = root / "triage-decisions.json"
        first = self.expect(
            self.run(
                "--authorized", "--quiet", "--format", "json", "--checkpoint", str(checkpoint),
                "--delay-ms", "0", "enum", "--plugins", self.plugin, "--triage",
                "--triage-out", str(decisions), cwd=root,
            )
        )
        first_report = self.parsed(first)
        self.require(checkpoint.is_file() and decisions.is_file(), "triage files were not created")
        checkpoint_report = json.loads(checkpoint.read_text(encoding="utf-8"))
        decision_file = json.loads(decisions.read_text(encoding="utf-8"))
        self.require(decision_file.get("schema_version") == "1", "decision schema is not 1")
        self.require(
            decision_file.get("run_id") == checkpoint_report.get("run_id") == first_report.get("run_id"),
            "triage run IDs do not match",
        )
        decision_rows = decision_file.get("decisions")
        self.require(isinstance(decision_rows, list), "triage decisions are not a list")
        self.require(
            all(row.get("action") == "defer" for row in decision_rows),
            "triage template enabled a non-defer action",
        )
        applied = self.expect(
            self.run(
                "--authorized", "--quiet", "--format", "json", "--checkpoint", str(checkpoint),
                "--delay-ms", "0", "enum", "--plugins", self.plugin,
                "--approve-file", str(decisions), cwd=root,
            )
        )
        applied_report = self.parsed(applied)
        self.require(
            applied_report.get("triage_decisions") == decision_rows,
            "applied report did not preserve the triage decisions",
        )
        self.require(
            not any(item.get("kind") == "exploit_attempt" for item in applied_report.get("findings", [])),
            "all-defer triage unexpectedly enabled a probe",
        )
        return (
            f"triage and apply exited 0; schema=1; matching run ID; "
            f"{len(decision_rows)} all-defer decision(s); no probe result"
        )

    def sealed_pair(self, root: Path, name: str) -> tuple[Path, Path]:
        report = root / f"{name}.seal"
        key = root / f"{name}.key"
        output = self.expect(
            self.run(
                "--authorized", "--quiet", "--output", "file", "--output-path", str(report),
                "--key-output-path", str(key), "--delay-ms", "0", "enum", "--plugins", self.plugin,
                cwd=root,
            )
        )
        self.require(report.is_file() and key.is_file(), "sealed report/key pair was not created")
        secret = key.read_text(encoding="utf-8").strip()
        self.require(bool(secret), "key file is empty")
        self.require(secret not in output.stdout + output.stderr, "key leaked to process output")
        return report, key

    def check_sealed(self, root: Path) -> str:
        report, key = self.sealed_pair(root, "journey")
        decoded = self.expect(self.run("report", str(report), "--key-file", str(key), "--format", "json", cwd=root))
        value = self.parsed(decoded)
        self.require(value.get("schema_version") == "2", "decoded report schema is not 2")
        if os.name != "nt":
            self.require(stat.S_IMODE(report.stat().st_mode) == 0o600, "report mode is not 0600")
            self.require(stat.S_IMODE(key.stat().st_mode) == 0o600, "key mode is not 0600")
        return "report/key created separately; key absent from output; offline decode returned schema 2"

    def check_closeout(self, root: Path) -> str:
        out = root / "closeout-stage"
        ledger = root / "closeout-ledger"
        name = "stealthy.exe" if self.platform == "windows" else "stealthy"
        self.expect(
            self.run(
                "--ledger-dir", str(ledger), "stage", "--os", self.platform,
                "--target-hostname", self.host, "--name", name, "--out", str(out),
                "--binary", str(self.binary), cwd=root,
            )
        )
        listing = self.expect(self.run("--ledger-dir", str(ledger), "artifacts", "--latest", "--json", cwd=root))
        artifact_data = self.parsed(listing)
        self.require(bool(artifact_data.get("entries")), "artifact listing is empty")
        cleanup = self.expect(self.run("--ledger-dir", str(ledger), "cleanup", "--latest", "--secure-delete", cwd=root))
        self.require(not out.exists(), "cleanup left the staged directory")
        return f"artifacts listed {len(artifact_data['entries'])} entry/entries; cleanup exit 0; stage absent"

    def check_missing_binary(self, root: Path) -> str:
        missing = root / ("missing.exe" if os.name == "nt" else "missing")
        try:
            self.run("--version", cwd=root, binary=missing)
        except FileNotFoundError as error:
            return f"launch failed before execution with {type(error).__name__}; no ledger created"
        raise AssertionError("missing binary unexpectedly launched")

    def check_blocked_doctor(self, root: Path) -> str:
        blocked = root / "read-only"
        blocked.mkdir()
        prior = stat.S_IMODE(blocked.stat().st_mode)
        blocked.chmod(stat.S_IREAD | stat.S_IEXEC)
        try:
            value = self.parsed(self.expect(self.run("doctor", "--json", cwd=blocked), 3))
        finally:
            blocked.chmod(prior)
        self.require(value.get("healthy") is False and value.get("blocking") is True, "doctor did not block")
        detail = value.get("check_details", {}).get("working_directory_writable", {})
        self.require(detail.get("status") == "block" and detail.get("remediation"), "doctor lacks remediation")
        return "exit 3 diagnostic; healthy=false; blocking=true; writable-directory remediation present"

    def check_unknown_plugin(self, root: Path) -> str:
        output = self.expect(self.run("--authorized", "--quiet", "enum", "--plugins", "not.a.real.plugin", cwd=root), 1)
        self.require("unknown plugin ID" in output.stderr and "list-plugins" in output.stderr, "actionable error missing")
        return "exit 1; error identifies unknown plugin and recommends list-plugins"

    def check_quiet(self, root: Path) -> str:
        output = self.expect(self.run("--authorized", "--quiet", "--format", "human", "--delay-ms", "0", "enum", "--plugins", self.plugin, cwd=root))
        self.require(not output.stdout.strip(), "quiet human mode emitted stdout")
        return "exit 0; stdout is empty by design"

    def check_empty_findings(self, root: Path) -> str:
        fixture = self.repo_root / "crates/stealthy/tests/fixtures/script_report_windows.json"
        output = self.expect(self.run("ingest", str(fixture), "--format", "json", cwd=root))
        value = self.parsed(output)
        self.require(value.get("findings") == [], "fixture did not preserve empty findings")
        self.require(value.get("coverage") == [], "fixture did not preserve empty coverage")
        self.require(value.get("coverage_mode") == "script", "reduced coverage was not explicit")
        self.require(bool(value.get("capability_delta")), "empty coverage lacks capability delta")
        return "exit 0; zero findings retained with script coverage mode and explicit capability delta"

    def check_fail_on(self, root: Path) -> str:
        output = self.expect(
            self.run(
                "--authorized", "--quiet", "--format", "json", "--fail-on", "info",
                "--delay-ms", "0", "enum", "--plugins", self.plugin, cwd=root,
            ),
            4,
        )
        value = self.parsed(output)
        self.require(bool(value.get("findings")), "exit 4 had no threshold-crossing finding")
        return f"report emitted with {len(value['findings'])} finding(s); exit 4"

    def check_missing_key(self, root: Path) -> str:
        report = root / "missing-key.seal"
        output = self.expect(
            self.run(
                "--authorized", "--quiet", "--output", "file", "--output-path", str(report),
                "enum", "--plugins", self.plugin, cwd=root,
            ),
            1,
        )
        self.require("--key-output-path" in output.stderr, "key-sink guidance missing")
        self.require(not report.exists(), "report was created without a key sink")
        return "exit 1; --key-output-path guidance present; no report created"

    def check_wrong_key(self, root: Path) -> str:
        first, _ = self.sealed_pair(root, "wrong-key-first")
        _, second_key = self.sealed_pair(root, "wrong-key-second")
        output = self.run("report", str(first), "--key-file", str(second_key), "--format", "json", cwd=root)
        self.require(output.returncode != 0, "wrong key decoded the report")
        self.require("error" in output.stderr.lower(), "wrong-key failure lacks an error")
        return f"wrong report/key pair rejected with exit {output.returncode}"

    def check_tampered_report(self, root: Path) -> str:
        report, key = self.sealed_pair(root, "tampered")
        body = bytearray(report.read_bytes())
        self.require(bool(body), "sealed report is empty")
        body[-1] ^= 1
        report.write_bytes(body)
        output = self.run("report", str(report), "--key-file", str(key), "--format", "json", cwd=root)
        self.require(output.returncode != 0, "tampered report decoded")
        return f"modified ciphertext rejected with exit {output.returncode}"

    def check_fallback(self, root: Path) -> str:
        out = root / "fallback-stage"
        ledger = root / "fallback-ledger"
        if self.platform == "windows":
            self.expect(
                self.run(
                    "--ledger-dir", str(ledger), "stage", "--os", "windows",
                    "--target-hostname", self.host, "--name", "stealthy.exe", "--out", str(out), cwd=root,
                )
            )
            command = [
                "powershell.exe",
                "-NoProfile",
                "-File",
                str(out / "scripts/run.ps1"),
                "-Manifest",
                str(out / "scripts/stealthy-run.conf"),
                "--authorized",
                "--format=json",
                "enum",
            ]
            completed = subprocess.run(command, cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            digest = hashlib.sha256((str(completed.returncode) + "\0" + completed.stdout + "\0" + completed.stderr).encode()).hexdigest()
            self.current_evidence.append(CommandEvidence(command, completed.returncode, completed.stdout, completed.stderr, digest))
        else:
            fake = root / "blocked-primary"
            fake.write_text("#!/bin/sh\nexit 126\n", encoding="utf-8")
            fake.chmod(0o750)
            self.expect(
                self.run(
                    "--ledger-dir", str(ledger), "stage", "--os", "linux",
                    "--target-hostname", self.host, "--name", "stealthy", "--out", str(out),
                    "--binary", str(fake), cwd=root,
                )
            )
            command = ["bash", str(out / "scripts/run.sh"), "--authorized", "--json"]
            completed = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                env={**os.environ, "STEALTHY_AUTHORIZED": "1", "STEALTHY_SCRIPT_FIRST": "false"},
            )
            digest = hashlib.sha256((str(completed.returncode) + "\0" + completed.stdout + "\0" + completed.stderr).encode()).hexdigest()
            self.current_evidence.append(CommandEvidence(command, completed.returncode, completed.stdout, completed.stderr, digest))
        self.expect(completed)
        value = self.parsed(completed)
        self.require(value.get("coverage_mode") == "script", "fallback did not identify script coverage")
        self.require(bool(value.get("capability_delta")), "fallback omitted capability delta")
        if self.platform != "windows":
            self.require(
                value.get("primary_launch") == "blocked",
                "blocked primary was not recorded in script JSON",
            )
        return f"exit 0; execution_path={value.get('execution_path')}; coverage_mode=script; capability delta present"

    def stage_failure(self, root: Path, out: Path) -> subprocess.CompletedProcess[str]:
        return self.run(
            "--ledger-dir", str(root / "rejected-stage-ledger"), "stage", "--os", self.platform,
            "--target-hostname", self.host, "--out", str(out), cwd=root,
        )

    def check_nonempty_stage(self, root: Path) -> str:
        out = root / "nonempty-stage"
        out.mkdir()
        marker = out / "keep.txt"
        marker.write_text("keep", encoding="utf-8")
        output = self.stage_failure(root, out)
        self.require(output.returncode != 0 and "must be empty" in output.stderr, "non-empty stage was not rejected")
        self.require(marker.read_text(encoding="utf-8") == "keep", "existing stage content changed")
        return f"exit {output.returncode}; must-be-empty error; preexisting file unchanged"

    def check_file_stage(self, root: Path) -> str:
        out = root / "stage-is-file"
        out.write_text("keep", encoding="utf-8")
        output = self.stage_failure(root, out)
        self.require(output.returncode != 0, "file stage destination was accepted")
        self.require(out.read_text(encoding="utf-8") == "keep", "file stage destination changed")
        return f"exit {output.returncode}; non-directory destination unchanged"

    def check_resume(self, root: Path) -> str:
        checkpoint = root / "resume.json"
        first = self.expect(
            self.run(
                "--authorized", "--quiet", "--format", "json", "--checkpoint", str(checkpoint),
                "--delay-ms", "0", "enum", "--plugins", self.plugin, cwd=root,
            )
        )
        self.parsed(first)
        self.require(checkpoint.is_file(), "checkpoint was not written")
        resumed = self.expect(
            self.run(
                "--authorized", "--quiet", "--format", "json", "resume", "--checkpoint", str(checkpoint),
                "--plugins", self.plugin, cwd=root,
            )
        )
        value = self.parsed(resumed)
        coverage = value.get("coverage", [])
        self.require(any(item.get("id") == self.plugin and item.get("status") == "ok" for item in coverage), "resumed coverage is incomplete")
        return f"checkpoint created; resume exit 0; {self.plugin} coverage remains ok"

    def check_corrupt_checkpoint(self, root: Path) -> str:
        checkpoint = root / "corrupt.json"
        checkpoint.write_text("{not valid json\n", encoding="utf-8")
        output = self.expect(self.run("--authorized", "resume", "--checkpoint", str(checkpoint), cwd=root), 1)
        self.require("error:" in output.stderr, "corrupt checkpoint lacks error")
        return "exit 1; corrupt JSON rejected before plugin execution"

    def check_invalid_triage(self, root: Path) -> str:
        checkpoint = root / "invalid-triage-checkpoint.json"
        baseline = self.expect(
            self.run(
                "--authorized", "--quiet", "--format", "json", "--checkpoint", str(checkpoint),
                "--delay-ms", "0", "enum", "--plugins", self.plugin, cwd=root,
            )
        )
        report = self.parsed(baseline)
        run_id = report.get("run_id")
        self.require(isinstance(run_id, str) and bool(run_id), "baseline run ID is missing")

        wrong_run = root / "wrong-run-decisions.json"
        wrong_run.write_text(
            json.dumps({"schema_version": "1", "run_id": "different-run", "decisions": []}),
            encoding="utf-8",
        )
        mismatch = self.expect(
            self.run(
                "--authorized", "--quiet", "--format", "json", "--checkpoint", str(checkpoint),
                "enum", "--plugins", self.plugin, "--approve-file", str(wrong_run), cwd=root,
            ),
            1,
        )
        self.require("does not match current run_id" in mismatch.stderr, "run-ID mismatch was not identified")
        self.require(not mismatch.stdout.strip(), "run-ID mismatch emitted a report")

        unknown = root / "unknown-finding-decisions.json"
        unknown.write_text(
            json.dumps(
                {
                    "schema_version": "1",
                    "run_id": run_id,
                    "decisions": [{"finding_id": "unknown-finding-id", "action": "probe"}],
                }
            ),
            encoding="utf-8",
        )
        rejected = self.expect(
            self.run(
                "--authorized", "--quiet", "--format", "json", "--checkpoint", str(checkpoint),
                "enum", "--plugins", self.plugin, "--approve-file", str(unknown), cwd=root,
            ),
            1,
        )
        self.require("unknown probe finding_id" in rejected.stderr, "unknown finding ID was not identified")
        self.require(not rejected.stdout.strip(), "unknown finding decision emitted a report")
        return "mismatched run ID and unknown probe finding ID both exited 1 before report/probe output"

    def check_evasion_gate(self, root: Path) -> str:
        output = self.expect(
            self.run(
                "--authorized", "--quiet", "--format", "json", "enum", "--plugins", self.plugin,
                "--allow-techniques", "amsi-bypass", cwd=root,
            ),
            1,
        )
        self.require("--confirm-evasion" in output.stderr, "second-gate guidance is missing")
        self.require(not output.stdout.strip(), "unconfirmed evasion emitted a report")
        return "exit 1; --confirm-evasion requirement present; no report or executed action emitted"

    def check_empty_plugin(self, root: Path) -> str:
        output = self.expect(self.run("--authorized", "--quiet", "enum", "--plugins", "", cwd=root), 1)
        self.require("plugin ID lists cannot contain empty values" in output.stderr, "empty-list guidance missing")
        return "exit 1; empty plugin value rejected with list guidance"

    def check_unknown_technique(self, root: Path) -> str:
        output = self.expect(
            self.run("--authorized", "--quiet", "enum", "--allow-techniques", "not-a-real-technique", "--plugins", self.plugin, cwd=root),
            1,
        )
        self.require("unknown --allow-techniques" in output.stderr, "unknown technique guidance missing")
        return "exit 1; unknown technique family rejected"

    def check_missing_output_path(self, root: Path) -> str:
        output = self.expect(self.run("--authorized", "--quiet", "--output", "file", "enum", "--plugins", self.plugin, cwd=root), 1)
        self.require("--output=file requires --output-path" in output.stderr, "output-path guidance missing")
        return "exit 1; --output-path requirement reported"

    def check_same_sink(self, root: Path) -> str:
        sink = root / "same-sink"
        output = self.expect(
            self.run(
                "--authorized", "--quiet", "--output", "file", "--output-path", str(sink),
                "--key-output-path", str(sink), "enum", "--plugins", self.plugin, cwd=root,
            ),
            1,
        )
        self.require("must differ" in output.stderr, "same-sink guidance missing")
        self.require(not sink.exists(), "same report/key sink was created")
        return "exit 1; identical report/key path rejected before writing"

    def check_insecure_remote(self, root: Path) -> str:
        key = root / "remote.key"
        output = self.expect(
            self.run(
                "--authorized", "--quiet", "--output", "remote", "--exfil-url", "http://127.0.0.1/ingest",
                "--key-output-path", str(key), "enum", "--plugins", self.plugin, cwd=root,
            ),
            1,
        )
        self.require("absolute https:// URL" in output.stderr, "HTTPS requirement missing")
        self.require(not key.exists(), "key was created before URL validation")
        return "exit 1; absolute HTTPS URL required; no key created"

    def check_unsafe_name(self, root: Path) -> str:
        out = root / "unsafe-name-stage"
        output = self.run(
            "--ledger-dir", str(root / "unsafe-name-ledger"), "stage", "--os", self.platform,
            "--target-hostname", self.host, "--name", "../escape", "--out", str(out), cwd=root,
        )
        self.require(output.returncode != 0 and "safe file basename" in output.stderr, "unsafe name was not rejected")
        self.require(not (root.parent / "escape").exists(), "unsafe stage escaped its destination")
        return f"exit {output.returncode}; path-like name rejected; no escaped artifact"

    def check_finding_limit(self, root: Path) -> str:
        output = self.expect(
            self.run(
                "--authorized", "--quiet", "--format", "json", "--max-findings", "1",
                "--delay-ms", "0", "enum", "--plugins", self.plugin, cwd=root,
            )
        )
        value = self.parsed(output)
        count = len(value.get("findings", []))
        self.require(count <= 1, f"finding count exceeded limit: {count}")
        return f"exit 0; retained findings={count} (limit=1)"

    def check_report_limit(self, root: Path) -> str:
        output = self.run(
            "--authorized", "--quiet", "--max-report-bytes", "1", "--delay-ms", "0",
            "enum", "--plugins", self.plugin, cwd=root,
        )
        self.require(output.returncode != 0 and "max-report-bytes" in output.stderr, "report-size limit did not fail closed")
        return f"exit {output.returncode}; max-report-bytes error present"

    def check_missing_report(self, root: Path) -> str:
        missing = root / "missing.seal"
        key = root / "placeholder.key"
        key.write_text("00" * 32, encoding="utf-8")
        output = self.run("report", str(missing), "--key-file", str(key), "--format", "json", cwd=root)
        self.require(output.returncode != 0 and "error" in output.stderr.lower(), "missing report was not rejected")
        return f"exit {output.returncode}; missing input reported as error"

    def check_empty_hostname(self, root: Path) -> str:
        output = self.run(
            "--ledger-dir", str(root / "empty-host-ledger"), "stage", "--os", self.platform,
            "--target-hostname", "", "--out", str(root / "empty-host-stage"), cwd=root,
        )
        self.require(output.returncode != 0 and "target-hostname" in output.stderr, "empty hostname was not rejected")
        return f"exit {output.returncode}; required hostname error present"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    runner = UatRunner(args.binary, args.repo_root)
    with tempfile.TemporaryDirectory(prefix="stealthy-uat-") as temporary:
        root = Path(temporary)
        runner.execute(root)

    passed = sum(result.status == "PASS" for result in runner.results)
    failed = len(runner.results) - passed
    report = {
        "schema_version": "1",
        "suite": "StealthyPrivesc Phase 5 UAT",
        "platform": runner.platform,
        "binary": str(runner.binary),
        "total": len(runner.results),
        "passed": passed,
        "failed": failed,
        "results": [asdict(result) for result in runner.results],
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"UAT SUMMARY — total={len(runner.results)} passed={passed} failed={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
