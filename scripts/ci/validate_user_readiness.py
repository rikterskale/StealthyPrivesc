#!/usr/bin/env python3
"""
User Readiness Validation Suite

Validates that StealthyPrivesc is production-ready for end users:
- Installation and verification procedures work
- First-user journey contract is met
- Documentation is complete and accurate
- Help text is consistent and helpful
- Output formats work as documented
- Error messages are actionable
- Platform support is clearly stated and tested
"""

import json
import os
import re
from collections import Counter
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple


class UserReadinessValidator:
    _ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
    _DOC_REQUIRED_PATHS = [
        "cli-reference.md",
        "user-guide.md",
        "operator-runbook.md",
        "support-policy.md",
        "report-schema.md",
    ]
    _MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

    def __init__(self, binary: str, repo_root: str = "."):
        self.binary = binary
        self.repo_root = Path(repo_root)
        self.errors: List[str] = []
        self._doctor: Optional[dict] = None
        self._plugins: Optional[List[str]] = None
        self._raw_plugin_lines: Optional[List[str]] = None

    def run(
        self,
        *args,
        expected_exit: int = 0,
        capture_output: bool = True,
        env: Optional[dict] = None,
    ) -> Tuple[int, str, str]:
        """Run the binary and return (exit_code, stdout, stderr)."""
        command_env = os.environ.copy()
        if env:
            command_env.update({k: str(v) for k, v in env.items()})
        try:
            result = subprocess.run(
                [self.binary, *args],
                capture_output=capture_output,
                text=True,
                timeout=30,
                env=command_env,
            )
            if capture_output and result.returncode != expected_exit:
                return result.returncode, result.stdout, result.stderr
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            self.errors.append(f"Command timeout: {self.binary} {' '.join(args)}")
            return -1, "", ""
        except Exception as e:
            self.errors.append(f"Command failed: {e}")
            return -1, "", ""

    def get_doctor(self) -> Optional[dict]:
        if self._doctor is not None:
            return self._doctor

        code, stdout, stderr = self.run("doctor", "--json")
        if code != 0:
            return None
        try:
            self._doctor = json.loads(stdout)
        except json.JSONDecodeError:
            self._doctor = None
            self.errors.append("doctor --json output is not valid JSON")
        return self._doctor

    def get_raw_plugin_lines(self) -> List[str]:
        if self._raw_plugin_lines is not None:
            return self._raw_plugin_lines

        code, stdout, stderr = self.run("--authorized", "list-plugins", "--tsv")
        if code != 0:
            self.errors.append("Could not read plugin list via --authorized list-plugins --tsv")
            self._raw_plugin_lines = []
            return self._raw_plugin_lines

        self._raw_plugin_lines = [line for line in stdout.splitlines() if line.strip()]
        return self._raw_plugin_lines

    def get_plugins(self) -> List[str]:
        if self._plugins is not None:
            return self._plugins

        plugins: List[str] = []
        for line in self.get_raw_plugin_lines():
            if line.lower().startswith("id\tname\tdescription"):
                continue
            parts = line.split("\t")
            if len(parts) >= 1 and parts[0].strip():
                plugins.append(parts[0].strip())
        self._plugins = plugins
        return self._plugins

    def get_smoke_plugin(self) -> Optional[str]:
        plugins = self.get_plugins()
        for plugin in [
            "linux.kernel_cve",
            "linux.app_control",
            "linux.groups",
            "windows.privileges",
            "windows.app_control",
            "windows.services",
            "windows.uac",
        ]:
            if plugin in plugins:
                return plugin
        return plugins[0] if plugins else None

    def check_installation_readiness(self):
        """Validate installation and verification procedures."""
        print("Checking installation readiness...")

        # Version command must work
        code, stdout, _ = self.run("--version")
        if code != 0:
            self.errors.append("--version command failed")
        elif not re.match(r"^stealthy \d+\.\d+\.\d+", stdout.strip()):
            self.errors.append(f"Invalid version format: {stdout.strip()}")

        # Doctor must report healthy
        doctor = self.get_doctor()
        if not doctor:
            self.errors.append("doctor command failed")
            return
        if not doctor.get("healthy"):
            self.errors.append("doctor reports unhealthy system")
        if doctor.get("schema_version") != "1":
            self.errors.append(
                f"doctor schema version is {doctor.get('schema_version')}, expected 1"
            )

        checks = doctor.get("checks", {})
        if not isinstance(checks, dict):
            self.errors.append("doctor output missing checks object")
        else:
            for check_name in ("supported_os", "plugins_available", "working_directory"):
                if not checks.get(check_name):
                    self.errors.append(f"doctor check '{check_name}' is false")

    def check_first_user_journey(self):
        """Validate the first-user journey contract."""
        print("Checking first-user journey contract...")

        resume_checkpoint = Path(tempfile.gettempdir()) / "stealthy-readiness-resume.json"

        # Commands that must remain blocked when not authorized
        for command in [
            ["enum"],
            ["list-plugins"],
            ["controls"],
            ["live-controls"],
            ["resume", "--checkpoint", str(resume_checkpoint)],
        ]:
            code, _, stderr = self.run(*command, expected_exit=2)
            if code != 2:
                self.errors.append(f"Unauthorized '{' '.join(command)}' should exit 2, got {code}")
            if "authorization" not in stderr.lower() and "authoriz" not in stderr.lower():
                self.errors.append(f"Unauthorized error for {' '.join(command)} lacks auth guidance")

        # Stage 1: Safe local checks (no auth required)
        for cmd in ["guide", "disclaimer"]:
            code, stdout, _ = self.run(cmd)
            if code != 0:
                self.errors.append(f"{cmd} command failed")
            if not stdout.strip():
                self.errors.append(f"{cmd} has no output")

        # Guide must mention authorization
        code, stdout, _ = self.run("guide")
        if "authoriz" not in stdout.lower():
            self.errors.append("guide command does not mention authorization")

        # Disclaimer must exist and mention authorized use
        code, stdout, _ = self.run("disclaimer")
        if "authoriz" not in stdout.lower():
            self.errors.append("disclaimer does not mention authorization")

        # Stage 3: Authorized list-plugins should be non-empty and unique
        code, stdout, _ = self.run("--authorized", "list-plugins", "--tsv")
        if code != 0:
            self.errors.append("--authorized list-plugins failed")
            return
        lines = [line for line in stdout.strip().split("\n") if line.strip()]
        if not lines:
            self.errors.append("list-plugins returned no plugins")
        plugin_ids = [line.split("\t")[0] for line in lines if line.split("\t")[0].strip()]
        if len(plugin_ids) != len(set(plugin_ids)):
            self.errors.append("list-plugins has duplicate plugin IDs")

    def check_help_text(self):
        """Validate help text completeness."""
        print("Checking help text completeness...")

        code, stdout, stderr = self.run("--help")
        if code != 0:
            self.errors.append("--help command failed")
        if not stdout.strip():
            self.errors.append("--help has no output")

        help_text = stdout.lower()
        required_topics = [
            "enum",
            "scan",
            "doctor",
            "guide",
            "list-plugins",
            "report",
            "stage",
            "controls",
            "live-controls",
            "diff",
        ]
        for topic in required_topics:
            if topic not in help_text:
                self.errors.append(f"--help does not mention '{topic}'")

        cli_reference = self.repo_root / "docs" / "cli-reference.md"
        if not cli_reference.exists():
            self.errors.append("cli-reference.md missing while validating help consistency")
        else:
            cli_reference_commands = set()
            for line in cli_reference.read_text(encoding="utf-8").splitlines():
                if line.startswith("## "):
                    for token in re.finditer(r"`([^`]+)`", line):
                        name = token.group(1).strip().lower()
                        if name:
                            cli_reference_commands.add(name)
            for topic in required_topics:
                if topic not in cli_reference_commands:
                    self.errors.append(
                        f"CLI reference does not document required help topic: {topic}"
                    )

        if "usage" not in help_text:
            self.errors.append("--help output does not include usage")
        if self._ANSI_PATTERN.search(stdout):
            self.errors.append("--help output contains ANSI color codes")

    def check_output_formats(self):
        """Validate all documented output formats work."""
        print("Checking output formats...")

        plugin = self.get_smoke_plugin()
        if not plugin:
            self.errors.append("No plugin available for output-format checks")
            return

        for fmt in ["json", "markdown", "sarif", "human"]:
            if fmt == "human":
                args = ["--authorized", "--format", fmt, "enum", "--plugins", plugin]
            else:
                args = [
                    "--authorized",
                    "--quiet",
                    "--format",
                    fmt,
                    "enum",
                    "--plugins",
                    plugin,
                ]
            code, stdout, _ = self.run(*args)
            if code not in [0, 4]:
                self.errors.append(f"Format '{fmt}' enum failed with exit {code}")
                continue
            if not stdout.strip():
                self.errors.append(f"Format '{fmt}' enum produced no output")

            if fmt == "json":
                try:
                    parsed = json.loads(stdout)
                    if not isinstance(parsed, dict):
                        self.errors.append("JSON output is not an object")
                        continue
                    for field in ("schema_version", "run_id", "authorized_use_ack", "mode"):
                        if field not in parsed:
                            self.errors.append(f"JSON output missing required field '{field}'")
                    if parsed.get("schema_version") != "2":
                        self.errors.append(
                            f"JSON output schema version is {parsed.get('schema_version')}, expected 2"
                        )
                except json.JSONDecodeError:
                    self.errors.append("Format 'json' output is not valid JSON")
            elif fmt == "markdown":
                if not stdout.startswith("# StealthyPrivesc report"):
                    self.errors.append("Markdown output does not start with expected header")
                if "Plugin coverage" not in stdout:
                    self.errors.append("Markdown output missing expected Plugin coverage section")
            elif fmt == "sarif":
                try:
                    parsed = json.loads(stdout)
                    if not isinstance(parsed, dict):
                        self.errors.append("SARIF output is not an object")
                        continue
                    if parsed.get("version") != "2.1.0":
                        self.errors.append(f"SARIF version is {parsed.get('version')}, expected 2.1.0")
                    runs = parsed.get("runs")
                    if not isinstance(runs, list) or not runs:
                        self.errors.append("SARIF output missing non-empty runs list")
                        continue
                    first_run = runs[0]
                    if not isinstance(first_run, dict):
                        self.errors.append("SARIF first run is not an object")
                        continue
                    tool = first_run.get("tool", {})
                    if not isinstance(tool, dict):
                        self.errors.append("SARIF first run tool object is invalid")
                        continue
                    if not isinstance(first_run.get("results"), list):
                        self.errors.append("SARIF first run missing results array")
                    if "properties" not in first_run:
                        self.errors.append("SARIF first run missing properties")
                    if "driver" not in tool:
                        self.errors.append("SARIF first run missing tool.driver metadata")
                except json.JSONDecodeError:
                    self.errors.append("Format 'sarif' output is not valid JSON")
            elif fmt == "human":
                if "StealthyPrivesc" not in stdout:
                    self.errors.append("Human output does not include StealthyPrivesc header")
                if stdout.lstrip().startswith("{"):
                    self.errors.append("Human output appears to be JSON")

    def check_error_messages(self):
        """Validate error messages are helpful."""
        print("Checking error messages...")

        code, _, stderr = self.run(
            "--authorized", "--quiet", "enum", "--plugins", "not.a.real.plugin", expected_exit=1
        )
        if code != 1:
            self.errors.append("Unknown plugin should exit 1")
        if "unknown" not in stderr.lower() and "plugin" not in stderr.lower():
            self.errors.append("Unknown plugin error message is not clear")
        if "list-plugins" not in stderr.lower():
            self.errors.append("Unknown plugin error should suggest list-plugins")

        code, _, stderr = self.run(
            "--authorized", "--quiet", "enum", "--allow-techniques", "not-a-real-technique", expected_exit=1
        )
        if code != 1:
            self.errors.append("Unknown allow-techniques should exit 1")
        if "unknown --allow-techniques" not in stderr.lower():
            self.errors.append("Unknown allow-techniques error message is unclear")

        code, _, stderr = self.run(
            "this-cmd-does-not-exist"
        )
        if code not in [1, 2]:
            self.errors.append("Unknown command should fail with parse error")
        lower = stderr.lower()
        if "unrecognized" not in lower and "unknown command" not in lower and "unrecognized command" not in lower:
            self.errors.append("Unknown command error message is unclear")

        code, _, stderr = self.run("--authorized", "--does-not-exist")
        if code not in [1, 2]:
            self.errors.append("Unknown global flag should fail with parse error")
        lower = stderr.lower()
        if "unrecognized" not in lower and "unknown option" not in lower and "unexpected option" not in lower and "unexpected argument" not in lower:
            self.errors.append("Unknown global flag error message is unclear")

        plugin = self.get_smoke_plugin()
        if not plugin:
            self.errors.append("No plugin available for output-format error checks")
            return

        code, _, stderr = self.run(
            "--authorized", "--quiet", "enum", "--plugins", plugin, "--format", "bogus"
        )
        if code not in [1, 2]:
            self.errors.append("Unknown output format should exit with an argument validation error")
        lower = stderr.lower()
        if "invalid value" not in lower and "unknown" not in lower and "possible values" not in lower:
            self.errors.append("Unknown output format error message is unclear")

    def check_output_modes(self):
        """Validate output mode and required argument boundaries."""
        print("Checking output modes...")

        plugin = self.get_smoke_plugin()
        if not plugin:
            self.errors.append("No plugin available for output-mode checks")
            return

        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "findings.seal"
            key_path = Path(tmp) / "findings.key"

            # output=file requires output-path
            code, _, stderr = self.run(
                "--authorized",
                "--quiet",
                "--output",
                "file",
                "enum",
                "--plugins",
                plugin,
                expected_exit=1,
            )
            if "--output=file requires --output-path" not in stderr:
                self.errors.append("output=file missing --output-path check")

            # output=file needs a protected key path unless plaintext mode requested
            code, _, stderr = self.run(
                "--authorized",
                "--quiet",
                "--output",
                "file",
                "--output-path",
                str(report_path),
                "enum",
                "--plugins",
                plugin,
                expected_exit=1,
            )
            if "--key-output-path" not in stderr:
                self.errors.append("output=file missing --key-output-path validation")

            # plaintext mode requires explicit output file
            code, _, stderr = self.run(
                "--authorized",
                "--quiet",
                "--plaintext-file",
                "enum",
                "--plugins",
                plugin,
                expected_exit=1,
            )
            if "--plaintext-file requires --output=file" not in stderr:
                self.errors.append("--plaintext-file requires output=file check missing")

            # --also-markdown requires output=file
            code, _, stderr = self.run(
                "--authorized",
                "--quiet",
                "--also-markdown",
                "enum",
                "--plugins",
                plugin,
                expected_exit=1,
            )
            if "--also-markdown requires --output=file" not in stderr:
                self.errors.append("--also-markdown requires output=file check missing")

            # encrypted output: key sink must differ from output sink
            code, _, stderr = self.run(
                "--authorized",
                "--quiet",
                "--output",
                "file",
                "--output-path",
                str(report_path),
                "--key-output-path",
                str(report_path),
                "enum",
                "--plugins",
                plugin,
                expected_exit=1,
            )
            if "must differ" not in stderr:
                self.errors.append("output=file did not reject identical --output-path and --key-output-path")

            # output=remote requires exfil URL
            code, _, stderr = self.run(
                "--authorized",
                "--quiet",
                "--output",
                "remote",
                "enum",
                "--plugins",
                plugin,
                expected_exit=1,
            )
            if "--output=remote requires --exfil-url" not in stderr:
                self.errors.append("output=remote missing exfil URL validation")

            # output=remote with exfil URL still requires key sink
            code, _, stderr = self.run(
                "--authorized",
                "--quiet",
                "--output",
                "remote",
                "--exfil-url",
                "https://example.invalid",
                "enum",
                "--plugins",
                plugin,
                expected_exit=1,
            )
            if "--key-output-path" not in stderr:
                self.errors.append("output=remote missing key-output-path validation")

            # output=remote succeeds when key sink is present
            remote_key = Path(tmp) / "findings.remote.key"
            code, _, _ = self.run(
                "--authorized",
                "--quiet",
                "--output",
                "remote",
                "--exfil-url",
                "https://example.invalid",
                "--key-output-path",
                str(remote_key),
                "enum",
                "--plugins",
                plugin,
            )
            if code not in [0, 4]:
                self.errors.append(f"--output remote returned unexpected code {code}")
            elif not remote_key.is_file():
                self.errors.append("--output remote did not create key output file")

            # output=file should work end-to-end for valid args
            code, stdout, _ = self.run(
                "--authorized",
                "--quiet",
                "--output",
                "file",
                "--output-path",
                str(report_path),
                "--key-output-path",
                str(key_path),
                "enum",
                "--plugins",
                plugin,
            )
            if code not in [0, 4]:
                self.errors.append(f"--output file returned non-success code {code}")
            elif not report_path.is_file() or not key_path.is_file():
                self.errors.append("--output file did not create report and key files")

    def check_accessibility(self):
        """Validate accessibility features (color control, etc)."""
        print("Checking accessibility...")

        plugin = self.get_smoke_plugin()
        if not plugin:
            self.errors.append("No plugin available for accessibility checks")
            return

        # --no-color must suppress ANSI and remain parseable
        code, stdout, stderr = self.run(
            "--authorized", "--no-color", "--format", "human", "enum", "--plugins", plugin
        )
        if code not in [0, 4]:
            self.errors.append("--no-color enum failed")
        if self._ANSI_PATTERN.search(stdout):
            self.errors.append("--no-color output contains ANSI color codes")

        # NO_COLOR env var should have same effect
        code, stdout, _ = self.run(
            "--authorized",
            "--format",
            "human",
            "enum",
            "--plugins",
            plugin,
            env={"NO_COLOR": "1"},
        )
        if code not in [0, 4]:
            self.errors.append("NO_COLOR enum failed")
        if self._ANSI_PATTERN.search(stdout):
            self.errors.append("NO_COLOR environment variable not respected")

        # --no-color should also apply to JSON
        code, stdout, _ = self.run(
            "--authorized",
            "--no-color",
            "--format",
            "json",
            "enum",
            "--plugins",
            plugin,
        )
        if code not in [0, 4]:
            self.errors.append("--no-color json failed")
        if self._ANSI_PATTERN.search(stdout):
            self.errors.append("--no-color json output contains ANSI color codes")

        # NO_COLOR env var should apply to JSON too
        code, stdout, _ = self.run(
            "--authorized",
            "--format",
            "json",
            "enum",
            "--plugins",
            plugin,
            env={"NO_COLOR": "1"},
        )
        if code not in [0, 4]:
            self.errors.append("NO_COLOR json failed")
        if self._ANSI_PATTERN.search(stdout):
            self.errors.append("NO_COLOR environment variable not respected for json output")

    def check_documentation_references(self):
        """Validate documentation references in help and docs."""
        print("Checking documentation references...")

        docs_dir = self.repo_root / "docs"
        if not docs_dir.exists():
            self.errors.append("docs directory is missing")
            return

        for doc in self._DOC_REQUIRED_PATHS:
            if not (docs_dir / doc).exists():
                self.errors.append(f"Required documentation missing: {doc}")

        for doc_name, required_examples in {
            "user-guide.md": ["guide", "enum", "disclaimer"],
            "operator-runbook.md": ["stage", "enum", "disclaimer"],
            "cli-reference.md": ["list-plugins", "enum", "report"],
            "report-schema.md": ["schema_version", "findings", "attack_paths"],
        }.items():
            doc_path = docs_dir / doc_name
            if not doc_path.exists():
                self.errors.append(f"Missing required doc: {doc_name}")
                continue
            content = doc_path.read_text(encoding="utf-8").lower()
            for example in required_examples:
                if example not in content:
                    self.errors.append(f"{doc_name}: missing example or section keyword '{example}'")

        # validate local markdown links
        for doc in docs_dir.glob("*.md"):
            content = doc.read_text(encoding="utf-8")
            for raw in self._MARKDOWN_LINK_RE.findall(content):
                target = raw.strip()
                if not target or target.startswith(("#", "http://", "https://", "mailto:", "ftp://", "//")):
                    continue
                target = target.split("#", 1)[0].strip()
                if not target or target.startswith("javascript:"):
                    continue
                if target.startswith(("./", "../")):
                    candidate = (doc.parent / target).resolve()
                else:
                    candidate = (docs_dir / target).resolve()
                if not candidate.exists():
                    self.errors.append(f"Broken docs link in {doc.name}: {target}")

        # install script checks done by workflow-free checks here
        install_script = self.repo_root / "scripts" / "install.sh"
        install_ps_script = self.repo_root / "scripts" / "install.ps1"
        if not install_script.exists():
            self.errors.append("scripts/install.sh missing")
        if not install_ps_script.exists():
            self.errors.append("scripts/install.ps1 missing")

    def check_environment_variables(self):
        """Validate documented environment variables work."""
        print("Checking environment variables...")

        plugin = self.get_smoke_plugin() or ""

        # STEALTHY_AUTHORIZED should work
        code, _, _ = self.run(
            "--quiet",
            "--format",
            "json",
            "enum",
            "--plugins",
            plugin,
            env={"STEALTHY_AUTHORIZED": "1"},
        )
        if code not in [0, 4]:
            self.errors.append("STEALTHY_AUTHORIZED environment variable does not work")

        # STEALTHY_KEY_OUTPUT_PATH alias
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "findings.seal"
            key = Path(tmp) / "findings.key"
            code, _, _ = self.run(
                "--authorized",
                "--quiet",
                "--output",
                "file",
                "--output-path",
                str(report),
                "enum",
                "--plugins",
                plugin,
                env={"STEALTHY_KEY_OUTPUT_PATH": str(key)},
            )
            if code not in [0, 4]:
                self.errors.append("STEALTHY_KEY_OUTPUT_PATH did not create a report key path")
            elif not report.is_file() or not key.is_file():
                self.errors.append("STEALTHY_KEY_OUTPUT_PATH output files were not created")

    def check_installation_checks(self):
        """Check install scripts and version metadata consistency."""
        print("Checking installation script and version metadata...")

        install_script = self.repo_root / "scripts" / "install.sh"
        install_ps_script = self.repo_root / "scripts" / "install.ps1"

        if not install_script.exists():
            self.errors.append("scripts/install.sh is missing")
        else:
            content = install_script.read_text(encoding="utf-8").lower()
            for needle in ["attestation verify", "checksum", "$home/.local/bin", "home/.local/bin"]:
                if needle not in content:
                    self.errors.append(f"install.sh is missing expected text: {needle}")

        if not install_ps_script.exists():
            self.errors.append("scripts/install.ps1 is missing")
        else:
            content = install_ps_script.read_text(encoding="utf-8").lower()
            for needle in ["attestation verification", "sha256", "localappdata"]:
                if needle not in content:
                    self.errors.append(f"install.ps1 is missing expected text: {needle}")

        # version and support-policy consistency
        cargo_toml = self.repo_root / "Cargo.toml"
        if not cargo_toml.exists():
            self.errors.append("Cargo.toml missing")
            return

        cargo_version = None
        for line in cargo_toml.read_text(encoding="utf-8").splitlines():
            if line.startswith("version"):
                match = re.search(r'version\s*=\s*"([^"]+)"', line)
                if match:
                    cargo_version = match.group(1)
                    break

        if not cargo_version:
            self.errors.append("Could not parse version from Cargo.toml")
            return

        if not re.match(r"^0\.[0-9]+\.[0-9]+$", cargo_version):
            self.errors.append(f"Version format is nonstandard: {cargo_version}")

        support_policy = self.repo_root / "docs" / "support-policy.md"
        if support_policy.exists():
            policy_content = support_policy.read_text(encoding="utf-8")
            if f"{cargo_version}" not in policy_content and cargo_version.split(".")[0] not in policy_content:
                self.errors.append("Version is not documented in support-policy.md")

    def check_plugin_coverage(self):
        """Validate plugin coverage is as documented."""
        print("Checking plugin coverage...")

        plugins = self.get_plugins()
        if not plugins:
            self.errors.append("No plugins found from list-plugins output")
            return

        raw_lines = self.get_raw_plugin_lines()
        if raw_lines and len(raw_lines) != len(plugins):
            self.errors.append("Plugin TSV row count does not match parsed plugin count")

        malformed_tsv_rows = []
        for line in raw_lines:
            if line.lower().startswith("id\tname\tdescription"):
                continue
            parts = line.split("\t", 2)
            if len(parts) != 3:
                malformed_tsv_rows.append(line)
                continue
            pid, name, description = [part.strip() for part in parts]
            if not pid or not name or not description:
                malformed_tsv_rows.append(line)
        if malformed_tsv_rows:
            self.errors.append(
                "list-plugins --tsv returned malformed rows: "
                + ", ".join(repr(row) for row in malformed_tsv_rows)
            )

        if len(plugins) != len(set(plugins)):
            self.errors.append("list-plugins contains duplicate plugin IDs")

        malformed = [p for p in plugins if not re.match(r"^[a-z0-9_]+\.[a-z0-9_]+$", p)]
        if malformed:
            self.errors.append(f"Malformed plugin IDs: {', '.join(malformed)}")

        if len(plugins) < 1:
            self.errors.append("Plugin list is unexpectedly small")

        doctor = self.get_doctor()
        if doctor:
            os_name = doctor.get("os", {}).get("os", "")
            if os_name == "linux" and not any(p.startswith("linux.") for p in plugins):
                self.errors.append("No linux namespace plugins found on linux build")
            if os_name == "windows" and not any(p.startswith("windows.") for p in plugins):
                self.errors.append("No windows namespace plugins found on windows build")

    def check_exit_codes(self):
        """Validate documented exit code behavior."""
        print("Checking exit codes...")

        # Exit 2 for auth failure
        code, _, _ = self.run("enum", expected_exit=2)
        if code != 2:
            self.errors.append(f"Unauthorized enum should exit 2, got {code}")

        plugin = self.get_smoke_plugin()
        if not plugin:
            self.errors.append("No plugin available for successful enum exit check")
            return

        # Exit 0 for successful enum
        code, _, _ = self.run("--authorized", "--quiet", "enum", "--plugins", plugin)
        if code not in [0, 4]:
            self.errors.append(f"Authorized enum should exit 0 or 4 (--fail-on), got {code}")

    def check_output_schema(self):
        """Validate output schema matches documentation."""
        print("Checking output schema...")

        plugin = self.get_smoke_plugin()
        if not plugin:
            self.errors.append("No plugin available for schema check")
            return

        code, stdout, _ = self.run(
            "--authorized", "--quiet", "--format", "json", "enum", "--plugins", plugin
        )
        if code not in [0, 4]:
            self.errors.append("Could not validate schema (enum failed)")
            return

        try:
            report = json.loads(stdout)
        except json.JSONDecodeError:
            self.errors.append("Could not parse JSON output for schema validation")
            return

        required_fields = [
            "schema_version",
            "run_id",
            "authorized_use_ack",
            "started_at_unix",
            "mode",
            "plugins_run",
            "identity",
            "assessments",
            "findings",
            "coverage",
            "profile",
            "coverage_mode",
            "os",
            "notes",
            "capability_delta",
            "attack_paths",
        ]
        for field in required_fields:
            if field not in report:
                self.errors.append(f"Report missing required field: {field}")

        if report.get("schema_version") != "2":
            self.errors.append(f"Report schema_version expected 2, got {report.get('schema_version')}")

        run_id = report.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            self.errors.append("Report run_id must be a non-empty string")

        profile = report.get("profile")
        if not isinstance(profile, str) or not profile:
            self.errors.append("Report profile must be a non-empty string")

        if not isinstance(report.get("started_at_unix"), int):
            self.errors.append("started_at_unix must be an integer")

        if not isinstance(report.get("authorized_use_ack"), bool):
            self.errors.append("authorized_use_ack must be boolean")

        findings = report.get("findings", [])
        if not isinstance(findings, list):
            self.errors.append("findings must be an array")
            findings = []

        if not isinstance(report.get("assessments", []), list):
            self.errors.append("assessments must be an array")
        elif len(report.get("assessments", [])) != len(findings):
            self.errors.append("assessments length must equal findings length")

        required_finding_fields = [
            "plugin",
            "kind",
            "severity",
            "title",
            "detail",
            "recommendation",
            "noisy",
            "leaves_artifacts",
            "finding_id",
            "mitre_techniques",
            "what_next",
            "next_command",
        ]
        for finding in findings:
            for field in required_finding_fields:
                if field not in finding:
                    self.errors.append(f"Finding missing required field: {field}")
            if (
                "plugin" in finding
                and not isinstance(finding.get("plugin"), str)
                or not finding.get("plugin")
            ):
                self.errors.append("Finding field 'plugin' must be a non-empty string")
            if not isinstance(finding.get("kind"), str):
                self.errors.append("Finding field 'kind' must be a string")
            if not isinstance(finding.get("severity"), str):
                self.errors.append("Finding field 'severity' must be a string")
            if not isinstance(finding.get("title"), str):
                self.errors.append("Finding field 'title' must be a string")
            if not isinstance(finding.get("detail"), str):
                self.errors.append("Finding field 'detail' must be a string")
            if not isinstance(finding.get("recommendation"), str):
                self.errors.append("Finding field 'recommendation' must be a string")
            if not isinstance(finding.get("noisy"), bool):
                self.errors.append("Finding field 'noisy' must be a boolean")
            if not isinstance(finding.get("leaves_artifacts"), bool):
                self.errors.append("Finding field 'leaves_artifacts' must be a boolean")
            if not isinstance(finding.get("finding_id"), str):
                self.errors.append("Finding field 'finding_id' must be a string")
            if not isinstance(finding.get("mitre_techniques"), list):
                self.errors.append("Finding field 'mitre_techniques' must be a list")
            if not isinstance(finding.get("what_next"), str):
                self.errors.append("Finding field 'what_next' must be a string")
            if not isinstance(finding.get("next_command"), str):
                self.errors.append("Finding field 'next_command' must be a string")

        coverage = report.get("coverage", [])
        if not isinstance(coverage, list):
            self.errors.append("coverage must be an array")
        else:
            coverage_ids: List[str] = []
            for entry in coverage:
                if not isinstance(entry, dict):
                    self.errors.append("Coverage entry must be an object")
                    continue
                for field in ["id", "status", "findings", "duration_ms"]:
                    if field not in entry:
                        self.errors.append(f"Coverage entry missing required field: {field}")
                if "id" in entry and (not isinstance(entry.get("id"), str) or not entry.get("id")):
                    self.errors.append("Coverage entry 'id' must be a non-empty string")
                else:
                    coverage_ids.append(entry.get("id"))
                if "status" in entry and not isinstance(entry.get("status"), str):
                    self.errors.append("Coverage entry 'status' must be a string")
                if "findings" in entry and not isinstance(entry.get("findings"), int):
                    self.errors.append("Coverage entry 'findings' must be an integer")
                elif isinstance(entry.get("findings"), int) and entry.get("findings") < 0:
                    self.errors.append("Coverage entry 'findings' must be >= 0")
                if "duration_ms" in entry and not isinstance(entry.get("duration_ms"), int):
                    self.errors.append("Coverage entry 'duration_ms' must be an integer")
                elif isinstance(entry.get("duration_ms"), int) and entry.get("duration_ms") < 0:
                    self.errors.append("Coverage entry 'duration_ms' must be >= 0")
            if len(coverage_ids) != len(set(coverage_ids)):
                self.errors.append("Coverage IDs must be unique")

        plugins_run = report.get("plugins_run")
        if not isinstance(plugins_run, list) or not plugins_run:
            self.errors.append("plugins_run should contain attempted plugin IDs")
        elif not all(isinstance(item, str) and item for item in plugins_run):
            self.errors.append("plugins_run entries must be non-empty strings")
        elif len(plugins_run) != len(set(plugins_run)):
            self.errors.append("plugins_run entries must be unique")

        if not isinstance(report.get("mode"), str):
            self.errors.append("Report mode must be a string")

        if report.get("coverage_mode") not in {"native", "script"}:
            self.errors.append(f"Unexpected coverage_mode: {report.get('coverage_mode')}")

        if report.get("mode") not in {
            "enumerate-only",
            "enumerate+auto-exploit",
            "enumerate+allow-techniques",
            "scan",
        }:
            self.errors.append(f"Unexpected report mode: {report.get('mode')}")

        if not isinstance(report.get("identity"), dict):
            self.errors.append("identity must be an object")
        else:
            if not isinstance(report["identity"].get("username"), str):
                self.errors.append("identity.username must be a string")
            if not isinstance(report["identity"].get("hostname"), str):
                self.errors.append("identity.hostname must be a string")
            if not isinstance(report["identity"].get("is_elevated"), bool):
                self.errors.append("identity.is_elevated must be a boolean")
            if not isinstance(report["identity"].get("elevation_source"), str):
                self.errors.append("identity.elevation_source must be a string")
            for field in ["username", "hostname", "is_elevated", "elevation_source"]:
                if field not in report["identity"]:
                    self.errors.append(f"identity missing field: {field}")

        if not isinstance(report.get("os"), dict):
            self.errors.append("Report os section must be an object")
        else:
            for field in ["family", "os"]:
                if field not in report["os"]:
                    self.errors.append(f"os metadata missing field: {field}")
                elif not isinstance(report["os"].get(field), str) or not report["os"].get(field):
                    self.errors.append(f"os field '{field}' must be a non-empty string")

        for field in ["notes", "capability_delta", "attack_paths", "assessments"]:
            if field not in report:
                self.errors.append(f"Report missing required field: {field}")
            elif not isinstance(report.get(field), list):
                self.errors.append(f"Report field '{field}' must be a list")

    def check_report_consistency(self):
        """Validate cross-section consistency for report payloads."""
        print("Checking report consistency...")

        plugin = self.get_smoke_plugin()
        if not plugin:
            self.errors.append("No plugin available for report consistency checks")
            return

        code, stdout, _ = self.run(
            "--authorized", "--quiet", "--format", "json", "enum", "--plugins", plugin
        )
        if code not in [0, 4]:
            self.errors.append("Could not run enum for report consistency checks")
            return
        try:
            report = json.loads(stdout)
        except json.JSONDecodeError:
            self.errors.append("Could not parse JSON output for report consistency checks")
            return

        self._validate_report_consistency(report, "report consistency")

    def _validate_report_consistency(self, report: dict, context: str) -> None:
        if not isinstance(report, dict):
            self.errors.append(f"{context}: report payload is not an object")
            return

        plugins_run = report.get("plugins_run")
        coverage = report.get("coverage")
        findings = report.get("findings")

        if not isinstance(plugins_run, list):
            self.errors.append(f"{context}: plugins_run must be an array")
            return
        if not isinstance(coverage, list):
            self.errors.append(f"{context}: coverage must be an array")
            return
        if not isinstance(findings, list):
            self.errors.append(f"{context}: findings must be an array")
            return

        if len(plugins_run) != len(coverage):
            self.errors.append(
                f"{context}: coverage length {len(coverage)} does not match plugins_run length {len(plugins_run)}"
            )

        if len(plugins_run) != len(set(plugins_run)):
            self.errors.append(f"{context}: plugins_run contains duplicate entries")

        coverage_ids = []
        for entry in coverage:
            if not isinstance(entry, dict):
                self.errors.append(f"{context}: coverage entry must be an object")
                continue
            plugin_id = entry.get("id")
            if not isinstance(plugin_id, str) or not plugin_id:
                self.errors.append(f"{context}: coverage.id must be a non-empty string")
                continue
            coverage_ids.append(plugin_id)
            if not isinstance(entry.get("findings"), int):
                self.errors.append(
                    f"{context}: coverage findings for {plugin_id} must be an integer"
                )

        if len(coverage_ids) != len(set(coverage_ids)):
            self.errors.append(f"{context}: coverage ids are not unique")
        if set(coverage_ids) != set(plugins_run):
            self.errors.append(f"{context}: coverage ids do not match plugins_run set")

        finding_counts = Counter(
            finding.get("plugin")
            for finding in findings
            if isinstance(finding, dict) and isinstance(finding.get("plugin"), str)
        )

        for plugin_id in plugins_run:
            if not isinstance(plugin_id, str):
                self.errors.append(f"{context}: plugins_run entry '{plugin_id}' is not a string")
                continue
            expected = finding_counts.get(plugin_id, 0)
            coverage_by_id = next(
                (entry for entry in coverage if isinstance(entry, dict) and entry.get("id") == plugin_id),
                None,
            )
            if coverage_by_id is not None and isinstance(coverage_by_id.get("findings"), int):
                if coverage_by_id["findings"] != expected:
                    self.errors.append(
                        f"{context}: coverage count mismatch for {plugin_id}: "
                        f"{coverage_by_id['findings']} vs {expected} findings"
                    )

        for finding in findings:
            if not isinstance(finding, dict):
                self.errors.append(f"{context}: finding entry must be an object")
                continue
            plugin_id = finding.get("plugin")
            if plugin_id not in plugins_run:
                self.errors.append(
                    f"{context}: finding.plugin '{plugin_id}' not present in plugins_run"
                )

    def validate_all(self) -> bool:
        """Run all validations."""
        self.check_installation_readiness()
        self.check_first_user_journey()
        self.check_help_text()
        self.check_output_formats()
        self.check_error_messages()
        self.check_output_modes()
        self.check_accessibility()
        self.check_documentation_references()
        self.check_environment_variables()
        self.check_installation_checks()
        self.check_plugin_coverage()
        self.check_report_consistency()
        self.check_exit_codes()
        self.check_output_schema()

        print("\n" + "=" * 60)
        print("User Readiness Validation Report")
        print("=" * 60)

        if self.errors:
            print(f"\n❌ ERRORS ({len(self.errors)}):")
            for error in self.errors:
                print(f"  • {error}")

        if not self.errors:
            print("\n✅ All user readiness checks passed")
            return True
        else:
            print(f"\n❌ User readiness validation failed with {len(self.errors)} error(s)")
            return False


def main():
    import argparse

    parser = argparse.ArgumentParser(description="User Readiness Validation Suite")
    parser.add_argument("binary", help="Path to stealthy binary")
    parser.add_argument("--repo-root", default=".", help="Repository root directory")
    parser.add_argument(
        "--strict-warnings",
        action="store_true",
        help="Legacy compatibility switch; currently retained for CI scripts (no warning channel is emitted)",
    )
    args = parser.parse_args()

    validator = UserReadinessValidator(args.binary, args.repo_root)
    success = validator.validate_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
