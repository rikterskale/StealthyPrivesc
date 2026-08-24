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
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple, Optional


class UserReadinessValidator:
    def __init__(self, binary: str, repo_root: str = "."):
        self.binary = binary
        self.repo_root = Path(repo_root)
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def run(self, *args, expected_exit: int = 0, capture_output: bool = True) -> Tuple[int, str, str]:
        """Run the binary and return (exit_code, stdout, stderr)."""
        try:
            result = subprocess.run(
                [self.binary, *args],
                capture_output=capture_output,
                text=True,
                timeout=30,
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

    def check_installation_readiness(self):
        """Validate installation and verification procedures."""
        print("Checking installation readiness...")

        # Version command must work
        code, stdout, stderr = self.run("--version")
        if code != 0:
            self.errors.append("--version command failed")
        elif not re.match(r"^stealthy \d+\.\d+\.\d+", stdout.strip()):
            self.errors.append(f"Invalid version format: {stdout.strip()}")

        # Doctor must report healthy
        code, stdout, stderr = self.run("doctor", "--json")
        if code != 0:
            self.errors.append("doctor command failed")
        else:
            try:
                doctor = json.loads(stdout)
                if not doctor.get("healthy"):
                    self.errors.append("doctor reports unhealthy system")
                if doctor.get("schema_version") != "1":
                    self.errors.append(f"doctor schema version is {doctor.get('schema_version')}, expected 1")
            except json.JSONDecodeError:
                self.errors.append("doctor --json output is not valid JSON")

    def check_first_user_journey(self):
        """Validate the first-user journey contract."""
        print("Checking first-user journey contract...")

        # Stage 1: Safe local checks (no auth required)
        commands = ["guide", "disclaimer"]
        for cmd in commands:
            code, stdout, stderr = self.run(cmd)
            if code != 0:
                self.errors.append(f"{cmd} command failed")
            if not stdout.strip():
                self.warnings.append(f"{cmd} has no output")

        # Guide must mention authorization
        code, stdout, stderr = self.run("guide")
        if "authoriz" not in stdout.lower():
            self.warnings.append("guide command does not mention authorization")

        # Disclaimer must exist and mention authorized use
        code, stdout, stderr = self.run("disclaimer")
        if "authoriz" not in stdout.lower():
            self.errors.append("disclaimer does not mention authorization")

        # Stage 2: Unauthorized enum must fail with exit code 2
        code, stdout, stderr = self.run("enum", expected_exit=2)
        if code != 2:
            self.errors.append(f"Unauthorized enum should exit 2, got {code}")
        if "authorization" not in stderr.lower() and "authorized" not in stderr.lower():
            self.warnings.append("Authorization error message not clear")

        # Stage 3: Authorized list-plugins must work
        code, stdout, stderr = self.run("--authorized", "list-plugins", "--tsv")
        if code != 0:
            self.errors.append("--authorized list-plugins failed")
        else:
            lines = stdout.strip().split("\n")
            if len(lines) < 2:  # header + at least one plugin
                self.errors.append("list-plugins returned no plugins")
            plugin_ids = [line.split("\t")[0] for line in lines[1:]]
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

        # Check for key command documentation
        help_text = stdout.lower()
        required_topics = ["enum", "doctor", "guide", "list-plugins", "report", "stage"]
        for topic in required_topics:
            if topic not in help_text:
                self.warnings.append(f"--help does not mention '{topic}'")

    def check_output_formats(self):
        """Validate all documented output formats work."""
        print("Checking output formats...")

        formats = ["json", "markdown", "sarif", "human"]
        for fmt in formats:
            code, stdout, stderr = self.run(
                "--authorized", "--quiet", "--format", fmt, "enum",
                "--plugins", "linux.kernel_cve"
            )
            if code not in [0, 4]:  # 4 is --fail-on exit code
                self.errors.append(f"Format '{fmt}' enum failed with exit {code}")
            else:
                if fmt == "json":
                    try:
                        parsed = json.loads(stdout)
                        if parsed.get("schema_version") != "2":
                            self.errors.append(f"JSON schema version is {parsed.get('schema_version')}, expected 2")
                    except json.JSONDecodeError:
                        self.errors.append(f"Format '{fmt}' output is not valid JSON")
                elif fmt == "markdown":
                    if not stdout.startswith("# StealthyPrivesc"):
                        self.warnings.append("Markdown output does not start with expected header")
                elif fmt == "sarif":
                    try:
                        parsed = json.loads(stdout)
                        if parsed.get("version") != "2.1.0":
                            self.errors.append(f"SARIF version is {parsed.get('version')}, expected 2.1.0")
                    except json.JSONDecodeError:
                        self.errors.append(f"Format '{fmt}' output is not valid JSON")

    def check_error_messages(self):
        """Validate error messages are helpful."""
        print("Checking error messages...")

        # Unknown plugin
        code, stdout, stderr = self.run(
            "--authorized", "--quiet", "enum",
            "--plugins", "not.a.real.plugin",
            expected_exit=1
        )
        if code != 1:
            self.errors.append("Unknown plugin should exit 1")
        if "unknown" not in stderr.lower() and "plugin" not in stderr.lower():
            self.warnings.append("Unknown plugin error message is not clear")
        if "list-plugins" not in stderr.lower():
            self.warnings.append("Unknown plugin error should suggest list-plugins")

        # Missing required flag
        code, stdout, stderr = self.run("enum", expected_exit=2)
        if "authoriz" not in stderr.lower():
            self.warnings.append("Missing auth error message should be clear")

    def check_accessibility(self):
        """Validate accessibility features (color control, etc)."""
        print("Checking accessibility...")

        # --no-color must work
        code, stdout, stderr = self.run(
            "--authorized", "--no-color", "--quiet", "enum",
            "--plugins", "linux.kernel_cve"
        )
        if code not in [0, 4]:
            self.errors.append("--no-color enum failed")

        # Verify no ANSI codes in no-color output
        ansi_pattern = re.compile(r"\x1b\[[0-9;]*m")
        if ansi_pattern.search(stdout):
            self.errors.append("--no-color output contains ANSI color codes")

        # NO_COLOR env var should work
        env = {"NO_COLOR": "1"}
        result = subprocess.run(
            [self.binary, "--authorized", "--quiet", "enum", "--plugins", "linux.kernel_cve"],
            capture_output=True,
            text=True,
            timeout=30,
            env={**subprocess.os.environ, **env},
        )
        if ansi_pattern.search(result.stdout):
            self.warnings.append("NO_COLOR environment variable not respected")

    def check_documentation_references(self):
        """Validate documentation references in help and output."""
        print("Checking documentation references...")

        code, stdout, stderr = self.run("--help")
        help_text = stdout.lower()

        # Check for documentation references
        docs_dir = self.repo_root / "docs"
        if docs_dir.exists():
            required_docs = [
                "cli-reference.md",
                "user-guide.md",
                "operator-runbook.md",
                "support-policy.md",
            ]
            for doc in required_docs:
                if not (docs_dir / doc).exists():
                    self.errors.append(f"Required documentation missing: {doc}")

    def check_environment_variables(self):
        """Validate documented environment variables work."""
        print("Checking environment variables...")

        # STEALTHY_AUTHORIZED should work
        result = subprocess.run(
            [self.binary, "--quiet", "--format", "json", "enum", "--plugins", "linux.kernel_cve"],
            capture_output=True,
            text=True,
            timeout=30,
            env={**subprocess.os.environ, "STEALTHY_AUTHORIZED": "1"},
        )
        if result.returncode not in [0, 4]:
            self.errors.append("STEALTHY_AUTHORIZED environment variable does not work")

    def check_plugin_coverage(self):
        """Validate plugin coverage is as documented."""
        print("Checking plugin coverage...")

        code, stdout, stderr = self.run("--authorized", "list-plugins", "--json")
        if code == 0:
            try:
                data = json.loads(stdout)
                plugins = data if isinstance(data, list) else data.get("plugins", [])
                if not plugins:
                    self.warnings.append("No plugins available")

                # Check platform specificity
                linux_plugins = [p for p in plugins if isinstance(p, dict) and p.get("id", "").startswith("linux.")]
                windows_plugins = [p for p in plugins if isinstance(p, dict) and p.get("id", "").startswith("windows.")]

                if not linux_plugins:
                    self.warnings.append("No Linux plugins found")
                if not windows_plugins:
                    self.warnings.append("No Windows plugins found")
            except (json.JSONDecodeError, KeyError):
                self.warnings.append("Could not parse plugin list JSON")
        else:
            # Try TSV format
            code, stdout, stderr = self.run("--authorized", "list-plugins", "--tsv")
            if code == 0 and stdout.strip():
                lines = stdout.strip().split("\n")[1:]  # skip header
                if len(lines) < 10:
                    self.warnings.append(f"Only {len(lines)} plugins listed, expected more coverage")

    def check_exit_codes(self):
        """Validate documented exit code behavior."""
        print("Checking exit codes...")

        # Exit 2 for auth failure
        code, _, _ = self.run("enum", expected_exit=2)
        if code != 2:
            self.errors.append(f"Unauthorized enum should exit 2, got {code}")

        # Exit 0 for successful enum
        code, _, _ = self.run("--authorized", "--quiet", "enum", "--plugins", "linux.kernel_cve")
        if code not in [0, 4]:
            self.errors.append(f"Authorized enum should exit 0 or 4 (--fail-on), got {code}")

    def check_output_schema(self):
        """Validate output schema matches documentation."""
        print("Checking output schema...")

        code, stdout, stderr = self.run(
            "--authorized", "--quiet", "--format", "json", "enum",
            "--plugins", "linux.kernel_cve"
        )
        if code not in [0, 4]:
            self.warnings.append("Could not validate schema (enum failed)")
            return

        try:
            report = json.loads(stdout)
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
            ]
            for field in required_fields:
                if field not in report:
                    self.errors.append(f"Report missing required field: {field}")

            # Validate finding schema
            if report.get("findings"):
                sample_finding = report["findings"][0]
                finding_fields = ["plugin", "kind", "severity", "title", "detail", "recommendation"]
                for field in finding_fields:
                    if field not in sample_finding:
                        self.errors.append(f"Finding missing required field: {field}")
        except json.JSONDecodeError:
            self.errors.append("Could not parse JSON output for schema validation")

    def validate_all(self) -> bool:
        """Run all validations."""
        self.check_installation_readiness()
        self.check_first_user_journey()
        self.check_help_text()
        self.check_output_formats()
        self.check_error_messages()
        self.check_accessibility()
        self.check_documentation_references()
        self.check_environment_variables()
        self.check_plugin_coverage()
        self.check_exit_codes()
        self.check_output_schema()

        print("\n" + "=" * 60)
        print("User Readiness Validation Report")
        print("=" * 60)

        if self.errors:
            print(f"\n❌ ERRORS ({len(self.errors)}):")
            for error in self.errors:
                print(f"  • {error}")

        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"  • {warning}")

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
    args = parser.parse_args()

    validator = UserReadinessValidator(args.binary, args.repo_root)
    success = validator.validate_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
