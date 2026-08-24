#!/usr/bin/env python3
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parents[2]
REQUIRED_SECTIONS = {
    Path("docs/design.md"): [
        "# StealthyPrivesc Design",
        "## Overview",
        "## Goals & Non-Goals",
        "## Key Decisions",
        "## Current architecture",
        "## Security & Privacy Considerations",
        "## Risks",
        "## Maintenance and delivery plan",
    ],
    Path("docs/capabilities.md"): [
        "# StealthyPrivesc Capabilities",
        "## Capability status",
        "## Initial MVP capabilities",
        "## Implemented command surface",
        "## Artifact workflow",
        "## Security, privacy, and operational controls",
        "## Explicitly out of scope for v1",
    ],
    Path("docs/first-user-journey.md"): [
        "# First-User Journey",
        "## Goals",
        "## Entry points",
        "## Journey stages",
        "## Non-interactive contract",
        "## CI contract",
        "## Safety boundary",
    ],
}


def main():
    failures = []
    markdown = sorted(path for path in ROOT.glob("*.md") if not path.name.startswith("."))
    markdown += sorted((ROOT / "docs").rglob("*.md"))
    link_pattern = re.compile(r"!?\[[^]]*\]\(([^)]+)\)")
    action_pattern = re.compile(r"^\s*uses:\s*[^@]+@([^\s#]+)")

    if not markdown:
        failures.append("no Markdown documentation found")
    for path in markdown:
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT)
        if not text.strip():
            failures.append(f"{relative}: document is empty")
        if not re.search(r"^#\s+\S+", text, re.MULTILINE):
            failures.append(f"{relative}: missing top-level Markdown heading")
        if text.count("```") % 2:
            failures.append(f"{relative}: unbalanced fenced code block")
        if "\t" in text:
            failures.append(f"{relative}: tab characters are not allowed")
        for line_number, line in enumerate(text.splitlines(), 1):
            trailing = line[len(line.rstrip(" \t")) :]
            if trailing and trailing != "  ":
                failures.append(f"{relative}:{line_number}: trailing whitespace")
        for raw_target in link_pattern.findall(text):
            target = raw_target.strip().split()[0].strip("<>")
            parsed = urlparse(target)
            if parsed.scheme or target.startswith("#") or not parsed.path:
                continue
            candidate = (path.parent / unquote(parsed.path)).resolve()
            try:
                candidate.relative_to(ROOT)
            except ValueError:
                failures.append(f"{relative}: link escapes repository: {target}")
                continue
            if not candidate.exists():
                failures.append(f"{relative}: missing local link target: {target}")

    for relative, sections in REQUIRED_SECTIONS.items():
        path = ROOT / relative
        if not path.exists():
            failures.append(f"{relative}: required document is missing")
            continue
        text = path.read_text(encoding="utf-8")
        for section in sections:
            if section not in text:
                failures.append(f"{relative}: required section missing: {section}")

    capabilities = (ROOT / "docs/capabilities.md").read_text(encoding="utf-8")
    for required_link in (
        "[`docs/design.md`](design.md)",
        "[`docs/first-user-journey.md`](first-user-journey.md)",
    ):
        if required_link not in capabilities:
            failures.append(f"docs/capabilities.md: missing required link {required_link}")

    action_count = 0
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = action_pattern.match(line)
            if not match:
                continue
            action_count += 1
            if not re.fullmatch(r"[0-9a-f]{40}", match.group(1)):
                failures.append(
                    f"{path.relative_to(ROOT)}:{line_number}: action is not pinned to a commit"
                )
    if action_count == 0:
        failures.append("no GitHub Actions references found")

    if failures:
        print(*failures, sep="\n")
        return 1
    print(f"Validated {len(markdown)} Markdown files and {action_count} pinned actions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
