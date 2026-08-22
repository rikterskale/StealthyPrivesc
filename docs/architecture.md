# Architecture

## Overview

StealthyPrivesc is a small Rust core plus independently selectable plugins, with pure-script fallbacks when a custom binary cannot execute under application control.

For the end-to-end visual flow, see the [Architecture Diagram](architecture-diagram.md).

## Data flow

1. CLI parses flags and applies the authorization boundary
2. Safe local commands (`guide`, `doctor`, `disclaimer`, `report`, `diff`) run without host enumeration
3. Core detects OS and enumerates identity with minimal process spawning
4. Plugin IDs are validated, then the registry is filtered by OS, `--plugins`, and `--skip`
5. Each plugin returns `Finding` values; core adds provenance, assessments, and coverage timing
6. Findings are stored in an encrypted in-memory store
7. Output mode emits a human report and optionally JSON, Markdown, SARIF, a sealed blob, or remote instructions

## Core modules

| Module | Responsibility |
| --- | --- |
| `core::os` | OS family / version hints via files and constants |
| `core::identity` | UID/user/groups without `id` where possible |
| `core::plugin` | Plugin trait and selection |
| `core::store` | ChaCha20-Poly1305 sealed export + zeroizing key |
| `core::evasion` | Low-and-slow delays and operator notes |
| `core::output` | memory / file / remote emission |
| `core::engine` | Orchestration |
| `exploit` | Policy gate for reversible probes only |

## Plugin contract

Each plugin implements:

- `id`, `name`, `description`, `platforms`
- `run(ctx) -> Vec<Finding>`

Plugins should prefer direct filesystem/registry reads. When a noisy helper is required, findings must set `noisy: true`.

## Script fallbacks

Under AppLocker/WDAC or missing binary execution:

- Linux: `scripts/linux/enum.sh`, `scripts/linux/enum.py`
- Windows: `scripts/windows/enum.ps1`, `enum.js`, MSBuild host stub

These mirror the highest-value checks without shipping a custom `.exe`.
