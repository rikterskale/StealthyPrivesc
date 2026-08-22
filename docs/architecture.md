# Architecture

## Overview

StealthyPrivesc is a small Rust core plus independently selectable plugins, with pure-script fallbacks when a custom binary cannot execute under application control.

## Data flow

1. CLI parses flags and requires `--i-understand-authorized-use-only`
2. Core detects OS and enumerates identity with minimal process spawning
3. Plugin registry is filtered by OS, `--plugins`, and `--skip`
4. Each plugin returns `Finding` values; core stores them in an encrypted in-memory store
5. Output mode emits a human report and optionally a sealed blob / remote instructions

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
