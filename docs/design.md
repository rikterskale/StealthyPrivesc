# Next-Gen Stealthy Privilege Escalation Tool

## Overview

StealthyPrivesc is a production-oriented enumeration framework for authorized assessments. It prioritizes living-off-the-land execution, quiet discovery, modular checks, and strict exploitation policy over noisy auto-pwn features.

## Goals & Non-Goals

### Goals

- Cross-platform core (Windows + Linux) with script fallbacks
- Quiet enumeration before any optional action
- Encrypted in-memory results by default
- Clear operator CLI and risk documentation
- Compilable Rust core with selectable plugins

### Non-Goals

- Fully automated exploitation of every finding
- Kernel exploit packs
- Silent C2 beaconing without operator configuration
- Extreme obfuscation that destroys maintainability

## Key Decisions

1. **Rust core** — smaller static releases and low-level control versus Go
2. **Enumerate-first** — recommendations are the default product
3. **Opt-in auto-exploit** — reversible probes only; kernel blocked
4. **Authorization gate** — CLI refuses to run without explicit ack
5. **Script fallbacks** — survive AppLocker/WDAC and missing binary execution
6. **Readable code** — stealth via behavior and LOLBIN use, not unreadable blobs

## Proposed Design

See [`architecture.md`](architecture.md) for module layout.

Primary binary: `stealthy`

Command surface:

- `stealthy disclaimer`
- `stealthy list-plugins`
- `stealthy enum [--auto-exploit] [--plugins ...] [--skip ...]`

Global flags cover quiet/verbose, delay, and output mode (`memory` / `file` / `remote`).

## Security & Privacy Considerations

- Authorization acknowledgment required
- No disk logs by default
- Sealed exports use ephemeral ChaCha20-Poly1305 keys zeroized on drop
- Findings that imply secret material avoid dumping raw secret bytes by default
- Operators must handle evidence under engagement ROE

## Risks

- Some checks (`sudo -l`, write probes) still generate telemetry
- False confidence if shallow scans miss deep filesystem issues
- Misuse outside authorization is a legal risk — mitigated by disclaimer gate and docs, not by technical impossibility

## PR Plan

1. Scaffold Cargo workspace + CLI authorization gate
2. Core store/engine/identity/os modules
3. Linux plugin set (10 checks)
4. Windows plugin set (8 checks)
5. Script fallbacks + operator docs
6. CI: rustfmt/clippy/test + markdown contract
