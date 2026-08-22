# Operator runbook modules

Use these task-based pages to enter the operator workflow quickly. They are
curated navigation and decision guides; the [full operator runbook](../operator-runbook.md)
remains the detailed copy-paste reference for every transport and platform
variant.

## Choose a module

| Need | Start here | Detailed reference |
| --- | --- | --- |
| Confirm scope, identity, and stop conditions | [Pre-flight](preflight.md) | [Runbook sections 0–0.3](../operator-runbook.md#0-pre-flight-do-this-every-time) |
| Build, verify, and package an artifact | [Build and package](build-and-package.md) | [Runbook section 1](../operator-runbook.md#1-build-matrix-operator-workstation) |
| Deploy and run on Linux or Windows | [Target operations](targets.md) | [Runbook sections 2–5](../operator-runbook.md#2-deploy-to-a-linux-target) |
| Export, review, clean up, or recover | [Evidence and recovery](evidence-and-recovery.md) | [Runbook sections 6.7–11](../operator-runbook.md#67-automation-and-ci-contract) |

## Standard sequence

1. Complete [Pre-flight](preflight.md) and confirm the ROE.
2. Use [Build and package](build-and-package.md) to select one reviewed
   artifact and record its provenance and hash.
3. Follow [Target operations](targets.md) for the smallest approved deployment
   and enumerate-only baseline.
4. Use [Evidence and recovery](evidence-and-recovery.md) to validate output,
   handle keys, close the host, or recover from interruption.

The authorization flag is an acknowledgment, not written permission. If a
module conflicts with the ROE, stop and follow the ROE.
