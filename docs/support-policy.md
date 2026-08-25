# Support policy

StealthyPrivesc is pre-1.0 software. Use a tagged, attested release for an
engagement; the `main` branch is development-only and may contain changes that
have not completed the tag release gate.

## Versioning before 1.0

Tagged releases use semantic-version-shaped `0.MINOR.PATCH` versions:

- `PATCH` releases fix defects and security issues without intentionally
  changing documented CLI or report-schema behavior.
- `MINOR` releases may add capabilities and may make a documented breaking
  change when the release notes include the migration path.
- Pre-release tags such as `-rc.1` are evaluation builds and are unsupported
  for production engagements.

Because the major version is zero, operators must still review release notes
before every upgrade. A tag alone does not expand an engagement's ROE.

## Supported release window and EOL

The current stable tagged release is fully supported. When a new minor release
is published, the immediately preceding minor remains eligible for critical
and high-severity security fixes for 90 days. Older minors and every untagged
commit are end-of-life.

Patch releases do not extend an older minor's 90-day window. Once a minor is
EOL, maintainers may still accept a report, but the supported remediation is an
upgrade to a current release.

## Supported release artifacts and platforms

The release workflow publishes and smoke-tests these full delivery kits:

| Asset | Runtime contract |
| --- | --- |
| `stealthy-linux-x86_64.tar.gz` | Linux x86-64 with a GNU-compatible userspace |
| `stealthy-linux-aarch64.tar.gz` | Linux aarch64 with a GNU-compatible userspace |
| `stealthy-windows-x86_64.zip` | 64-bit Windows using the MSVC build |

Each kit contains the native binary, platform fallback scripts, selected
operator documentation, `RELEASE-MANIFEST.json`, and an internal `SHA256SUMS`.
The release also publishes SPDX JSON SBOMs, a top-level checksum manifest,
`RELEASE-EVIDENCE.json`, and GitHub artifact attestations.

The release record must also include the completed
[production-readiness acceptance criteria](production-readiness.md), platform
smoke-test results, and any explicitly skipped checks.

Other source-build targets, including Windows GNU and Linux musl, are
best-effort developer targets unless a future release matrix lists them.
Script fallbacks are supported as explicitly reduced, enumerate-only coverage;
they do not promise native-plugin parity.

## Report-schema compatibility

Schema `2` is the current enumeration-report contract. Within a supported
minor series, patch releases may add optional fields but will not remove or
reinterpret existing fields. Consumers must ignore unknown fields and tolerate
documented optional fields.

A removal, incompatible type change, or semantic reinterpretation requires a
schema-version change and migration notes. `finding_id` stability depends on
the stable `plugin`, `object`, and `condition` identity tuple; presentation
changes to `title` are not identity changes. Script reports must retain their
`coverage_mode`, `capability_delta`, `coverage`, and notes through ingestion.

Compatibility guarantees apply only to schemas produced by supported tagged
releases. Keep the original sealed or script report when normalizing evidence.

## Security-fix policy

Report vulnerabilities privately as described in [SECURITY.md](../SECURITY.md).
Maintainers target acknowledgment within five business days and severity
triage within ten business days. After confirmation, the target remediation
windows are:

| Severity | Target for a supported release |
| --- | --- |
| Critical | Fix or documented mitigation within 7 calendar days |
| High | Fix or documented mitigation within 30 calendar days |
| Medium / Low | Next practical patch or minor release |

These are response targets, not guarantees; coordinated disclosure may change
the public release date. Critical and high fixes are considered for the
previous minor only while it remains inside its 90-day support window.
