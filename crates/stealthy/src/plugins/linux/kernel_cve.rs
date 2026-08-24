use anyhow::Result;
use std::cmp::Ordering;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};
use crate::exploit;

pub struct KernelCvePlugin;

const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl Ord for KernelVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch))
    }
}

impl PartialOrd for KernelVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct OsRelease {
    id: String,
    version_id: String,
    pretty_name: String,
}

#[derive(Debug)]
struct KernelHint {
    cve: &'static str,
    range: &'static str,
    note: &'static str,
}

impl Plugin for KernelCvePlugin {
    fn id(&self) -> &'static str {
        "linux.kernel_cve"
    }
    fn name(&self) -> &'static str {
        "Kernel version vs known LPE CVEs (informational)"
    }
    fn description(&self) -> &'static str {
        "Parse kernel and distro package evidence for recommend-only historical CVE hints"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let release = read_bounded("/proc/sys/kernel/osrelease", 4096)
            .or_else(|| read_bounded("/proc/version", 4096))
            .unwrap_or_else(|| "unknown".into())
            .lines()
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string();
        let parsed = parse_kernel_version(&release);
        let os_release = read_bounded("/etc/os-release", 64 * 1024)
            .map(|text| parse_os_release(&text))
            .unwrap_or_default();
        let version_signature = read_bounded("/proc/version_signature", 16 * 1024)
            .map(|value| value.trim().to_string());
        let package_version = (!ctx.cancelled())
            .then(|| read_kernel_package_version(&release, &ctx.cancel))
            .flatten();

        findings.push(Finding {
            plugin: self.id().into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Info,
            title: "Kernel and distribution evidence".into(),
            detail: evidence_detail(
                &release,
                parsed,
                &os_release,
                package_version.as_deref(),
                version_signature.as_deref(),
            ),
            recommendation: "Validate possible exposure against the distribution security tracker and exact package changelog. No exploit is executed.".into(),
            noisy: false,
            leaves_artifacts: false,
            object: release.clone(),
            condition: "kernel-distro-package-evidence".into(),
            technique_id: "kernel-version-assessment".into(),
            ..Default::default()
        });

        if let Some(version) = parsed {
            for hint in kernel_hints(version) {
                if ctx.cancelled() {
                    break;
                }
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Recommendation,
                    severity: Severity::Medium,
                    title: format!("Heuristic kernel review: {}", hint.cve),
                    detail: format!(
                        "{}; parsed_kernel={}.{}.{} upstream_range={} distro={} distro_version={} package_version={} uncertainty=distribution_backports_and_vendor_patch_levels_can_invalidate_this_hint",
                        hint.note,
                        version.major,
                        version.minor,
                        version.patch,
                        hint.range,
                        value_or_unknown(&os_release.id),
                        value_or_unknown(&os_release.version_id),
                        package_version.as_deref().unwrap_or("unavailable")
                    ),
                    recommendation: format!(
                        "Treat {} as a triage hint only. Confirm fixed-package status in the {} security tracker before any ROE-approved testing.",
                        hint.cve,
                        value_or_unknown(&os_release.id)
                    ),
                    noisy: false,
                    leaves_artifacts: false,
                    object: format!("kernel:{release}:{}", hint.cve),
                    condition: "heuristic-cve-range-match".into(),
                    mitre_techniques: vec!["T1068".into()],
                    technique_id: "kernel-exploit".into(),
                    ..Default::default()
                });
            }
        } else if !ctx.cancelled() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Recommendation,
                severity: Severity::Info,
                title: "Kernel release could not be parsed".into(),
                detail: format!("release={release}; no substring CVE matching was attempted"),
                recommendation:
                    "Collect an exact kernel package version and consult the distribution tracker."
                        .into(),
                noisy: false,
                leaves_artifacts: false,
                object: release.clone(),
                condition: "kernel-version-unparseable".into(),
                ..Default::default()
            });
        }

        let kernel = exploit::TechniqueFamily::KernelExploit;
        let allowed = ctx.allow_techniques.allows(kernel);
        if !ctx.cancelled() && (allowed || ctx.auto_exploit) {
            findings.push(exploit::technique_status(self.id(), kernel, allowed));
        }

        Ok(findings)
    }
}

fn read_bounded(path: impl AsRef<Path>, max_bytes: u64) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.by_ref().take(max_bytes).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn parse_kernel_version(release: &str) -> Option<KernelVersion> {
    let numeric = release.split_whitespace().find(|token| {
        token
            .chars()
            .next()
            .is_some_and(|value| value.is_ascii_digit())
    })?;
    let mut parts = numeric.split(|character: char| !character.is_ascii_digit());
    Some(KernelVersion {
        major: parts.next()?.parse().ok()?,
        minor: parts.next()?.parse().ok()?,
        patch: parts
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
    })
}

fn parse_os_release(text: &str) -> OsRelease {
    let mut release = OsRelease::default();
    for line in text.lines() {
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let value = raw_value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .replace("\\\"", "\"");
        match key.trim() {
            "ID" => release.id = value,
            "VERSION_ID" => release.version_id = value,
            "PRETTY_NAME" => release.pretty_name = value,
            _ => {}
        }
    }
    release
}

fn read_kernel_package_version(kernel_release: &str, cancel: &AtomicBool) -> Option<String> {
    let status = read_bounded("/var/lib/dpkg/status", MAX_METADATA_BYTES)?;
    parse_dpkg_kernel_package(&status, kernel_release, Some(cancel))
}

fn parse_dpkg_kernel_package(
    status: &str,
    kernel_release: &str,
    cancel: Option<&AtomicBool>,
) -> Option<String> {
    for paragraph in status.split("\n\n") {
        if cancel.is_some_and(|flag| flag.load(AtomicOrdering::SeqCst)) {
            return None;
        }
        let mut package = None;
        let mut version = None;
        for line in paragraph.lines() {
            if let Some(value) = line.strip_prefix("Package: ") {
                package = Some(value.trim());
            } else if let Some(value) = line.strip_prefix("Version: ") {
                version = Some(value.trim());
            }
        }
        let Some(package) = package else {
            continue;
        };
        if package.starts_with("linux-image-") && package.contains(kernel_release) {
            return version.map(|value| format!("{package}={value}"));
        }
    }
    None
}

fn kernel_hints(version: KernelVersion) -> Vec<KernelHint> {
    let mut hints = Vec::new();
    let dirty_cow_min = KernelVersion {
        major: 2,
        minor: 6,
        patch: 22,
    };
    let dirty_cow_mainline_fix = KernelVersion {
        major: 4,
        minor: 8,
        patch: 3,
    };
    if version >= dirty_cow_min && version < dirty_cow_mainline_fix {
        hints.push(KernelHint {
            cve: "CVE-2016-5195",
            range: "upstream_mainline_2.6.22_to_4.8.2",
            note: "Parsed release falls in the broad upstream Dirty COW era",
        });
    }
    if dirty_pipe_candidate(version) {
        hints.push(KernelHint {
            cve: "CVE-2022-0847",
            range: "upstream_5.8_to_branch_specific_fixes",
            note: "Parsed release falls in an upstream Dirty Pipe candidate branch",
        });
    }
    hints
}

fn dirty_pipe_candidate(version: KernelVersion) -> bool {
    if version.major != 5 {
        return false;
    }
    match version.minor {
        8..=9 => true,
        10 => version.patch < 102,
        11..=14 => true,
        15 => version.patch < 25,
        16 => version.patch < 11,
        _ => false,
    }
}

fn evidence_detail(
    release: &str,
    parsed: Option<KernelVersion>,
    os_release: &OsRelease,
    package_version: Option<&str>,
    version_signature: Option<&str>,
) -> String {
    let parsed = parsed
        .map(|version| format!("{}.{}.{}", version.major, version.minor, version.patch))
        .unwrap_or_else(|| "unavailable".into());
    format!(
        "kernel_release={release} parsed_kernel={parsed} distro={} distro_version={} distro_name={} package_version={} version_signature={}",
        value_or_unknown(&os_release.id),
        value_or_unknown(&os_release.version_id),
        value_or_unknown(&os_release.pretty_name),
        package_version.unwrap_or("unavailable"),
        version_signature.unwrap_or("unavailable")
    )
}

fn value_or_unknown(value: &str) -> &str {
    if value.is_empty() {
        "unknown"
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::{
        dirty_pipe_candidate, kernel_hints, parse_dpkg_kernel_package, parse_kernel_version,
        parse_os_release, KernelVersion,
    };

    #[test]
    fn parses_distribution_suffixed_kernel_release() {
        assert_eq!(
            parse_kernel_version("5.15.0-107-generic"),
            Some(KernelVersion {
                major: 5,
                minor: 15,
                patch: 0
            })
        );
        assert_eq!(
            parse_kernel_version("Linux version 6.8.12-arch1-1"),
            Some(KernelVersion {
                major: 6,
                minor: 8,
                patch: 12
            })
        );
    }

    #[test]
    fn golden_distro_and_package_metadata_are_parsed() {
        let os = parse_os_release(include_str!(
            "../../../tests/fixtures/linux/os-release.golden"
        ));
        assert_eq!(os.id, "ubuntu");
        assert_eq!(os.version_id, "22.04");
        let package = parse_dpkg_kernel_package(
            include_str!("../../../tests/fixtures/linux/dpkg-status.golden"),
            "5.15.0-107-generic",
            None,
        );
        assert_eq!(
            package.as_deref(),
            Some("linux-image-5.15.0-107-generic=5.15.0-107.117")
        );
    }

    #[test]
    fn uses_branch_specific_dirty_pipe_fixes() {
        assert!(dirty_pipe_candidate(KernelVersion {
            major: 5,
            minor: 10,
            patch: 101
        }));
        assert!(!dirty_pipe_candidate(KernelVersion {
            major: 5,
            minor: 10,
            patch: 102
        }));
        assert!(kernel_hints(KernelVersion {
            major: 5,
            minor: 15,
            patch: 24
        })
        .iter()
        .any(|hint| hint.cve == "CVE-2022-0847"));
    }
}
