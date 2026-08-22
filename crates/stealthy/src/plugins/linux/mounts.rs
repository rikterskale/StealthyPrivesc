use anyhow::Result;
use std::fs;
use std::path::Path;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct MountsPlugin;

impl Plugin for MountsPlugin {
    fn id(&self) -> &'static str {
        "linux.mounts"
    }
    fn name(&self) -> &'static str {
        "Mounts / passwd writability"
    }
    fn description(&self) -> &'static str {
        "Interesting mount options and whether /etc/passwd is writable"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, _ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // /etc/passwd writable => classic user add path (recommend only; never auto-write)
        let passwd = Path::new("/etc/passwd");
        match fs::OpenOptions::new().write(true).open(passwd) {
            Ok(_) => findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Misconfiguration,
                severity: Severity::Critical,
                title: "/etc/passwd is writable".into(),
                detail: "Opened O_WRONLY successfully — do not modify without explicit approval."
                    .into(),
                recommendation: "Writable passwd enables local user/UID 0 insertion. Manual only."
                    .into(),
                noisy: false,
                leaves_artifacts: true,
                ..Default::default()
            }),
            Err(_) => findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "/etc/passwd not writable".into(),
                detail: "Expected on hardened hosts.".into(),
                recommendation: "Continue with sudo/SUID/container checks.".into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            }),
        }

        // Parse /proc/self/mountinfo for user-interesting mounts
        if let Ok(text) = fs::read_to_string("/proc/self/mountinfo") {
            for line in text.lines() {
                // mountinfo: ... - fstype source superopts
                let lower = line.to_lowercase();
                let interesting_fs = lower.contains(" fuse")
                    || lower.contains(" nfs")
                    || lower.contains(" cifs")
                    || lower.contains(" overlay")
                    || lower.contains(" squashfs");
                let missing_nosuid = !lower.contains("nosuid")
                    && (lower.contains("/home")
                        || lower.contains("/tmp")
                        || lower.contains("/dev/shm")
                        || lower.contains("/var/tmp"));
                if interesting_fs || missing_nosuid {
                    let sev = if missing_nosuid && !interesting_fs {
                        Severity::Low
                    } else {
                        Severity::Info
                    };
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Enumeration,
                        severity: sev,
                        title: if missing_nosuid {
                            "Mount may allow suid on user-writable area".into()
                        } else {
                            "Interesting mount".into()
                        },
                        detail: truncate(line, 300),
                        recommendation: "Review mount options (nosuid/nodev/noexec) against hardening baselines."
                            .into(),
                        noisy: false,
                        leaves_artifacts: false,
                        ..Default::default()
                    });
                }
            }
        }

        // User namespaces hint
        if Path::new("/proc/sys/kernel/unprivileged_userns_clone").is_file() {
            if let Ok(v) = fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
                let v = v.trim();
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Enumeration,
                    severity: if v == "1" {
                        Severity::Low
                    } else {
                        Severity::Info
                    },
                    title: format!("unprivileged_userns_clone={v}"),
                    detail:
                        "Unprivileged user namespaces expand some container/LPE research surfaces."
                            .into(),
                    recommendation:
                        "Informational — opt in with --allow-techniques kernel-exploit when ROE permits.".into(),
                    noisy: false,
                    leaves_artifacts: false,
                    ..Default::default()
                });
            }
        }

        Ok(findings)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}
