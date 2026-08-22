use anyhow::Result;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct NfsPlugin;

impl Plugin for NfsPlugin {
    fn id(&self) -> &'static str {
        "linux.nfs"
    }
    fn name(&self) -> &'static str {
        "NFS no_root_squash"
    }
    fn description(&self) -> &'static str {
        "Parse local exports / mounts for no_root_squash and related risk flags"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, _ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        if let Ok(exports) = std::fs::read_to_string("/etc/exports") {
            for line in exports.lines() {
                let t = line.trim();
                if t.is_empty() || t.starts_with('#') {
                    continue;
                }
                let severity = if t.contains("no_root_squash") {
                    Severity::Critical
                } else if t.contains("root_squash") {
                    Severity::Info
                } else {
                    Severity::Low
                };
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: if t.contains("no_root_squash") {
                        FindingKind::Misconfiguration
                    } else {
                        FindingKind::Enumeration
                    },
                    severity,
                    title: "NFS export entry".into(),
                    detail: t.to_string(),
                    recommendation: if t.contains("no_root_squash") {
                        "no_root_squash allows remote root to write as local root on the share — classic privesc vector.".into()
                    } else {
                        "Review export options and client ACLs.".into()
                    },
                    noisy: false,
                    leaves_artifacts: false,
                });
            }
        }

        // Mounted NFS from /proc/mounts (no `mount` spawn).
        if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
            for line in mounts.lines() {
                if line.contains(" nfs") || line.contains(" nfs4") {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Enumeration,
                        severity: Severity::Low,
                        title: "NFS mount present".into(),
                        detail: line.to_string(),
                        recommendation: "Check whether the export allows UID remapping abuse."
                            .into(),
                        noisy: false,
                        leaves_artifacts: false,
                    });
                }
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No local NFS exports/mounts noted".into(),
                detail: "/etc/exports missing or empty; no nfs mounts in /proc/mounts.".into(),
                recommendation:
                    "Remote share discovery is out of scope for this quiet local plugin.".into(),
                noisy: false,
                leaves_artifacts: false,
            });
        }

        Ok(findings)
    }
}
