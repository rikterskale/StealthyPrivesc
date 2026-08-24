use anyhow::Result;
use std::io::Read;
use std::path::Path;

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

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        if let Some(exports) = read_text_bounded(Path::new("/etc/exports"), 1024 * 1024) {
            for line in exports.lines() {
                if ctx.cancelled() {
                    break;
                }
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
                    object: t.split_whitespace().next().unwrap_or(t).into(),
                    condition: if t.contains("no_root_squash") {
                        "nfs-export-no-root-squash"
                    } else {
                        "nfs-export-observed"
                    }
                    .into(),
                    technique_id: "nfs-export".into(),
                    ..Default::default()
                });
            }
        }

        // Mounted NFS from /proc/mounts (no `mount` spawn).
        if let Some(mounts) = read_text_bounded(Path::new("/proc/mounts"), 4 * 1024 * 1024) {
            for line in mounts.lines() {
                if ctx.cancelled() {
                    break;
                }
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
                        object: line.split_whitespace().nth(1).unwrap_or(line).into(),
                        condition: "nfs-mount-present".into(),
                        technique_id: "nfs-mount".into(),
                        ..Default::default()
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
                object: "local-nfs-configuration".into(),
                condition: "no-local-nfs-observed".into(),
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn read_text_bounded(path: &Path, max_bytes: u64) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.by_ref().take(max_bytes).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}
