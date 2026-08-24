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
            scan_exports(&exports, &ctx.cancel, self.id(), &mut findings);
        }

        // Mounted NFS from /proc/mounts (no `mount` spawn).
        if let Some(mounts) = read_text_bounded(Path::new("/proc/mounts"), 4 * 1024 * 1024) {
            scan_mounts(&mounts, &ctx.cancel, self.id(), &mut findings);
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

fn scan_exports(
    text: &str,
    cancel: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    plugin: &str,
    findings: &mut Vec<Finding>,
) {
    for line in text.lines() {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let no_root = t.contains("no_root_squash");
        findings.push(Finding {
            plugin: plugin.into(),
            kind: if no_root { FindingKind::Misconfiguration } else { FindingKind::Enumeration },
            severity: if no_root { Severity::Critical } else if t.contains("root_squash") { Severity::Info } else { Severity::Low },
            title: "NFS export entry".into(), detail: t.into(),
            recommendation: if no_root { "no_root_squash allows remote root to write as local root on the share — classic privesc vector." } else { "Review export options and client ACLs." }.into(),
            noisy: false, leaves_artifacts: false,
            object: t.split_whitespace().next().unwrap_or(t).into(),
            condition: if no_root { "nfs-export-no-root-squash" } else { "nfs-export-observed" }.into(),
            technique_id: "nfs-export".into(), ..Default::default()
        });
    }
}

fn scan_mounts(
    text: &str,
    cancel: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    plugin: &str,
    findings: &mut Vec<Finding>,
) {
    for line in text.lines() {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        if line.contains(" nfs") || line.contains(" nfs4") {
            findings.push(Finding {
                plugin: plugin.into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Low,
                title: "NFS mount present".into(),
                detail: line.into(),
                recommendation: "Check whether the export allows UID remapping abuse.".into(),
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

fn read_text_bounded(path: &Path, max_bytes: u64) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.by_ref().take(max_bytes).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::{read_text_bounded, scan_exports, scan_mounts};
    use std::sync::{atomic::AtomicBool, Arc};

    #[test]
    fn bounded_reader_handles_missing_and_truncated_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exports");
        std::fs::write(&path, b"0123456789").unwrap();
        assert_eq!(read_text_bounded(&path, 4).as_deref(), Some("0123"));
        assert!(read_text_bounded(&dir.path().join("missing"), 10).is_none());
    }

    #[test]
    fn parsers_classify_exports_mounts_and_cancellation() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut findings = Vec::new();
        scan_exports(
            "# comment\n/export *(no_root_squash)\n/data *(root_squash)\n",
            &cancel,
            "linux.nfs",
            &mut findings,
        );
        scan_mounts(
            "server:/share /mnt nfs4 rw 0 0\n/dev/sda / ext4 rw 0 0\n",
            &cancel,
            "linux.nfs",
            &mut findings,
        );
        assert!(findings
            .iter()
            .any(|f| f.condition == "nfs-export-no-root-squash"));
        assert!(findings.iter().any(|f| f.condition == "nfs-mount-present"));
        cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        let count = findings.len();
        scan_exports(
            "/other *(no_root_squash)",
            &cancel,
            "linux.nfs",
            &mut findings,
        );
        assert_eq!(findings.len(), count);
    }
}
