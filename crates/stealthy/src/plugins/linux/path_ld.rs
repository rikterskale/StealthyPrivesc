use anyhow::Result;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};
use crate::exploit;

pub struct PathLdPlugin;

impl Plugin for PathLdPlugin {
    fn id(&self) -> &'static str {
        "linux.path_ld"
    }
    fn name(&self) -> &'static str {
        "Writable PATH / LD_* "
    }
    fn description(&self) -> &'static str {
        "Find writable PATH entries and risky LD_PRELOAD / LD_LIBRARY_PATH settings"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        if let Ok(path) = env::var("PATH") {
            for entry in path.split(':').filter(|s| !s.is_empty()) {
                let p = Path::new(entry);
                if !p.exists() {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Misconfiguration,
                        severity: Severity::Medium,
                        title: format!("PATH entry missing (hijack candidate): {entry}"),
                        detail: "A missing PATH component can be created by the user if a parent dir is writable.".into(),
                        recommendation: "Check whether you can create this directory and plant a trojan binary name.".into(),
                        noisy: false,
                        leaves_artifacts: false,
                        ..Default::default()
                    });
                    continue;
                }
                if let Ok(meta) = fs::metadata(p) {
                    let mode = meta.permissions().mode();
                    if mode & 0o002 != 0 {
                        findings.push(Finding {
                            plugin: self.id().into(),
                            kind: FindingKind::Misconfiguration,
                            severity: Severity::High,
                            title: format!("World-writable PATH entry: {entry}"),
                            detail: format!("mode={mode:o}"),
                            recommendation: "Binary planting in PATH is a classic privesc if privileged processes inherit PATH.".into(),
                            noisy: false,
                            leaves_artifacts: false,
                            ..Default::default()
                        });
                        if ctx.auto_exploit {
                            if let Ok(true) = exploit::writable_probe(p) {
                                findings.push(Finding {
                                    plugin: self.id().into(),
                                    kind: FindingKind::ExploitAttempt,
                                    severity: Severity::High,
                                    title: format!("Confirmed writable PATH dir: {entry}"),
                                    detail: "Reversible marker write/delete succeeded.".into(),
                                    recommendation:
                                        "Do not plant binaries unless explicitly authorized."
                                            .into(),
                                    noisy: true,
                                    leaves_artifacts: false,
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
        }

        for var in ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT"] {
            if let Ok(val) = env::var(var) {
                if !val.is_empty() {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Enumeration,
                        severity: Severity::Medium,
                        title: format!("{var} is set"),
                        detail: val,
                        recommendation: "Inherited loader variables can redirect privileged dynamically linked programs.".into(),
                        noisy: false,
                        leaves_artifacts: false,
                        ..Default::default()
                    });
                }
            }
        }

        // /etc/ld.so.preload readable?
        if let Ok(text) = fs::read_to_string("/etc/ld.so.preload") {
            if !text.trim().is_empty() {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Enumeration,
                    severity: Severity::High,
                    title: "/etc/ld.so.preload is non-empty".into(),
                    detail: text.trim().to_string(),
                    recommendation: "If writable, this is a powerful persistence/privesc primitive — handle with extreme care.".into(),
                    noisy: false,
                    leaves_artifacts: false,
                    ..Default::default()
                });
            }
        }

        if let Ok(meta) = fs::metadata("/etc/ld.so.preload") {
            let mode = meta.permissions().mode();
            if mode & 0o002 != 0 {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Misconfiguration,
                    severity: Severity::Critical,
                    title: "/etc/ld.so.preload is world-writable".into(),
                    detail: format!("mode={mode:o}"),
                    recommendation: "Critical misconfiguration. Do not modify without explicit approval.".into(),
                    noisy: false,
                    leaves_artifacts: true,
                    ..Default::default()
                });
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No obvious PATH/LD issues".into(),
                detail: "PATH entries were not world-writable; LD_* unset or empty.".into(),
                recommendation:
                    "Still review sudo secure_path and systemd Environment= directives.".into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }

        Ok(findings)
    }
}
