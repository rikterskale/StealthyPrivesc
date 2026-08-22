use anyhow::Result;
use std::fs;
use std::path::Path;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};
use crate::exploit;
use crate::plugins::linux::util;

pub struct PolkitPlugin;

impl Plugin for PolkitPlugin {
    fn id(&self) -> &'static str {
        "linux.polkit"
    }
    fn name(&self) -> &'static str {
        "Polkit / pkexec"
    }
    fn description(&self) -> &'static str {
        "pkexec presence and writable polkit rules directories"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let euid = util::euid();

        for cand in ["/usr/bin/pkexec", "/bin/pkexec"] {
            let p = Path::new(cand);
            if p.is_file() {
                use std::os::unix::fs::MetadataExt;
                let meta = fs::metadata(p)?;
                let suid = meta.mode() & 0o4000 != 0;
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Enumeration,
                    severity: if suid {
                        Severity::Info
                    } else {
                        Severity::Low
                    },
                    title: format!("pkexec present: {cand}"),
                    detail: format!("mode={:o} suid={suid}", meta.mode()),
                    recommendation: "Review polkit rules; historical pkexec CVEs are kernel/tooling dependent — never auto-exploit."
                        .into(),
                    noisy: false,
                    leaves_artifacts: false,
                });
            }
        }

        let rule_dirs = [
            "/etc/polkit-1/rules.d",
            "/etc/polkit-1/localauthority",
            "/etc/polkit-1/localauthority/50-local.d",
            "/usr/share/polkit-1/rules.d",
        ];

        for dir in rule_dirs {
            let p = Path::new(dir);
            if !p.exists() {
                continue;
            }
            if let Ok(meta) = fs::metadata(p) {
                if util::is_writable_by_euid(&meta, euid, &util::current_gids()) {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Misconfiguration,
                        severity: Severity::Critical,
                        title: format!("Writable polkit path: {dir}"),
                        detail: format!("path={dir}"),
                        recommendation: "Writable polkit rules can grant root actions to low-priv users."
                            .into(),
                        noisy: false,
                        leaves_artifacts: false,
                    });
                    if ctx.auto_exploit && p.is_dir() {
                        if let Ok(true) = exploit::writable_probe(p) {
                            findings.push(Finding {
                                plugin: self.id().into(),
                                kind: FindingKind::ExploitAttempt,
                                severity: Severity::Critical,
                                title: format!("Confirmed writable polkit dir: {dir}"),
                                detail: "Reversible marker write/delete succeeded.".into(),
                                recommendation: "Do not drop rules without explicit approval."
                                    .into(),
                                noisy: true,
                                leaves_artifacts: false,
                            });
                        }
                    }
                }
            }
            // World-writable rule files inside
            if p.is_dir() {
                if let Ok(rd) = fs::read_dir(p) {
                    for entry in rd.flatten().take(100) {
                        if let Ok(meta) = entry.metadata() {
                            if util::is_writable_by_euid(&meta, euid, &util::current_gids()) {
                                findings.push(Finding {
                                    plugin: self.id().into(),
                                    kind: FindingKind::Misconfiguration,
                                    severity: Severity::High,
                                    title: format!(
                                        "Writable polkit entry: {}",
                                        entry.path().display()
                                    ),
                                    detail: format!("path={}", entry.path().display()),
                                    recommendation:
                                        "Inspect rule contents for overly broad allow actions."
                                            .into(),
                                    noisy: false,
                                    leaves_artifacts: false,
                                });
                            }
                        }
                    }
                }
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No obvious polkit misconfigurations".into(),
                detail: "pkexec/rules paths checked.".into(),
                recommendation: "Review custom .rules files manually if present.".into(),
                noisy: false,
                leaves_artifacts: false,
            });
        }

        Ok(findings)
    }
}
