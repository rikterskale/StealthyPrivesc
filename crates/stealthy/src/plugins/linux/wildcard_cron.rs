use anyhow::Result;
use std::fs;
use std::path::Path;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct WildcardCronPlugin;

impl Plugin for WildcardCronPlugin {
    fn id(&self) -> &'static str {
        "linux.wildcard_cron"
    }
    fn name(&self) -> &'static str {
        "Cron wildcard injection hints"
    }
    fn description(&self) -> &'static str {
        "Look for cron scripts using tar/chown/rsync with wildcards in writable dirs"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, _ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let cron_dirs = [
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
        ];

        for dir in cron_dirs {
            let p = Path::new(dir);
            if !p.is_dir() {
                continue;
            }
            if let Ok(rd) = fs::read_dir(p) {
                for entry in rd.flatten() {
                    if let Ok(text) = fs::read_to_string(entry.path()) {
                        scan_cron_script(&entry.path().to_string_lossy(), &text, &mut findings);
                    }
                }
            }
        }

        if let Ok(text) = fs::read_to_string("/etc/crontab") {
            scan_cron_script("/etc/crontab", &text, &mut findings);
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No obvious wildcard-prone cron commands found".into(),
                detail: "Scanned readable cron directories for tar/chown/rsync wildcards.".into(),
                recommendation: "User crontabs may still be vulnerable; inspect with care.".into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn scan_cron_script(path: &str, text: &str, findings: &mut Vec<Finding>) {
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let lower = t.to_lowercase();
        let risky =
            (lower.contains("tar ") || lower.contains("chown ") || lower.contains("rsync "))
                && t.contains('*');
        if risky {
            findings.push(Finding {
                plugin: "linux.wildcard_cron".into(),
                kind: FindingKind::Misconfiguration,
                severity: Severity::Medium,
                title: format!("Possible wildcard injection in {path}"),
                detail: t.to_string(),
                recommendation: "If the working directory is writable, filename-based option injection may be possible (classic tar/chown tricks).".into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }
    }
}
