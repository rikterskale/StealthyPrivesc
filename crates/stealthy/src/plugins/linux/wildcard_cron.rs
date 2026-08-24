use anyhow::Result;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let cron_dirs = [
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
        ];

        for dir in cron_dirs {
            if ctx.cancelled() {
                break;
            }
            let p = Path::new(dir);
            if !p.is_dir() {
                continue;
            }
            if let Ok(rd) = fs::read_dir(p) {
                for entry in rd.flatten().take(500) {
                    if ctx.cancelled() {
                        break;
                    }
                    if let Some(text) = read_text_bounded(&entry.path(), 1024 * 1024) {
                        scan_cron_script(
                            &entry.path().to_string_lossy(),
                            &text,
                            &ctx.cancel,
                            &mut findings,
                        );
                    }
                }
            }
        }

        if !ctx.cancelled() {
            if let Some(text) = read_text_bounded(Path::new("/etc/crontab"), 1024 * 1024) {
                scan_cron_script("/etc/crontab", &text, &ctx.cancel, &mut findings);
            }
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
                object: "readable-system-cron-files".into(),
                condition: "no-wildcard-command-candidate".into(),
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn read_text_bounded(path: &Path, max_bytes: u64) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.by_ref().take(max_bytes).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn scan_cron_script(path: &str, text: &str, cancel: &Arc<AtomicBool>, findings: &mut Vec<Finding>) {
    for line in text.lines() {
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let lower = t.to_lowercase();
        let risky =
            (lower.contains("tar ") || lower.contains("chown ") || lower.contains("rsync "))
                && t.contains('*');
        if risky {
            let gtfo_binary = ["tar", "chown", "rsync"]
                .into_iter()
                .find(|binary| lower.contains(&format!("{binary} ")));
            let annotation = gtfo_binary
                .filter(|binary| *binary == "tar")
                .map(|binary| format!("; gtfobins.binary={binary} gtfobins.functions=shell,file-read,file-write,sudo gtfobins.url=https://gtfobins.github.io/gtfobins/{binary}/ recommend_only=true"))
                .unwrap_or_default();
            findings.push(Finding {
                plugin: "linux.wildcard_cron".into(),
                kind: FindingKind::Misconfiguration,
                severity: Severity::Medium,
                title: format!("Possible wildcard injection in {path}"),
                detail: format!("{t}{annotation}"),
                recommendation: "If the working directory is writable, filename-based option injection may be possible (classic tar/chown tricks).".into(),
                noisy: false,
                leaves_artifacts: false,
                object: format!("{path}:{t}"),
                condition: "cron-wildcard-command-candidate".into(),
                mitre_techniques: vec!["T1053.003".into()],
                technique_id: if annotation.is_empty() {
                    "cron-wildcard-injection"
                } else {
                    "gtfobins"
                }
                .into(),
                ..Default::default()
            });
        }
    }
}
