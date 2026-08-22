use anyhow::Result;
use std::path::Path;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct ScheduledTasksPlugin;

impl Plugin for ScheduledTasksPlugin {
    fn id(&self) -> &'static str {
        "windows.scheduled_tasks"
    }
    fn name(&self) -> &'static str {
        "Scheduled tasks"
    }
    fn description(&self) -> &'static str {
        "Enumerate task XML under System32\\Tasks for high-privilege indicators"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["windows"]
    }

    fn run(&self, _ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let roots = [r"C:\Windows\System32\Tasks", r"C:\Windows\SysWOW64\Tasks"];

        for root in roots {
            walk_tasks(Path::new(root), 3, &mut findings);
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No readable scheduled task XML findings".into(),
                detail: "Task store may be inaccessible without elevation.".into(),
                recommendation: "Use schtasks /query when process creation is acceptable.".into(),
                noisy: false,
                leaves_artifacts: false,
            });
        }

        Ok(findings)
    }
}

fn walk_tasks(dir: &Path, depth: u32, findings: &mut Vec<Finding>) {
    if depth == 0 || !dir.is_dir() {
        return;
    }
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in rd.flatten().take(200) {
        let path = entry.path();
        if path.is_dir() {
            walk_tasks(&path, depth - 1, findings);
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            let elevated = text.contains("<RunLevel>HighestAvailable</RunLevel>")
                || text.contains("S-1-5-18")
                || text.to_lowercase().contains("nt authority\\system");
            let user_context = text.contains("<UserId>") || text.contains("<Principal");
            if elevated || user_context {
                findings.push(Finding {
                    plugin: "windows.scheduled_tasks".into(),
                    kind: if elevated {
                        FindingKind::Misconfiguration
                    } else {
                        FindingKind::Enumeration
                    },
                    severity: if elevated {
                        Severity::Medium
                    } else {
                        Severity::Low
                    },
                    title: format!("Scheduled task XML: {}", path.display()),
                    detail: truncate(&text, 400),
                    recommendation:
                        "Check whether the action binary/script is writable by low-priv users."
                            .into(),
                    noisy: false,
                    leaves_artifacts: false,
                });
            }
            for cmd in extract_commands(&text) {
                let bin = strip_quotes_path(&cmd);
                if !bin.is_empty()
                    && std::path::Path::new(&bin).is_file()
                    && super::acl::is_writable_for_current_user(Path::new(&bin)).unwrap_or_else(
                        || std::fs::OpenOptions::new().append(true).open(&bin).is_ok(),
                    )
                {
                    findings.push(Finding {
                        plugin: "windows.scheduled_tasks".into(),
                        kind: FindingKind::Misconfiguration,
                        severity: if elevated {
                            Severity::Critical
                        } else {
                            Severity::High
                        },
                        title: format!("Writable task action binary: {bin}"),
                        detail: format!("task={} command={cmd}", path.display()),
                        recommendation: "High-priv tasks with writable actions are classic privesc — modify only with approval."
                            .into(),
                        noisy: false,
                        leaves_artifacts: true,
                    });
                }
            }
        }
    }
}

fn extract_commands(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<Command>") {
        rest = &rest[start + "<Command>".len()..];
        if let Some(end) = rest.find("</Command>") {
            let cmd = rest[..end].trim().to_string();
            if !cmd.is_empty() {
                out.push(cmd);
            }
            rest = &rest[end + "</Command>".len()..];
        } else {
            break;
        }
    }
    out
}

fn strip_quotes_path(cmd: &str) -> String {
    super::executable_path(cmd).unwrap_or_default()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}
