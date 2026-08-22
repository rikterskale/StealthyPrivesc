use anyhow::Result;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct SuidPlugin;

impl Plugin for SuidPlugin {
    fn id(&self) -> &'static str {
        "linux.suid"
    }
    fn name(&self) -> &'static str {
        "SUID/SGID and capabilities"
    }
    fn description(&self) -> &'static str {
        "Find SUID/SGID binaries and file capabilities via direct filesystem walks"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let roots = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"];

        // Interesting SUID names commonly abused (informational — not an exploit list to run).
        let interesting = [
            "nmap",
            "vim",
            "vi",
            "find",
            "bash",
            "sh",
            "python",
            "python3",
            "perl",
            "ruby",
            "less",
            "more",
            "man",
            "awk",
            "env",
            "cp",
            "mv",
            "tar",
            "zip",
            "gcc",
            "make",
            "docker",
            "podman",
            "strace",
            "systemctl",
            "pkexec",
        ];

        for root in roots {
            let path = Path::new(root);
            if !path.is_dir() {
                continue;
            }
            walk_limited(path, 2, &mut |p, meta| {
                let mode = meta.mode();
                let suid = mode & 0o4000 != 0;
                let sgid = mode & 0o2000 != 0;
                if !suid && !sgid {
                    return;
                }
                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                let flagged = interesting
                    .iter()
                    .any(|i| name == *i || name.starts_with(i));
                let severity = if flagged {
                    Severity::High
                } else {
                    Severity::Medium
                };
                findings.push(Finding {
                    plugin: "linux.suid".into(),
                    kind: FindingKind::Misconfiguration,
                    severity,
                    title: format!(
                        "{}{} binary: {}",
                        if suid { "SUID " } else { "" },
                        if sgid { "SGID" } else { "" },
                        p.display()
                    ),
                    detail: format!("mode={mode:o} uid={} gid={}", meta.uid(), meta.gid()),
                    recommendation: "Cross-check against GTFOBins / capability guidance. Do not execute abuse payloads without approval.".into(),
                    noisy: false,
                    leaves_artifacts: false,
                    ..Default::default()
                });
            });
        }

        // Capabilities via getcap if present (optional, slightly noisier).
        if let Ok(out) = std::process::Command::new("getcap")
            .args(["-r", "/usr/bin"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines().take(50) {
                if line.contains('=') {
                    findings.push(Finding {
                        plugin: "linux.suid".into(),
                        kind: FindingKind::Enumeration,
                        severity: Severity::Medium,
                        title: "File capability".into(),
                        detail: line.to_string(),
                        recommendation:
                            "Review cap_setuid/cap_sys_admin style capabilities carefully.".into(),
                        noisy: true,
                        leaves_artifacts: false,
                        ..Default::default()
                    });
                }
            }
        }

        if ctx.auto_exploit {
            findings.push(Finding {
                plugin: "linux.suid".into(),
                kind: FindingKind::Recommendation,
                severity: Severity::Info,
                title: "SUID abuse not covered by reversible auto-exploit".into(),
                detail:
                    "SUID abuse is high-signal and often irreversible from a telemetry perspective."
                        .into(),
                recommendation:
                    "Exploit manually with ROE approval, or track related high-impact flags under --allow-techniques."
                        .into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: "linux.suid".into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No unusual SUID/SGID hits in shallow scan".into(),
                detail: "Shallow depth-limited walk of common bin dirs completed.".into(),
                recommendation:
                    "Expand search depth manually if engagement requires full filesystem coverage."
                        .into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn walk_limited(dir: &Path, depth: u32, f: &mut dyn FnMut(&PathBuf, &std::fs::Metadata)) {
    if depth == 0 {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_symlink() {
            continue;
        }
        if meta.is_file() {
            f(&path, &meta);
        } else if meta.is_dir() {
            walk_limited(&path, depth - 1, f);
        }
    }
}
