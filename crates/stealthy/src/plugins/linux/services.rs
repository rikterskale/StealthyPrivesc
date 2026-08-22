use anyhow::Result;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};
use crate::plugins::linux::util;

pub struct ServicesPlugin;

impl Plugin for ServicesPlugin {
    fn id(&self) -> &'static str {
        "linux.services"
    }
    fn name(&self) -> &'static str {
        "Writable service configuration"
    }
    fn description(&self) -> &'static str {
        "Find writable service configs under /etc and common daemon dirs"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["linux"]
    }

    fn run(&self, _ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let euid = util::euid();
        let gids = util::current_gids();

        let paths = [
            "/etc/nginx",
            "/etc/apache2",
            "/etc/httpd",
            "/etc/mysql",
            "/etc/postgresql",
            "/etc/redis",
            "/etc/docker",
            "/etc/supervisor",
            "/etc/init.d",
        ];

        for path in paths {
            let p = Path::new(path);
            if !p.exists() {
                continue;
            }
            scan_writable(p, 2, euid, &gids, &mut findings);
        }

        // World-writable files under /etc (shallow) — high signal, keep capped.
        if let Ok(rd) = fs::read_dir("/etc") {
            for entry in rd.flatten().take(300) {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        let mode = meta.permissions().mode();
                        if mode & 0o002 != 0 {
                            findings.push(Finding {
                                plugin: self.id().into(),
                                kind: FindingKind::Misconfiguration,
                                severity: Severity::High,
                                title: format!("World-writable file in /etc: {}", entry.path().display()),
                                detail: format!("mode={mode:o}"),
                                recommendation: "World-writable config under /etc can yield privilege or persistence.".into(),
                                noisy: false,
                                leaves_artifacts: false,
                                ..Default::default()
                            });
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
                title: "No obvious writable service configs".into(),
                detail: "Checked common daemon config directories.".into(),
                recommendation: "Review package-specific paths for the target role.".into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn scan_writable(dir: &Path, depth: u32, euid: u32, gids: &[u32], findings: &mut Vec<Finding>) {
    if depth == 0 {
        return;
    }
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in rd.flatten().take(100) {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mode = meta.permissions().mode();
        if util::is_effectively_writable(&path, euid, gids).unwrap_or(false) {
            findings.push(Finding {
                plugin: "linux.services".into(),
                kind: FindingKind::Misconfiguration,
                severity: Severity::High,
                title: format!("World-writable service path: {}", path.display()),
                detail: format!("mode={mode:o}"),
                recommendation: "Determine which privileged process reads this path.".into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }
        if meta.is_dir() {
            scan_writable(&path, depth - 1, euid, gids, findings);
        }
    }
}
