use anyhow::Result;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let euid = util::euid();
        let gids = util::current_gids();
        let allow_getfacl = !ctx.prefer_quiet;

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
            if ctx.cancelled() {
                break;
            }
            let p = Path::new(path);
            if !p.exists() {
                continue;
            }
            scan_writable(p, 2, euid, &gids, allow_getfacl, &ctx.cancel, &mut findings);
        }

        // World-writable files under /etc (shallow) — high signal, keep capped.
        if let Ok(rd) = fs::read_dir("/etc") {
            for entry in rd.flatten().take(300) {
                if ctx.cancelled() {
                    break;
                }
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
                                object: entry.path().display().to_string(),
                                condition: "world-writable-etc-file".into(),
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
                object: "common-service-config-paths".into(),
                condition: "no-writable-service-config".into(),
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn scan_writable(
    dir: &Path,
    depth: u32,
    euid: u32,
    gids: &[u32],
    allow_getfacl: bool,
    cancel: &Arc<AtomicBool>,
    findings: &mut Vec<Finding>,
) {
    if depth == 0 || cancel.load(Ordering::SeqCst) {
        return;
    }
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in rd.flatten().take(100) {
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        let path = entry.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let mode = meta.permissions().mode();
        if util::is_effectively_writable_opts(&path, euid, gids, allow_getfacl).unwrap_or(false) {
            findings.push(Finding {
                plugin: "linux.services".into(),
                kind: FindingKind::Misconfiguration,
                severity: Severity::High,
                title: format!("Current-user writable service path: {}", path.display()),
                detail: format!("mode={mode:o}"),
                recommendation: "Determine which privileged process reads this path.".into(),
                noisy: false,
                leaves_artifacts: false,
                object: path.display().to_string(),
                condition: "service-path-current-user-writable".into(),
                ..Default::default()
            });
        }
        if meta.is_dir() {
            scan_writable(
                &path,
                depth - 1,
                euid,
                gids,
                allow_getfacl,
                cancel,
                findings,
            );
        }
    }
}
