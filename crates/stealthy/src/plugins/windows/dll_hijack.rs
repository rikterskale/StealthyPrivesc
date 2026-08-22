use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct DllHijackPlugin;

impl Plugin for DllHijackPlugin {
    fn id(&self) -> &'static str {
        "windows.dll_hijack"
    }
    fn name(&self) -> &'static str {
        "DLL hijack candidates"
    }
    fn description(&self) -> &'static str {
        "Look for writable directories in trusted search paths / application folders"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["windows"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(sysroot) = std::env::var("SystemRoot") {
            candidates.push(PathBuf::from(&sysroot));
            candidates.push(PathBuf::from(format!(r"{sysroot}\System32")));
            candidates.push(PathBuf::from(format!(r"{sysroot}\SysWOW64")));
        }
        if let Ok(path) = std::env::var("PATH") {
            for part in path.split(';').filter(|s| !s.is_empty()).take(30) {
                candidates.push(PathBuf::from(part));
            }
        }
        // Common auto-start / trusted app dirs
        for p in [
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            r"C:\ProgramData",
        ] {
            candidates.push(PathBuf::from(p));
        }

        for dir in candidates {
            if !dir.is_dir() {
                continue;
            }
            // Write probes leave momentary artifacts — only with --auto-exploit.
            if ctx.auto_exploit && is_dir_writable(&dir) {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Misconfiguration,
                    severity: Severity::High,
                    title: format!("Writable search/app directory: {}", dir.display()),
                    detail: "Writable dirs in loader search order enable DLL planting.".into(),
                    recommendation: "Identify privileged processes that load DLLs from this path before any write test.".into(),
                    noisy: true,
                    leaves_artifacts: false,
                    ..Default::default()
                });
            }
        }

        if !ctx.auto_exploit {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Recommendation,
                severity: Severity::Info,
                title: "DLL writability probes skipped (enumerate-only)".into(),
                detail:
                    "Enable --auto-exploit for reversible write probes of search-path directories."
                        .into(),
                recommendation: "Keep enum-only on high-sensitivity hosts.".into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }

        // Missing DLL hint: look for known side-load bait names only as info (no drops).
        let bait = ["version.dll", "dwmapi.dll", "winmm.dll", "textshaping.dll"];
        if let Ok(cwd) = std::env::current_dir() {
            for name in bait {
                let p = cwd.join(name);
                if !p.exists() {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Enumeration,
                        severity: Severity::Low,
                        title: format!("Common hijack DLL name absent in CWD: {name}"),
                        detail: format!("cwd={}", cwd.display()),
                        recommendation:
                            "Only relevant if a privileged app is started from this writable CWD."
                                .into(),
                        noisy: false,
                        leaves_artifacts: false,
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
                title: "No writable trusted-path directories detected".into(),
                detail: "Checked SystemRoot, PATH entries, and Program Files roots.".into(),
                recommendation: "Per-app hijack analysis still required for thorough coverage."
                    .into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn is_dir_writable(dir: &Path) -> bool {
    crate::exploit::writable_probe(dir).unwrap_or(false)
}
