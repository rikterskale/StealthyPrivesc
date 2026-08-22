use anyhow::Result;
use std::path::PathBuf;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};
use crate::exploit;

pub struct EnvPathPlugin;

impl Plugin for EnvPathPlugin {
    fn id(&self) -> &'static str {
        "windows.env_path"
    }
    fn name(&self) -> &'static str {
        "PATH hijack candidates"
    }
    fn description(&self) -> &'static str {
        "Writable or missing PATH entries (process env + HKCU Environment)"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["windows"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut entries: Vec<(String, String)> = Vec::new();

        if let Ok(path) = std::env::var("PATH") {
            for e in path.split(';').filter(|s| !s.is_empty()) {
                entries.push(("env".into(), e.to_string()));
            }
        }
        if let Some(hkcu) = read_hkcu_path() {
            for e in hkcu.split(';').filter(|s| !s.is_empty()) {
                entries.push(("hkcu".into(), e.to_string()));
            }
        }

        for (src, entry) in entries {
            let p = PathBuf::from(&entry);
            if !p.exists() {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Misconfiguration,
                    severity: Severity::Medium,
                    title: format!("PATH entry missing ({src}): {entry}"),
                    detail:
                        "Missing PATH components can be created if a parent directory is writable."
                            .into(),
                    recommendation:
                        "Check whether you can create this directory and plant a binary name."
                            .into(),
                    noisy: false,
                    leaves_artifacts: false,
                });
                continue;
            }
            if p.is_dir() && ctx.auto_exploit {
                if let Ok(true) = exploit::writable_probe(&p) {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::ExploitAttempt,
                        severity: Severity::High,
                        title: format!("Confirmed writable PATH dir ({src}): {entry}"),
                        detail: "Reversible marker write/delete succeeded.".into(),
                        recommendation: "Do not plant binaries unless explicitly authorized."
                            .into(),
                        noisy: true,
                        leaves_artifacts: false,
                    });
                }
            } else if p.is_dir() {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Enumeration,
                    severity: Severity::Info,
                    title: format!("PATH dir present ({src}): {entry}"),
                    detail: "Writability not probed in enumerate-only mode.".into(),
                    recommendation: "Re-run with --auto-exploit to confirm writable PATH dirs."
                        .into(),
                    noisy: false,
                    leaves_artifacts: false,
                });
            }
        }

        if !ctx.auto_exploit {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Recommendation,
                severity: Severity::Info,
                title: "PATH writability probes skipped (enumerate-only)".into(),
                detail: "Enable --auto-exploit for reversible write probes of PATH directories."
                    .into(),
                recommendation: "Keep enum-only on high-sensitivity hosts.".into(),
                noisy: false,
                leaves_artifacts: false,
            });
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No obvious PATH hijack candidates".into(),
                detail: "Checked process PATH and HKCU Environment Path.".into(),
                recommendation: "Also review machine PATH under HKLM\\...\\Session Manager\\Environment."
                    .into(),
                noisy: false,
                leaves_artifacts: false,
            });
        }

        Ok(findings)
    }
}

#[cfg(windows)]
fn read_hkcu_path() -> Option<String> {
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_CURRENT_USER, KEY_READ,
    };
    unsafe {
        let sub = to_wide("Environment");
        let mut key = ptr::null_mut();
        if RegOpenKeyExW(HKEY_CURRENT_USER, sub.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return None;
        }
        let name = to_wide("Path");
        let mut ty = 0u32;
        let mut len = 0u32;
        if RegQueryValueExW(
            key,
            name.as_ptr(),
            ptr::null_mut(),
            &mut ty,
            ptr::null_mut(),
            &mut len,
        ) != 0
        {
            RegCloseKey(key);
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        if RegQueryValueExW(
            key,
            name.as_ptr(),
            ptr::null_mut(),
            &mut ty,
            buf.as_mut_ptr(),
            &mut len,
        ) != 0
        {
            RegCloseKey(key);
            return None;
        }
        RegCloseKey(key);
        let u16s: Vec<u16> = buf
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|c| *c != 0)
            .collect();
        Some(String::from_utf16_lossy(&u16s))
    }
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(not(windows))]
fn read_hkcu_path() -> Option<String> {
    None
}
