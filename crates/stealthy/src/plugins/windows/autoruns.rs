use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct AutorunsPlugin;

impl Plugin for AutorunsPlugin {
    fn id(&self) -> &'static str {
        "windows.autoruns"
    }
    fn name(&self) -> &'static str {
        "Autoruns / Startup"
    }
    fn description(&self) -> &'static str {
        "Run keys and Startup folders pointing at writable targets"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["windows"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (hive, path) in run_key_values() {
            let target = extract_path_from_command(&path);
            let writable = target
                .as_ref()
                .map(|t| is_writable_file(t))
                .unwrap_or(false);
            findings.push(Finding {
                plugin: self.id().into(),
                kind: if writable {
                    FindingKind::Misconfiguration
                } else {
                    FindingKind::Enumeration
                },
                severity: if writable {
                    Severity::High
                } else {
                    Severity::Low
                },
                title: format!("Autorun ({hive}): {path}"),
                detail: target.unwrap_or_else(|| "(unparsed)".into()),
                recommendation: if writable {
                    "Writable autorun target can yield code execution in the Run-key principal context."
                        .into()
                } else {
                    "Informational — verify binary integrity if unexpected.".into()
                },
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }

        for dir in startup_dirs() {
            if !dir.is_dir() {
                continue;
            }
            let candidate = Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: format!("Startup folder: {}", dir.display()),
                detail: "Present.".into(),
                recommendation: "Use --auto-exploit to probe directory writability.".into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            };
            let probe_allowed = ctx.probe_allowed_for(&candidate);
            findings.push(candidate);
            if probe_allowed && dir_writable(&dir) {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::ExploitAttempt,
                    severity: Severity::High,
                    title: format!("Confirmed writable Startup folder: {}", dir.display()),
                    detail: "Reversible marker write/delete succeeded.".into(),
                    recommendation: "Persistence-adjacent — obtain approval before any plant."
                        .into(),
                    noisy: true,
                    leaves_artifacts: false,
                    ..Default::default()
                });
            }
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for entry in rd.flatten().take(50) {
                    let p = entry.path();
                    if p.is_file() && is_writable_file(&p.to_string_lossy()) {
                        findings.push(Finding {
                            plugin: self.id().into(),
                            kind: FindingKind::Misconfiguration,
                            severity: Severity::High,
                            title: format!("Writable Startup entry: {}", p.display()),
                            detail: p.display().to_string(),
                            recommendation: "Replace/modify only with ROE approval.".into(),
                            noisy: false,
                            leaves_artifacts: true,
                            ..Default::default()
                        });
                    }
                }
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No writable autorun/startup findings".into(),
                detail: "Checked common Run keys and Startup folders.".into(),
                recommendation: "Expand to Scheduled Tasks / services for persistence coverage."
                    .into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

fn extract_path_from_command(cmd: &str) -> Option<String> {
    // Expand simple env vars
    let t = cmd.trim();
    let expanded = t.replace(
        "%SystemRoot%",
        &std::env::var("SystemRoot").unwrap_or_default(),
    );
    super::executable_path(&expanded)
}

fn is_writable_file(path: &str) -> bool {
    super::acl::is_writable_for_current_user(Path::new(path)).unwrap_or(false)
}

fn dir_writable(dir: &Path) -> bool {
    crate::exploit::writable_probe(dir).unwrap_or(false)
}

fn startup_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(appdata) = std::env::var("APPDATA") {
        out.push(PathBuf::from(appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
    }
    if let Ok(programdata) = std::env::var("ProgramData") {
        out.push(PathBuf::from(programdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
    }
    out
}

#[cfg(windows)]
fn run_key_values() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let keys = [
        (
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            true,
        ),
        (
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            true,
        ),
        (
            "HKLM",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            false,
        ),
        (
            "HKLM",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            false,
        ),
        (
            "HKLM",
            r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            false,
        ),
    ];
    for (hive, sub, hkcu) in keys {
        for (name, val) in enum_run_values(hkcu, sub) {
            out.push((format!("{hive}\\{sub}\\{name}"), val));
        }
    }
    out
}

#[cfg(windows)]
fn enum_run_values(hkcu: bool, subpath: &str) -> Vec<(String, String)> {
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ,
    };
    let mut out = Vec::new();
    unsafe {
        let root = if hkcu {
            HKEY_CURRENT_USER
        } else {
            HKEY_LOCAL_MACHINE
        };
        let sub = to_wide(subpath);
        let mut key = ptr::null_mut();
        if RegOpenKeyExW(root, sub.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return out;
        }
        let mut index = 0u32;
        loop {
            let mut name = vec![0u16; 256];
            let mut name_len = name.len() as u32;
            let mut data = vec![0u8; 1024];
            let mut data_len = data.len() as u32;
            let mut ty = 0u32;
            let status = RegEnumValueW(
                key,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                ptr::null_mut(),
                &mut ty,
                data.as_mut_ptr(),
                &mut data_len,
            );
            if status != 0 {
                break;
            }
            let n = String::from_utf16_lossy(&name[..name_len as usize]);
            let u16s: Vec<u16> = data[..data_len as usize]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .take_while(|c| *c != 0)
                .collect();
            let v = String::from_utf16_lossy(&u16s);
            if !v.is_empty() {
                out.push((n, v));
            }
            index += 1;
            if index > 200 {
                break;
            }
        }
        RegCloseKey(key);
    }
    out
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(not(windows))]
fn run_key_values() -> Vec<(String, String)> {
    Vec::new()
}
