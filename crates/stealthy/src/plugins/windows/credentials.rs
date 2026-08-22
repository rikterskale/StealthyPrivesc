use anyhow::Result;
use std::path::Path;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct CredentialsPlugin;

impl Plugin for CredentialsPlugin {
    fn id(&self) -> &'static str {
        "windows.credentials"
    }
    fn name(&self) -> &'static str {
        "Credential files / unattend"
    }
    fn description(&self) -> &'static str {
        "Hunt common on-disk credential and unattend locations (existence only by default)"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["windows"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let dump_allowed = ctx
            .allow_techniques
            .allows(crate::exploit::TechniqueFamily::CredentialDump);

        let paths = [
            r"C:\Windows\Panther\Unattend.xml",
            r"C:\Windows\Panther\unattend.xml",
            r"C:\Windows\System32\sysprep\unattend.xml",
            r"C:\Windows\System32\sysprep\Sysprep.xml",
            r"C:\unattend.xml",
            r"C:\Windows\repair\SAM",
            r"C:\Windows\System32\config\RegBack\SAM",
            r"C:\Windows\System32\config\RegBack\SYSTEM",
        ];

        for p in paths {
            if Path::new(p).is_file() {
                let readable = std::fs::File::open(p).is_ok();
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Credential,
                    severity: if readable {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    title: format!("Credential-related file present: {p}"),
                    detail: if dump_allowed {
                        format!("readable={readable} (credential-dump opted in; dump scaffold not executed yet)")
                    } else {
                        format!("readable={readable} (contents not dumped; use --allow-techniques credential-dump when ROE permits)")
                    },
                    recommendation:
                        "Unattend/SAM backups often contain secrets. Handle under evidence rules; dump/exfil via --allow-techniques credential-dump when approved."
                            .into(),
                    noisy: false,
                    leaves_artifacts: false,
                });
            }
        }

        // Registry autologon indicators
        if let Some(detail) = autologon_hint()? {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Credential,
                severity: Severity::High,
                title: "AutoLogon registry configuration present".into(),
                detail,
                recommendation: "DefaultPassword in Winlogon is a classic credential leak.".into(),
                noisy: false,
                leaves_artifacts: false,
            });
        }

        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            for rel in [
                r"AppData\Roaming\Microsoft\Credentials",
                r"AppData\Local\Microsoft\Credentials",
                r".aws\credentials",
                r".azure\MSAL_TokenCache.json",
            ] {
                let p = Path::new(&userprofile).join(rel);
                if p.exists() {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Credential,
                        severity: Severity::Medium,
                        title: format!("User credential material path: {}", p.display()),
                        detail: "Path exists; not parsed by default.".into(),
                        recommendation: "Review offline with approved tooling.".into(),
                        noisy: false,
                        leaves_artifacts: false,
                    });
                }
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No common credential files found".into(),
                detail: "Checked unattend/sysprep/RegBack and user credential dirs.".into(),
                recommendation: "Expand to IIS / web.config and app-specific secrets as needed."
                    .into(),
                noisy: false,
                leaves_artifacts: false,
            });
        }

        Ok(findings)
    }
}

#[cfg(windows)]
fn autologon_hint() -> Result<Option<String>> {
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ,
    };
    unsafe {
        let sub = to_wide(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
        let mut key = ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return Ok(None);
        }
        let auto = reg_sz(key, "AutoAdminLogon");
        let user = reg_sz(key, "DefaultUserName");
        let has_pw = reg_sz(key, "DefaultPassword").is_some();
        RegCloseKey(key);
        if auto.as_deref() == Some("1") || has_pw {
            Ok(Some(format!(
                "AutoAdminLogon={auto:?} DefaultUserName={user:?} DefaultPassword_present={has_pw}"
            )))
        } else {
            Ok(None)
        }
    }
}

#[cfg(windows)]
fn reg_sz(key: windows_sys::Win32::System::Registry::HKEY, name: &str) -> Option<String> {
    use std::ptr;
    use windows_sys::Win32::System::Registry::RegQueryValueExW;
    unsafe {
        let w = to_wide(name);
        let mut ty = 0u32;
        let mut len = 0u32;
        if RegQueryValueExW(
            key,
            w.as_ptr(),
            ptr::null_mut(),
            &mut ty,
            ptr::null_mut(),
            &mut len,
        ) != 0
        {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        if RegQueryValueExW(
            key,
            w.as_ptr(),
            ptr::null_mut(),
            &mut ty,
            buf.as_mut_ptr(),
            &mut len,
        ) != 0
        {
            return None;
        }
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
fn autologon_hint() -> Result<Option<String>> {
    Ok(None)
}
