use anyhow::Result;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct PrivilegesPlugin;

impl Plugin for PrivilegesPlugin {
    fn id(&self) -> &'static str {
        "windows.privileges"
    }
    fn name(&self) -> &'static str {
        "Token privileges"
    }
    fn description(&self) -> &'static str {
        "Enumerate SeImpersonate / SeDebug / SeBackup and related privileges"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["windows"]
    }

    fn run(&self, _ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        match enumerate_privileges() {
            Ok(privs) => {
                let interesting = [
                    "SeImpersonatePrivilege",
                    "SeAssignPrimaryTokenPrivilege",
                    "SeDebugPrivilege",
                    "SeBackupPrivilege",
                    "SeRestorePrivilege",
                    "SeTakeOwnershipPrivilege",
                    "SeLoadDriverPrivilege",
                    "SeTcbPrivilege",
                ];
                for p in &privs {
                    let high = interesting.iter().any(|i| p.name == *i);
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Enumeration,
                        severity: if high && p.enabled {
                            Severity::High
                        } else if high {
                            Severity::Medium
                        } else {
                            Severity::Info
                        },
                        title: format!("Privilege {} (enabled={})", p.name, p.enabled),
                        detail: p.name.clone(),
                        recommendation: if p.name == "SeImpersonatePrivilege" && p.enabled {
                            "Potato-family / GodPotato-style techniques may apply — use only with approval; high EDR visibility.".into()
                        } else if high {
                            "Review abuse potential for this privilege; prefer manual operator judgment.".into()
                        } else {
                            "Informational.".into()
                        },
                        noisy: false,
                        leaves_artifacts: false,
                    });
                }
                let potato = privs.iter().any(|p| {
                    p.enabled
                        && (p.name == "SeImpersonatePrivilege"
                            || p.name == "SeAssignPrimaryTokenPrivilege")
                });
                if potato {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Recommendation,
                        severity: Severity::High,
                        title: "Potato-family token impersonation opportunity".into(),
                        detail: "SeImpersonate and/or SeAssignPrimaryToken is enabled on this token."
                            .into(),
                        recommendation: "Manual review for JuicyPotato/RoguePotato/GodPotato-class techniques if ROE allows. High EDR visibility — never auto-executed by this tool."
                            .into(),
                        noisy: false,
                        leaves_artifacts: false,
                    });
                }

                if privs.is_empty() {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Enumeration,
                        severity: Severity::Info,
                        title: "No privileges returned".into(),
                        detail: "Token privilege enumeration returned empty.".into(),
                        recommendation: "Verify process token access rights.".into(),
                        noisy: false,
                        leaves_artifacts: false,
                    });
                }
            }
            Err(e) => {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Enumeration,
                    severity: Severity::Low,
                    title: "Privilege enumeration failed".into(),
                    detail: e.to_string(),
                    recommendation: "Fall back to whoami /priv via script agents if permitted."
                        .into(),
                    noisy: false,
                    leaves_artifacts: false,
                });
            }
        }

        Ok(findings)
    }
}

struct Priv {
    name: String,
    enabled: bool,
}

#[cfg(windows)]
fn enumerate_privileges() -> Result<Vec<Priv>> {
    use std::mem;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, LookupPrivilegeNameW, TokenPrivileges, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == FALSE {
            anyhow::bail!("OpenProcessToken failed");
        }

        let mut len = 0u32;
        GetTokenInformation(token, TokenPrivileges, ptr::null_mut(), 0, &mut len);

        let mut buf = vec![0u8; len as usize];
        if GetTokenInformation(
            token,
            TokenPrivileges,
            buf.as_mut_ptr() as *mut _,
            len,
            &mut len,
        ) == FALSE
        {
            CloseHandle(token);
            anyhow::bail!("GetTokenInformation failed");
        }

        let tp = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
        let count = tp.PrivilegeCount as usize;
        let mut out = Vec::with_capacity(count);

        for i in 0..count {
            let la = &*tp.Privileges.as_ptr().add(i);
            let mut name_len = 256u32;
            let mut name = vec![0u16; name_len as usize];
            if LookupPrivilegeNameW(ptr::null(), &la.Luid, name.as_mut_ptr(), &mut name_len) == 0 {
                continue;
            }
            let name = String::from_utf16_lossy(&name[..name_len as usize]);
            let enabled = la.Attributes & 0x2 != 0; // SE_PRIVILEGE_ENABLED
            out.push(Priv { name, enabled });
        }

        CloseHandle(token);
        let _ = mem::size_of::<TOKEN_PRIVILEGES>();
        Ok(out)
    }
}

#[cfg(not(windows))]
fn enumerate_privileges() -> Result<Vec<Priv>> {
    Ok(vec![])
}
