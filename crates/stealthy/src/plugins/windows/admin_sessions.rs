use anyhow::Result;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct AdminSessionsPlugin;

impl Plugin for AdminSessionsPlugin {
    fn id(&self) -> &'static str {
        "windows.admin_sessions"
    }
    fn name(&self) -> &'static str {
        "Local Administrators / sessions"
    }
    fn description(&self) -> &'static str {
        "Identify local Administrators group membership and interactive session clues"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["windows"]
    }

    fn run(&self, _ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        match local_admins() {
            Ok(members) => {
                if members.is_empty() {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Enumeration,
                        severity: Severity::Info,
                        title: "Local Administrators enumeration returned no members".into(),
                        detail: "API succeeded but list empty — unexpected on most hosts.".into(),
                        recommendation: "Cross-check with scripts/windows/enum.ps1.".into(),
                        noisy: false,
                        leaves_artifacts: false,
                        ..Default::default()
                    });
                }
                for m in members {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Enumeration,
                        severity: Severity::Low,
                        title: format!("Local Administrators member: {m}"),
                        detail: m,
                        recommendation:
                            "Cross-check for active sessions / tokens of these principals.".into(),
                        noisy: false,
                        leaves_artifacts: false,
                        ..Default::default()
                    });
                }
            }
            Err(e) => {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Enumeration,
                    severity: Severity::Info,
                    title: "Could not enumerate local Administrators via NetAPI".into(),
                    detail: e.to_string(),
                    recommendation: "Use scripts/windows/enum.ps1 (Get-LocalGroupMember) when PowerShell is allowed."
                        .into(),
                    noisy: false,
                    leaves_artifacts: false,
                    ..Default::default()
                });
            }
        }

        if let Ok(session) = std::env::var("SESSIONNAME") {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: format!("SESSIONNAME={session}"),
                detail: "Environment session hint.".into(),
                recommendation: "Interactive sessions of admins may enable token impersonation if SeImpersonate is held."
                    .into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }

        if let Ok(user) = std::env::var("USERNAME") {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: format!("Current USERNAME={user}"),
                detail: std::env::var("USERDOMAIN").unwrap_or_default(),
                recommendation: "Compare against Administrators membership list.".into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No admin/session findings".into(),
                detail: "Enumeration returned empty.".into(),
                recommendation: "Retry with elevated context or script fallback.".into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

#[cfg(windows)]
fn local_admins() -> Result<Vec<String>> {
    use std::ptr;
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NetApiBufferFree, NetLocalGroupGetMembers, MAX_PREFERRED_LENGTH,
    };

    // LOCALGROUP_MEMBERS_INFO_3 layout: single PWSTR domainandname pointer.
    #[repr(C)]
    struct LocalGroupMembersInfo3 {
        domainandname: *mut u16,
    }

    unsafe {
        let group = to_wide("Administrators");
        let mut buf: *mut u8 = ptr::null_mut();
        let mut entries = 0u32;
        let mut total = 0u32;
        let mut resume = 0usize;
        let status = NetLocalGroupGetMembers(
            ptr::null(),
            group.as_ptr(),
            3,
            &mut buf,
            MAX_PREFERRED_LENGTH,
            &mut entries,
            &mut total,
            &mut resume,
        );
        if status != 0 {
            anyhow::bail!("NetLocalGroupGetMembers failed with status {status}");
        }
        let mut out = Vec::new();
        if !buf.is_null() && entries > 0 {
            let slice =
                std::slice::from_raw_parts(buf as *const LocalGroupMembersInfo3, entries as usize);
            for m in slice {
                if m.domainandname.is_null() {
                    continue;
                }
                let mut len = 0usize;
                while *m.domainandname.add(len) != 0 {
                    len += 1;
                    if len > 512 {
                        break;
                    }
                }
                let name =
                    String::from_utf16_lossy(std::slice::from_raw_parts(m.domainandname, len));
                out.push(name);
            }
            NetApiBufferFree(buf as *mut _);
        }
        Ok(out)
    }
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(not(windows))]
fn local_admins() -> Result<Vec<String>> {
    Ok(vec![])
}
