use anyhow::Result;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};
use crate::exploit::{self, TechniqueFamily};

pub struct AlwaysInstallElevatedPlugin;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyState {
    FullyEnabled,
    PartiallyEnabled,
    Disabled,
    Unknown,
}

impl PolicyState {
    #[cfg(test)]
    fn as_str(self) -> &'static str {
        match self {
            Self::FullyEnabled => "fully_enabled",
            Self::PartiallyEnabled => "partially_enabled",
            Self::Disabled => "disabled",
            Self::Unknown => "unknown",
        }
    }
}

fn classify_policy(hklm: Option<u32>, hkcu: Option<u32>) -> PolicyState {
    match (hklm, hkcu) {
        (Some(1), Some(1)) => PolicyState::FullyEnabled,
        (Some(_), Some(_)) if hklm == Some(1) || hkcu == Some(1) => PolicyState::PartiallyEnabled,
        (Some(_), Some(_)) => PolicyState::Disabled,
        _ => PolicyState::Unknown,
    }
}

impl Plugin for AlwaysInstallElevatedPlugin {
    fn id(&self) -> &'static str {
        "windows.always_install_elevated"
    }
    fn name(&self) -> &'static str {
        "AlwaysInstallElevated"
    }
    fn description(&self) -> &'static str {
        "Check HKLM/HKCU AlwaysInstallElevated installer policy"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["windows"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let hklm = read_aie(true)?;
        let hkcu = read_aie(false)?;

        let state = classify_policy(hklm, hkcu);

        match state {
            PolicyState::FullyEnabled => {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Misconfiguration,
                    severity: Severity::Critical,
                    title: "AlwaysInstallElevated enabled (HKLM+HKCU)".into(),
                    detail: "Both machine and user policies are 1 — MSI installs run elevated.".into(),
                    recommendation: "Classic privesc via crafted MSI. Extremely noisy on modern EDR — opt in with --allow-techniques msi when ROE permits.".into(),
                    noisy: true,
                    leaves_artifacts: true,
                    object: r"HKLM+HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated".into(),
                    condition: "always-install-elevated-fully-enabled".into(),
                    ..Default::default()
                });
                let msi = TechniqueFamily::Msi;
                let allowed = ctx.allow_techniques.allows(msi);
                if allowed || ctx.auto_exploit {
                    findings.push(exploit::technique_status(self.id(), msi, allowed));
                }
            }
            PolicyState::PartiallyEnabled => findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Misconfiguration,
                severity: Severity::Low,
                title: "AlwaysInstallElevated policy is only partially enabled".into(),
                detail: format!("HKLM={hklm:?} HKCU={hkcu:?}; both values must equal 1 for the elevation condition"),
                recommendation: "Disable the enabled half to remove the inconsistent installer policy. No MSI was created or executed."
                    .into(),
                noisy: false,
                leaves_artifacts: false,
                object: r"HKLM+HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated".into(),
                condition: "always-install-elevated-partially-enabled".into(),
                ..Default::default()
            }),
            PolicyState::Disabled => findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "AlwaysInstallElevated is disabled".into(),
                detail: format!("HKLM={hklm:?} HKCU={hkcu:?}"),
                recommendation: "No action.".into(),
                noisy: false,
                leaves_artifacts: false,
                object: r"HKLM+HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated".into(),
                condition: "always-install-elevated-disabled".into(),
                ..Default::default()
            }),
            PolicyState::Unknown => findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "AlwaysInstallElevated state is incomplete".into(),
                detail: format!("HKLM={hklm:?} HKCU={hkcu:?}; at least one policy value was absent or unreadable"),
                recommendation: "Treat the condition as unknown, not disabled; verify both policy hives from an approved context."
                    .into(),
                noisy: false,
                leaves_artifacts: false,
                object: r"HKLM+HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated".into(),
                condition: "always-install-elevated-state-unknown".into(),
                ..Default::default()
            }),
        }

        Ok(findings)
    }
}

#[cfg(windows)]
fn read_aie(hklm: bool) -> Result<Option<u32>> {
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
        KEY_READ, REG_DWORD,
    };

    unsafe {
        let root = if hklm {
            HKEY_LOCAL_MACHINE
        } else {
            HKEY_CURRENT_USER
        };
        let sub = to_wide(r"SOFTWARE\Policies\Microsoft\Windows\Installer");
        let mut key = ptr::null_mut();
        if RegOpenKeyExW(root, sub.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return Ok(None);
        }
        let name = to_wide("AlwaysInstallElevated");
        let mut ty = 0u32;
        let mut data: u32 = 0;
        let mut len = 4u32;
        let status = RegQueryValueExW(
            key,
            name.as_ptr(),
            ptr::null_mut(),
            &mut ty,
            &mut data as *mut u32 as *mut u8,
            &mut len,
        );
        RegCloseKey(key);
        if status != 0 || ty != REG_DWORD || len != std::mem::size_of::<u32>() as u32 {
            return Ok(None);
        }
        Ok(Some(data))
    }
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(not(windows))]
fn read_aie(_hklm: bool) -> Result<Option<u32>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::classify_policy;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct PolicyFixture {
        hklm: Option<u32>,
        hkcu: Option<u32>,
        expected: String,
    }

    #[test]
    fn golden_registry_state_classification() {
        let fixtures: Vec<PolicyFixture> = serde_json::from_str(include_str!(
            "../../../tests/fixtures/windows/always_install_elevated_cases.json"
        ))
        .unwrap();
        for fixture in fixtures {
            assert_eq!(
                classify_policy(fixture.hklm, fixture.hkcu).as_str(),
                fixture.expected
            );
        }
    }
}
