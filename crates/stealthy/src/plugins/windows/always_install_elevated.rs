use anyhow::Result;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct AlwaysInstallElevatedPlugin;

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

    fn run(&self, _ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let hklm = read_aie(true)?;
        let hkcu = read_aie(false)?;

        match (hklm, hkcu) {
            (Some(1), Some(1)) => findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Misconfiguration,
                severity: Severity::Critical,
                title: "AlwaysInstallElevated enabled (HKLM+HKCU)".into(),
                detail: "Both machine and user policies are 1 — MSI installs run elevated.".into(),
                recommendation: "Classic privesc via crafted MSI. Extremely noisy on modern EDR — operator approval required.".into(),
                noisy: true,
                leaves_artifacts: true,
            }),
            _ => findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "AlwaysInstallElevated not fully enabled".into(),
                detail: format!("HKLM={hklm:?} HKCU={hkcu:?}"),
                recommendation: "No action.".into(),
                noisy: false,
                leaves_artifacts: false,
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
        KEY_READ,
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
        if status != 0 {
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
