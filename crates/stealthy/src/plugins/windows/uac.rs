use anyhow::Result;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct UacPlugin;

impl Plugin for UacPlugin {
    fn id(&self) -> &'static str {
        "windows.uac"
    }
    fn name(&self) -> &'static str {
        "UAC settings"
    }
    fn description(&self) -> &'static str {
        "Enumerate EnableLUA / ConsentPromptBehaviorAdmin and related UAC policies"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["windows"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let keys = [
            ("EnableLUA", "UAC master switch (0 = disabled)"),
            (
                "ConsentPromptBehaviorAdmin",
                "Admin consent prompt behavior",
            ),
            ("ConsentPromptBehaviorUser", "User consent prompt behavior"),
            ("FilterToken", "Admin approval mode filtering"),
            (
                "LocalAccountTokenFilterPolicy",
                "Remote UAC filtering for local accounts",
            ),
        ];

        for (name, desc) in keys {
            if ctx.cancelled() {
                break;
            }
            if let Some(v) = read_u32(name)? {
                let severity = match (name, v) {
                    ("EnableLUA", 0) => Severity::High,
                    ("ConsentPromptBehaviorAdmin", 0) => Severity::Medium,
                    ("LocalAccountTokenFilterPolicy", 1) => Severity::Medium,
                    _ => Severity::Info,
                };
                findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Enumeration,
                        severity,
                        title: format!("UAC {name}={v}"),
                        detail: desc.into(),
                        recommendation: "Weak UAC settings enable auto-elevation / token abuse paths; validate against hardening baselines.".into(),
                        noisy: false,
                        leaves_artifacts: false,
                        object: format!(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\{name}"),
                        condition: format!("uac-policy-value:{v}"),
                        ..Default::default()
                    });
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "Unable to read UAC policy values".into(),
                detail: "Registry queries returned no values.".into(),
                recommendation: "Confirm registry access; use script fallback if needed.".into(),
                noisy: false,
                leaves_artifacts: false,
                object: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System".into(),
                condition: "no-uac-policy-value-readable".into(),
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

#[cfg(windows)]
fn read_u32(value: &str) -> Result<Option<u32>> {
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
    };
    unsafe {
        let sub = to_wide(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
        let mut key = ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return Ok(None);
        }
        let name = to_wide(value);
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
            Ok(None)
        } else {
            Ok(Some(data))
        }
    }
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(not(windows))]
fn read_u32(_value: &str) -> Result<Option<u32>> {
    Ok(None)
}
