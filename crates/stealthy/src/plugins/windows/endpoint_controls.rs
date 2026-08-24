//! Enumerate Windows host controls that affect binary/script execution.
//!
//! Detection only: AppLocker, WDAC/CI, SmartScreen, AMSI providers, Defender/AV
//! product registry signals. Does not disable or evade controls. When ROE
//! permits, `--allow-techniques endpoint-bypass` records alternate-path intent
//! and approved-fixture validation (see docs/techniques.md).

use anyhow::Result;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};
use crate::exploit::{self, TechniqueFamily};

pub struct EndpointControlsPlugin;

impl Plugin for EndpointControlsPlugin {
    fn id(&self) -> &'static str {
        "windows.endpoint_controls"
    }
    fn name(&self) -> &'static str {
        "Endpoint / execution controls"
    }
    fn description(&self) -> &'static str {
        "Report AppLocker, WDAC, SmartScreen, AMSI, and AV/EDR registry signals"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["windows"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut blocking = false;

        if !ctx.cancelled() {
            findings.extend(applocker_findings(&mut blocking)?);
        }
        if !ctx.cancelled() {
            findings.extend(wdac_findings(&mut blocking)?);
        }
        if !ctx.cancelled() {
            findings.extend(smartscreen_findings()?);
        }
        if !ctx.cancelled() {
            findings.extend(amsi_findings(ctx)?);
        }
        if !ctx.cancelled() {
            findings.extend(defender_av_findings(ctx)?);
        }
        if !ctx.cancelled() {
            findings.extend(powershell_policy_findings()?);
        }

        if findings.is_empty() && !ctx.cancelled() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No Windows endpoint-control signals collected".into(),
                detail: "Registry queries returned no AppLocker/WDAC/SmartScreen/AMSI/AV evidence."
                    .into(),
                recommendation:
                    "Confirm registry access; use scripts/windows fallbacks if the PE cannot run."
                        .into(),
                noisy: false,
                leaves_artifacts: false,
                object: "windows-endpoint-control-registry".into(),
                condition: "no-endpoint-control-signal-collected".into(),
                ..Default::default()
            });
        }

        if blocking {
            let tech = TechniqueFamily::EndpointBypass;
            let allowed = ctx.allow_techniques.allows(tech);
            let artifact = ctx.artifact_path.as_deref();
            let artifact_text = artifact.map(|p| p.display().to_string());
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Recommendation,
                severity: Severity::Medium,
                title: "Custom PE may be constrained by host policy".into(),
                detail: "AppLocker and/or WDAC/CI policy evidence was observed.".into(),
                recommendation: exploit::endpoint_bypass_what_next(
                    allowed,
                    artifact_text.as_deref(),
                    true,
                ),
                noisy: false,
                leaves_artifacts: false,
                object: artifact_text.clone().unwrap_or_else(|| "none".into()),
                condition: if allowed {
                    "endpoint-bypass-opted-in".into()
                } else {
                    "endpoint-bypass-available".into()
                },
                technique_id: tech.id().into(),
                ..Default::default()
            });
            if allowed || ctx.auto_exploit {
                findings.push(exploit::technique_status_with_artifact(
                    self.id(),
                    tech,
                    allowed,
                    artifact,
                ));
            }
        }

        Ok(findings)
    }
}

fn applocker_findings(blocking: &mut bool) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let root = r"SOFTWARE\Policies\Microsoft\Windows\SrpV2";
    let exe = key_exists(Hive::LocalMachine, &format!(r"{root}\Exe"));
    let script = key_exists(Hive::LocalMachine, &format!(r"{root}\Script"));
    let msi = key_exists(Hive::LocalMachine, &format!(r"{root}\Msi"));
    let dll = key_exists(Hive::LocalMachine, &format!(r"{root}\Dll"));
    let appx = key_exists(Hive::LocalMachine, &format!(r"{root}\Appx"));

    if exe || script || msi || dll || appx {
        *blocking = true;
        out.push(Finding {
            plugin: "windows.endpoint_controls".into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Medium,
            title: "AppLocker policy keys present".into(),
            detail: format!(
                "SrpV2 rule collections observed: Exe={exe} Script={script} Msi={msi} Dll={dll} Appx={appx}"
            ),
            recommendation: "Custom .exe may be denied. Prefer script fallbacks allowlisted by policy, or an approved signed host binary.".into(),
            noisy: false,
            leaves_artifacts: false,
            object: format!(r"HKLM\{root}"),
            condition: "applocker-policy-key-present".into(),
            ..Default::default()
        });
    } else {
        out.push(Finding {
            plugin: "windows.endpoint_controls".into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Info,
            title: "AppLocker SrpV2 policy keys not found".into(),
            detail: format!(r"HKLM\{root}\{{Exe,Script,Msi,Dll,Appx}} absent or unreadable."),
            recommendation:
                "Still check local SRP / WDAC; absence here is not proof of no controls.".into(),
            noisy: false,
            leaves_artifacts: false,
            object: format!(r"HKLM\{root}"),
            condition: "applocker-policy-key-absent-or-unreadable".into(),
            ..Default::default()
        });
    }
    Ok(out)
}

fn wdac_findings(blocking: &mut bool) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let ci_policy = key_exists(
        Hive::LocalMachine,
        r"SYSTEM\CurrentControlSet\Control\CI\Policy",
    );
    let device_guard = read_u32(
        Hive::LocalMachine,
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
        "EnableVirtualizationBasedSecurity",
    )?;
    let hvci = read_u32(
        Hive::LocalMachine,
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
        "Enabled",
    )?;
    let umci = read_u32(
        Hive::LocalMachine,
        r"SYSTEM\CurrentControlSet\Control\CI",
        "VulnerableDriverBlocklistEnable",
    )?;

    if ci_policy || device_guard == Some(1) || hvci == Some(1) {
        *blocking = true;
        out.push(Finding {
            plugin: "windows.endpoint_controls".into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Medium,
            title: "WDAC / Code Integrity signals present".into(),
            detail: format!(
                "CI\\Policy key={ci_policy}; VBS={device_guard:?}; HVCI={hvci:?}; VulnerableDriverBlocklist={umci:?}"
            ),
            recommendation: "WDAC/CI can block unsigned PEs. Prefer allowlisted script hosts or ROE-approved signed builds.".into(),
            noisy: false,
            leaves_artifacts: false,
            object: r"HKLM\SYSTEM\CurrentControlSet\Control\CI".into(),
            condition: "wdac-code-integrity-signal-present".into(),
            ..Default::default()
        });
    } else {
        out.push(Finding {
            plugin: "windows.endpoint_controls".into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Info,
            title: "No strong WDAC/CI policy signals".into(),
            detail: format!("CI\\Policy={ci_policy}; VBS={device_guard:?}; HVCI={hvci:?}"),
            recommendation:
                "Informational; confirm with Get-CIPolicy / enterprise inventory when available."
                    .into(),
            noisy: false,
            leaves_artifacts: false,
            object: r"HKLM\SYSTEM\CurrentControlSet\Control\CI".into(),
            condition: "no-strong-wdac-signal".into(),
            ..Default::default()
        });
    }
    Ok(out)
}

fn smartscreen_findings() -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let enabled = read_string(
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        "SmartScreenEnabled",
    )?;
    let shell = read_u32(
        Hive::LocalMachine,
        r"SOFTWARE\Policies\Microsoft\Windows\System",
        "EnableSmartScreen",
    )?;
    let detail =
        format!("Explorer.SmartScreenEnabled={enabled:?}; Policies.EnableSmartScreen={shell:?}");
    let active = matches!(
        enabled.as_deref(),
        Some("RequireAdmin") | Some("Warn") | Some("On")
    ) || shell == Some(1);
    out.push(Finding {
        plugin: "windows.endpoint_controls".into(),
        kind: FindingKind::Enumeration,
        severity: if active {
            Severity::Low
        } else {
            Severity::Info
        },
        title: if active {
            "SmartScreen appears enabled".into()
        } else {
            "SmartScreen policy soft/absent".into()
        },
        detail,
        recommendation: "SmartScreen may warn or block unmarked downloads. Prefer checksum-verified install from an approved channel.".into(),
        noisy: false,
        leaves_artifacts: false,
        object: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SmartScreenEnabled"
            .into(),
        condition: if active {
            "smartscreen-active-signal"
        } else {
            "smartscreen-soft-or-absent"
        }
        .into(),
        ..Default::default()
    });
    Ok(out)
}

fn amsi_findings(ctx: &PluginContext<'_>) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let providers = list_subkeys(
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\AMSI\Providers",
        ctx,
    )?;
    if providers.is_empty() {
        out.push(Finding {
            plugin: "windows.endpoint_controls".into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Info,
            title: "No AMSI providers enumerated".into(),
            detail: r"HKLM\SOFTWARE\Microsoft\AMSI\Providers empty or unreadable.".into(),
            recommendation:
                "Script hosts may still load AMSI; treat script fallbacks as auditable.".into(),
            noisy: false,
            leaves_artifacts: false,
            object: r"HKLM\SOFTWARE\Microsoft\AMSI\Providers".into(),
            condition: "no-amsi-provider-enumerated".into(),
            ..Default::default()
        });
    } else {
        out.push(Finding {
            plugin: "windows.endpoint_controls".into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Low,
            title: format!("AMSI providers registered ({})", providers.len()),
            detail: truncate(&providers.join(", "), 300),
            recommendation: "AMSI inspects script content. Prefer approved script hosts; do not attempt AMSI disable/patch in this tool.".into(),
            noisy: false,
            leaves_artifacts: false,
            object: r"HKLM\SOFTWARE\Microsoft\AMSI\Providers".into(),
            condition: "amsi-provider-registered".into(),
            ..Default::default()
        });
    }
    Ok(out)
}

fn defender_av_findings(ctx: &PluginContext<'_>) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let disable = read_u32(
        Hive::LocalMachine,
        r"SOFTWARE\Policies\Microsoft\Windows Defender",
        "DisableAntiSpyware",
    )?;
    let realtime = read_u32(
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        "DisableRealtimeMonitoring",
    )?;
    out.push(Finding {
        plugin: "windows.endpoint_controls".into(),
        kind: FindingKind::Enumeration,
        severity: Severity::Info,
        title: "Windows Defender policy signals".into(),
        detail: format!("DisableAntiSpyware={disable:?}; DisableRealtimeMonitoring={realtime:?}"),
        recommendation: "Presence of Defender policy keys indicates AV context; do not attempt to disable AV/EDR from this tool.".into(),
        noisy: false,
        leaves_artifacts: false,
        object: r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender".into(),
        condition: "defender-policy-signals-collected".into(),
        ..Default::default()
    });

    // Lightweight product-name hints from uninstall registry (read-only, capped).
    let mut products = Vec::new();
    for root in [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ] {
        if ctx.cancelled() {
            break;
        }
        for sub in list_subkeys(Hive::LocalMachine, root, ctx)?
            .into_iter()
            .take(200)
        {
            if ctx.cancelled() {
                break;
            }
            let path = format!(r"{root}\{sub}");
            if let Some(name) = read_string(Hive::LocalMachine, &path, "DisplayName")? {
                let lower = name.to_ascii_lowercase();
                if lower.contains("defender")
                    || lower.contains("crowdstrike")
                    || lower.contains("falcon")
                    || lower.contains("sentinel")
                    || lower.contains("carbon black")
                    || lower.contains("cylance")
                    || lower.contains("symantec")
                    || lower.contains("norton")
                    || lower.contains("mcafee")
                    || lower.contains("kaspersky")
                    || lower.contains("eset")
                    || lower.contains("trend micro")
                    || lower.contains("sophos")
                    || lower.contains("bitdefender")
                    || lower.contains("cortex")
                    || lower.contains("xdr")
                    || lower.contains("edr")
                {
                    products.push(name);
                }
            }
        }
    }
    products.sort();
    products.dedup();
    if products.is_empty() {
        out.push(Finding {
            plugin: "windows.endpoint_controls".into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Info,
            title: "No well-known AV/EDR products in uninstall keys".into(),
            detail: "Heuristic DisplayName scan found no matching vendor strings.".into(),
            recommendation:
                "Absence from uninstall keys is not proof of no EDR; confirm with asset inventory."
                    .into(),
            noisy: true,
            leaves_artifacts: false,
            object: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall".into(),
            condition: "no-known-av-product-signal".into(),
            ..Default::default()
        });
    } else {
        out.push(Finding {
            plugin: "windows.endpoint_controls".into(),
            kind: FindingKind::Enumeration,
            severity: Severity::Low,
            title: format!("AV/EDR product signals ({})", products.len()),
            detail: truncate(&products.join("; "), 400),
            recommendation: "Expect telemetry on PE drops and script hosts. Prefer approved channels; do not attempt AV/EDR disable from this tool.".into(),
            noisy: true,
            leaves_artifacts: false,
            object: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall".into(),
            condition: "av-edr-product-signal-present".into(),
            ..Default::default()
        });
    }
    Ok(out)
}

fn powershell_policy_findings() -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let exec = read_string(
        Hive::LocalMachine,
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell",
        "ExecutionPolicy",
    )?;
    let machine = read_string(
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell",
        "ExecutionPolicy",
    )?;
    out.push(Finding {
        plugin: "windows.endpoint_controls".into(),
        kind: FindingKind::Enumeration,
        severity: Severity::Info,
        title: "PowerShell execution policy signals".into(),
        detail: format!("Policies.ExecutionPolicy={exec:?}; ShellIds={machine:?}"),
        recommendation: "If powershell.exe is constrained, use enum.js / cscript or MSBuild EnumTasks when those hosts are allowlisted.".into(),
        noisy: false,
        leaves_artifacts: false,
        object: r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell".into(),
        condition: "powershell-execution-policy-signal".into(),
        ..Default::default()
    });
    Ok(out)
}

fn truncate(s: &str, max: usize) -> String {
    let mut chars = s.chars();
    let prefix: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

#[derive(Clone, Copy)]
enum Hive {
    LocalMachine,
}

#[cfg(windows)]
fn key_exists(hive: Hive, subkey: &str) -> bool {
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ,
    };
    unsafe {
        let root = match hive {
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
        };
        let sub = to_wide(subkey);
        let mut key = ptr::null_mut();
        let status = RegOpenKeyExW(root, sub.as_ptr(), 0, KEY_READ, &mut key);
        if status == 0 {
            RegCloseKey(key);
            true
        } else {
            false
        }
    }
}

#[cfg(not(windows))]
fn key_exists(_hive: Hive, _subkey: &str) -> bool {
    false
}

#[cfg(windows)]
fn read_u32(hive: Hive, subkey: &str, value: &str) -> Result<Option<u32>> {
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD,
    };
    unsafe {
        let root = match hive {
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
        };
        let sub = to_wide(subkey);
        let mut key = ptr::null_mut();
        if RegOpenKeyExW(root, sub.as_ptr(), 0, KEY_READ, &mut key) != 0 {
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
        if status != 0 || ty != REG_DWORD {
            Ok(None)
        } else {
            Ok(Some(data))
        }
    }
}

#[cfg(not(windows))]
fn read_u32(_hive: Hive, _subkey: &str, _value: &str) -> Result<Option<u32>> {
    Ok(None)
}

#[cfg(windows)]
#[allow(clippy::chunks_exact_to_as_chunks)]
fn read_string(hive: Hive, subkey: &str, value: &str) -> Result<Option<String>> {
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_EXPAND_SZ,
        REG_SZ,
    };
    unsafe {
        let root = match hive {
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
        };
        let sub = to_wide(subkey);
        let mut key = ptr::null_mut();
        if RegOpenKeyExW(root, sub.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return Ok(None);
        }
        let name = to_wide(value);
        let mut ty = 0u32;
        let mut len = 0u32;
        let probe = RegQueryValueExW(
            key,
            name.as_ptr(),
            ptr::null_mut(),
            &mut ty,
            ptr::null_mut(),
            &mut len,
        );
        if probe != 0 || len == 0 {
            RegCloseKey(key);
            return Ok(None);
        }
        let mut buf = vec![0u8; len as usize];
        let status = RegQueryValueExW(
            key,
            name.as_ptr(),
            ptr::null_mut(),
            &mut ty,
            buf.as_mut_ptr(),
            &mut len,
        );
        RegCloseKey(key);
        if status != 0 || (ty != REG_SZ && ty != REG_EXPAND_SZ) {
            return Ok(None);
        }
        let u16s: Vec<u16> = buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|c| *c != 0)
            .collect();
        Ok(Some(String::from_utf16_lossy(&u16s)))
    }
}

#[cfg(not(windows))]
fn read_string(_hive: Hive, _subkey: &str, _value: &str) -> Result<Option<String>> {
    Ok(None)
}

#[cfg(windows)]
fn list_subkeys(hive: Hive, subkey: &str, ctx: &PluginContext<'_>) -> Result<Vec<String>> {
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryInfoKeyW, HKEY_LOCAL_MACHINE, KEY_READ,
    };
    unsafe {
        let root = match hive {
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
        };
        let sub = to_wide(subkey);
        let mut key = ptr::null_mut();
        if RegOpenKeyExW(root, sub.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return Ok(Vec::new());
        }
        let mut count = 0u32;
        let mut max_name = 0u32;
        let info = RegQueryInfoKeyW(
            key,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut count,
            &mut max_name,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if info != 0 {
            RegCloseKey(key);
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut name = vec![0u16; (max_name as usize) + 2];
        for i in 0..count {
            if ctx.cancelled() {
                break;
            }
            let mut name_len = name.len() as u32;
            let status = RegEnumKeyExW(
                key,
                i,
                name.as_mut_ptr(),
                &mut name_len,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if status != 0 {
                continue;
            }
            out.push(String::from_utf16_lossy(&name[..name_len as usize]));
        }
        RegCloseKey(key);
        Ok(out)
    }
}

#[cfg(not(windows))]
fn list_subkeys(_hive: Hive, _subkey: &str, _ctx: &PluginContext<'_>) -> Result<Vec<String>> {
    Ok(Vec::new())
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
