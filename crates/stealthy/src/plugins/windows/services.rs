use anyhow::Result;

use crate::core::plugin::{Plugin, PluginContext};
use crate::core::types::{Finding, FindingKind, Severity};

pub struct ServicesPlugin;

impl Plugin for ServicesPlugin {
    fn id(&self) -> &'static str {
        "windows.services"
    }
    fn name(&self) -> &'static str {
        "Service misconfigurations"
    }
    fn description(&self) -> &'static str {
        "Unquoted service paths and writable service binaries (quiet registry/file checks)"
    }
    fn platforms(&self) -> &'static [&'static str] {
        &["windows"]
    }

    fn run(&self, ctx: &mut PluginContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (name, image_path, account) in list_service_image_paths()? {
            if is_unquoted_path(&image_path) {
                findings.push(Finding {
                    plugin: self.id().into(),
                    kind: FindingKind::Misconfiguration,
                    severity: Severity::High,
                    title: format!("Unquoted service path: {name}"),
                    detail: format!("account={account} image_path={image_path}"),
                    recommendation: "Unquoted paths with spaces can allow binary planting in parent dirs if writable. Verify the service account and directory ACLs under the approved scope.".into(),
                    noisy: false,
                    leaves_artifacts: false,
                    ..Default::default()
                });

                if let Some(bin) = super::executable_path(&image_path) {
                    for parent in unquoted_plant_dirs(&bin) {
                        findings.push(Finding {
                            plugin: self.id().into(),
                            kind: FindingKind::Recommendation,
                            severity: Severity::Medium,
                            title: format!("Unquoted plant candidate dir ({name}): {parent}"),
                            detail: "Verify ACLs on this intermediate directory.".into(),
                            recommendation: "If writable by low-priv users, plant a matching .exe name ahead of the real binary."
                                .into(),
                            noisy: false,
                            leaves_artifacts: false,
                            ..Default::default()
                        });
                        if ctx.auto_exploit {
                            let p = std::path::Path::new(&parent);
                            if p.is_dir() {
                                if let Ok(true) = crate::exploit::writable_probe(p) {
                                    findings.push(Finding {
                                        plugin: self.id().into(),
                                        kind: FindingKind::ExploitAttempt,
                                        severity: Severity::Critical,
                                        title: format!(
                                            "Confirmed writable unquoted parent ({name}): {parent}"
                                        ),
                                        detail: "Reversible marker write/delete succeeded.".into(),
                                        recommendation: "Planting/replacing service binaries requires ROE approval (--allow-techniques service-replace)."
                                            .into(),
                                        noisy: true,
                                        leaves_artifacts: false,
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }
            }

            if let Some(bin) = super::executable_path(&image_path) {
                if super::acl::is_writable_for_current_user(std::path::Path::new(&bin))
                    .unwrap_or(false)
                {
                    findings.push(Finding {
                        plugin: self.id().into(),
                        kind: FindingKind::Misconfiguration,
                        severity: Severity::Critical,
                        title: format!("Writable service binary: {name}"),
                        detail: format!("account={account} binary={bin}"),
                        recommendation: "Replacing a service binary is high-impact and noisy — opt in with --allow-techniques service-replace when ROE permits.".into(),
                        noisy: false,
                        leaves_artifacts: true,
                        ..Default::default()
                    });
                    let tech = crate::exploit::TechniqueFamily::ServiceReplace;
                    let allowed = ctx.allow_techniques.allows(tech);
                    if allowed || ctx.auto_exploit {
                        findings.push(crate::exploit::technique_status(self.id(), tech, allowed));
                    }
                }
            }
        }

        if findings.is_empty() {
            findings.push(Finding {
                plugin: self.id().into(),
                kind: FindingKind::Enumeration,
                severity: Severity::Info,
                title: "No unquoted/writable service issues found in scan".into(),
                detail: "Enumerated service ImagePath values from the SCM/registry.".into(),
                recommendation:
                    "Also review service DACLs with accesschk when permitted (SDDL enum deferred)."
                        .into(),
                noisy: false,
                leaves_artifacts: false,
                ..Default::default()
            });
        }

        Ok(findings)
    }
}

/// Intermediate directories that Windows may search for an unquoted spaced path.
fn unquoted_plant_dirs(bin: &str) -> Vec<String> {
    // Example: C:\Program Files\Vendor\svc.exe → try "C:\Program.exe" plant via "C:\"
    // and "C:\Program Files\Vendor" parents that exist before the final component.
    let mut out = Vec::new();
    let normalized = bin.replace('/', "\\");
    if !normalized.contains(' ') {
        return out;
    }
    // For each space-separated prefix that looks like a path root, add its parent.
    // Practical approach: walk parents of the resolved path and also the truncated
    // "C:\Program" style prefix commonly abused.
    if let Some(parent) = std::path::Path::new(&normalized).parent() {
        out.push(parent.to_string_lossy().to_string());
        if let Some(gp) = parent.parent() {
            out.push(gp.to_string_lossy().to_string());
        }
    }
    // Classic: path starts with "C:\Program Files\..." → "C:\" is plant root for Program.exe
    if let Some(idx) = normalized.find(' ') {
        let prefix = &normalized[..idx];
        if let Some(parent) = std::path::Path::new(prefix).parent() {
            out.push(parent.to_string_lossy().to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

fn is_unquoted_path(image: &str) -> bool {
    let trimmed = image.trim();
    if trimmed.starts_with('"') {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    [".exe", ".com", ".bat", ".cmd"]
        .iter()
        .filter_map(|extension| lower.find(extension))
        .min()
        .map(|end| trimmed[..end].chars().any(char::is_whitespace))
        .unwrap_or(false)
}

#[cfg(windows)]
fn list_service_image_paths() -> Result<Vec<(String, String, String)>> {
    use std::ptr;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    let mut out = Vec::new();
    unsafe {
        let sub = to_wide(r"SYSTEM\CurrentControlSet\Services");
        let mut hkey = ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            anyhow::bail!("RegOpenKeyExW Services failed");
        }

        let mut index = 0u32;
        loop {
            let mut name_buf = vec![0u16; 256];
            let mut name_len = name_buf.len() as u32;
            let status = RegEnumKeyExW(
                hkey,
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if status != 0 {
                break;
            }
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let path_key = to_wide(&format!(r"SYSTEM\CurrentControlSet\Services\{name}"));
            let mut sk = ptr::null_mut();
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, path_key.as_ptr(), 0, KEY_READ, &mut sk) == 0 {
                if let Some(val) = reg_query_string(sk, "ImagePath") {
                    let account = reg_query_string(sk, "ObjectName")
                        .unwrap_or_else(|| "(service account unavailable)".into());
                    out.push((name, val, account));
                }
                RegCloseKey(sk);
            }
            index += 1;
            if index > 2000 {
                break;
            }
        }
        RegCloseKey(hkey);
    }
    Ok(out)
}

#[cfg(windows)]
fn reg_query_string(
    hkey: windows_sys::Win32::System::Registry::HKEY,
    name: &str,
) -> Option<String> {
    use std::ptr;
    use windows_sys::Win32::System::Registry::RegQueryValueExW;
    unsafe {
        let wname = to_wide(name);
        let mut ty = 0u32;
        let mut len = 0u32;
        if RegQueryValueExW(
            hkey,
            wname.as_ptr(),
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
            hkey,
            wname.as_ptr(),
            ptr::null_mut(),
            &mut ty,
            buf.as_mut_ptr(),
            &mut len,
        ) != 0
        {
            return None;
        }
        // REG_SZ / REG_EXPAND_SZ
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
fn list_service_image_paths() -> Result<Vec<(String, String, String)>> {
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::is_unquoted_path;

    #[test]
    fn detects_unquoted_spaced_service_paths() {
        assert!(is_unquoted_path(
            r"C:\Program Files\Vendor\service.exe -k run"
        ));
        assert!(!is_unquoted_path(
            r#""C:\Program Files\Vendor\service.exe" -k run"#
        ));
        assert!(!is_unquoted_path(r"C:\Windows\System32\service.exe"));
    }
}
